//! 唯一 unsafe 边界。调用方保证非空指针有效且对齐；长度与空指针检查无法证明任意外部地址有效。
use crate::{bridge, state::*};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

#[repr(C)]
pub struct DpEvent {
    pub abi_version: u32,
    pub kind: u32,
    pub request_id: u64,
    pub connection: u64,
    pub status: u32,
    pub struct_size: u32,
    pub payload: *const u8,
    pub payload_len: usize,
}
fn guarded(f: impl FnOnce() -> Result<(), u32>) -> u32 {
    catch_unwind(AssertUnwindSafe(f))
        .map(|r| r.err().unwrap_or(OK))
        .unwrap_or(INTERNAL)
}
/// # Safety
/// For nonzero length `pointer` must point to `len` readable bytes for this call.
unsafe fn copy(pointer: *const u8, len: usize, max: usize) -> Result<Vec<u8>, u32> {
    if len > max || len > isize::MAX as usize || (len != 0 && pointer.is_null()) {
        return Err(INVALID);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: caller's C ABI contract guarantees readability; bounds checked above.
    Ok(unsafe { std::slice::from_raw_parts(pointer, len) }.to_vec())
}
/// # Safety
/// `output` must be a valid aligned writable u64 for the duration of this call.
unsafe fn output_zero(output: *mut u64) -> Result<(), u32> {
    if output.is_null() || !(output as usize).is_multiple_of(std::mem::align_of::<u64>()) {
        return Err(INVALID);
    }
    // SAFETY: required by ABI caller; null/alignment checked.
    unsafe { output.write(0) };
    Ok(())
}
#[unsafe(no_mangle)]
pub extern "C" fn dp_abi_version() -> u32 {
    1
}
/// Capability bits: reliable messages, external async CAS, explicit memory store.
#[unsafe(no_mangle)]
pub extern "C" fn dp_capabilities() -> u64 {
    1 | 2 | 4
}

/// # Safety
/// Input is readable during the call; output is valid writable u64. Callback code must
/// remain loaded until successful release, must not unwind/longjmp, and may retain no event pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dp_sdk_create(
    config: *const u8,
    len: usize,
    callback: Option<Callback>,
    context: u64,
    out_sdk: *mut u64,
) -> u32 {
    guarded(|| {
        // SAFETY: forwarded ABI preconditions.
        unsafe {
            output_zero(out_sdk)?;
        }
        let callback = callback.ok_or(INVALID)?;
        let bytes = unsafe { copy(config, len, 16384)? };
        let config: bridge::Config = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
        if !config.validate() {
            return Err(INVALID);
        }
        // Mobile trust initialization and host keystores are not claimed by this Linux milestone.
        if !cfg!(target_os = "linux") {
            return Err(UNSUPPORTED);
        }
        let mut registry = registry().lock().map_err(|_| INTERNAL)?;
        if registry.len() >= 16 {
            return Err(FULL);
        }
        let id = next_id()?;
        let (commands, receiver) = tokio::sync::mpsc::channel(32);
        let (events, event_rx) = std::sync::mpsc::sync_channel(97);
        let instance = Arc::new(Instance {
            commands,
            events,
            operations: Mutex::new(Default::default()),
            storage: Mutex::new(Default::default()),
            shutting: AtomicBool::new(false),
            stop: Default::default(),
            runtime_done: AtomicBool::new(false),
            callback_done: AtomicBool::new(false),
            shutdown_id: AtomicU64::new(0),
            connection_id: AtomicU64::new(0),
            closing_connection: AtomicU64::new(0),
            data_count: AtomicUsize::new(0),
            control_count: AtomicUsize::new(0),
            threads: Mutex::new(Vec::new()),
        });
        // Worker cannot run user-facing work until both threads and the registry exist.
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let worker_instance = instance.clone();
        let worker = std::thread::Builder::new()
            .name("peerloom-runtime".into())
            .spawn(move || {
                if start_rx.recv().is_ok() {
                    bridge::runtime(worker_instance, config, receiver);
                }
            })
            .map_err(|_| INTERNAL)?;
        let callback_instance = instance.clone();
        let callback_thread = std::thread::Builder::new()
            .name("peerloom-callback".into())
            .spawn(move || {
                while let Ok(event) = event_rx.recv() {
                    let deliver = event.validity.as_ref().is_none_or(|v| {
                        v.is_valid()
                            && !callback_instance.shutting.load(Ordering::Acquire)
                            && callback_instance.closing_connection.load(Ordering::Acquire)
                                != event.connection
                    });
                    if deliver {
                        let view = DpEvent {
                            abi_version: 1,
                            kind: event.kind,
                            request_id: event.request,
                            connection: event.connection,
                            status: event.status,
                            struct_size: std::mem::size_of::<DpEvent>() as u32,
                            payload: if event.payload.is_empty() {
                                std::ptr::null()
                            } else {
                                event.payload.as_ptr()
                            },
                            payload_len: event.payload.len(),
                        };
                        callback(context, &view);
                    }
                    callback_instance.release_credit(&event);
                    if event.kind == SHUTDOWN {
                        break;
                    }
                }
                callback_instance
                    .callback_done
                    .store(true, Ordering::Release);
            });
        let callback_thread = match callback_thread {
            Ok(thread) => thread,
            Err(_) => {
                // No callback or network work has started. Roll back the waiting thread;
                // never return a hidden live handle on create failure.
                drop(start_tx);
                let _ = worker.join();
                return Err(INTERNAL);
            }
        };
        instance
            .threads
            .lock()
            .map_err(|_| INTERNAL)?
            .extend([callback_thread, worker]);
        registry.insert(id, instance);
        unsafe { out_sdk.write(id) };
        let _ = start_tx.send(());
        Ok(())
    })
}
/// # Safety
/// Input/output pointer contracts are the same as create; inputs are copied before returning.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dp_sdk_submit(
    sdk: u64,
    operation: u32,
    connection: u64,
    input: *const u8,
    len: usize,
    out_request: *mut u64,
) -> u32 {
    guarded(|| {
        unsafe {
            output_zero(out_request)?;
        }
        let instance = lookup(sdk)?;
        let bytes = unsafe { copy(input, len, if operation == 4 { 65536 } else { 16384 })? };
        let id = instance.submit(operation, connection, bytes)?;
        unsafe { out_request.write(id) };
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn dp_sdk_cancel(sdk: u64, request: u64) -> u32 {
    guarded(|| {
        let instance = lookup(sdk)?;
        let ops = instance.operations.lock().map_err(|_| INTERNAL)?;
        let phase = ops.get(&request).ok_or(HANDLE)?;
        match phase.compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) | Err(2) => Ok(()),
            Err(1 | 4) => Err(BUSY),
            _ => Err(NOT_READY),
        }
    })
}
/// # Safety
/// Valid writable out_request is required; shutdown is nonblocking and cannot roll back in-flight work.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dp_sdk_shutdown(sdk: u64, out_request: *mut u64) -> u32 {
    guarded(|| {
        unsafe {
            output_zero(out_request)?;
        }
        let instance = lookup(sdk)?;
        // Serialize admission and shutdown ID assignment. Auto-stop may already have a terminal event.
        let _ops = instance.operations.lock().map_err(|_| INTERNAL)?;
        if instance.shutting.load(Ordering::Acquire) {
            return Err(CLOSED);
        }
        let id = next_id()?;
        instance
            .shutdown_id
            .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CLOSED)?;
        instance.stop();
        unsafe { out_request.write(id) };
        Ok(())
    })
}
/// # Safety
/// Reply bytes must be readable for len bytes; successful completion copies them immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dp_storage_complete(
    sdk: u64,
    request: u64,
    status: u32,
    json: *const u8,
    len: usize,
) -> u32 {
    guarded(|| {
        let instance = lookup(sdk)?;
        let payload = unsafe { copy(json, len, 16384)? };
        if !matches!(status, OK | BUSY | INTERNAL) {
            return Err(INVALID);
        }
        let sender = instance
            .storage
            .lock()
            .map_err(|_| INTERNAL)?
            .remove(&request)
            .ok_or(HANDLE)?;
        sender
            .send(StorageReply { status, payload })
            .map_err(|_| NOT_READY)
    })
}
/// Returns OK only after final callback returned and all owned threads terminated. No joining self.
#[unsafe(no_mangle)]
pub extern "C" fn dp_sdk_release(sdk: u64) -> u32 {
    guarded(|| {
        let mut registry = registry().lock().map_err(|_| INTERNAL)?;
        let instance = registry.get(&sdk).ok_or(HANDLE)?;
        if !instance.callback_done.load(Ordering::Acquire)
            || !instance.runtime_done.load(Ordering::Acquire)
        {
            return Err(BUSY);
        }
        let mut threads = instance.threads.lock().map_err(|_| INTERNAL)?;
        if threads.iter().any(|t| !t.is_finished()) {
            return Err(BUSY);
        }
        for thread in threads.drain(..) {
            thread.join().map_err(|_| INTERNAL)?;
        }
        drop(threads);
        registry.remove(&sdk);
        Ok(())
    })
}
/// 0 created/running, 1 shutting down, 2 quiescent, 3 invalid handle. No blocking wait API.
#[unsafe(no_mangle)]
pub extern "C" fn dp_sdk_state(sdk: u64) -> u32 {
    let Ok(instance) = lookup(sdk) else {
        return 3;
    };
    if instance.callback_done.load(Ordering::Acquire)
        && instance.runtime_done.load(Ordering::Acquire)
    {
        2
    } else if instance.shutting.load(Ordering::Acquire) {
        1
    } else {
        0
    }
}
