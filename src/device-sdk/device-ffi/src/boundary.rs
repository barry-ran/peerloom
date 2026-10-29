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
    pub channel: u64,
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
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| FULL)?;
    bytes.extend_from_slice(unsafe { std::slice::from_raw_parts(pointer, len) });
    Ok(bytes)
}
/// # Safety
/// Caller guarantees readable input for the duration of the immediate submit.
unsafe fn borrowed<'a>(pointer: *const u8, len: usize, max: usize) -> Result<&'a [u8], u32> {
    if len > max || len > isize::MAX as usize || (len != 0 && pointer.is_null()) {
        return Err(INVALID);
    }
    if len == 0 {
        return Ok(&[]);
    }
    Ok(unsafe { std::slice::from_raw_parts(pointer, len) })
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
/// Capability bits are additive; ABI1 prefix remains stable.
#[unsafe(no_mangle)]
pub extern "C" fn dp_capabilities() -> u64 {
    1 | 2 | 4 | 8 | 16 | 32 | 64 | 128
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
        // Native validation stage: promote this exact SHA only after every required
        // Windows/macOS/iOS/Android native gate passes. No separate test-only create path.
        if !cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "windows",
            target_os = "android"
        )) {
            return Err(UNSUPPORTED);
        }
        let mut registry = registry().lock().map_err(|_| INTERNAL)?;
        registry.try_reserve(1).map_err(|_| FULL)?;
        let id = next_id()?;
        let budget = crate::budget::Budget::new(config.ffi_resource_budget_bytes)?;
        let (commands, receiver) = crate::queue::channel(budget.clone());
        let (events, event_rx) = crate::queue::channel(budget.clone());
        let shutdown_terminal = Mutex::new(Some(events.try_reserve(true)?));
        let instance = Arc::new(Instance {
            commands,
            events,
            budget,
            shutdown_terminal,
            operations: Mutex::new(Default::default()),
            object_counts: Arc::new(ObjectCounts::default()),
            storage: Mutex::new(Default::default()),
            shutting: AtomicBool::new(false),
            stop: Default::default(),
            runtime_done: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            callback_done: AtomicBool::new(false),
            shutdown_id: AtomicU64::new(0),
            handles: Mutex::new(
                crate::handles::HandleRegistry::new(
                    config.max_connections,
                    config.max_channels_per_connection,
                )
                .map_err(handle_error)?,
            ),
            device_id: Mutex::new(None),
            resetting: AtomicBool::new(false),
            reset_active: AtomicBool::new(false),
            reading_count: AtomicUsize::new(0),
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
                while let Some(mut event) = event_rx.blocking_recv() {
                    let deliver = event.validity.as_ref().is_none_or(|v| {
                        v.is_valid()
                            && !callback_instance.resetting.load(Ordering::Acquire)
                            && !callback_instance.shutting.load(Ordering::Acquire)
                    });
                    if !deliver && event.kind == COMPLETE {
                        event.payload.fill(0);
                        event.payload.clear();
                        event.status = CLOSED;
                    }
                    if deliver || event.kind == COMPLETE {
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
                            channel: event.channel,
                        };
                        callback(context, &view);
                    }
                    let shutdown = event.kind == SHUTDOWN;
                    callback_instance.release_credit(event);
                    if shutdown {
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
        let bytes = unsafe { borrowed(input, len, if operation == 4 { 65536 } else { 16384 })? };
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

/// Read-only gate check for host executor delivery; does not extend authorization.
#[unsafe(no_mangle)]
pub extern "C" fn dp_connection_is_valid(sdk: u64, connection: u64) -> u32 {
    guarded(|| {
        let instance = lookup(sdk)?;
        if instance.shutting.load(Ordering::Acquire) || instance.resetting.load(Ordering::Acquire) {
            return Err(CLOSED);
        }
        instance
            .handles
            .lock()
            .map_err(|_| INTERNAL)?
            .connection(connection)
            .map_err(handle_error)?;
        Ok(())
    })
}
/// Child validity includes parent ownership, generation and local admission fences.
#[unsafe(no_mangle)]
pub extern "C" fn dp_channel_is_valid(sdk: u64, connection: u64, channel: u64) -> u32 {
    guarded(|| {
        let instance = lookup(sdk)?;
        if instance.shutting.load(Ordering::Acquire) || instance.resetting.load(Ordering::Acquire) {
            return Err(CLOSED);
        }
        instance
            .handles
            .lock()
            .map_err(|_| INTERNAL)?
            .channel(connection, channel)
            .map_err(handle_error)?;
        Ok(())
    })
}
/// # Safety
/// Input must be readable for len bytes, out_request aligned and writable for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dp_channel_submit(
    sdk: u64,
    connection: u64,
    channel: u64,
    operation: u32,
    input: *const u8,
    len: usize,
    out_request: *mut u64,
) -> u32 {
    guarded(|| {
        // SAFETY: forwarded ABI call preconditions; no pointer crosses the operation boundary.
        unsafe {
            output_zero(out_request)?;
        }
        let bytes = unsafe { borrowed(input, len, 65536)? };
        let id = lookup(sdk)?.submit_channel(operation, connection, channel, bytes)?;
        unsafe {
            out_request.write(id);
        }
        Ok(())
    })
}

/// Test-only observation; absent from default-feature release artifacts.
#[cfg(feature = "test-diagnostics")]
#[unsafe(no_mangle)]
pub extern "C" fn dp_test_pending_stream_reads(sdk: u64) -> u64 {
    lookup(sdk)
        .map(|instance| instance.reading_count.load(Ordering::Acquire) as u64)
        .unwrap_or(u64::MAX)
}
#[cfg(feature = "test-diagnostics")]
#[unsafe(no_mangle)]
pub extern "C" fn dp_test_ffi_resource_bytes(sdk: u64, field: u32) -> u64 {
    lookup(sdk)
        .map(|instance| {
            let (total, data, critical) = instance.budget.snapshot();
            match field {
                0 => total as u64,
                1 => data as u64,
                2 => critical as u64,
                _ => u64::MAX,
            }
        })
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use std::time::{Duration, Instant};

    extern "C" fn callback(_: u64, _: *const DpEvent) {}

    #[test]
    fn more_than_sixteen_instances_can_quiesce_and_release() {
        struct Owned(Vec<u64>);
        impl Drop for Owned {
            fn drop(&mut self) {
                for &sdk in &self.0 {
                    let mut request = 0;
                    // SAFETY: local aligned output remains writable throughout the call.
                    unsafe {
                        dp_sdk_shutdown(sdk, &mut request);
                    }
                }
                let deadline = Instant::now() + Duration::from_secs(10);
                while !self.0.is_empty() && Instant::now() < deadline {
                    self.0.retain(|&sdk| dp_sdk_release(sdk) != OK);
                    std::thread::sleep(Duration::from_millis(1));
                }
                assert!(self.0.is_empty(), "all owned instances must release");
            }
        }
        let config = br#"{"abi_version":1,"origin":"https://localhost","application_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","storage":"memory"}"#;
        let mut owned = Owned(Vec::new());
        for _ in 0..20 {
            let mut sdk = 0;
            // SAFETY: config and output are valid for the call; callback is static.
            let result = unsafe {
                dp_sdk_create(config.as_ptr(), config.len(), Some(callback), 0, &mut sdk)
            };
            assert_eq!(result, OK);
            owned.0.push(sdk);
        }
        let ids = owned.0.clone();
        drop(owned);
        assert!(ids.into_iter().all(|sdk| dp_sdk_state(sdk) == 3));
    }
}
