use device_core::sdk::ConnectionValidity;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
};
use tokio::sync::{Notify, mpsc, oneshot};

pub const OK: u32 = 0;
pub const INVALID: u32 = 1;
pub const NOT_READY: u32 = 2;
pub const CLOSED: u32 = 5;
pub const FULL: u32 = 6;
pub const UNSUPPORTED: u32 = 7;
pub const HANDLE: u32 = 8;
pub const CANCELLED: u32 = 9;
pub const UNKNOWN: u32 = 10;
pub const BUSY: u32 = 11;
pub const INTERNAL: u32 = 255;
pub const COMPLETE: u32 = 1;
pub const SHUTDOWN: u32 = 9;
pub const STORAGE: u32 = 10;

pub type Callback = extern "C" fn(u64, *const crate::boundary::DpEvent);
static NEXT: AtomicU64 = AtomicU64::new(1);
static REGISTRY: OnceLock<Mutex<HashMap<u64, Arc<Instance>>>> = OnceLock::new();
pub fn next_id() -> Result<u64, u32> {
    NEXT.try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .map_err(|_| INTERNAL)
}
pub fn registry() -> &'static Mutex<HashMap<u64, Arc<Instance>>> {
    REGISTRY.get_or_init(Default::default)
}
pub fn lookup(id: u64) -> Result<Arc<Instance>, u32> {
    registry()
        .lock()
        .map_err(|_| INTERNAL)?
        .get(&id)
        .cloned()
        .ok_or(HANDLE)
}

/// phase: 0 queued, 1 running, 2 cancelled before start, 3 complete, 4 irreversible close queued.
pub struct Operation {
    pub id: u64,
    pub kind: u32,
    pub connection: u64,
    pub input: Vec<u8>,
    pub phase: Arc<AtomicUsize>,
}
pub struct Event {
    pub kind: u32,
    pub request: u64,
    pub connection: u64,
    pub status: u32,
    pub payload: Vec<u8>,
    pub validity: Option<ConnectionValidity>,
    pub class: u8,
}
impl Event {
    pub fn new(kind: u32, request: u64, connection: u64, status: u32, payload: Vec<u8>) -> Self {
        Self {
            kind,
            request,
            connection,
            status,
            payload,
            validity: None,
            class: 0,
        }
    }
}
pub struct StorageReply {
    pub status: u32,
    pub payload: Vec<u8>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetRequest {
    pub expected_device_id: String,
    #[serde(default)]
    pub retry: bool,
}
pub struct Instance {
    pub device_id: Mutex<Option<String>>,
    pub resetting: AtomicBool,
    pub reset_active: AtomicBool,
    pub commands: mpsc::Sender<Operation>,
    pub events: std::sync::mpsc::SyncSender<Event>,
    pub operations: Mutex<HashMap<u64, Arc<AtomicUsize>>>,
    pub storage: Mutex<HashMap<u64, oneshot::Sender<StorageReply>>>,
    pub shutting: AtomicBool,
    pub stop: Notify,
    pub runtime_done: AtomicBool,
    pub callback_done: AtomicBool,
    pub shutdown_id: AtomicU64,
    pub connection_id: AtomicU64,
    pub connection_validity: Mutex<Option<(u64, ConnectionValidity)>>,
    pub closing_connection: AtomicU64,
    pub data_count: AtomicUsize,
    pub control_count: AtomicUsize,
    pub threads: Mutex<Vec<JoinHandle<()>>>,
}
impl Instance {
    pub fn stop(&self) {
        let _ = self
            .shutdown_id
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire);
        self.shutting.store(true, Ordering::Release);
        self.stop.notify_one();
    }
    pub fn emit(&self, mut event: Event) -> bool {
        let count = if event.kind == COMPLETE || event.kind == SHUTDOWN {
            None
        } else if event.kind == 6 {
            event.class = 1;
            Some(&self.data_count)
        } else {
            event.class = 2;
            Some(&self.control_count)
        };
        if let Some(count) = count
            && count
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < 32).then_some(n + 1)
                })
                .is_err()
        {
            self.stop();
            return false;
        }
        match self.events.try_send(event) {
            Ok(()) => true,
            Err(e) => {
                let event = match e {
                    std::sync::mpsc::TrySendError::Full(e)
                    | std::sync::mpsc::TrySendError::Disconnected(e) => e,
                };
                self.release_credit(&event);
                self.stop();
                false
            }
        }
    }
    pub fn release_credit(&self, event: &Event) {
        match event.class {
            1 => {
                self.data_count.fetch_sub(1, Ordering::AcqRel);
            }
            2 => {
                self.control_count.fetch_sub(1, Ordering::AcqRel);
            }
            _ => {}
        }
        if event.kind == COMPLETE
            && let Ok(mut ops) = self.operations.lock()
        {
            ops.remove(&event.request);
        }
    }
    pub fn finish(&self, op: Operation, status: u32, payload: Vec<u8>) {
        if op.kind == 7 {
            self.reset_active.store(false, Ordering::Release);
        }
        op.phase.store(3, Ordering::Release);
        self.emit(Event::new(COMPLETE, op.id, op.connection, status, payload));
    }
    pub fn submit(&self, kind: u32, connection: u64, input: Vec<u8>) -> Result<u64, u32> {
        if self.shutting.load(Ordering::Acquire) {
            return Err(CLOSED);
        }
        if !(1..=7).contains(&kind) {
            return Err(UNSUPPORTED);
        }
        let mut ops = self.operations.lock().map_err(|_| INTERNAL)?;
        if self.shutting.load(Ordering::Acquire) {
            return Err(CLOSED);
        }
        if ops.len() >= 32 {
            return Err(FULL);
        }
        if self.resetting.load(Ordering::Acquire) && kind != 7 {
            return Err(CLOSED);
        }
        if kind == 7 {
            if connection != 0 {
                return Err(HANDLE);
            }
            let request: ResetRequest = serde_json::from_slice(&input).map_err(|_| INVALID)?;
            if self.device_id.lock().map_err(|_| INTERNAL)?.as_deref()
                != Some(&request.expected_device_id)
            {
                return Err(INVALID);
            }
            if self.reset_active.load(Ordering::Acquire) {
                return Err(BUSY);
            }
            if self.resetting.load(Ordering::Acquire) != request.retry {
                return Err(INVALID);
            }
        }
        if matches!(kind, 4 | 6) {
            if connection == 0 || self.connection_id.load(Ordering::Acquire) != connection {
                return Err(HANDLE);
            }
            if self.closing_connection.load(Ordering::Acquire) == connection {
                return Err(CLOSED);
            }
        }
        if kind == 6 && !input.is_empty() {
            return Err(INVALID);
        }
        let id = next_id()?;
        // Reserve queue space before irreversible reset/close admission or cancellation.
        let permit = self.commands.try_reserve().map_err(|_| FULL)?;
        if kind == 7 {
            self.resetting.store(true, Ordering::Release);
            self.reset_active.store(true, Ordering::Release);
            for phase in ops.values() {
                let _ = phase.compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
            }
        }
        if kind == 6 {
            self.closing_connection.store(connection, Ordering::Release);
        }
        // Close/reset admission cannot be cancelled after its local fence takes effect.
        let phase = Arc::new(AtomicUsize::new(if matches!(kind, 6 | 7) { 4 } else { 0 }));
        permit.send(Operation {
            id,
            kind,
            connection,
            input,
            phase: phase.clone(),
        });
        ops.insert(id, phase);
        Ok(id)
    }
}

#[cfg(test)]
mod reset_tests {
    use super::*;
    const DEVICE: &str = "00000000-0000-4000-8000-000000000001";
    fn setup() -> (
        Instance,
        mpsc::Receiver<Operation>,
        std::sync::mpsc::Receiver<Event>,
    ) {
        let (commands, receiver) = mpsc::channel(32);
        let (events, callbacks) = std::sync::mpsc::sync_channel(97);
        (
            Instance {
                commands,
                events,
                operations: Mutex::new(Default::default()),
                storage: Mutex::new(Default::default()),
                shutting: AtomicBool::new(false),
                stop: Notify::new(),
                runtime_done: AtomicBool::new(false),
                callback_done: AtomicBool::new(false),
                shutdown_id: AtomicU64::new(0),
                connection_id: AtomicU64::new(0),
                connection_validity: Mutex::new(None),
                device_id: Mutex::new(Some(DEVICE.into())),
                resetting: AtomicBool::new(false),
                reset_active: AtomicBool::new(false),
                closing_connection: AtomicU64::new(0),
                data_count: AtomicUsize::new(0),
                control_count: AtomicUsize::new(0),
                threads: Mutex::new(Vec::new()),
            },
            receiver,
            callbacks,
        )
    }
    fn reset(retry: bool) -> Vec<u8> {
        serde_json::json!({"expected_device_id":DEVICE,"retry":retry})
            .to_string()
            .into_bytes()
    }
    #[test]
    fn reset_admission_fences_and_cancels_queued_but_not_running_operations() {
        let (instance, mut commands, _callbacks) = setup();
        let queued = instance.submit(2, 0, vec![]).unwrap();
        let running = instance.submit(5, 0, vec![]).unwrap();
        instance.operations.lock().unwrap()[&running].store(1, Ordering::Release);
        assert_eq!(
            instance.submit(7, 0, b"{\"expected_device_id\":\"wrong\"}".to_vec()),
            Err(INVALID)
        );
        assert!(!instance.resetting.load(Ordering::Acquire));
        let reset_id = instance.submit(7, 0, reset(false)).unwrap();
        assert!(instance.resetting.load(Ordering::Acquire));
        assert_eq!(instance.submit(2, 0, vec![]), Err(CLOSED));
        assert_eq!(instance.submit(7, 0, reset(true)), Err(BUSY));
        {
            let operations = instance.operations.lock().unwrap();
            assert_eq!(operations[&queued].load(Ordering::Acquire), 2);
            assert_eq!(operations[&running].load(Ordering::Acquire), 1);
            assert_eq!(operations[&reset_id].load(Ordering::Acquire), 4);
        }
        commands.try_recv().unwrap();
        commands.try_recv().unwrap();
        let op = commands.try_recv().unwrap();
        instance.finish(op, UNKNOWN, vec![]);
        assert!(instance.resetting.load(Ordering::Acquire));
        assert_eq!(instance.submit(7, 0, reset(false)), Err(INVALID));
        assert!(instance.submit(7, 0, reset(true)).is_ok());
    }
}
