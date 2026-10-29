use crate::handles::{ChannelKind, HandleError, HandleRegistry, ScopedValidity, Validity};
use device_core::sdk::{ChannelValidity, ConnectionValidity};
#[derive(Clone)]
pub enum Authority {
    #[cfg(test)]
    Test,
    Connection(ConnectionValidity),
    Channel(ChannelValidity),
}
impl Validity for Authority {
    fn is_valid(&self) -> bool {
        match self {
            #[cfg(test)]
            Self::Test => true,
            Self::Connection(value) => value.is_valid(),
            Self::Channel(value) => value.is_valid(),
        }
    }
}
pub fn handle_error(error: HandleError) -> u32 {
    match error {
        HandleError::InvalidConfiguration => INVALID,
        HandleError::InvalidHandle => HANDLE,
        HandleError::Closed => CLOSED,
        HandleError::Full => FULL,
        HandleError::Allocator => INTERNAL,
    }
}
use crate::{budget, queue};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
};
use tokio::sync::{Notify, oneshot};

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
    pub channel: u64,
    pub input: Vec<u8>,
    pub read_buffer: Option<Vec<u8>>,
    pub deadline: Option<std::time::Instant>,
    pub phase: Arc<AtomicUsize>,
}
pub struct Event {
    pub kind: u32,
    pub request: u64,
    pub connection: u64,
    pub channel: u64,
    pub status: u32,
    pub payload: Vec<u8>,
    pub validity: Option<ScopedValidity<Authority>>,
    pub class: u8,
    pub bytes: Option<budget::Permit>,
    object: Option<ObjectLease>,
}
impl Event {
    pub fn new(kind: u32, request: u64, connection: u64, status: u32, payload: Vec<u8>) -> Self {
        Self {
            kind,
            request,
            connection,
            channel: 0,
            status,
            payload,
            validity: None,
            class: 0,
            bytes: None,
            object: None,
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
pub fn critical_operation(kind: u32) -> bool {
    matches!(kind, 6 | 7 | 68)
}
impl queue::Item for Operation {
    fn key(&self) -> u64 {
        self.connection
    }
    fn critical(&self) -> bool {
        critical_operation(self.kind)
    }
}
impl queue::Item for Event {
    fn key(&self) -> u64 {
        self.connection
    }
    fn critical(&self) -> bool {
        self.class == 2 || self.kind == SHUTDOWN
    }
    fn lane(&self) -> usize {
        if self.class == 3 {
            2
        } else {
            usize::from(self.critical())
        }
    }
    fn barrier(&self) -> bool {
        self.kind == SHUTDOWN
    }
}
#[derive(Default)]
pub struct ObjectCounts {
    connections: AtomicUsize,
    streams: AtomicUsize,
}
struct ObjectLease {
    counts: Arc<ObjectCounts>,
    kind: u8,
}
impl Drop for ObjectLease {
    fn drop(&mut self) {
        let count = if self.kind == 1 {
            &self.counts.connections
        } else {
            &self.counts.streams
        };
        let previous = count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}
/// One lifecycle notification reserved before publishing its object.
pub struct LifecycleTicket {
    slot: queue::Reservation<Event>,
    bytes: budget::Permit,
    object: Option<ObjectLease>,
}
impl LifecycleTicket {
    pub fn send(self, instance: &Instance, mut event: Event) -> bool {
        if event.payload.capacity() > 256 {
            drop(event);
            instance.stop();
            return false;
        }
        event.class = 3;
        event.bytes = Some(self.bytes);
        event.object = self.object;
        match self.slot.send(event) {
            Ok(()) => true,
            Err(error) => {
                instance.release_credit(error.into_inner());
                instance.stop();
                false
            }
        }
    }
}
pub struct Tracked {
    pub phase: Arc<AtomicUsize>,
    pub critical: bool,
    pub read: Option<(u64, u64)>,
    pub terminal: Option<queue::Reservation<Event>>,
    _bytes: budget::Permit,
}
impl std::ops::Deref for Tracked {
    type Target = AtomicUsize;
    fn deref(&self) -> &Self::Target {
        &self.phase
    }
}
#[derive(Default)]
pub struct Operations {
    lanes: [HashMap<u64, Tracked>; 2],
    capacity_bytes: [Option<budget::Permit>; 2],
}
impl Operations {
    pub fn get(&self, id: &u64) -> Option<&Tracked> {
        self.lanes[0].get(id).or_else(|| self.lanes[1].get(id))
    }
    fn get_mut(&mut self, id: &u64) -> Option<&mut Tracked> {
        let lane = usize::from(self.lanes[1].contains_key(id));
        self.lanes[lane].get_mut(id)
    }
    fn remove(&mut self, id: &u64) {
        self.lanes[0].remove(id);
        self.lanes[1].remove(id);
    }
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &Tracked)> {
        self.lanes.iter().flat_map(|lane| lane.iter())
    }
    fn values(&self) -> impl Iterator<Item = &Tracked> {
        self.lanes.iter().flat_map(|lane| lane.values())
    }
    fn insert(&mut self, id: u64, value: Tracked) {
        self.lanes[usize::from(value.critical)].insert(id, value);
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lanes.iter().map(HashMap::len).sum()
    }
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.lanes.iter().all(HashMap::is_empty)
    }
    fn reserve(&mut self, budget: &Arc<budget::Budget>, critical: bool) -> Result<(), u32> {
        let index = usize::from(critical);
        let lane = &mut self.lanes[index];
        if lane.len() < lane.capacity() {
            return Ok(());
        }
        let required = lane
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_next_power_of_two())
            .ok_or(FULL)?;
        let entry_bytes = std::mem::size_of::<(u64, Tracked)>()
            .checked_add(32)
            .ok_or(FULL)?;
        let mut charge =
            budget.reserve(required.checked_mul(entry_bytes).ok_or(FULL)?, critical)?;
        let mut replacement = HashMap::new();
        replacement.try_reserve(required).map_err(|_| FULL)?;
        charge.grow_to(
            replacement
                .capacity()
                .checked_mul(entry_bytes)
                .ok_or(FULL)?,
        )?;
        replacement.extend(lane.drain());
        drop(std::mem::replace(lane, replacement));
        self.capacity_bytes[index] = Some(charge);
        Ok(())
    }
}
#[cfg(test)]
impl std::ops::Index<&u64> for Operations {
    type Output = Tracked;
    fn index(&self, id: &u64) -> &Tracked {
        self.get(id).expect("tracked operation")
    }
}
pub struct Instance {
    pub device_id: Mutex<Option<String>>,
    pub resetting: AtomicBool,
    pub reset_active: AtomicBool,
    pub reading_count: AtomicUsize,
    pub commands: queue::Sender<Operation>,
    pub events: queue::Sender<Event>,
    pub budget: Arc<budget::Budget>,
    pub shutdown_terminal: Mutex<Option<queue::Reservation<Event>>>,
    pub operations: Mutex<Operations>,
    pub object_counts: Arc<ObjectCounts>,
    pub storage: Mutex<HashMap<u64, oneshot::Sender<StorageReply>>>,
    pub shutting: AtomicBool,
    pub stop: Notify,
    pub runtime_done: AtomicBool,
    pub failed: AtomicBool,
    pub callback_done: AtomicBool,
    pub shutdown_id: AtomicU64,
    pub handles: Mutex<HandleRegistry<Authority>>,
    pub threads: Mutex<Vec<JoinHandle<()>>>,
}
impl Instance {
    pub fn reserve_lifecycle(&self, kind: u8) -> Result<LifecycleTicket, u32> {
        // Closed payload is a fixed session UUID JSON or empty child event.
        let bytes = self.budget.reserve_lane(256 + budget::EVENT_METADATA, 2)?;
        let slot = self.events.try_reserve_lane(2)?;
        let object = if matches!(kind, 1 | 2) {
            let count = if kind == 1 {
                &self.object_counts.connections
            } else {
                &self.object_counts.streams
            };
            count
                .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
                .map_err(|_| FULL)?;
            Some(ObjectLease {
                counts: self.object_counts.clone(),
                kind,
            })
        } else {
            None
        };
        Ok(LifecycleTicket {
            slot,
            bytes,
            object,
        })
    }
    pub fn stop(&self) {
        let _ = self
            .shutdown_id
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire);
        self.shutting.store(true, Ordering::Release);
        self.stop.notify_one();
    }
    pub fn emit(&self, mut event: Event) -> bool {
        let result = if event.kind == COMPLETE {
            let reservation = self.operations.lock().ok().and_then(|mut ops| {
                let entry = ops.get_mut(&event.request)?;
                event.class = if entry.critical { 2 } else { 0 };
                entry.terminal.take()
            });
            match reservation {
                Some(permit) => permit.send(event),
                None => {
                    self.failed.store(true, Ordering::Release);
                    self.stop();
                    return false;
                }
            }
        } else if event.kind == SHUTDOWN {
            let reservation = self
                .shutdown_terminal
                .lock()
                .ok()
                .and_then(|mut value| value.take());
            match reservation {
                Some(permit) => permit.send(event),
                None => {
                    self.failed.store(true, Ordering::Release);
                    return false;
                }
            }
        } else {
            event.class = if event.kind == STORAGE {
                2
            } else if matches!(event.kind, 3 | 7 | 8 | 11 | 13) {
                3
            } else {
                1
            };
            let bytes = event
                .payload
                .capacity()
                .checked_add(budget::EVENT_METADATA)
                .and_then(|bytes| {
                    self.budget
                        .reserve_lane(
                            bytes,
                            match event.class {
                                2 => 1,
                                3 => 2,
                                _ => 0,
                            },
                        )
                        .ok()
                });
            let Some(bytes) = bytes else {
                self.stop();
                return false;
            };
            event.bytes = Some(bytes);
            self.events.try_send(event)
        };
        match result {
            Ok(()) => true,
            Err(error) => {
                self.release_credit(error.into_inner());
                self.stop();
                false
            }
        }
    }
    /// The callback borrow has ended. Destroy payload capacity BEFORE returning
    /// either operation or event byte credit; suppressed events follow this path.
    pub fn release_credit(&self, mut event: Event) {
        drop(std::mem::take(&mut event.payload));
        if event.kind == COMPLETE
            && let Ok(mut ops) = self.operations.lock()
        {
            ops.remove(&event.request);
        }
        drop(event.bytes.take());
    }
    pub fn finish(&self, mut op: Operation, status: u32, payload: Vec<u8>) {
        if op.kind == 7 {
            self.reset_active.store(false, Ordering::Release);
        }
        drop(std::mem::take(&mut op.input));
        drop(op.read_buffer.take());
        op.phase.store(3, Ordering::Release);
        let mut event = Event::new(COMPLETE, op.id, op.connection, status, payload);
        event.channel = op.channel;
        self.emit(event);
    }
    pub fn submit(&self, kind: u32, connection: u64, input: impl AsRef<[u8]>) -> Result<u64, u32> {
        if !(1..=9).contains(&kind) {
            return Err(UNSUPPORTED);
        }
        self.submit_scoped(kind, connection, 0, input.as_ref())
    }
    pub fn submit_channel(
        &self,
        kind: u32,
        connection: u64,
        channel: u64,
        input: impl AsRef<[u8]>,
    ) -> Result<u64, u32> {
        if !(1..=5).contains(&kind) {
            return Err(UNSUPPORTED);
        }
        self.submit_scoped(63 + kind, connection, channel, input.as_ref())
    }
    fn submit_scoped(
        &self,
        kind: u32,
        connection: u64,
        channel: u64,
        input: &[u8],
    ) -> Result<u64, u32> {
        if self.shutting.load(Ordering::Acquire) {
            return Err(CLOSED);
        }
        if !(1..=9).contains(&kind) && !(64..=68).contains(&kind) {
            return Err(UNSUPPORTED);
        }
        let mut ops = self.operations.lock().map_err(|_| INTERNAL)?;
        if self.shutting.load(Ordering::Acquire) {
            return Err(CLOSED);
        }
        if self.resetting.load(Ordering::Acquire) && kind != 7 {
            return Err(CLOSED);
        }
        if kind == 7 {
            if connection != 0 {
                return Err(HANDLE);
            }
            let request: ResetRequest = serde_json::from_slice(input).map_err(|_| INVALID)?;
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
        let mut handles = self.handles.lock().map_err(|_| INTERNAL)?;
        let (connections, streams) = handles.capacity_counts().map_err(handle_error)?;
        // Includes retired objects whose Closed event is still borrowed/queued.
        // Registry maximum also covers the brief registration-before-worker phase.
        let connections = connections.max(self.object_counts.connections.load(Ordering::Acquire));
        let streams = streams.max(self.object_counts.streams.load(Ordering::Acquire));
        let (data_limit, critical_limit) = budget::limits(connections, streams)?;
        let critical = critical_operation(kind);
        let used = ops.values().filter(|op| op.critical == critical).count();
        if used >= if critical { critical_limit } else { data_limit } {
            return Err(FULL);
        }
        let mut reply_bytes = 16384usize;

        if matches!(kind, 4 | 6 | 8) {
            handles.connection(connection).map_err(handle_error)?;
        }
        if kind >= 64 {
            let mode = handles
                .channel_kind(connection, channel)
                .map_err(handle_error)?;
            let stream = mode == ChannelKind::ReliableStream;
            if (kind == 64 && stream) || (matches!(kind, 65..=67) && !stream) {
                return Err(UNSUPPORTED);
            }
            if matches!(kind, 66 | 67) {
                handles
                    .check_writable(connection, channel)
                    .map_err(handle_error)?;
            }
            if kind == 65 {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Read {
                    max_bytes: usize,
                }
                let read: Read = serde_json::from_slice(input).map_err(|_| INVALID)?;
                reply_bytes = read.max_bytes;
                if ops
                    .values()
                    .any(|op| op.read == Some((connection, channel)))
                {
                    return Err(BUSY);
                }
                if !(1..=65536).contains(&read.max_bytes) {
                    return Err(INVALID);
                }
            }
        }
        if matches!(kind, 6 | 67 | 68) && !input.is_empty() {
            return Err(INVALID);
        }
        let now = std::time::Instant::now();
        let deadline = match kind {
            4 | 66 | 67 => Some(
                now.checked_add(std::time::Duration::from_secs(30))
                    .ok_or(INVALID)?,
            ),
            64 => Some(
                handles
                    .message_deadline(connection, channel, now)
                    .map_err(handle_error)?,
            ),
            _ => None,
        };
        if critical {
            reply_bytes = if kind == 7 { 16384 } else { 0 };
        }
        let charge = input
            .len()
            .checked_add(reply_bytes)
            .and_then(|n| n.checked_add(budget::OP_METADATA))
            .ok_or(FULL)?;
        let mut bytes = self.budget.reserve(charge, critical)?;
        ops.reserve(&self.budget, critical)?;
        let terminal = self.events.try_reserve(critical)?;
        let permit = self.commands.try_reserve(critical)?;
        let mut copied = Vec::new();
        copied.try_reserve_exact(input.len()).map_err(|_| FULL)?;
        copied.extend_from_slice(input);
        let read_buffer = if kind == 65 {
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(reply_bytes).map_err(|_| FULL)?;
            bytes.grow_to(
                copied
                    .capacity()
                    .checked_add(buffer.capacity())
                    .and_then(|n| n.checked_add(budget::OP_METADATA))
                    .ok_or(FULL)?,
            )?;
            buffer.resize(reply_bytes, 0);
            Some(buffer)
        } else {
            bytes.grow_to(
                copied
                    .capacity()
                    .checked_add(reply_bytes)
                    .and_then(|n| n.checked_add(budget::OP_METADATA))
                    .ok_or(FULL)?,
            )?;
            None
        };
        let id = next_id()?;
        // All memory and terminal space precede irreversible fence changes.
        if kind == 7 {
            handles.clear();
            self.resetting.store(true, Ordering::Release);
            self.reset_active.store(true, Ordering::Release);
            for phase in ops.values() {
                let _ = phase.compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
            }
        }
        if kind == 6 {
            handles.close_connection(connection).map_err(handle_error)?;
        }
        if kind == 67 {
            handles
                .finish_write(connection, channel)
                .map_err(handle_error)?;
        }
        if kind == 68 {
            handles
                .close_channel(connection, channel)
                .map_err(handle_error)?;
        }
        // Close/reset admission cannot be cancelled after its local fence takes effect.
        let phase = Arc::new(AtomicUsize::new(if matches!(kind, 6 | 7 | 67 | 68) {
            4
        } else {
            0
        }));
        ops.insert(
            id,
            Tracked {
                phase: phase.clone(),
                critical,
                read: (kind == 65).then_some((connection, channel)),
                terminal: Some(terminal),
                _bytes: bytes,
            },
        );
        let operation = Operation {
            id,
            kind,
            connection,
            channel,
            input: copied,
            read_buffer,
            deadline,
            phase: phase.clone(),
        };
        drop(handles);
        drop(ops);
        if let Err(error) = permit.send(operation) {
            self.finish(error.into_inner(), CLOSED, Vec::new());
        }
        Ok(id)
    }
}

/// Every routed worker operation owns its terminal credit through abort/panic as well.
/// A running task dropped without an observed result is unknown, never falsely cancelled.
pub struct CompletionGuard {
    instance: Arc<Instance>,
    operation: Option<Operation>,
}
impl CompletionGuard {
    pub fn start(instance: Arc<Instance>, operation: Operation) -> Option<Self> {
        let expected = if matches!(operation.kind, 6 | 7 | 67 | 68) {
            4
        } else {
            0
        };
        if operation
            .phase
            .compare_exchange(expected, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            instance.finish(operation, CANCELLED, Vec::new());
            return None;
        }
        Some(Self {
            instance,
            operation: Some(operation),
        })
    }
    pub fn operation(&self) -> &Operation {
        self.operation.as_ref().expect("live operation")
    }
    pub fn take_read_buffer(&mut self) -> Vec<u8> {
        self.operation
            .as_mut()
            .expect("live operation")
            .read_buffer
            .take()
            .expect("READ admission reserves buffer")
    }
    pub fn finish(
        mut self,
        status: u32,
        payload: Vec<u8>,
        validity: Option<ScopedValidity<Authority>>,
    ) {
        let mut operation = self.operation.take().expect("live operation");
        drop(std::mem::take(&mut operation.input));
        drop(operation.read_buffer.take());
        operation.phase.store(3, Ordering::Release);
        let mut event = Event::new(
            COMPLETE,
            operation.id,
            operation.connection,
            status,
            payload,
        );
        event.channel = operation.channel;
        event.validity = validity;
        self.instance.emit(event);
    }
    pub fn opened(mut self, channel: u64, payload: Vec<u8>, validity: ScopedValidity<Authority>) {
        self.operation.as_mut().expect("live operation").channel = channel;
        self.finish(OK, payload, Some(validity));
    }
}
impl Drop for CompletionGuard {
    fn drop(&mut self) {
        if let Some(operation) = self.operation.take() {
            self.instance.finish(operation, UNKNOWN, Vec::new());
        }
    }
}

#[cfg(test)]
mod reset_tests {
    use super::*;
    const DEVICE: &str = "00000000-0000-4000-8000-000000000001";
    fn setup() -> (Instance, queue::Receiver<Operation>, queue::Receiver<Event>) {
        let budget = budget::Budget::new(budget::DEFAULT_BYTES).unwrap();
        let (commands, receiver) = queue::channel(budget.clone());
        let (events, callbacks) = queue::channel(budget.clone());
        let shutdown_terminal = Mutex::new(Some(events.try_reserve(true).unwrap()));
        (
            Instance {
                commands,
                events,
                budget,
                shutdown_terminal,
                operations: Mutex::new(Default::default()),
                object_counts: Arc::new(ObjectCounts::default()),
                storage: Mutex::new(Default::default()),
                shutting: AtomicBool::new(false),
                stop: Notify::new(),
                runtime_done: AtomicBool::new(false),
                failed: AtomicBool::new(false),
                callback_done: AtomicBool::new(false),
                shutdown_id: AtomicU64::new(0),
                handles: Mutex::new(HandleRegistry::new(1, 1).unwrap()),
                device_id: Mutex::new(Some(DEVICE.into())),
                resetting: AtomicBool::new(false),
                reset_active: AtomicBool::new(false),
                reading_count: AtomicUsize::new(0),
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
    fn object_lifetime_is_returned_on_suppression_failure_and_unused_ticket_drop() {
        let (instance, _commands, mut events) = setup();
        let unused = instance.reserve_lifecycle(1).unwrap();
        assert_eq!(
            instance.object_counts.connections.load(Ordering::Acquire),
            1
        );
        drop(unused);
        assert_eq!(
            instance.object_counts.connections.load(Ordering::Acquire),
            0
        );
        let suppressed = instance.reserve_lifecycle(2).unwrap();
        assert!(suppressed.send(&instance, Event::new(13, 0, 1, CLOSED, Vec::new())));
        let event = events.try_recv().unwrap();
        // Callback dispatch uses this identical settlement path after suppressing
        // an invalid event: no callback invocation is required to release its lease.
        instance.release_credit(event);
        assert_eq!(instance.object_counts.streams.load(Ordering::Acquire), 0);
        let oversized = instance.reserve_lifecycle(2).unwrap();
        assert!(!oversized.send(&instance, Event::new(13, 0, 1, CLOSED, vec![0; 257])));
        assert_eq!(instance.object_counts.streams.load(Ordering::Acquire), 0);
        let failed = instance.reserve_lifecycle(1).unwrap();
        events.close();
        assert!(!failed.send(&instance, Event::new(7, 0, 1, CLOSED, Vec::new())));
        assert_eq!(
            instance.object_counts.connections.load(Ordering::Acquire),
            0
        );
    }
    #[test]
    fn queued_closed_lifetimes_keep_management_capacity_until_callback_returns() {
        let (instance, commands, events) = setup();
        *instance.handles.lock().unwrap() = HandleRegistry::new(0, 0).unwrap();
        let connection_ticket = instance.reserve_lifecycle(1).unwrap();
        let parent = {
            let mut handles = instance.handles.lock().unwrap();
            handles
                .add_connection(Authority::Test, || {
                    next_id().map_err(|_| HandleError::Allocator)
                })
                .unwrap()
        };
        let mut tickets = Vec::new();
        for _ in 0..500 {
            let ticket = instance.reserve_lifecycle(2).unwrap();
            let id = instance
                .handles
                .lock()
                .unwrap()
                .add_channel(parent, ChannelKind::ReliableStream, Authority::Test, || {
                    next_id().map_err(|_| HandleError::Allocator)
                })
                .unwrap();
            instance.submit_scoped(68, parent, id, &[]).unwrap();
            let operation = commands.try_recv().unwrap();
            instance.finish(operation, OK, Vec::new());
            tickets.push((id, ticket));
        }
        // Simulate all worker removals with callback thread paused. Operation
        // completions and Closed events still retain their independent leases.
        instance.handles.lock().unwrap().clear();
        for (id, ticket) in tickets {
            let mut event = Event::new(13, 0, parent, CLOSED, Vec::new());
            event.channel = id;
            assert!(ticket.send(&instance, event));
        }
        assert_eq!(instance.object_counts.streams.load(Ordering::Acquire), 500);
        let reset_id = instance.submit(7, 0, reset(false)).unwrap();
        let reset = commands.try_recv().unwrap();
        assert_eq!(reset.id, reset_id);
        instance.finish(reset, OK, Vec::new());
        let mut complete = 0;
        let mut closed = 0;
        while let Ok(event) = events.try_recv() {
            if event.kind == COMPLETE {
                complete += 1;
            } else {
                assert_eq!(event.kind, 13);
                closed += 1;
            }
            instance.release_credit(event);
        }
        assert_eq!((complete, closed), (501, 500));
        assert_eq!(instance.object_counts.streams.load(Ordering::Acquire), 0);
        drop(connection_ticket);
        assert_eq!(
            instance.object_counts.connections.load(Ordering::Acquire),
            0
        );
    }
    #[test]
    fn lifecycle_tickets_survive_paused_callback_and_exhausted_critical_bytes() {
        let (instance, commands, events) = setup();
        let tickets: Vec<_> = (0..500)
            .map(|_| instance.reserve_lifecycle(0).unwrap())
            .collect();
        let (total, _, _) = instance.budget.snapshot();
        let fill = instance
            .budget
            .reserve_lane(instance.budget.remaining_lane(2), 2)
            .unwrap();
        assert!(instance.reserve_lifecycle(0).is_err());
        assert!(instance.emit(Event::new(STORAGE, 999, 0, OK, b"{}".to_vec())));
        let storage = events.try_recv().unwrap();
        assert_eq!(storage.kind, STORAGE);
        instance.release_credit(storage);
        // Even with lifecycle bytes exhausted, fresh reset and its completion
        // have a physically separate map/queue/budget lane.
        let request = instance.submit(7, 0, reset(false)).unwrap();
        let operation = commands.try_recv().unwrap();
        assert_eq!(operation.id, request);
        instance.finish(operation, OK, Vec::new());
        let completion = events.try_recv().unwrap();
        assert_eq!(completion.request, request);
        instance.release_credit(completion);
        for (id, ticket) in tickets.into_iter().enumerate() {
            assert!(ticket.send(
                &instance,
                Event::new(13, 0, id as u64 + 1, CLOSED, Vec::new())
            ));
        }
        for id in 1..=500 {
            let event = events.try_recv().unwrap();
            assert_eq!(event.connection, id);
            instance.release_credit(event);
        }
        drop(fill);
        let budget = instance.budget.clone();
        drop(commands);
        drop(events);
        drop(instance);
        assert_eq!(budget.snapshot(), (total, 0, 0));
    }
    #[test]
    fn five_hundred_read_permits_survive_shrink_and_data_exhaustion() {
        let (instance, commands, callbacks) = setup();
        *instance.handles.lock().unwrap() = HandleRegistry::new(0, 0).unwrap();
        let mut scopes = Vec::new();
        for _ in 0..500 {
            let mut handles = instance.handles.lock().unwrap();
            let allocate = || next_id().map_err(|_| HandleError::Allocator);
            let connection = handles.add_connection(Authority::Test, allocate).unwrap();
            let channel = handles
                .add_channel(
                    connection,
                    ChannelKind::ReliableStream,
                    Authority::Test,
                    allocate,
                )
                .unwrap();
            scopes.push((connection, channel));
        }
        for &(connection, channel) in &scopes {
            instance
                .submit_channel(2, connection, channel, br#"{"max_bytes":65536}"#)
                .unwrap();
            assert_eq!(
                instance.submit_channel(2, connection, channel, br#"{"max_bytes":65536}"#),
                Err(BUSY)
            );
        }
        assert_eq!(instance.operations.lock().unwrap().len(), 500);
        // Admission is NOT the running-read witness; only stream_read polling
        // enters its RAII scope. This unit is not a real 500-peer acceptance.
        assert_eq!(instance.reading_count.load(Ordering::Acquire), 0);
        let (total, used, _) = instance.budget.snapshot();
        let reserve = (256 * 1024).max(total / 8);
        let full = instance
            .budget
            .reserve(total - reserve - used, false)
            .unwrap();
        assert_eq!(instance.submit(2, 0, []), Err(FULL));
        let reset_id = instance.submit(7, 0, reset(false)).unwrap();
        let reset_op = commands.try_recv().unwrap();
        assert_eq!(reset_op.id, reset_id);
        instance.finish(reset_op, OK, vec![]);
        assert_eq!(
            instance.handles.lock().unwrap().capacity_counts().unwrap(),
            (0, 0)
        );
        for _ in 0..500 {
            let op = commands.try_recv().unwrap();
            assert_eq!(op.phase.load(Ordering::Acquire), 2);
            instance.finish(op, CANCELLED, vec![]);
        }
        assert_eq!(instance.operations.lock().unwrap().len(), 501);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..501 {
            let event = callbacks.try_recv().unwrap();
            assert!(seen.insert(event.request));
            instance.release_credit(event);
        }
        assert!(instance.operations.lock().unwrap().is_empty());
        assert!(callbacks.try_recv().is_err());
        drop(full);
        let budget = instance.budget.clone();
        drop(commands);
        drop(callbacks);
        drop(instance);
        assert_eq!(budget.snapshot(), (total, 0, 0));
    }

    #[test]
    fn baseline_terminal_capacity_is_not_thirty_two_pending_operations() {
        let (instance, commands, _callbacks) = setup();
        for _ in 0..64 {
            instance
                .submit(2, 0, vec![])
                .expect("baseline has at least 64 terminal credits");
            // Remove queue occupancy: these operations remain pending, just like
            // long-lived READs, and retain their terminal reservation.
            let _running = commands.try_recv().unwrap();
        }
        assert_eq!(instance.operations.lock().unwrap().len(), 64);
    }

    #[test]
    fn reset_admission_fences_and_cancels_queued_but_not_running_operations() {
        let (instance, commands, _callbacks) = setup();
        let queued = instance.submit(2, 0, vec![]).unwrap();
        let running = instance.submit(5, 0, vec![]).unwrap();
        instance.operations.lock().unwrap()[&running].store(1, Ordering::Release);
        assert_eq!(
            instance.submit(7, 0, b"{\"expected_device_id\":\"wrong\"}"),
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
        let first = commands.try_recv().unwrap();
        assert_eq!(
            first.id, reset_id,
            "management lane precedes ordinary queued work"
        );
        commands.try_recv().unwrap();
        commands.try_recv().unwrap();
        instance.finish(first, UNKNOWN, vec![]);
        assert!(instance.resetting.load(Ordering::Acquire));
        assert_eq!(instance.submit(7, 0, reset(false)), Err(INVALID));
        assert!(instance.submit(7, 0, reset(true)).is_ok());
    }
}
