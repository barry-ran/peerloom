//! Per-connection/channel workers keep pending stream reads off the control actor.
use crate::{
    bridge::error,
    handles::{ChannelKind, ScopedValidity},
    queue,
    state::*,
};
use device_core::{
    QueueConfig,
    sdk::{Connection, SdkByteStream, SdkChannel, SdkMessageChannel, SendDisposition},
};
use device_protocol::{ChannelMode, OverflowPolicy};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    sync::watch,
    task::{JoinHandle, JoinSet},
};

type Gate = ScopedValidity<Authority>;
pub struct Task {
    pub commands: queue::Sender<Queued>,
    pub closed: Option<LifecycleTicket>,
    stop: watch::Sender<bool>,
    join: JoinHandle<()>,
}
impl Task {
    pub fn route(&self, instance: &Arc<Instance>, operation: Operation) {
        let critical = critical_operation(operation.kind);
        if let Err(reason) = self.commands.try_send(Queued {
            instance: instance.clone(),
            operation: Some(operation),
        }) {
            let status = FULL;
            // A failed critical route must still wake all pending READs under
            // this task; its local fence has already made rollback impossible.
            if critical {
                self.stop.send_replace(true);
            }
            instance.finish(reason.into_inner().take(), status, Vec::new());
        }
    }
    pub async fn close(mut self) -> u32 {
        self.stop.send_replace(true);
        match tokio::time::timeout(Duration::from_secs(15), &mut self.join).await {
            Ok(Ok(())) => OK,
            Ok(Err(_)) => INTERNAL,
            Err(_) => {
                self.join.abort();
                let _ = (&mut self.join).await;
                UNKNOWN
            }
        }
    }
}
impl Drop for Task {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        // The runtime still owns and drains spawned futures before final shutdown.
        self.join.abort();
    }
}
pub struct Queued {
    instance: Arc<Instance>,
    operation: Option<Operation>,
}
impl queue::Item for Queued {
    fn key(&self) -> u64 {
        self.operation.as_ref().map_or(0, |op| op.connection)
    }
    fn critical(&self) -> bool {
        self.operation
            .as_ref()
            .is_some_and(|op| critical_operation(op.kind))
    }
}
impl Queued {
    fn take(mut self) -> Operation {
        self.operation.take().expect("queued operation")
    }
}
impl Drop for Queued {
    fn drop(&mut self) {
        if let Some(operation) = self.operation.take() {
            let status = if operation.phase.load(Ordering::Acquire) == 4 {
                UNKNOWN
            } else {
                CANCELLED
            };
            self.instance.finish(operation, status, Vec::new());
        }
    }
}
fn drain(instance: &Instance, commands: &mut queue::Receiver<Queued>) -> Vec<Operation> {
    commands.close();
    let mut irreversible = Vec::new();
    while let Ok(queued) = commands.try_recv() {
        let operation = queued.take();
        if operation.phase.load(Ordering::Acquire) == 4 {
            irreversible.push(operation);
        } else {
            instance.finish(operation, CANCELLED, Vec::new());
        }
    }
    irreversible
}
fn settle_cleanup(instance: &Instance, operations: Vec<Operation>, status: u32) {
    for operation in operations {
        let result = if matches!(operation.kind, 6 | 68) {
            status
        } else {
            CLOSED
        };
        instance.finish(operation, result, Vec::new());
    }
}
fn finish_result(guard: CompletionGuard, result: Result<Vec<u8>, u32>, gate: Option<Gate>) {
    match result {
        Ok(bytes) => guard.finish(OK, bytes, gate),
        Err(status) => guard.finish(status, Vec::new(), None),
    }
}
struct Registration {
    instance: Arc<Instance>,
    parent: u64,
    channel: Option<u64>,
    status: u32,
    closed: Option<LifecycleTicket>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.status = INTERNAL;
            self.instance.failed.store(true, Ordering::Release);
            self.instance.stop();
        }
        if let Ok(mut handles) = self.instance.handles.lock() {
            if let Some(channel) = self.channel {
                let _ = handles.remove_channel(self.parent, channel);
            } else {
                let _ = handles.remove_connection(self.parent);
            }
        }
        if let Some(channel) = self.channel {
            let mut event = Event::new(13, 0, self.parent, self.status, Vec::new());
            event.channel = channel;
            if let Some(ticket) = self.closed.take() {
                ticket.send(&self.instance, event);
            }
        }
    }
}
fn mode(channel: &SdkChannel) -> ChannelKind {
    match channel {
        SdkChannel::Stream(_) => ChannelKind::ReliableStream,
        SdkChannel::Message(channel) if channel.mode() == ChannelMode::LowLatencyMessage => {
            ChannelKind::LowLatencyMessage
        }
        _ => ChannelKind::ReliableMessage,
    }
}
fn channel_info(
    channel: &SdkChannel,
    epoch: Option<u64>,
) -> (device_core::sdk::ChannelValidity, Vec<u8>) {
    let (validity, label, session, generation, mode) = match channel {
        SdkChannel::Message(value) => (
            value.validity(),
            value.label(),
            value.session_id(),
            value.negotiation_generation(),
            value.mode(),
        ),
        SdkChannel::Stream(value) => (
            value.validity(),
            value.label(),
            value.session_id(),
            value.negotiation_generation(),
            ChannelMode::ReliableStream,
        ),
    };
    let mut metadata =
        json!({"label":label,"mode":mode_name(mode),"session_id":session,"generation":generation});
    exclusive_metadata(&mut metadata, epoch);
    (validity, metadata.to_string().into_bytes())
}
fn spawn_channel(
    instance: Arc<Instance>,
    parent: u64,
    channel: SdkChannel,
    ttl: Option<Duration>,
    epoch: Option<u64>,
) -> Result<(u64, Gate, Vec<u8>, Task), u32> {
    let kind = mode(&channel);
    let closed = instance.reserve_lifecycle(if kind == ChannelKind::ReliableStream {
        2
    } else {
        0
    })?;
    let (validity, payload) = channel_info(&channel, epoch);
    let (id, gate) = {
        let mut handles = instance.handles.lock().map_err(|_| INTERNAL)?;
        let id = handles
            .add_channel(parent, kind, Authority::Channel(validity), || {
                next_id().map_err(|_| crate::handles::HandleError::Allocator)
            })
            .map_err(handle_error)?;
        if let Some(ttl) = ttl {
            handles
                .set_message_ttl(parent, id, ttl)
                .map_err(handle_error)?;
        }
        (id, handles.channel(parent, id).map_err(handle_error)?)
    };
    let (sender, receiver) = queue::channel(instance.budget.clone());
    let (stop, stopped) = watch::channel(false);
    let worker_gate = gate.clone();
    let registration = Registration {
        instance: instance.clone(),
        parent,
        channel: Some(id),
        status: UNKNOWN,
        closed: Some(closed),
    };
    let join = tokio::spawn(async move {
        let mut registration = registration;
        match channel {
            SdkChannel::Message(channel) => {
                message_worker(
                    instance.clone(),
                    parent,
                    id,
                    worker_gate,
                    channel,
                    receiver,
                    stopped,
                )
                .await
            }
            SdkChannel::Stream(channel) => {
                stream_worker(
                    instance.clone(),
                    parent,
                    id,
                    worker_gate,
                    channel,
                    receiver,
                    stopped,
                )
                .await
            }
        }
        registration.status = CLOSED;
    });
    Ok((
        id,
        gate,
        payload,
        Task {
            closed: None,
            commands: sender,
            stop,
            join,
        },
    ))
}
async fn message_worker(
    instance: Arc<Instance>,
    parent: u64,
    id: u64,
    gate: Gate,
    mut channel: SdkMessageChannel,
    mut commands: queue::Receiver<Queued>,
    mut stop: watch::Receiver<bool>,
) {
    let sender = channel.sender();
    let mut sends = JoinSet::new();
    let mut close = None;
    loop {
        if *stop.borrow() || !gate.is_valid() {
            break;
        }
        tokio::select! {
            _ = stop.changed() => {},
            Some(_) = sends.join_next(), if !sends.is_empty() => {},
            operation = commands.recv() => {
                let Some(operation) = operation else { break };
                let Some(guard) = CompletionGuard::start(instance.clone(), operation.take()) else { continue };
                match guard.operation().kind {
                    64 => {
                        let sender = sender.clone();
                        sends.spawn(async move {
                            let result = sender.send_before(&guard.operation().input, guard.operation().deadline.expect("message admission deadline")).await.map(|value| {
                                json!({"disposition":if value == SendDisposition::Sent {"sent"} else {"dropped"}}).to_string().into_bytes()
                            }).map_err(error);
                            finish_result(guard, result, None);
                        });
                    }
                    68 => { close = Some(guard); break; }
                    _ => guard.finish(UNSUPPORTED, Vec::new(), None),
                }
            },
            received = channel.receive() => {
                match received {
                    Ok(payload) => {
                        let mut event = Event::new(14, 0, parent, OK, payload);
                        event.channel = id;
                        event.validity = Some(gate.clone());
                        if !instance.emit(event) { break; }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    let pending = drain(&instance, &mut commands);
    let status = channel.close().await.err().map(error).unwrap_or(OK);
    // Closing the child resolves all core send futures; abort is a bounded final fallback.
    if tokio::time::timeout(Duration::from_secs(2), async {
        while sends.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        sends.abort_all();
        while sends.join_next().await.is_some() {}
    }
    settle_cleanup(&instance, pending, status);
    if let Some(guard) = close {
        guard.finish(status, Vec::new(), None);
    }
}

struct ReadScope {
    instance: Arc<Instance>,
    entered: bool,
}
impl ReadScope {
    fn new(instance: Arc<Instance>) -> Self {
        Self {
            instance,
            entered: false,
        }
    }
    fn enter(&mut self) {
        if !self.entered {
            self.instance.reading_count.fetch_add(1, Ordering::AcqRel);
            self.entered = true;
        }
    }
}
impl Drop for ReadScope {
    fn drop(&mut self) {
        if self.entered {
            self.instance.reading_count.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
async fn stream_read(
    reader: &mut device_core::sdk::SdkStreamReader,
    pending: &mut Option<(Vec<u8>, ReadScope, CompletionGuard)>,
) -> Result<usize, device_core::sdk::SdkError> {
    match pending {
        Some((buffer, scope, _)) => {
            scope.enter();
            reader.read(buffer).await
        }
        None => std::future::pending().await,
    }
}
async fn stream_worker(
    instance: Arc<Instance>,
    _parent: u64,
    _id: u64,
    gate: Gate,
    channel: SdkByteStream,
    mut commands: queue::Receiver<Queued>,
    mut stop: watch::Receiver<bool>,
) {
    let (mut reader, writer) = channel.split();
    let (write_tx, mut write_rx) = queue::channel::<Queued>(instance.budget.clone());
    let writer_instance = instance.clone();
    let writer_gate = gate.clone();
    let mut writer_stop = stop.clone();
    let mut writer_task = tokio::spawn(async move {
        loop {
            if *writer_stop.borrow() || !writer_gate.is_valid() {
                break;
            }
            let queued = tokio::select! {
                _ = writer_stop.changed() => continue,
                command = write_rx.recv() => match command { Some(command) => command, None => break },
            };
            let Some(guard) = CompletionGuard::start(writer_instance.clone(), queued.take()) else {
                continue;
            };
            let result = if guard.operation().kind == 67 {
                writer
                    .shutdown_write_before(
                        guard
                            .operation()
                            .deadline
                            .expect("stream admission deadline"),
                    )
                    .await
                    .map(|_| Vec::new())
                    .map_err(error)
            } else {
                writer
                    .write_before(
                        &guard.operation().input,
                        guard
                            .operation()
                            .deadline
                            .expect("stream admission deadline"),
                    )
                    .await
                    .map(|written| json!({"written":written}).to_string().into_bytes())
                    .map_err(error)
            };
            finish_result(guard, result, None);
        }
        let pending = drain(&writer_instance, &mut write_rx);
        let status = writer.close().await.err().map(error).unwrap_or(OK);
        settle_cleanup(&writer_instance, pending, status);
    });
    let mut reading = None;
    let mut close = None;
    loop {
        if *stop.borrow() || !gate.is_valid() {
            break;
        }
        tokio::select! {
            _ = stop.changed() => {},
            operation = commands.recv() => {
                let Some(queued) = operation else { break };
                if matches!(queued.operation.as_ref().unwrap().kind, 66 | 67) {
                    if let Err(reason) = write_tx.try_send(queued) {
                        instance.finish(reason.into_inner().take(), FULL, Vec::new());
                    }
                    continue;
                }
                let Some(guard) = CompletionGuard::start(instance.clone(), queued.take()) else { continue };
                match guard.operation().kind {
                    65 if reading.is_none() => {
                        let mut guard = guard;
                        let buffer = guard.take_read_buffer();
                        // Buffer precedes guard so abort drops memory before its
                        // UNKNOWN terminal can return the byte reservation.
                        reading = Some((buffer, ReadScope::new(instance.clone()), guard));
                    }
                    65 => guard.finish(BUSY, Vec::new(), None),
                    68 => { close = Some(guard); break; }
                    _ => guard.finish(UNSUPPORTED, Vec::new(), None),
                }
            },
            received = stream_read(&mut reader, &mut reading) => {
                let (mut buffer, scope, guard) = reading.take().expect("only enabled for active read");
                drop(scope);
                match received {
                    Ok(bytes) => { buffer.truncate(bytes); guard.finish(OK, buffer, Some(gate.clone())); },
                    Err(reason) => { drop(buffer); guard.finish(error(reason), Vec::new(), None); },
                }
            }
        }
    }
    let pending = drain(&instance, &mut commands);
    if let Some((mut buffer, scope, guard)) = reading.take() {
        drop(scope);
        buffer.fill(0);
        drop(buffer);
        guard.finish(CLOSED, Vec::new(), None);
    }
    drop(write_tx);
    let mut status = reader.close().await.err().map(error).unwrap_or(OK);
    match tokio::time::timeout(Duration::from_secs(15), &mut writer_task).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            instance.failed.store(true, Ordering::Release);
            instance.stop();
            status = INTERNAL;
        }
        Err(_) => {
            writer_task.abort();
            let _ = writer_task.await;
            status = UNKNOWN;
        }
    }
    settle_cleanup(&instance, pending, status);
    if let Some(guard) = close {
        guard.finish(status, Vec::new(), None);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    label: String,
    #[serde(deserialize_with = "read_mode")]
    mode: ChannelMode,
    #[serde(default)]
    queue: Option<MessageQueueOptions>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageQueueOptions {
    max_messages: usize,
    max_bytes: usize,
    ttl_ms: u64,
    #[serde(deserialize_with = "read_overflow")]
    overflow: OverflowPolicy,
}
impl Open {
    fn queue(&self) -> Result<QueueConfig, u32> {
        if self.label.is_empty() || self.label.len() > 128 {
            return Err(INVALID);
        }
        if self.mode == ChannelMode::ReliableStream && self.queue.is_some() {
            return Err(INVALID);
        }
        let Some(value) = &self.queue else {
            return Ok(QueueConfig::default());
        };
        if !(1..=256).contains(&value.max_messages)
            || !(1..=1024 * 1024).contains(&value.max_bytes)
            || !(1..=60000).contains(&value.ttl_ms)
        {
            return Err(INVALID);
        }
        Ok(QueueConfig {
            max_messages: value.max_messages,
            max_bytes: value.max_bytes,
            max_message_bytes: value.max_bytes.min(65536),
            ttl: Duration::from_millis(value.ttl_ms),
            overflow: value.overflow,
        })
    }
}

pub fn spawn_connection(
    instance: Arc<Instance>,
    id: u64,
    gate: Gate,
    mut connection: Connection,
) -> Result<Task, u32> {
    let epoch = connection.target_epoch();
    let closed = instance.reserve_lifecycle(1)?;
    let mut incoming = connection.take_incoming_channels().map_err(error)?;
    let default_sender = connection.default_sender();
    let (sender, mut commands) = queue::channel::<Queued>(instance.budget.clone());
    let (stop, mut stopped) = watch::channel(false);
    let registration = Registration {
        instance: instance.clone(),
        parent: id,
        channel: None,
        status: UNKNOWN,
        closed: None,
    };
    let join = tokio::spawn(async move {
        let _registration = registration;
        let mut children: HashMap<u64, Task> = HashMap::new();
        let mut sends = JoinSet::new();
        let mut close = None;
        loop {
            // Reclaim finished children; closed handles are removed by their own worker.
            children.retain(|_, child| !child.join.is_finished());
            if *stopped.borrow() || !gate.is_valid() {
                break;
            }
            tokio::select! {
                _ = stopped.changed() => {},
                Some(_) = sends.join_next(), if !sends.is_empty() => {},
                operation = commands.recv() => {
                    let Some(queued) = operation else { break };
                    if queued.operation.as_ref().unwrap().kind >= 64 {
                        let operation = queued.take();
                        if let Some(child) = children.get(&operation.channel) { child.route(&instance, operation); }
                        else { instance.finish(operation, CLOSED, Vec::new()); }
                        continue;
                    }
                    let Some(guard) = CompletionGuard::start(instance.clone(), queued.take()) else { continue };
                    match guard.operation().kind {
                        4 => {
                            let sender = default_sender.clone();
                            sends.spawn(async move {
                                let result = sender.send_before(&guard.operation().input, guard.operation().deadline.expect("message admission deadline")).await.map(|_| Vec::new()).map_err(error);
                                finish_result(guard, result, None);
                            });
                        }
                        6 => { close = Some(guard); break; }
                        8 => {
                            let result = async {
                                let request: Open = serde_json::from_slice(&guard.operation().input).map_err(|_| INVALID)?;
                                let queue = request.queue()?;
                                let channel = if request.mode == ChannelMode::ReliableStream {
                                    SdkChannel::Stream(connection.open_stream(&request.label).await.map_err(error)?)
                                } else {
                                    SdkChannel::Message(connection.open_message(&request.label, request.mode, queue).await.map_err(error)?)
                                };
                                spawn_channel(instance.clone(), id, channel, Some(queue.ttl), epoch)
                            }.await;
                            match result {
                                Ok((channel, validity, payload, task)) => { children.insert(channel, task); guard.opened(channel, payload, validity); },
                                Err(status) => guard.finish(status, Vec::new(), None),
                            }
                        }
                        _ => guard.finish(UNSUPPORTED, Vec::new(), None),
                    }
                },
                received = connection.receive() => match received {
                    Ok(payload) => {
                        let mut event = Event::new(6, 0, id, OK, payload);
                        event.validity = Some(gate.clone());
                        if !instance.emit(event) { break; }
                    }
                    Err(_) => break,
                },
                received = incoming.receive() => match received {
                    Ok(channel) => match spawn_channel(instance.clone(), id, channel, None, epoch) {
                        Ok((channel, validity, payload, task)) => {
                            children.insert(channel, task);
                            let mut event = Event::new(12, 0, id, OK, payload);
                            event.channel = channel;
                            event.validity = Some(validity);
                            if !instance.emit(event) { break; }
                        }
                        Err(_) => break,
                    },
                    Err(_) => break,
                }
            }
        }
        let pending = drain(&instance, &mut commands);
        // Close core parent first, invalidating every child's in-flight/read gates.
        let mut status = connection.close().await.err().map(error).unwrap_or(OK);
        let mut closes = JoinSet::new();
        for (_, child) in children {
            closes.spawn(child.close());
        }
        while let Some(result) = closes.join_next().await {
            if !matches!(result, Ok(OK)) {
                status = UNKNOWN;
            }
        }
        if tokio::time::timeout(Duration::from_secs(2), async {
            while sends.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            sends.abort_all();
            while sends.join_next().await.is_some() {}
        }
        settle_cleanup(&instance, pending, status);
        if let Some(guard) = close {
            guard.finish(status, Vec::new(), None);
        }
    });
    Ok(Task {
        closed: Some(closed),
        commands: sender,
        stop,
        join,
    })
}

fn mode_name(value: ChannelMode) -> &'static str {
    match value {
        ChannelMode::ReliableMessage => "reliable_message",
        ChannelMode::LowLatencyMessage => "low_latency_message",
        ChannelMode::ReliableStream => "reliable_stream",
    }
}
fn read_mode<'de, D: serde::Deserializer<'de>>(reader: D) -> Result<ChannelMode, D::Error> {
    match String::deserialize(reader)?.as_str() {
        "reliable_message" => Ok(ChannelMode::ReliableMessage),
        "low_latency_message" => Ok(ChannelMode::LowLatencyMessage),
        "reliable_stream" => Ok(ChannelMode::ReliableStream),
        _ => Err(serde::de::Error::custom("unsupported channel mode")),
    }
}
fn read_overflow<'de, D: serde::Deserializer<'de>>(reader: D) -> Result<OverflowPolicy, D::Error> {
    match String::deserialize(reader)?.as_str() {
        "fail" => Ok(OverflowPolicy::Fail),
        "drop_oldest" => Ok(OverflowPolicy::DropOldest),
        "drop_newest" => Ok(OverflowPolicy::DropNewest),
        _ => Err(serde::de::Error::custom("unsupported overflow policy")),
    }
}

/// Read-only authority metadata; omitted entirely for legacy non-exclusive sessions.
pub(crate) fn exclusive_metadata(value: &mut serde_json::Value, epoch: Option<u64>) {
    if let Some(epoch) = epoch {
        value["exclusive_target"] = json!(true);
        value["exclusive_protocol_version"] = json!(1);
        value["target_epoch"] = json!(epoch.to_string());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exclusive_metadata_is_versioned_and_absent_for_legacy_sessions() {
        let mut legacy = serde_json::json!({"generation": 1});
        super::exclusive_metadata(&mut legacy, None);
        assert_eq!(legacy, serde_json::json!({"generation": 1}));
        super::exclusive_metadata(&mut legacy, Some(i64::MAX as u64));
        assert_eq!(legacy["exclusive_target"], true);
        assert_eq!(legacy["exclusive_protocol_version"], 1);
        assert_eq!(legacy["target_epoch"], "9223372036854775807");
    }

    use super::*;
    #[test]
    fn wire_modes_are_strict_and_stream_rejects_message_drop_options() {
        let stream: Open =
            serde_json::from_str(r#"{"label":"s","mode":"reliable_stream"}"#).unwrap();
        assert!(stream.queue().is_ok());
        let bad: Open = serde_json::from_str(r#"{"label":"s","mode":"reliable_stream","queue":{"max_messages":1,"max_bytes":64,"ttl_ms":1,"overflow":"drop_oldest"}}"#).unwrap();
        assert_eq!(bad.queue().err(), Some(INVALID));
        assert!(serde_json::from_str::<Open>(r#"{"label":"s","mode":"unknown"}"#).is_err());
        let message: Open = serde_json::from_str(r#"{"label":"m","mode":"low_latency_message","queue":{"max_messages":1,"max_bytes":64,"ttl_ms":7,"overflow":"drop_newest"}}"#).unwrap();
        assert_eq!(message.queue().unwrap().ttl, Duration::from_millis(7));
        assert_eq!(mode_name(message.mode), "low_latency_message");
    }
}
