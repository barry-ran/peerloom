//! Parent-scoped typed channels. No raw transport or authorization-extending setter escapes.
use super::*;
use crate::{QueueConfig, QueueError};
use std::sync::atomic::AtomicUsize;
use tokio::sync::Notify;

mod message;
mod stream;
pub use message::{SdkMessageChannel, SdkMessageSender, SendDisposition};
pub use stream::{SdkByteStream, SdkStreamReader, SdkStreamWriter};

pub enum SdkChannel {
    Message(SdkMessageChannel),
    Stream(SdkByteStream),
}

struct ChannelGate {
    parent: Arc<Gate>,
    closed: AtomicBool,
    changed: Notify,
    finished: AtomicBool,
    drained: Notify,
}
impl ChannelGate {
    fn new(parent: Arc<Gate>) -> Arc<Self> {
        Arc::new(Self {
            parent,
            closed: AtomicBool::new(false),
            changed: Notify::new(),
            finished: AtomicBool::new(false),
            drained: Notify::new(),
        })
    }
    fn check(&self) -> Result<(), SdkError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(SdkError::Closed);
        }
        self.parent.check()
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
    fn finished(&self) {
        self.finished.store(true, Ordering::Release);
        self.drained.notify_waiters();
    }
    async fn close_and_wait(&self) -> Result<(), SdkError> {
        self.close();
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let drained = self.drained.notified();
                tokio::pin!(drained);
                drained.as_mut().enable();
                if self.finished.load(Ordering::Acquire) || self.parent.check().is_err() {
                    return;
                }
                drained.await;
            }
        })
        .await
        .map_err(|_| SdkError::Transport(TransportError::Timeout))
    }
    async fn invalidated(&self) {
        loop {
            let local = self.changed.notified();
            let parent = self.parent.changed.notified();
            tokio::pin!(local, parent);
            local.as_mut().enable();
            parent.as_mut().enable();
            if self.check().is_err() {
                return;
            }
            let deadline = match self.parent.deadline.lock() {
                Ok(value) => *value,
                Err(_) => return,
            };
            let Some(deadline) = deadline else {
                return;
            };
            tokio::select! {
                _ = &mut local => {},
                _ = &mut parent => {},
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {},
            }
        }
    }
}

#[derive(Clone)]
pub struct ChannelValidity(Arc<ChannelGate>);
impl ChannelValidity {
    pub fn is_valid(&self) -> bool {
        self.0.check().is_ok()
    }
}

#[derive(Clone)]
struct Scope {
    session_id: String,
    generation: u64,
    label: String,
    mode: ChannelMode,
    gate: Arc<ChannelGate>,
}
impl Scope {
    fn validity(&self) -> ChannelValidity {
        ChannelValidity(self.gate.clone())
    }
}

/// Counts active construction/handshakes/workers. Lifetime backend creation remains
/// independently bounded by TransportConfig.max_channels and is never decremented here.
struct ActiveChannels {
    used: AtomicUsize,
    limit: usize,
}
struct ActivePermit(Arc<ActiveChannels>);
impl ActiveChannels {
    fn reserve(self: &Arc<Self>) -> Result<ActivePermit, SdkError> {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < self.limit).then_some(used + 1)
            })
            .map_err(|_| SdkError::Busy)?;
        Ok(ActivePermit(self.clone()))
    }
}
impl Drop for ActivePermit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}

fn queue_error(error: QueueError) -> SdkError {
    match error {
        QueueError::Full => SdkError::QueueFull,
        QueueError::MessageTooLarge => SdkError::MessageTooLarge,
        QueueError::Closed => SdkError::Closed,
        QueueError::Expired => SdkError::Transport(TransportError::Timeout),
        _ => SdkError::InvalidConfiguration,
    }
}

pub(super) struct OpenRequest {
    label: String,
    mode: ChannelMode,
    queue: QueueConfig,
    result: oneshot::Sender<Result<SdkChannel, SdkError>>,
}

use crate::outbound::OutboundBudget;
use device_transport_webrtc::{IncomingChannel, stream::ByteStream};
use tokio::task::JoinSet;

enum RawChannel {
    Message(MessageChannel, ChannelMode),
    Stream(ByteStream),
}
impl RawChannel {
    async fn ready(&mut self) -> Result<String, SdkError> {
        match self {
            Self::Message(raw, _) => {
                let label = raw.metadata().await.map_err(SdkError::Transport)?.label;
                raw.wait_open().await.map_err(SdkError::Transport)?;
                Ok(label)
            }
            Self::Stream(raw) => {
                let label = raw.metadata().await.map_err(stream_error)?.label;
                raw.wait_open().await.map_err(stream_error)?;
                Ok(label)
            }
        }
    }
    async fn close(&mut self) {
        match self {
            Self::Message(raw, _) => {
                let _ = raw.close().await;
            }
            Self::Stream(raw) => {
                let _ = raw.close().await;
            }
        }
    }
}
fn stream_error(error: device_transport_webrtc::stream::StreamError) -> SdkError {
    match error {
        device_transport_webrtc::stream::StreamError::Transport(error) => {
            SdkError::Transport(error)
        }
        _ => SdkError::Closed,
    }
}
struct Prepared {
    raw: RawChannel,
    label: String,
    queue: QueueConfig,
    permit: ActivePermit,
    response: Option<oneshot::Sender<Result<SdkChannel, SdkError>>>,
}
type OpenResponse = oneshot::Sender<Result<SdkChannel, SdkError>>;
fn bind(
    prepared: Prepared,
    parent: &Scope,
    budget: &OutboundBudget,
    workers: &mut JoinSet<(bool, Result<(), SdkError>)>,
    is_default: bool,
) -> Result<(SdkChannel, Option<OpenResponse>), SdkError> {
    let mut scope = parent.clone();
    scope.label = prepared.label;
    scope.gate = ChannelGate::new(parent.gate.parent.clone());
    let handle = match prepared.raw {
        RawChannel::Message(raw, mode) => {
            scope.mode = mode;
            let (handle, worker) = message::wrap(scope, prepared.queue, budget.clone())?;
            workers.spawn(async move { (is_default, worker.run(raw, prepared.permit).await) });
            SdkChannel::Message(handle)
        }
        RawChannel::Stream(raw) => {
            scope.mode = ChannelMode::ReliableStream;
            let (handle, worker) = stream::wrap(scope, budget.clone());
            workers.spawn(async move { (is_default, worker.run(raw, prepared.permit).await) });
            SdkChannel::Stream(handle)
        }
    };
    Ok((handle, prepared.response))
}
fn valid_queue(queue: QueueConfig) -> bool {
    queue.max_messages > 0
        && queue.max_messages <= 4096
        && queue.max_bytes > 0
        && queue.max_bytes <= 16 * 1024 * 1024
        && queue.max_message_bytes > 0
        && queue.max_message_bytes <= 65536
        && queue.max_message_bytes <= queue.max_bytes
        && !queue.ttl.is_zero()
        && queue.ttl <= Duration::from_secs(3600)
}
impl Connection {
    pub fn default_sender(&self) -> SdkMessageSender {
        self.default.sender()
    }
    async fn open_typed(
        &self,
        label: &str,
        mode: ChannelMode,
        queue: QueueConfig,
    ) -> Result<SdkChannel, SdkError> {
        self.gate.check()?;
        if label.len() > 128 || !valid_queue(queue) {
            return Err(SdkError::InvalidConfiguration);
        }
        let (result, completion) = oneshot::channel();
        self.channels
            .try_send(OpenRequest {
                label: label.into(),
                mode,
                queue,
                result,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SdkError::QueueFull,
                _ => SdkError::Closed,
            })?;
        completion.await.map_err(|_| SdkError::Closed)?
    }
    pub async fn open_message(
        &self,
        label: &str,
        mode: ChannelMode,
        queue: QueueConfig,
    ) -> Result<SdkMessageChannel, SdkError> {
        if mode == ChannelMode::ReliableStream {
            return Err(SdkError::InvalidConfiguration);
        }
        match self.open_typed(label, mode, queue).await? {
            SdkChannel::Message(channel) => Ok(channel),
            _ => Err(SdkError::Closed),
        }
    }
    pub async fn open_stream(&self, label: &str) -> Result<SdkByteStream, SdkError> {
        match self
            .open_typed(label, ChannelMode::ReliableStream, QueueConfig::default())
            .await?
        {
            SdkChannel::Stream(channel) => Ok(channel),
            _ => Err(SdkError::Closed),
        }
    }
    pub fn take_incoming_channels(&mut self) -> Result<SdkIncomingChannels, SdkError> {
        self.gate.check()?;
        self.incoming.take().ok_or(SdkError::Closed)
    }
    pub async fn accept_channel(&mut self) -> Result<SdkChannel, SdkError> {
        self.incoming
            .as_mut()
            .ok_or(SdkError::Closed)?
            .receive()
            .await
    }
}

pub struct SdkIncomingChannels {
    gate: Arc<ChannelGate>,
    received: mpsc::Receiver<SdkChannel>,
}
impl SdkIncomingChannels {
    pub async fn receive(&mut self) -> Result<SdkChannel, SdkError> {
        self.gate.check()?;
        tokio::select! {
            biased;
            _ = self.gate.invalidated() => Err(SdkError::Closed),
            channel = self.received.recv() => { self.gate.check()?; channel.ok_or(SdkError::Closed) },
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    peer: Arc<PeerTransport>,
    initial: MessageChannel,
    id: String,
    generation: u64,
    parent: Arc<Gate>,
    active_limit: usize,
    budget: OutboundBudget,
    events: mpsc::Sender<Internal>,
    sdk: mpsc::Sender<Command>,
    peer_device_id: String,
    request_id: Option<String>,
) -> Result<(), SdkError> {
    let active = Arc::new(ActiveChannels {
        used: AtomicUsize::new(0),
        limit: active_limit,
    });
    let scope = Scope {
        session_id: id.clone(),
        generation,
        label: String::new(),
        mode: ChannelMode::ReliableMessage,
        gate: ChannelGate::new(parent.clone()),
    };
    let mut workers = JoinSet::new();
    let mut preparing: JoinSet<Result<Prepared, SdkError>> = JoinSet::new();
    let default = Prepared {
        raw: RawChannel::Message(initial, ChannelMode::ReliableMessage),
        label: "peerloom.reliable".into(),
        queue: QueueConfig {
            max_messages: 32,
            max_bytes: 2 * 1024 * 1024,
            ..QueueConfig::default()
        },
        permit: active.reserve()?,
        response: None,
    };
    let (SdkChannel::Message(default), _) = bind(default, &scope, &budget, &mut workers, true)?
    else {
        unreachable!()
    };
    let (channels, mut opens) = mpsc::channel::<OpenRequest>(active_limit);
    let (incoming, received) = mpsc::channel(active_limit);
    events
        .send(Internal::Ready(
            id.clone(),
            generation,
            Connection {
                session_id: id,
                peer_device_id,
                request_id,
                generation,
                default,
                channels,
                incoming: Some(SdkIncomingChannels {
                    gate: scope.gate.clone(),
                    received,
                }),
                gate: parent.clone(),
                sdk,
            },
        ))
        .await
        .map_err(|_| SdkError::Closed)?;
    loop {
        scope.gate.check()?;
        tokio::select! {
            _ = scope.gate.invalidated() => return Err(SdkError::Closed),
            _ = peer.wait_interrupted() => return Err(SdkError::Transport(TransportError::Ice)),
            result = workers.join_next(), if !workers.is_empty() => {
                match result {
                    Some(Ok((true, result))) => return result,
                    Some(Err(_)) => return Err(SdkError::Closed),
                    _ => {},
                }
            },
            result = preparing.join_next(), if !preparing.is_empty() => {
                match result {
                    Some(Ok(Ok(prepared))) => {
                        let (handle, response) = bind(prepared, &scope, &budget, &mut workers, false)?;
                        if let Some(response) = response { let _ = response.send(Ok(handle)); }
                        else if let Err(error) = incoming.try_send(handle) { drop(error.into_inner()); }
                    },
                    Some(Ok(Err(_))) => {}, // The request's own response is settled by its task.
                    Some(Err(_)) => return Err(SdkError::Closed),
                    None => {},
                }
            },
            request = opens.recv() => {
                let Some(request) = request else { return Ok(()); };
                if request.result.is_closed() { continue; }
                let permit = match active.reserve() {
                    Ok(permit) => permit,
                    Err(error) => { let _ = request.result.send(Err(error)); continue; },
                };
                let peer = peer.clone();
                let gate = scope.gate.clone();
                preparing.spawn(async move {
                    let operation = async {
                        let mut raw = match request.mode {
                            ChannelMode::ReliableStream => RawChannel::Stream(peer.create_stream(&request.label).await.map_err(stream_error)?),
                            mode => RawChannel::Message(peer.create_channel(&request.label, mode).await.map_err(SdkError::Transport)?, mode),
                        };
                        match raw.ready().await {
                            Ok(label) => Ok((raw, label)),
                            Err(error) => { raw.close().await; Err(error) },
                        }
                    };
                    let result = tokio::select! { biased;
                        _ = gate.invalidated() => Err(SdkError::Closed),
                        result = operation => result,
                    };
                    match result {
                        Ok((raw,label)) => Ok(Prepared { raw, label, queue: request.queue, permit, response: Some(request.result) }),
                        Err(error) => { let _ = request.result.send(Err(error.clone())); Err(error) },
                    }
                });
            },
            result = peer.accept_incoming() => {
                let raw = match result {
                    Ok(IncomingChannel::ReliableMessage(raw)) => RawChannel::Message(raw, ChannelMode::ReliableMessage),
                    Ok(IncomingChannel::LowLatencyMessage(raw)) => RawChannel::Message(raw, ChannelMode::LowLatencyMessage),
                    Ok(IncomingChannel::ReliableStream(raw)) => RawChannel::Stream(raw),
                    Err(TransportError::Timeout | TransportError::UnsupportedChannel) => continue,
                    Err(error) => return Err(SdkError::Transport(error)),
                };
                let permit = active.reserve();
                let gate = scope.gate.clone();
                preparing.spawn(async move {
                    let mut raw = raw;
                    let permit = match permit { Ok(permit) => permit, Err(error) => { raw.close().await; return Err(error); } };
                    let result = tokio::select! { biased;
                        _ = gate.invalidated() => Err(SdkError::Closed),
                        result = raw.ready() => result,
                    };
                    match result {
                        Ok(label) => Ok(Prepared { raw, label, queue: QueueConfig::default(), permit, response: None }),
                        Err(error) => { raw.close().await; Err(error) },
                    }
                });
            },
        }
    }
}

#[cfg(test)]
pub(super) fn test_connection() -> (Connection, Arc<Gate>, mpsc::Sender<Vec<u8>>) {
    let (sdk, _) = mpsc::channel(1);
    let (channels, _) = mpsc::channel(1);
    let (_, received) = mpsc::channel(1);
    let gate = Arc::new(Gate::default());
    gate.update(Some(Instant::now() + Duration::from_secs(60)));
    let id = uuid::Uuid::new_v4().to_string();
    let scope = Scope {
        session_id: id.clone(),
        generation: 1,
        label: "peerloom.reliable".into(),
        mode: ChannelMode::ReliableMessage,
        gate: ChannelGate::new(gate.clone()),
    };
    let (mut default, worker) = message::wrap(
        scope.clone(),
        QueueConfig::default(),
        OutboundBudget::new(4 * 1024 * 1024, 1024).unwrap(),
    )
    .unwrap();
    let send = worker.test_sender();
    default.retain_test_worker(worker);
    (
        Connection {
            session_id: id,
            peer_device_id: uuid::Uuid::nil().to_string(),
            request_id: None,
            generation: 1,
            default,
            channels,
            incoming: Some(SdkIncomingChannels {
                gate: scope.gate,
                received,
            }),
            gate: gate.clone(),
            sdk,
        },
        gate,
        send,
    )
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    #[test]
    fn active_construction_and_workers_share_slot_without_reclaiming_lifetime_counter() {
        let active = Arc::new(ActiveChannels {
            used: AtomicUsize::new(0),
            limit: 2,
        });
        let first = active.reserve().unwrap();
        let second = active.reserve().unwrap();
        assert!(matches!(active.reserve(), Err(SdkError::Busy)));
        drop(first);
        assert!(active.reserve().is_ok());
        assert_eq!(active.used.load(Ordering::Acquire), 1);
        drop(second);
        assert_eq!(active.used.load(Ordering::Acquire), 0);
    }
    #[tokio::test]
    async fn lease_and_installation_invalidate_all_children_but_child_close_is_local() {
        let parent = Arc::new(Gate::default());
        parent.update(Some(Instant::now() + Duration::from_secs(60)));
        let a = ChannelGate::new(parent.clone());
        let b = ChannelGate::new(parent.clone());
        a.close();
        assert_eq!(a.check(), Err(SdkError::Closed));
        assert!(b.check().is_ok());
        parent.update(Some(Instant::now()));
        b.invalidated().await;
        assert_eq!(b.check(), Err(SdkError::AuthorizationExpired));
        parent.installation_closed.store(true, Ordering::Release);
        parent.update(Some(Instant::now() + Duration::from_secs(60)));
        assert_eq!(b.check(), Err(SdkError::Closed));
    }
}
