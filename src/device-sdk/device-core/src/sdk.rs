//! 单身份/单WSS的有界多会话编排；每个会话仍只有可靠消息通道。
//! WSS 自动恢复；已接受会话可按授权的新代重建连接，不是原地 ICE restart。
#[cfg(test)]
mod multiconnection_tests;
mod reset;
mod session_map;
use session_map::SessionMap;
const MAX_CONNECTIONS: usize = 32;
use crate::{
    identity::{
        IdempotencyKey, IdentityClient, IdentityError, IdentitySession, RegistrationRequest,
    },
    lease::LeaseGuard,
    signaling::{Envelope, SignalClient, SignalError},
};
use device_protocol::{ChannelMode, ConnectionPolicy};
use device_storage::{IdentityStore, SecretString, StoredIdentity};
use device_transport_webrtc::{
    CandidateKind, MessageChannel, PeerTransport, SessionDescription, TransportConfig,
    TransportError,
};
use serde_json::json;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

#[derive(Clone)]
pub struct SdkConfig {
    pub origin: String,
    pub application_id: String,
    pub development_loopback: bool,
    pub transport: TransportConfig,
    /// Auto/RelayOnly fetch approved TURN servers for each accepted session.
    /// Set false only for an explicitly supplied static ICE configuration.
    pub managed_relays: bool,
    pub max_connections: usize,
    pub max_channels_per_connection: usize,
    pub auto_reconnect: bool,
}
impl SdkConfig {
    pub fn new(origin: String, application_id: String) -> Self {
        Self {
            origin,
            application_id,
            development_loopback: false,
            transport: TransportConfig::default(),
            managed_relays: true,
            max_connections: 1,
            max_channels_per_connection: 1,
            auto_reconnect: true,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    InvalidConfiguration,
    Identity(IdentityError),
    Signal(SignalError),
    Transport(TransportError),
    Offline,
    Busy,
    Closed,
    AuthorizationExpired,
    QueueFull,
    MessageTooLarge,
    RequestOutcomeUnknown,
    Rejected(String),
}
impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SdkError {}
#[derive(Debug)]
pub enum SdkEvent {
    Online,
    Offline,
    IncomingConnection {
        session_id: String,
        source_device_id: String,
    },
    ConnectionReady(Connection),
    /// An admitted outgoing request failed before a session was established.
    ConnectionRequestFailed {
        target_device_id: String,
        request_id: String,
        reason: SdkError,
    },
    ConnectionClosed {
        session_id: String,
        reason: SdkError,
    },
    Stopped(SdkError),
    IdentityPersistencePending,
}

#[derive(Default)]
struct Gate {
    installation_closed: Arc<AtomicBool>,
    closed: AtomicBool,
    deadline: Mutex<Option<Instant>>,
    changed: tokio::sync::Notify,
}
impl Gate {
    fn check(&self) -> Result<(), SdkError> {
        if self.closed.load(Ordering::Acquire) || self.installation_closed.load(Ordering::Acquire) {
            return Err(SdkError::Closed);
        }
        let deadline = *self.deadline.lock().map_err(|_| SdkError::Closed)?;
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            return Err(SdkError::AuthorizationExpired);
        }
        Ok(())
    }
    fn update(&self, deadline: Option<Instant>) {
        if let Ok(mut value) = self.deadline.lock() {
            *value = deadline;
        }
        self.changed.notify_waiters();
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}
struct SendRequest {
    data: Vec<u8>,
    expires: Instant,
    result: oneshot::Sender<Result<(), SdkError>>,
}
/// 不暴露 raw transport；截止后旧接收队列也不能继续向应用交付。
pub struct Connection {
    session_id: String,
    generation: u64,
    commands: mpsc::Sender<SendRequest>,
    messages: mpsc::Receiver<Vec<u8>>,
    gate: Arc<Gate>,
    sdk: mpsc::Sender<Command>,
}
impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}
/// 只读授权观察器；跨 ABI 排队的事件在交付前必须再次检查，不提供恢复/延长授权能力。
#[derive(Clone)]
pub struct ConnectionValidity(Arc<Gate>);
impl ConnectionValidity {
    pub fn is_valid(&self) -> bool {
        self.0.check().is_ok()
    }
}
impl Connection {
    pub fn validity(&self) -> ConnectionValidity {
        ConnectionValidity(self.gate.clone())
    }
    pub fn negotiation_generation(&self) -> u64 {
        self.generation
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub async fn send(&self, data: &[u8]) -> Result<(), SdkError> {
        self.gate.check()?;
        if data.len() > 65536 {
            return Err(SdkError::MessageTooLarge);
        }
        let (result, completion) = oneshot::channel();
        self.commands
            .try_send(SendRequest {
                data: data.to_vec(),
                expires: Instant::now() + Duration::from_secs(30),
                result,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => SdkError::QueueFull,
                _ => SdkError::Closed,
            })?;
        completion.await.map_err(|_| SdkError::Closed)?
    }
    pub async fn receive(&mut self) -> Result<Vec<u8>, SdkError> {
        loop {
            let changed = self.gate.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.gate.check()?;
            let deadline = self
                .gate
                .deadline
                .lock()
                .map_err(|_| SdkError::Closed)?
                .ok_or(SdkError::AuthorizationExpired)?;
            tokio::select! {
                biased;
                _=&mut changed=>continue,
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(deadline))=>continue,
                data=self.messages.recv()=>{let data=data.ok_or(SdkError::Closed)?;self.gate.check()?;return Ok(data);}
            }
        }
    }
    pub async fn close(self) -> Result<(), SdkError> {
        self.gate.close();
        let (done, completion) = oneshot::channel();
        match tokio::time::timeout(
            Duration::from_secs(5),
            self.sdk.send(Command::CloseConnection(
                self.session_id.clone(),
                self.generation,
                Some(done),
            )),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Ok(()),
            Err(_) => return Err(SdkError::QueueFull),
        }
        tokio::time::timeout(Duration::from_secs(12), completion)
            .await
            .map_err(|_| SdkError::Transport(TransportError::Timeout))?
            .map_err(|_| SdkError::Closed)
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.gate.close();
        let _ = self.sdk.try_send(Command::CloseConnection(
            self.session_id.clone(),
            self.generation,
            None,
        ));
    }
}

pub struct DeviceSdk {
    identity_state: Arc<tokio::sync::Mutex<IdentitySession>>,
    installation_closed: Arc<AtomicBool>,
    reset_started: bool,
    reset_complete: bool,
    reset_shutdown_unknown: bool,
    device_id: String,
    commands: mpsc::Sender<Command>,
    events: mpsc::Receiver<SdkEvent>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl DeviceSdk {
    pub async fn load(config: SdkConfig, store: Arc<dyn IdentityStore>) -> Result<Self, SdkError> {
        let identity = Self::identity(&config, store).await?;
        Self::start(config, identity, true).await
    }
    /// 调用者需保留 request/key 的副本：创建 future 取消或进程崩溃后，以同 key/body
    /// 在服务端有限 replay 窗口内恢复。此 facade 不声称实现持久化变更日志。
    pub async fn register(
        config: SdkConfig,
        store: Arc<dyn IdentityStore>,
        request: RegistrationRequest,
        key: IdempotencyKey,
    ) -> Result<Self, SdkError> {
        let mut identity = Self::identity(&config, store).await?;
        match identity.register(request, key).await {
            Ok(()) => {}
            Err(IdentityError::Storage(_)) if identity.identity().is_some() => {}
            Err(error) => return Err(SdkError::Identity(error)),
        }
        // The successful registration response is authoritative. Do not discard its new
        // in-memory credential merely because the optional persistence step failed.
        Self::start(config, identity, false).await
    }
    async fn identity(
        config: &SdkConfig,
        store: Arc<dyn IdentityStore>,
    ) -> Result<IdentitySession, SdkError> {
        if !(1..=MAX_CONNECTIONS).contains(&config.max_connections)
            || config.max_channels_per_connection != 1
        {
            return Err(SdkError::InvalidConfiguration);
        }
        validate_transport_configuration(config)?;
        let client = IdentityClient::new(
            &config.origin,
            config.development_loopback,
            Duration::from_secs(10),
        )
        .map_err(SdkError::Identity)?;
        IdentitySession::load(client, config.application_id.clone(), store)
            .await
            .map_err(SdkError::Identity)
    }
    async fn start(
        config: SdkConfig,
        identity: IdentitySession,
        verify: bool,
    ) -> Result<Self, SdkError> {
        let stored = identity
            .identity()
            .cloned()
            .ok_or(SdkError::Identity(IdentityError::NoIdentity))?;
        if verify {
            identity.device_self().await.map_err(SdkError::Identity)?;
        }
        let device_id = stored.device_id.clone();
        let (commands, command_rx) = mpsc::channel(32);
        let (events_tx, events) = mpsc::channel(config.max_connections * 4 + 8);
        let (stop, stop_rx) = oneshot::channel();
        let sdk_commands = commands.clone();
        let actor = Actor::new(config, identity, stored, sdk_commands, events_tx);
        let identity_state = actor.identity.clone();
        let installation_closed = actor.installation_closed.clone();
        let task = tokio::spawn(async move {
            actor.run(command_rx, stop_rx).await;
        });
        Ok(Self {
            identity_state,
            installation_closed,
            reset_started: false,
            reset_complete: false,
            reset_shutdown_unknown: false,
            device_id,
            commands,
            events,
            stop: Some(stop),
            task: Some(task),
        })
    }
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    pub async fn connect(&self, target_device_id: &str) -> Result<(), SdkError> {
        self.connect_with_request(target_device_id)
            .await
            .map(|_| ())
    }
    /// Returns the stable signaling request ID after bounded local admission.
    /// Later failure is correlated through `ConnectionRequestFailed`; admission is not readiness.
    pub async fn connect_with_request(&self, target_device_id: &str) -> Result<String, SdkError> {
        if self.reset_started {
            return Err(SdkError::Closed);
        }
        let target = uuid::Uuid::parse_str(target_device_id)
            .map_err(|_| SdkError::InvalidConfiguration)?
            .to_string();
        let (tx, rx) = oneshot::channel();
        self.commands
            .try_send(Command::Connect(target, tx))
            .map_err(|_| SdkError::QueueFull)?;
        rx.await.map_err(|_| SdkError::Closed)?
    }
    pub async fn accept(&self, session_id: &str) -> Result<(), SdkError> {
        self.respond(session_id, true).await
    }
    pub async fn reject(&self, session_id: &str) -> Result<(), SdkError> {
        self.respond(session_id, false).await
    }
    async fn respond(&self, session_id: &str, accept: bool) -> Result<(), SdkError> {
        if self.reset_started {
            return Err(SdkError::Closed);
        }
        let (tx, rx) = oneshot::channel();
        self.commands
            .try_send(Command::Respond(session_id.into(), accept, tx))
            .map_err(|_| SdkError::QueueFull)?;
        rx.await.map_err(|_| SdkError::Closed)?
    }
    /// 主动轮换后用新凭证重建 WSS；旧数据授权期限在 sync/renew 前不延长。
    pub async fn refresh_credentials(&self) -> Result<(), SdkError> {
        if self.reset_started {
            return Err(SdkError::Closed);
        }
        let (tx, rx) = oneshot::channel();
        self.commands
            .try_send(Command::Refresh(tx))
            .map_err(|_| SdkError::QueueFull)?;
        rx.await.map_err(|_| SdkError::Closed)?
    }
    pub async fn next_event(&mut self) -> Option<SdkEvent> {
        if self.reset_started {
            return None;
        }
        self.events.recv().await
    }
    pub async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut()
            && tokio::time::timeout(Duration::from_secs(35), &mut *task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        self.task.take();
    }
}
impl Drop for DeviceSdk {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
enum Command {
    Connect(String, oneshot::Sender<Result<String, SdkError>>),
    Respond(String, bool, oneshot::Sender<Result<(), SdkError>>),
    CloseConnection(String, u64, Option<oneshot::Sender<()>>),
    Refresh(oneshot::Sender<Result<(), SdkError>>),
}
enum Internal {
    Description(String, u64, &'static str, String),
    Ready(String, u64, Connection),
    Closed(String, u64, SdkError),
}
struct Worker {
    control: mpsc::Sender<SessionDescription>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
struct Session {
    id: String,
    source: String,
    target: String,
    guard: LeaseGuard,
    gate: Arc<Gate>,
    worker: Option<Worker>,
    renew_at: Instant,
    ready: bool,
    generation: u64,
    recovery_at: Option<Instant>,
    recovery_attempt: u32,
    sync_pending: bool,
    requests: std::collections::VecDeque<(String, u64)>,
}
type RefreshOutcome = (Result<(), IdentityError>, Option<StoredIdentity>);

struct Actor {
    installation_closed: Arc<AtomicBool>,
    config: SdkConfig,
    identity: Arc<tokio::sync::Mutex<IdentitySession>>,
    identity_client: IdentityClient,
    refresh: Option<JoinHandle<RefreshOutcome>>,
    refresh_waiters: Vec<oneshot::Sender<Result<(), SdkError>>>,
    refresh_at: Instant,
    refresh_needs_retry: bool,
    online_since: Option<Instant>,
    unstable_connections: u32,
    stored: StoredIdentity,
    commands: mpsc::Sender<Command>,
    events: mpsc::Sender<SdkEvent>,
    signal: Option<SignalClient>,
    rejected_sessions: std::collections::VecDeque<String>,
    dial: Option<JoinHandle<Result<SignalClient, SignalError>>>,
    retry_at: Instant,
    attempt: u32,
    sessions: SessionMap<Session>,
    internal_tx: mpsc::Sender<Internal>,
    internal_rx: mpsc::Receiver<Internal>,
}
impl Actor {
    fn new(
        config: SdkConfig,
        identity: IdentitySession,
        stored: StoredIdentity,
        commands: mpsc::Sender<Command>,
        events: mpsc::Sender<SdkEvent>,
    ) -> Self {
        let (internal_tx, internal_rx) = mpsc::channel(config.max_connections * 4 + 8);
        let dirty = identity.needs_persistence();
        if dirty {
            let _ = events.try_send(SdkEvent::IdentityPersistencePending);
        }
        Self {
            sessions: SessionMap::new(config.max_connections)
                .expect("validated connection capacity"),
            config,
            installation_closed: Arc::new(AtomicBool::new(false)),
            identity_client: identity.client.clone(),
            identity: Arc::new(tokio::sync::Mutex::new(identity)),
            refresh: None,
            refresh_waiters: Vec::new(),
            refresh_at: Instant::now()
                + if dirty {
                    Duration::from_secs(30)
                } else {
                    Duration::from_secs(12 * 3600)
                },
            refresh_needs_retry: dirty,
            online_since: None,
            unstable_connections: 0,
            stored,
            commands,
            events,
            signal: None,
            rejected_sessions: std::collections::VecDeque::new(),
            dial: None,
            retry_at: Instant::now(),
            attempt: 0,
            internal_tx,
            internal_rx,
        }
    }
    fn emit(&self, event: SdkEvent) -> Result<(), SdkError> {
        self.events.try_send(event).map_err(|_| SdkError::QueueFull)
    }
    async fn run(mut self, mut commands: mpsc::Receiver<Command>, mut stop: oneshot::Receiver<()>) {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let result: Result<(), SdkError> = async {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stop => return Ok(()),
                    _ = tick.tick() => self.tick().await?,
                    dial = async {
                        match &mut self.dial {
                            Some(task) => task.await,
                            None => std::future::pending().await,
                        }
                    } => {
                        self.dial.take();
                        match dial.map_err(|_| SdkError::Closed)? {
                            Ok(signal) => self.connected(signal).await?,
                            Err(error) => self.disconnected(error).await?,
                        }
                    },
                    message = async {
                        match &mut self.signal {
                            Some(signal) => signal.receive().await,
                            None => std::future::pending().await,
                        }
                    } => match message {
                        Ok(message) => self.message(message).await?,
                        Err(error) => self.disconnected(error).await?,
                    },
                    refreshed = async {
                        match &mut self.refresh {
                            Some(task) => task.await,
                            None => std::future::pending().await,
                        }
                    } => {
                        self.refresh.take();
                        let (outcome, latest) = refreshed.map_err(|_| SdkError::Closed)?;
                        self.refreshed(outcome, latest).await?;
                    },
                    command = commands.recv() => {
                        let Some(command) = command else { return Ok(()); };
                        self.command(command).await?;
                    },
                    event = self.internal_rx.recv() => {
                        if let Some(event) = event { self.internal(event).await?; }
                    }
                }
            }
        }
        .await;
        self.sessions.close_admission();
        for (_, session) in self.sessions.iter() {
            session.gate.close();
        }
        // Graceful close lets a bounded in-flight credential mutation finish, instead of
        // dropping its new token after the server has already rotated the old one.
        if let Some(mut task) = self.refresh.take()
            && tokio::time::timeout(Duration::from_secs(22), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.dial.take() {
            task.abort();
            let _ = task.await;
        }
        self.close_all().await;
        if let Some(signal) = self.signal.take() {
            signal.close().await;
        }
        if let Err(error) = result {
            let _ = self.events.try_send(SdkEvent::Stopped(error));
        }
    }
    async fn connected(&mut self, signal: SignalClient) -> Result<(), SdkError> {
        if !self.refresh_needs_retry {
            self.refresh_at = Instant::now()
                + signal
                    .server_clock()
                    .remaining_until(&self.stored.expires_at, Instant::now())
                    .unwrap_or_default()
                    .saturating_sub(Duration::from_secs(300))
                    .min(Duration::from_secs(12 * 3600));
        }
        self.online_since = Some(Instant::now());
        self.signal = Some(signal);
        self.emit(SdkEvent::Online)?;
        let ids: Vec<String> = self
            .sessions
            .iter_mut()
            .map(|(id, session)| {
                session.sync_pending = true;
                id.to_owned()
            })
            .collect();
        for id in ids {
            match self.send("sync.request", Some(&id), json!({})).await {
                Ok(_) => {}
                Err(SdkError::Signal(error)) => {
                    self.disconnected(error).await?;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn start_refresh(&mut self) {
        let identity = self.identity.clone();
        self.refresh = Some(tokio::spawn(async move {
            let mut identity = identity.lock().await;
            let operation = async {
                if identity.needs_persistence() {
                    identity.retry_persist().await
                } else if identity.has_pending_mutation() {
                    identity.retry_pending().await
                } else {
                    identity.refresh(IdempotencyKey::random()).await
                }
            };
            let result = tokio::time::timeout(Duration::from_secs(20), operation)
                .await
                .unwrap_or(Err(IdentityError::Transport));
            (result, identity.identity().cloned())
        }));
    }
    async fn refreshed(
        &mut self,
        outcome: Result<(), IdentityError>,
        latest: Option<StoredIdentity>,
    ) -> Result<(), SdkError> {
        let changed = latest.as_ref().is_some_and(|latest| {
            latest.device_credential.expose() != self.stored.device_credential.expose()
        });
        if let Some(latest) = latest {
            self.stored = latest;
        }
        for waiter in self.refresh_waiters.drain(..) {
            let _ = waiter.send(outcome.clone().map_err(SdkError::Identity));
        }
        if matches!(outcome, Err(IdentityError::Storage(_))) && !self.refresh_needs_retry {
            self.emit(SdkEvent::IdentityPersistencePending)?;
        }
        self.refresh_needs_retry = outcome.is_err();
        self.refresh_at = Instant::now() + refresh_delay(&outcome);
        if changed {
            if let Some(task) = self.dial.take() {
                task.abort();
                let _ = task.await;
            }
            if let Some(signal) = self.signal.take() {
                signal.close().await;
                self.emit(SdkEvent::Offline)?;
            }
            self.online_since = None;
            self.retry_at = Instant::now();
        }
        if matches!(outcome, Err(IdentityError::Server {status:400..=428 | 430..=499,..})
            | Err(IdentityError::InvalidConfiguration | IdentityError::InvalidRequest | IdentityError::InvalidResponse | IdentityError::ResponseTooLarge))
        {
            return Err(SdkError::Identity(outcome.unwrap_err()));
        }
        Ok(())
    }
    async fn disconnected(&mut self, error: SignalError) -> Result<(), SdkError> {
        if let Some(signal) = self.signal.take() {
            signal.close().await;
        }
        self.emit(SdkEvent::Offline)?;
        for (target_device_id, request_id) in self.sessions.drain_pending() {
            let Some(request_id) = request_id else {
                continue;
            };
            self.emit(SdkEvent::ConnectionRequestFailed {
                target_device_id,
                request_id,
                reason: SdkError::RequestOutcomeUnknown,
            })?;
        }
        let refreshing = self.refresh.is_some();
        if error == SignalError::InvalidMessage
            || (!refreshing
                && (!self.config.auto_reconnect
                    || matches!(
                        error,
                        SignalError::AuthorizationRejected | SignalError::PolicyRejected
                    )))
        {
            return Err(SdkError::Signal(error));
        }
        if self
            .online_since
            .take()
            .is_some_and(|started| started.elapsed() < Duration::from_secs(30))
        {
            self.unstable_connections = self.unstable_connections.saturating_add(1);
            if self.unstable_connections >= 8 {
                return Err(SdkError::Signal(SignalError::PolicyRejected));
            }
        }
        self.retry_at = Instant::now() + backoff(self.attempt);
        self.attempt = self.attempt.saturating_add(1);
        Ok(())
    }
    async fn send(
        &mut self,
        kind: &str,
        session: Option<&str>,
        payload: serde_json::Value,
    ) -> Result<String, SdkError> {
        let generation = session
            .and_then(|id| self.sessions.get(id))
            .map_or(1, |value| value.generation);
        self.send_generation(kind, session, payload, generation)
            .await
    }
    async fn send_generation(
        &mut self,
        kind: &str,
        session: Option<&str>,
        payload: serde_json::Value,
        generation: u64,
    ) -> Result<String, SdkError> {
        let request = self
            .signal
            .as_ref()
            .ok_or(SdkError::Offline)?
            .send_generation(kind, session, payload, generation)
            .await
            .map_err(SdkError::Signal)?;
        if let Some(value) = session.and_then(|id| self.sessions.get_mut(id)) {
            // Errors carry request_id but not necessarily session_id. Route only
            // a bounded recent request from this exact transport generation.
            if value.requests.len() == 16 {
                value.requests.pop_front();
            }
            value.requests.push_back((request.clone(), generation));
        }
        Ok(request)
    }

    async fn tick(&mut self) -> Result<(), SdkError> {
        let now = Instant::now();
        if self
            .online_since
            .is_some_and(|started| started.elapsed() >= Duration::from_secs(30))
        {
            self.attempt = 0;
            self.unstable_connections = 0;
        }
        if self.refresh.is_none() && now >= self.refresh_at {
            self.start_refresh();
        }
        if self.signal.is_none()
            && self.dial.is_none()
            && self.refresh.is_none()
            && now >= self.retry_at
        {
            let client = self.identity_client.clone();
            let token = self.stored.device_credential.clone();
            self.dial = Some(tokio::spawn(async move {
                SignalClient::connect(&client, &token).await
            }));
        }
        let ids: Vec<String> = self.sessions.iter().map(|(id, _)| id.to_owned()).collect();
        for id in ids {
            let Some(session) = self.sessions.get(&id) else {
                continue;
            };
            let expired = session
                .guard
                .deadline()
                .is_some_and(|deadline| now >= deadline);
            let closed = session.gate.closed.load(Ordering::Acquire) && session.worker.is_none();
            if expired || closed {
                self.close_session(
                    &id,
                    if closed {
                        SdkError::Closed
                    } else {
                        SdkError::AuthorizationExpired
                    },
                    true,
                )
                .await;
                continue;
            }
            let recovering =
                !session.sync_pending && session.recovery_at.is_some_and(|at| now >= at);
            if self.signal.is_some() && recovering {
                match self
                    .send("session.reconnecting", Some(&id), json!({}))
                    .await
                {
                    Ok(_) => {
                        let session = self.sessions.get_mut(&id).expect("actor-owned session");
                        session.recovery_attempt = session.recovery_attempt.saturating_add(1);
                        session.recovery_at = Some(now + backoff(session.recovery_attempt));
                    }
                    Err(SdkError::Signal(error)) => {
                        self.disconnected(error).await?;
                    }
                    Err(_) => {}
                }
            }
            let renew = self.sessions.get(&id).is_some_and(|session| {
                !session.sync_pending && now >= session.renew_at && session.guard.is_authorized(now)
            });
            if self.signal.is_some() && renew {
                match self.send("session.renew", Some(&id), json!({})).await {
                    Ok(request) => {
                        let session = self.sessions.get_mut(&id).expect("actor-owned session");
                        if session.guard.renewal_requested(request).is_err() {
                            self.close_session(&id, SdkError::AuthorizationExpired, true)
                                .await;
                        } else {
                            session.renew_at = now + Duration::from_secs(15);
                        }
                    }
                    Err(SdkError::Signal(error)) => self.disconnected(error).await?,
                    Err(_) => {}
                }
            }
        }
        Ok(())
    }

    async fn command(&mut self, command: Command) -> Result<(), SdkError> {
        match command {
            Command::Refresh(result) => {
                if self.refresh_waiters.len() >= 32 {
                    let _ = result.send(Err(SdkError::Busy));
                } else {
                    self.refresh_waiters.push(result);
                    if self.refresh.is_none() {
                        self.start_refresh();
                    }
                }
            }
            Command::Connect(target, result) => {
                let outcome = if target == self.stored.device_id {
                    Err(SdkError::InvalidConfiguration)
                } else if self.signal.is_none() {
                    Err(SdkError::Offline)
                } else {
                    match self.sessions.reserve_outgoing(target.clone()) {
                        Err(_) => Err(SdkError::Busy),
                        Ok(reservation) => {
                            match self
                                .send("session.request", None, json!({"target_device_id":target}))
                                .await
                            {
                                Ok(request) => {
                                    if self
                                        .sessions
                                        .bind_request(reservation, request.clone())
                                        .is_ok()
                                    {
                                        Ok(request)
                                    } else {
                                        self.sessions.release_reservation(reservation);
                                        Err(SdkError::Closed)
                                    }
                                }
                                Err(error) => {
                                    self.sessions.release_reservation(reservation);
                                    Err(error)
                                }
                            }
                        }
                    }
                };
                let _ = result.send(outcome);
            }
            Command::Respond(id, accept, result) => {
                let outcome = if self
                    .sessions
                    .get(&id)
                    .is_none_or(|session| session.target != self.stored.device_id)
                {
                    Err(SdkError::Closed)
                } else {
                    if !accept {
                        self.sessions
                            .get(&id)
                            .expect("known target session")
                            .gate
                            .close();
                    }
                    let outcome = self
                        .send(
                            if accept {
                                "session.accept"
                            } else {
                                "session.reject"
                            },
                            Some(&id),
                            json!({}),
                        )
                        .await
                        .map(|_| ());
                    if !accept {
                        // Local refusal is irreversible even if its WSS result is uncertain.
                        self.close_session(
                            &id,
                            SdkError::Rejected("CLIENT_REJECTED".into()),
                            false,
                        )
                        .await;
                    }
                    outcome
                };
                let _ = result.send(outcome);
            }
            Command::CloseConnection(id, generation, done) => {
                if self.sessions.get(&id).is_some_and(|session| {
                    session.generation == generation && (session.ready || done.is_some())
                }) {
                    self.close_session(&id, SdkError::Closed, true).await;
                }
                if let Some(done) = done {
                    let _ = done.send(());
                }
            }
        }
        Ok(())
    }

    async fn message(&mut self, message: Envelope) -> Result<(), SdkError> {
        if message.kind == "error" {
            let Some(request) = message.request_id.as_deref() else {
                return Ok(());
            };
            let code = message.payload["code"]
                .as_str()
                .unwrap_or("REQUEST_DENIED")
                .to_owned();
            if let Some(target_device_id) = self.sessions.pending_target(request).map(str::to_owned)
            {
                self.sessions.reject_request(request);
                self.emit(SdkEvent::ConnectionRequestFailed {
                    target_device_id,
                    request_id: request.to_owned(),
                    reason: SdkError::Rejected(code),
                })?;
                return Ok(());
            }
            let routed = self.sessions.iter().find_map(|(id, session)| {
                session
                    .requests
                    .iter()
                    .find(|(value, _)| value == request)
                    .map(|(_, generation)| {
                        (
                            id.to_owned(),
                            *generation,
                            session.generation,
                            session.recovery_at.is_some(),
                        )
                    })
            });
            let Some((id, sent_generation, current_generation, recovering)) = routed else {
                return Ok(());
            };
            if sent_generation != current_generation {
                return Ok(());
            }
            if recovering
                && matches!(
                    code.as_str(),
                    "NEGOTIATION_RATE_LIMIT" | "NEGOTIATION_STALE"
                )
            {
                self.send("sync.request", Some(&id), json!({})).await?;
                if let Some(session) = self.sessions.get_mut(&id) {
                    session.sync_pending = true;
                }
            } else {
                self.close_session(&id, SdkError::Rejected(code), false)
                    .await;
            }
            return Ok(());
        }
        if matches!(
            message.kind.as_str(),
            "session.pending" | "session.updated" | "session.terminated" | "sync.snapshot"
        ) {
            let id = message
                .session_id
                .clone()
                .ok_or(SdkError::Signal(SignalError::InvalidMessage))?;
            let source = message.payload["source_device_id"]
                .as_str()
                .ok_or(SdkError::Signal(SignalError::InvalidMessage))?
                .to_owned();
            let target = message.payload["target_device_id"]
                .as_str()
                .ok_or(SdkError::Signal(SignalError::InvalidMessage))?
                .to_owned();
            if source != self.stored.device_id && target != self.stored.device_id {
                return Err(SdkError::Signal(SignalError::InvalidMessage));
            }
            let generation = message.payload["negotiation_generation"]
                .as_u64()
                .unwrap_or(1);
            if !(1..=32).contains(&generation) {
                return Err(SdkError::Signal(SignalError::InvalidMessage));
            }
            let mut incoming = false;
            if self.sessions.get(&id).is_none() {
                if message.kind == "session.terminated"
                    || message.payload["state"] == "closed"
                    || self.rejected_sessions.contains(&id)
                    || self.sessions.has_seen(&id)
                {
                    return Ok(());
                }
                let request = message.request_id.as_deref();
                if source == self.stored.device_id {
                    let Some(expected) =
                        request.and_then(|request| self.sessions.pending_target(request))
                    else {
                        return Ok(());
                    };
                    if expected != target {
                        return Err(SdkError::Signal(SignalError::InvalidMessage));
                    }
                }
                let guard = LeaseGuard::new(id.clone(), source.clone(), target.clone())
                    .map_err(|_| SdkError::Signal(SignalError::InvalidMessage))?;
                let session = Session {
                    id: id.clone(),
                    source: source.clone(),
                    target: target.clone(),
                    guard,
                    gate: Arc::new(Gate {
                        installation_closed: self.installation_closed.clone(),
                        ..Gate::default()
                    }),
                    worker: None,
                    renew_at: Instant::now() + Duration::from_secs(10),
                    ready: false,
                    generation,
                    recovery_at: None,
                    recovery_attempt: 0,
                    sync_pending: false,
                    requests: std::collections::VecDeque::new(),
                };
                let inserted = if source == self.stored.device_id {
                    self.sessions.promote(
                        request.expect("correlated outgoing request"),
                        &target,
                        id.clone(),
                        session,
                    )
                } else {
                    incoming = true;
                    self.sessions.insert_incoming(id.clone(), session)
                };
                if inserted.is_err() {
                    // Decline only this incoming session; never replace a live sibling.
                    if incoming {
                        if self.rejected_sessions.len() == 32 {
                            self.rejected_sessions.pop_front();
                        }
                        self.rejected_sessions.push_back(id.clone());
                        let kind = if message.payload["state"] == "authorizing" {
                            "session.reject"
                        } else {
                            "session.terminate"
                        };
                        let _ = self
                            .send_generation(kind, Some(&id), json!({}), generation)
                            .await;
                        return Ok(());
                    }
                    return Err(SdkError::Signal(SignalError::InvalidMessage));
                }
            }
            let previous = self.sessions.get(&id).expect("admitted session").generation;
            if generation < previous {
                return Ok(());
            }
            if generation > previous {
                self.replace_generation(&id, generation).await?;
            }
            let clock = self
                .signal
                .as_ref()
                .ok_or(SdkError::Offline)?
                .server_clock();
            let session = self.sessions.get_mut(&id).expect("admitted session");
            if session
                .guard
                .apply(&message, &clock, Instant::now())
                .is_err()
            {
                self.close_session(&id, SdkError::AuthorizationExpired, true)
                    .await;
                return Ok(());
            }
            if message.payload["state"] == "closed" {
                self.close_session(
                    &id,
                    SdkError::Rejected(
                        message.payload["close_reason"]
                            .as_str()
                            .unwrap_or("SESSION_CLOSED")
                            .into(),
                    ),
                    false,
                )
                .await;
                return Ok(());
            }
            session.gate.update(session.guard.deadline());
            if message.kind == "sync.snapshot" {
                session.sync_pending = false;
            }
            let spawn = session.guard.is_authorized(Instant::now())
                && session.source == self.stored.device_id
                && session.worker.is_none()
                && session.recovery_at.is_none();
            if incoming && message.payload["state"] == "authorizing" {
                self.emit(SdkEvent::IncomingConnection {
                    session_id: id.clone(),
                    source_device_id: source,
                })?;
            }
            if spawn {
                self.spawn_worker(&id, None)?;
            }
        } else if message.kind == "session.offer" || message.kind == "session.answer" {
            let Some(id) = message.session_id.as_deref() else {
                return Err(SdkError::Signal(SignalError::InvalidMessage));
            };
            let Some(session) = self.sessions.get(id) else {
                return Ok(());
            };
            if message
                .negotiation_generation
                .is_some_and(|generation| generation < session.generation)
            {
                return Ok(());
            }
            if message.negotiation_generation != Some(session.generation)
                || !session.guard.is_authorized(Instant::now())
            {
                self.close_session(id, SdkError::Signal(SignalError::InvalidMessage), true)
                    .await;
                return Ok(());
            }
            let Some(sdp) = message.payload["sdp"].as_str() else {
                self.close_session(id, SdkError::Signal(SignalError::InvalidMessage), true)
                    .await;
                return Ok(());
            };
            let result = if message.kind == "session.offer" {
                if session.target != self.stored.device_id || session.worker.is_some() {
                    Err(SdkError::Signal(SignalError::InvalidMessage))
                } else {
                    match SessionDescription::offer(sdp.to_owned()) {
                        Ok(offer) => self.spawn_worker(id, Some(offer)),
                        Err(_) => Err(SdkError::Transport(TransportError::Negotiation)),
                    }
                }
            } else {
                match SessionDescription::answer(sdp.to_owned()) {
                    Ok(answer) => {
                        session
                            .worker
                            .as_ref()
                            .ok_or(SdkError::Closed)
                            .and_then(|worker| {
                                worker
                                    .control
                                    .try_send(answer)
                                    .map_err(|_| SdkError::QueueFull)
                            })
                    }
                    Err(_) => Err(SdkError::Transport(TransportError::Negotiation)),
                }
            };
            if let Err(error) = result {
                self.close_session(id, error, true).await;
            }
        }
        Ok(())
    }
    fn spawn_worker(
        &mut self,
        id: &str,
        offer: Option<SessionDescription>,
    ) -> Result<(), SdkError> {
        let session = self.sessions.get_mut(id).ok_or(SdkError::Closed)?;
        let (control, answers) = mpsc::channel(1);
        let (stop, stopped) = oneshot::channel();
        let id = session.id.clone();
        let generation = session.generation;
        let gate = session.gate.clone();
        let mut config = self.config.transport.clone();
        config.max_channels = 1;
        let managed_relay =
            if self.config.managed_relays && config.policy != ConnectionPolicy::DirectOnly {
                Some(ManagedRelayRequest {
                    client: self.identity_client.clone(),
                    credential: self.stored.device_credential.clone(),
                })
            } else {
                None
            };
        let events = self.internal_tx.clone();
        let sdk = self.commands.clone();
        let task = tokio::spawn(async move {
            transport_worker(
                id,
                generation,
                gate,
                config,
                managed_relay,
                offer,
                answers,
                stopped,
                events,
                sdk,
            )
            .await;
        });
        session.worker = Some(Worker {
            control,
            stop: Some(stop),
            task,
        });
        Ok(())
    }
    async fn internal(&mut self, event: Internal) -> Result<(), SdkError> {
        match event {
            Internal::Description(id, generation, kind, sdp) => {
                if self
                    .sessions
                    .get(&id)
                    .is_some_and(|session| session.generation == generation)
                    && self
                        .send(kind, Some(&id), json!({"sdp":sdp}))
                        .await
                        .is_err()
                {
                    self.close_session(&id, SdkError::Offline, false).await;
                }
            }
            Internal::Ready(id, generation, connection) => {
                if self.sessions.get(&id).is_some_and(|session| {
                    session.generation == generation && session.guard.is_authorized(Instant::now())
                }) {
                    self.sessions.get_mut(&id).expect("current session").ready = true;
                    let _ = self.send("session.connected", Some(&id), json!({})).await;
                    self.emit(SdkEvent::ConnectionReady(connection))?;
                }
            }
            Internal::Closed(id, generation, error) => {
                if let Some(session) = self.sessions.get(&id)
                    && session.generation == generation
                {
                    if self.config.auto_reconnect
                        && recoverable_transport_error(&error)
                        && session.guard.is_authorized(Instant::now())
                        && session.generation < 32
                    {
                        self.prepare_recovery(&id, error).await?;
                    } else {
                        self.close_session(&id, error, true).await;
                    }
                }
            }
        }
        Ok(())
    }
    async fn stop_generation(&mut self, id: &str) {
        let Some(session) = self.sessions.get_mut(id) else {
            return;
        };
        session.gate.close();
        if let Some(mut worker) = session.worker.take() {
            if let Some(stop) = worker.stop.take() {
                let _ = stop.send(());
            }
            if tokio::time::timeout(Duration::from_secs(5), &mut worker.task)
                .await
                .is_err()
            {
                worker.task.abort();
                let _ = (&mut worker.task).await;
            }
        }
    }
    async fn prepare_recovery(&mut self, id: &str, reason: SdkError) -> Result<(), SdkError> {
        self.stop_generation(id).await;
        let session = self.sessions.get_mut(id).ok_or(SdkError::Closed)?;
        session.gate = Arc::new(Gate {
            installation_closed: self.installation_closed.clone(),
            ..Gate::default()
        });
        session.gate.update(session.guard.deadline());
        session.ready = false;
        session.recovery_at = Some(Instant::now() + backoff(session.recovery_attempt));
        self.emit(SdkEvent::ConnectionClosed {
            session_id: id.to_owned(),
            reason,
        })
    }
    async fn replace_generation(&mut self, id: &str, generation: u64) -> Result<(), SdkError> {
        let was_ready = self.sessions.get(id).is_some_and(|session| session.ready);
        self.stop_generation(id).await;
        let session = self.sessions.get_mut(id).ok_or(SdkError::Closed)?;
        session.generation = generation;
        session.gate = Arc::new(Gate {
            installation_closed: self.installation_closed.clone(),
            ..Gate::default()
        });
        session.gate.update(session.guard.deadline());
        session.ready = false;
        session.recovery_at = None;
        // Old-generation error replies cannot terminate the newly authorized handle.
        session.requests.clear();
        if was_ready {
            self.emit(SdkEvent::ConnectionClosed {
                session_id: id.to_owned(),
                reason: SdkError::Transport(TransportError::Closed),
            })?;
        }
        Ok(())
    }
    async fn close_session(&mut self, id: &str, reason: SdkError, notify: bool) {
        let Some(session) = self.sessions.get_mut(id) else {
            return;
        };
        session.gate.close();
        session.guard.invalidate();
        let generation = session.generation;
        if notify {
            let _ = self
                .send_generation("session.terminate", Some(id), json!({}), generation)
                .await;
        }
        // Keep the slot charged until its bounded worker teardown finishes.
        self.stop_generation(id).await;
        self.sessions.remove(id);
        let _ = self.emit(SdkEvent::ConnectionClosed {
            session_id: id.to_owned(),
            reason,
        });
    }
    async fn close_all(&mut self) {
        self.sessions.close_admission();
        self.sessions.drain_pending();
        // Fence every connection before the first await, then stop all workers.
        for (_, session) in self.sessions.iter_mut() {
            session.gate.close();
            session.guard.invalidate();
        }
        let mut workers: Vec<Worker> = self
            .sessions
            .drain_sessions()
            .filter_map(|mut session| session.worker.take())
            .collect();
        for worker in &mut workers {
            if let Some(stop) = worker.stop.take() {
                let _ = stop.send(());
            }
        }
        // All joins share one bound; never N * five seconds on SDK/reset shutdown.
        if tokio::time::timeout(
            Duration::from_secs(5),
            futures_util::future::join_all(workers.iter_mut().map(|worker| &mut worker.task)),
        )
        .await
        .is_err()
        {
            for worker in &workers {
                worker.task.abort();
            }
            let _ =
                futures_util::future::join_all(workers.iter_mut().map(|worker| &mut worker.task))
                    .await;
        }
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        self.sessions.close_admission();
        for (_, session) in self.sessions.iter() {
            session.gate.close();
        }
        if let Some(task) = self.refresh.as_ref() {
            task.abort();
        }
        if let Some(task) = self.dial.as_ref() {
            task.abort();
        }
    }
}
fn refresh_delay(outcome: &Result<(), IdentityError>) -> Duration {
    match outcome {
        Ok(()) => Duration::from_secs(12 * 3600),
        Err(IdentityError::Storage(_)) => Duration::from_secs(30),
        // Preserve the original key/token and retry within the server's 30s overlap.
        Err(_) => Duration::from_millis(1000 + (uuid::Uuid::new_v4().as_u128() % 1000) as u64),
    }
}

fn backoff(attempt: u32) -> Duration {
    let base = 1u64 << attempt.min(5);
    let max = (base * 1000).min(30000);
    let spread = max / 5;
    let random = (uuid::Uuid::new_v4().as_u128() % (spread as u128 + 1)) as u64;
    Duration::from_millis((max + random).min(30000))
}

async fn guarded_send(channel: &MessageChannel, gate: &Gate, data: &[u8]) -> Result<(), SdkError> {
    loop {
        let changed = gate.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        gate.check()?;
        let deadline = gate
            .deadline
            .lock()
            .map_err(|_| SdkError::Closed)?
            .ok_or(SdkError::AuthorizationExpired)?;
        tokio::select! {
            biased;
            _=&mut changed=>{gate.check()?;},
            _=tokio::time::sleep_until(tokio::time::Instant::from_std(deadline))=>{gate.check()?;},
            result=channel.send(data)=>return result.map_err(SdkError::Transport),
        }
    }
}

fn valid_message_metadata(metadata: &device_transport_webrtc::ChannelMetadata) -> bool {
    metadata.label == "peerloom.reliable"
        && metadata.protocol.is_empty()
        && metadata.is_reliable_ordered()
}

fn validate_transport_configuration(config: &SdkConfig) -> Result<(), SdkError> {
    if config.managed_relays && config.transport.policy != ConnectionPolicy::DirectOnly {
        if !config.transport.ice_servers.is_empty() {
            return Err(SdkError::InvalidConfiguration);
        }
        // Validate all resource limits now. RelayOnly's required TURN nodes can
        // only be checked after the authorized session HTTP result arrives.
        let mut deferred = config.transport.clone();
        deferred.policy = ConnectionPolicy::Auto;
        deferred.validate().map_err(SdkError::Transport)
    } else {
        config.transport.validate().map_err(SdkError::Transport)
    }
}

struct ManagedRelayRequest {
    client: IdentityClient,
    credential: SecretString,
}

#[allow(clippy::too_many_arguments)]
async fn transport_worker(
    id: String,
    generation: u64,
    gate: Arc<Gate>,
    mut config: TransportConfig,
    managed_relay: Option<ManagedRelayRequest>,
    offer: Option<SessionDescription>,
    mut answers: mpsc::Receiver<SessionDescription>,
    mut stop: oneshot::Receiver<()>,
    events: mpsc::Sender<Internal>,
    sdk: mpsc::Sender<Command>,
) {
    if let Some(relay) = managed_relay {
        let fetch = async {
            gate.check()?;
            let configuration = relay
                .client
                .session_ice_servers_generation(&id, &relay.credential, generation)
                .await
                .map_err(SdkError::Identity)?;
            gate.check()?;
            configuration
                .into_live_servers()
                .map_err(SdkError::Identity)
        };
        let fetched = tokio::select! {
            biased;
            _ = &mut stop => {
                gate.close();
                // The actor may already be awaiting this worker during close.
                // Do not wait for space in its own full internal event queue.
                let _ = events.try_send(Internal::Closed(id.clone(), generation, SdkError::Closed));
                return;
            },
            result = fetch => result,
        };
        match fetched {
            Ok(servers) => config.ice_servers = servers,
            Err(error) => {
                gate.close();
                report_worker_closed(&events, id, generation, error, &mut stop).await;
                return;
            }
        }
    }
    let requires_relay = config.policy == ConnectionPolicy::RelayOnly;
    let peer = match PeerTransport::new(config).await {
        Ok(peer) => peer,
        Err(error) => {
            gate.close();
            report_worker_closed(
                &events,
                id,
                generation,
                SdkError::Transport(error),
                &mut stop,
            )
            .await;
            return;
        }
    };
    let operation = async {
        gate.check()?;
        let mut channel: MessageChannel = if let Some(offer) = offer {
            let answer = peer
                .answer_offer(offer)
                .await
                .map_err(SdkError::Transport)?;
            events
                .send(Internal::Description(
                    id.clone(),
                    generation,
                    "session.answer",
                    answer.sdp,
                ))
                .await
                .map_err(|_| SdkError::Closed)?;
            peer.accept_channel().await.map_err(SdkError::Transport)?
        } else {
            let channel = peer
                .create_channel("peerloom.reliable", ChannelMode::ReliableMessage)
                .await
                .map_err(SdkError::Transport)?;
            let offer = peer.create_offer().await.map_err(SdkError::Transport)?;
            events
                .send(Internal::Description(
                    id.clone(),
                    generation,
                    "session.offer",
                    offer.sdp,
                ))
                .await
                .map_err(|_| SdkError::Closed)?;
            let answer = tokio::time::timeout(Duration::from_secs(30), answers.recv())
                .await
                .map_err(|_| SdkError::Transport(TransportError::Timeout))?
                .ok_or(SdkError::Closed)?;
            peer.apply_answer(answer)
                .await
                .map_err(SdkError::Transport)?;
            channel
        };
        let metadata = channel.metadata().await.map_err(SdkError::Transport)?;
        if !valid_message_metadata(&metadata) {
            return Err(SdkError::Transport(TransportError::UnsupportedChannel));
        }
        channel.wait_open().await.map_err(SdkError::Transport)?;
        if requires_relay
            && !matches!(
                peer.selected_candidate_types()
                    .await
                    .map_err(SdkError::Transport)?,
                Some((CandidateKind::Relay, _))
            )
        {
            return Err(SdkError::Transport(TransportError::RelayRequired));
        }
        gate.check()?;
        let (send, mut sends) = mpsc::channel::<SendRequest>(32);
        let (receive, messages) = mpsc::channel(32);
        events
            .send(Internal::Ready(
                id.clone(),
                generation,
                Connection {
                    session_id: id.clone(),
                    generation,
                    commands: send,
                    messages,
                    gate: gate.clone(),
                    sdk,
                },
            ))
            .await
            .map_err(|_| SdkError::Closed)?;
        loop {
            let changed = gate.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            gate.check()?;
            let deadline = gate
                .deadline
                .lock()
                .map_err(|_| SdkError::Closed)?
                .ok_or(SdkError::AuthorizationExpired)?;
            tokio::select! {
                _ = &mut changed => { gate.check()?; },
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => { gate.check()?; },
                request = sends.recv() => {
                    let Some(request) = request else { return Ok(()); };
                    let result = if Instant::now() >= request.expires {
                        Err(SdkError::Transport(TransportError::Timeout))
                    } else {
                        gate.check()?;
                        guarded_send(&channel, &gate, &request.data).await
                    };
                    let _ = request.result.send(result);
                },
                _ = peer.wait_interrupted() => return Err(SdkError::Transport(TransportError::Ice)),
                data = channel.receive() => match data {
                    Ok(data) => { gate.check()?; receive.try_send(data).map_err(|_|SdkError::QueueFull)?; },
                    Err(TransportError::Timeout) => {},
                    Err(error) => return Err(SdkError::Transport(error)),
                }
            }
        }
    };
    let result = tokio::select! {
        biased;
        _ = &mut stop => None,
        result = operation => Some(result),
    };
    gate.close();
    let _ = peer.close().await;
    if let Some(result) = result {
        report_worker_closed(
            &events,
            id,
            generation,
            result.err().unwrap_or(SdkError::Closed),
            &mut stop,
        )
        .await;
    }
}

async fn report_worker_closed(
    events: &mpsc::Sender<Internal>,
    id: String,
    generation: u64,
    error: SdkError,
    stop: &mut oneshot::Receiver<()>,
) {
    tokio::select! {
        biased;
        _ = stop => {},
        _ = events.send(Internal::Closed(id, generation, error)) => {},
    }
}

fn recoverable_transport_error(error: &SdkError) -> bool {
    matches!(
        error,
        SdkError::Transport(
            TransportError::Timeout
                | TransportError::Closed
                | TransportError::Io(_)
                | TransportError::Ice
                | TransportError::Relay
                | TransportError::Dtls
                | TransportError::Sctp
                | TransportError::WebRtc
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn terminal_worker_notification_cancels_with_full_actor_queue() {
        let (events, mut received) = mpsc::channel(1);
        events
            .send(Internal::Closed("queued".into(), 1, SdkError::Closed))
            .await
            .unwrap();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            report_worker_closed(
                &events,
                "session".into(),
                2,
                SdkError::Transport(TransportError::Ice),
                &mut stopped,
            )
            .await;
        });
        tokio::task::yield_now().await;
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            received.recv().await,
            Some(Internal::Closed(_, 1, _))
        ));
        assert!(received.recv().await.is_none());
    }

    #[tokio::test]
    async fn terminal_worker_notification_preserves_generation() {
        let (events, mut received) = mpsc::channel(1);
        let (_stop, mut stopped) = oneshot::channel();
        report_worker_closed(
            &events,
            "session".into(),
            7,
            SdkError::Transport(TransportError::Ice),
            &mut stopped,
        )
        .await;
        assert!(matches!(received.recv().await,
            Some(Internal::Closed(id, 7, SdkError::Transport(TransportError::Ice))) if id == "session"));
    }

    #[test]
    fn recovery_does_not_retry_denial_or_expired_authority() {
        for error in [
            SdkError::Closed,
            SdkError::AuthorizationExpired,
            SdkError::Rejected("TARGET_REJECTED".into()),
            SdkError::Identity(IdentityError::InvalidResponse),
            SdkError::Transport(TransportError::RelayRequired),
            SdkError::Transport(TransportError::InvalidConfiguration),
        ] {
            assert!(!recoverable_transport_error(&error));
        }
        assert!(recoverable_transport_error(&SdkError::Transport(
            TransportError::Ice
        )));
    }

    #[test]
    fn managed_relay_policy_defers_only_missing_nodes_and_rejects_mixed_configuration() {
        let mut config = SdkConfig::new(
            "https://server.example".into(),
            uuid::Uuid::nil().to_string(),
        );
        config.transport.policy = ConnectionPolicy::RelayOnly;
        assert!(validate_transport_configuration(&config).is_ok());
        config.managed_relays = false;
        assert_eq!(
            validate_transport_configuration(&config),
            Err(SdkError::Transport(TransportError::RelayRequired))
        );
        config
            .transport
            .ice_servers
            .push(device_transport_webrtc::RTCIceServer {
                urls: vec!["turn:relay.example:3478".into()],
                username: "test".into(),
                credential: "test".into(),
            });
        assert!(validate_transport_configuration(&config).is_ok());
        config.managed_relays = true;
        assert_eq!(
            validate_transport_configuration(&config),
            Err(SdkError::InvalidConfiguration)
        );
        config.transport.policy = ConnectionPolicy::DirectOnly;
        assert_eq!(
            validate_transport_configuration(&config),
            Err(SdkError::Transport(TransportError::RelayForbidden))
        );
    }

    #[tokio::test]
    async fn managed_ice_fetch_is_cancellable_before_transport_creation() {
        for prefill in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = IdentityClient::new(
                &format!("http://{}", listener.local_addr().unwrap()),
                true,
                Duration::from_secs(10),
            )
            .unwrap();
            let gate = Arc::new(Gate {
                installation_closed: Arc::new(AtomicBool::new(false)),
                closed: AtomicBool::new(false),
                deadline: Mutex::new(Some(Instant::now() + Duration::from_secs(60))),
                changed: tokio::sync::Notify::new(),
            });
            let (stop, stopped) = oneshot::channel();
            let (_answers, answers) = mpsc::channel(1);
            let (events, mut received) = mpsc::channel(1);
            if prefill {
                assert!(
                    events
                        .try_send(Internal::Closed("queued".into(), 1, SdkError::Closed))
                        .is_ok()
                );
            }
            let (sdk, _commands) = mpsc::channel(1);
            let task = tokio::spawn(transport_worker(
                uuid::Uuid::nil().to_string(),
                1,
                gate.clone(),
                TransportConfig::default(),
                Some(ManagedRelayRequest {
                    client,
                    credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
                }),
                None,
                answers,
                stopped,
                events,
                sdk,
            ));
            let (_socket, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .unwrap()
                .unwrap();
            stop.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert!(gate.check().is_err());
            assert!(matches!(
                received.recv().await,
                Some(Internal::Closed(_, _, SdkError::Closed))
            ));
        }
    }

    #[tokio::test]
    async fn managed_ice_response_after_authorization_expiry_cannot_start_transport() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = IdentityClient::new(
            &format!("http://{}", listener.local_addr().unwrap()),
            true,
            Duration::from_secs(2),
        )
        .unwrap();
        let id = uuid::Uuid::nil().to_string();
        let body = json!({"session_id":id,"negotiation_generation":1,"ice_servers":[]}).to_string();
        let gate = Arc::new(Gate {
            installation_closed: Arc::new(AtomicBool::new(false)),
            closed: AtomicBool::new(false),
            deadline: Mutex::new(Some(Instant::now() + Duration::from_secs(60))),
            changed: tokio::sync::Notify::new(),
        });
        let server_gate = gate.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            assert!(socket.read(&mut bytes).await.unwrap() > 0);
            server_gate.update(Some(Instant::now()));
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        });
        let (_stop, stopped) = oneshot::channel();
        let (_answers, answers) = mpsc::channel(1);
        let (events, mut received) = mpsc::channel(4);
        let (sdk, _commands) = mpsc::channel(1);
        transport_worker(
            id,
            1,
            gate.clone(),
            TransportConfig::default(),
            Some(ManagedRelayRequest {
                client,
                credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
            }),
            None,
            answers,
            stopped,
            events,
            sdk,
        )
        .await;
        server.await.unwrap();
        assert!(matches!(
            received.recv().await,
            Some(Internal::Closed(_, _, SdkError::AuthorizationExpired))
        ));
        assert!(gate.check().is_err());
    }

    #[test]
    fn facade_rejects_wrong_label_protocol_and_unreliable_channels() {
        let mut metadata = device_transport_webrtc::ChannelMetadata {
            label: "peerloom.reliable".into(),
            protocol: String::new(),
            ordered: true,
            max_retransmits: None,
            max_packet_life_time: None,
        };
        assert!(valid_message_metadata(&metadata));
        metadata.max_retransmits = Some(0);
        assert!(!valid_message_metadata(&metadata));
        metadata.max_retransmits = None;
        metadata.max_packet_life_time = Some(10);
        assert!(!valid_message_metadata(&metadata));
        metadata.max_packet_life_time = None;
        metadata.ordered = false;
        assert!(!valid_message_metadata(&metadata));
        metadata.ordered = true;
        metadata.protocol = "peerloom.stream.v1".into();
        assert!(!valid_message_metadata(&metadata));
        metadata.protocol.clear();
        metadata.label = "other".into();
        assert!(!valid_message_metadata(&metadata));
    }
    #[test]
    fn uncertain_rotation_retry_fits_old_token_overlap() {
        let retry = refresh_delay(&Err(IdentityError::Transport));
        assert!((Duration::from_secs(1)..Duration::from_secs(2)).contains(&retry));
        assert_eq!(
            refresh_delay(&Err(IdentityError::Storage(
                device_storage::StorageError::Unavailable
            ))),
            Duration::from_secs(30)
        );
    }
    #[test]
    fn retry_backoff_is_bounded_and_reaches_thirty_seconds() {
        for attempt in 0..100 {
            let delay = backoff(attempt);
            assert!((Duration::from_secs(1)..=Duration::from_secs(30)).contains(&delay));
        }
        assert_eq!(backoff(10), Duration::from_secs(30));
    }
    fn connection() -> (Connection, Arc<Gate>, mpsc::Sender<Vec<u8>>) {
        let (commands, _) = mpsc::channel(1);
        let (send, messages) = mpsc::channel(1);
        let (sdk, _) = mpsc::channel(1);
        let gate = Arc::new(Gate::default());
        gate.update(Some(Instant::now() + Duration::from_secs(60)));
        (
            Connection {
                generation: 1,
                session_id: uuid::Uuid::new_v4().to_string(),
                commands,
                messages,
                gate: gate.clone(),
                sdk,
            },
            gate,
            send,
        )
    }
    #[test]
    fn readonly_validity_observer_tracks_expiry_and_owner_drop() {
        let (connection, gate, _) = connection();
        let observer = connection.validity();
        assert!(observer.is_valid());
        gate.update(Some(Instant::now()));
        assert!(!observer.is_valid());
        gate.update(Some(Instant::now() + Duration::from_secs(10)));
        assert!(observer.is_valid());
        drop(connection);
        assert!(!observer.is_valid());
        gate.update(Some(Instant::now() + Duration::from_secs(10)));
        assert!(!observer.is_valid());
    }
    #[tokio::test]
    async fn revoke_wakes_pending_receive_and_blocks_buffered_delivery() {
        let (mut connection, gate, _send) = connection();
        let receive = tokio::spawn(async move { connection.receive().await });
        tokio::task::yield_now().await;
        gate.close();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), receive)
                .await
                .unwrap()
                .unwrap(),
            Err(SdkError::Closed)
        );
    }
    #[tokio::test]
    async fn queued_payload_is_not_delivered_after_expiry() {
        let (mut connection, gate, send) = connection();
        send.send(vec![1, 2, 3]).await.unwrap();
        gate.update(Some(Instant::now()));
        assert_eq!(
            connection.receive().await,
            Err(SdkError::AuthorizationExpired)
        );
        assert_eq!(
            connection.send(b"late").await,
            Err(SdkError::AuthorizationExpired)
        );
    }
}
