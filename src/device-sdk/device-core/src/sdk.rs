//! 最小原生编排 facade：容量1、单条可靠消息通道。没有字节流/FFI/ICE restart。
//! WSS 自动恢复；数据连接失败后需显式 connect 创建新授权会话。
use crate::{
    identity::{
        IdempotencyKey, IdentityClient, IdentityError, IdentitySession, RegistrationRequest,
    },
    lease::LeaseGuard,
    signaling::{Envelope, SignalClient, SignalError},
};
use device_protocol::ChannelMode;
use device_storage::{IdentityStore, StoredIdentity};
use device_transport_webrtc::{
    MessageChannel, PeerTransport, SessionDescription, TransportConfig, TransportError,
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
    ConnectionClosed {
        session_id: String,
        reason: SdkError,
    },
    Stopped(SdkError),
    IdentityPersistencePending,
}

#[derive(Default)]
struct Gate {
    closed: AtomicBool,
    deadline: Mutex<Option<Instant>>,
    changed: tokio::sync::Notify,
}
impl Gate {
    fn check(&self) -> Result<(), SdkError> {
        if self.closed.load(Ordering::Acquire) {
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
impl Connection {
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
        let _ = self
            .sdk
            .try_send(Command::CloseConnection(self.session_id.clone(), None));
    }
}

pub struct DeviceSdk {
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
        if config.max_connections != 1 || config.max_channels_per_connection != 1 {
            return Err(SdkError::InvalidConfiguration);
        }
        config.transport.validate().map_err(SdkError::Transport)?;
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
        let (events_tx, events) = mpsc::channel(32);
        let (stop, stop_rx) = oneshot::channel();
        let sdk_commands = commands.clone();
        let task = tokio::spawn(async move {
            Actor::new(config, identity, stored, sdk_commands, events_tx)
                .run(command_rx, stop_rx)
                .await;
        });
        Ok(Self {
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
        let (tx, rx) = oneshot::channel();
        self.commands
            .try_send(Command::Respond(session_id.into(), accept, tx))
            .map_err(|_| SdkError::QueueFull)?;
        rx.await.map_err(|_| SdkError::Closed)?
    }
    /// 主动轮换后用新凭证重建 WSS；旧数据授权期限在 sync/renew 前不延长。
    pub async fn refresh_credentials(&self) -> Result<(), SdkError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .try_send(Command::Refresh(tx))
            .map_err(|_| SdkError::QueueFull)?;
        rx.await.map_err(|_| SdkError::Closed)?
    }
    pub async fn next_event(&mut self) -> Option<SdkEvent> {
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
    Connect(String, oneshot::Sender<Result<(), SdkError>>),
    Respond(String, bool, oneshot::Sender<Result<(), SdkError>>),
    CloseConnection(String, Option<oneshot::Sender<()>>),
    Refresh(oneshot::Sender<Result<(), SdkError>>),
}
enum Internal {
    Description(String, &'static str, String),
    Ready(String, Connection),
    Closed(String, SdkError),
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
}
type RefreshOutcome = (Result<(), IdentityError>, Option<StoredIdentity>);

struct Actor {
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
    sync_pending: bool,
    rejected_sessions: std::collections::VecDeque<String>,
    dial: Option<JoinHandle<Result<SignalClient, SignalError>>>,
    retry_at: Instant,
    attempt: u32,
    session: Option<Session>,
    pending: Option<String>,
    desired_target: Option<String>,
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
        let (internal_tx, internal_rx) = mpsc::channel(16);
        let dirty = identity.needs_persistence();
        if dirty {
            let _ = events.try_send(SdkEvent::IdentityPersistencePending);
        }
        Self {
            config,
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
            sync_pending: false,
            rejected_sessions: std::collections::VecDeque::new(),
            dial: None,
            retry_at: Instant::now(),
            attempt: 0,
            session: None,
            pending: None,
            desired_target: None,
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
        if let Some(session) = self.session.as_ref() {
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
        self.close_session(SdkError::Closed, false).await;
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
        self.sync_pending = self.session.is_some();
        if let Some(session) = &self.session {
            match self
                .send("sync.request", Some(&session.id.clone()), json!({}))
                .await
            {
                Ok(_) => {}
                Err(SdkError::Signal(error)) => self.disconnected(error).await?,
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
        if self.pending.take().is_some() && self.session.is_none() {
            // The old server-side request may have committed. Do not invent a new key.
            self.emit(SdkEvent::ConnectionClosed {
                session_id: String::new(),
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
        &self,
        kind: &str,
        session: Option<&str>,
        payload: serde_json::Value,
    ) -> Result<String, SdkError> {
        self.signal
            .as_ref()
            .ok_or(SdkError::Offline)?
            .send(kind, session, payload)
            .await
            .map_err(SdkError::Signal)
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
        if self.session.as_ref().is_some_and(|session| {
            session.gate.closed.load(Ordering::Acquire)
                || session
                    .guard
                    .deadline()
                    .is_some_and(|deadline| now >= deadline)
        }) {
            let reason = if self
                .session
                .as_ref()
                .is_some_and(|session| session.gate.closed.load(Ordering::Acquire))
            {
                SdkError::Closed
            } else {
                SdkError::AuthorizationExpired
            };
            self.close_session(reason, true).await;
        }
        if self.signal.is_some()
            && !self.sync_pending
            && self
                .session
                .as_ref()
                .is_some_and(|session| now >= session.renew_at && session.guard.is_authorized(now))
        {
            let id = self.session.as_ref().unwrap().id.clone();
            match self.send("session.renew", Some(&id), json!({})).await {
                Ok(request) => {
                    let session = self.session.as_mut().unwrap();
                    session
                        .guard
                        .renewal_requested(request)
                        .map_err(|_| SdkError::AuthorizationExpired)?;
                    session.renew_at = now + Duration::from_secs(15);
                }
                Err(SdkError::Signal(error)) => self.disconnected(error).await?,
                Err(error) => return Err(error),
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
                let outcome = if self.session.is_some() || self.pending.is_some() {
                    Err(SdkError::Busy)
                } else if target == self.stored.device_id {
                    Err(SdkError::InvalidConfiguration)
                } else {
                    match self
                        .send("session.request", None, json!({"target_device_id":target}))
                        .await
                    {
                        Ok(id) => {
                            self.pending = Some(id);
                            self.desired_target = Some(target);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    }
                };
                let _ = result.send(outcome);
            }
            Command::Respond(id, accept, result) => {
                let outcome = if self.session.as_ref().is_none_or(|session| {
                    session.id != id || session.target != self.stored.device_id
                }) {
                    Err(SdkError::Closed)
                } else {
                    self.send(
                        if accept {
                            "session.accept"
                        } else {
                            "session.reject"
                        },
                        Some(&id),
                        json!({}),
                    )
                    .await
                    .map(|_| ())
                };
                let _ = result.send(outcome);
            }
            Command::CloseConnection(id, done) => {
                if self.session.as_ref().is_some_and(|s| s.id == id) {
                    self.desired_target = None;
                    self.close_session(SdkError::Closed, true).await;
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
            let code = message.payload["code"]
                .as_str()
                .unwrap_or("REQUEST_DENIED")
                .to_owned();
            self.pending = None;
            let had_session = self.session.is_some();
            self.close_session(SdkError::Rejected(code.clone()), false)
                .await;
            if !had_session {
                self.emit(SdkEvent::ConnectionClosed {
                    session_id: message.session_id.unwrap_or_default(),
                    reason: SdkError::Rejected(code),
                })?;
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
            if self.session.is_none() {
                if message.kind == "session.terminated" {
                    return Ok(());
                }
                if source == self.stored.device_id
                    && (self.pending.is_none()
                        || self.pending.as_ref() != message.request_id.as_ref())
                {
                    return Ok(());
                }
                if source == self.stored.device_id && self.desired_target.as_ref() != Some(&target)
                {
                    return Err(SdkError::Signal(SignalError::InvalidMessage));
                }
                self.pending = None;
                let guard = LeaseGuard::new(id.clone(), source.clone(), target.clone())
                    .map_err(|_| SdkError::Signal(SignalError::InvalidMessage))?;
                self.session = Some(Session {
                    id: id.clone(),
                    source: source.clone(),
                    target: target.clone(),
                    guard,
                    gate: Arc::new(Gate::default()),
                    worker: None,
                    renew_at: Instant::now() + Duration::from_secs(10),
                    ready: false,
                });
                if target == self.stored.device_id && message.payload["state"] == "authorizing" {
                    self.emit(SdkEvent::IncomingConnection {
                        session_id: id.clone(),
                        source_device_id: source,
                    })?;
                }
            }
            if self
                .session
                .as_ref()
                .is_some_and(|session| session.id != id)
            {
                if target == self.stored.device_id
                    && message.kind == "session.pending"
                    && message.payload["state"] == "authorizing"
                    && !self.rejected_sessions.contains(&id)
                {
                    if self.rejected_sessions.len() == 32 {
                        self.rejected_sessions.pop_front();
                    }
                    self.rejected_sessions.push_back(id.clone());
                    let _ = self.send("session.reject", Some(&id), json!({})).await;
                }
                return Ok(());
            }
            let clock = self
                .signal
                .as_ref()
                .ok_or(SdkError::Offline)?
                .server_clock();
            let session = self.session.as_mut().unwrap();
            if session
                .guard
                .apply(&message, &clock, Instant::now())
                .is_err()
            {
                self.close_session(SdkError::AuthorizationExpired, true)
                    .await;
                return Ok(());
            }
            if message.payload["state"] == "closed" {
                self.close_session(
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
                self.sync_pending = false;
            }
            if session.guard.is_authorized(Instant::now())
                && session.source == self.stored.device_id
                && session.worker.is_none()
            {
                self.spawn_worker(None)?;
            }
        } else if message.kind == "session.offer" || message.kind == "session.answer" {
            let session = self.session.as_ref().ok_or(SdkError::Closed)?;
            if message.session_id.as_deref() != Some(&session.id)
                || message.negotiation_generation != Some(1)
                || !session.guard.is_authorized(Instant::now())
            {
                return Err(SdkError::Signal(SignalError::InvalidMessage));
            }
            let sdp = message.payload["sdp"]
                .as_str()
                .ok_or(SdkError::Signal(SignalError::InvalidMessage))?
                .to_owned();
            if message.kind == "session.offer" {
                if session.target != self.stored.device_id || session.worker.is_some() {
                    return Err(SdkError::Signal(SignalError::InvalidMessage));
                }
                self.spawn_worker(Some(
                    SessionDescription::offer(sdp)
                        .map_err(|_| SdkError::Transport(TransportError::Negotiation))?,
                ))?;
            } else {
                let answer = SessionDescription::answer(sdp)
                    .map_err(|_| SdkError::Transport(TransportError::Negotiation))?;
                session
                    .worker
                    .as_ref()
                    .ok_or(SdkError::Closed)?
                    .control
                    .try_send(answer)
                    .map_err(|_| SdkError::QueueFull)?;
            }
        }
        Ok(())
    }
    fn spawn_worker(&mut self, offer: Option<SessionDescription>) -> Result<(), SdkError> {
        let session = self.session.as_mut().ok_or(SdkError::Closed)?;
        let (control, answers) = mpsc::channel(1);
        let (stop, stopped) = oneshot::channel();
        let id = session.id.clone();
        let gate = session.gate.clone();
        let mut config = self.config.transport.clone();
        config.max_channels = 1;
        let events = self.internal_tx.clone();
        let sdk = self.commands.clone();
        let task = tokio::spawn(async move {
            transport_worker(id, gate, config, offer, answers, stopped, events, sdk).await;
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
            Internal::Description(id, kind, sdp) => {
                if self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.id == id)
                    && self
                        .send(kind, Some(&id), json!({"sdp":sdp}))
                        .await
                        .is_err()
                {
                    self.close_session(SdkError::Offline, false).await;
                }
            }
            Internal::Ready(id, connection) => {
                if self.session.as_ref().is_some_and(|session| {
                    session.id == id && session.guard.is_authorized(Instant::now())
                }) {
                    self.session.as_mut().unwrap().ready = true;
                    let _ = self.send("session.connected", Some(&id), json!({})).await;
                    self.emit(SdkEvent::ConnectionReady(connection))?;
                }
            }
            Internal::Closed(id, error) => {
                if self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.id == id)
                {
                    self.close_session(error, true).await;
                }
            }
        }
        Ok(())
    }
    async fn close_session(&mut self, reason: SdkError, notify: bool) {
        let Some(mut session) = self.session.take() else {
            return;
        };
        session.gate.close();
        session.guard.invalidate();
        if notify {
            let _ = self
                .send("session.terminate", Some(&session.id), json!({}))
                .await;
        }
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
        let _ = self.emit(SdkEvent::ConnectionClosed {
            session_id: session.id,
            reason,
        });
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        if let Some(session) = self.session.as_ref() {
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

#[allow(clippy::too_many_arguments)]
async fn transport_worker(
    id: String,
    gate: Arc<Gate>,
    config: TransportConfig,
    offer: Option<SessionDescription>,
    mut answers: mpsc::Receiver<SessionDescription>,
    mut stop: oneshot::Receiver<()>,
    events: mpsc::Sender<Internal>,
    sdk: mpsc::Sender<Command>,
) {
    let peer = match PeerTransport::new(config).await {
        Ok(peer) => peer,
        Err(error) => {
            let _ = events
                .send(Internal::Closed(id, SdkError::Transport(error)))
                .await;
            return;
        }
    };
    let operation = async {
        let mut channel: MessageChannel = if let Some(offer) = offer {
            let answer = peer
                .answer_offer(offer)
                .await
                .map_err(SdkError::Transport)?;
            events
                .send(Internal::Description(
                    id.clone(),
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
        gate.check()?;
        let (send, mut sends) = mpsc::channel::<SendRequest>(32);
        let (receive, messages) = mpsc::channel(32);
        events
            .send(Internal::Ready(
                id.clone(),
                Connection {
                    session_id: id.clone(),
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
                data = channel.receive() => match data {
                    Ok(data) => { gate.check()?; receive.try_send(data).map_err(|_|SdkError::QueueFull)?; },
                    Err(TransportError::Timeout) => {},
                    Err(error) => return Err(SdkError::Transport(error)),
                }
            }
        }
    };
    let result =
        tokio::select! {biased;_=&mut stop=>Err(SdkError::Closed),result=operation=>result};
    gate.close();
    let _ = peer.close().await;
    let _ = events.try_send(Internal::Closed(
        id,
        result.err().unwrap_or(SdkError::Closed),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
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
