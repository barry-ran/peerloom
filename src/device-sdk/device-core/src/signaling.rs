//! 原生有界信令连接：后台 heartbeat，显式 close，无自动重连或会话恢复承诺。
use crate::identity::IdentityClient;
use device_storage::SecretString;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
const LIMIT: usize = 128 * 1024;
const MAX_SEQ: u64 = 9_007_199_254_740_991;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalError {
    InvalidMessage,
    Transport,
    Timeout,
    Closed,
    QueueFull,
    AuthorizationRejected,
    PolicyRejected,
}
impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SignalError {}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fencing_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiation_generation: Option<u64>,
    pub seq: u64,
    pub sent_at: String,
    pub payload: Value,
}
// 不打印 fence、SDP 或 payload。
impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("type", &self.kind)
            .field("id", &self.id)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}
impl Envelope {
    fn new(kind: &str, payload: Value) -> Result<Self, SignalError> {
        Ok(Self {
            v: 1,
            kind: kind.into(),
            id: uuid::Uuid::new_v4().to_string(),
            request_id: None,
            session_id: None,
            connection_generation: None,
            fencing_token: None,
            negotiation_generation: None,
            seq: 0,
            sent_at: timestamp()?,
            payload,
        })
    }
    fn validate(&self) -> Result<(), SignalError> {
        if self.v != 1
            || self.seq > MAX_SEQ
            || uuid::Uuid::parse_str(&self.id).is_err()
            || self.kind.len() > 64
            || self.kind.is_empty()
            || !self.sent_at.ends_with('Z')
            || time::OffsetDateTime::parse(
                &self.sent_at,
                &time::format_description::well_known::Rfc3339,
            )
            .is_err()
            || self.payload.as_object().is_none_or(|p| p.len() > 32)
            || [&self.session_id, &self.request_id].iter().any(|id| {
                id.as_ref()
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_err())
            })
            || self
                .connection_generation
                .is_some_and(|g| g == 0 || g > MAX_SEQ)
            || self
                .negotiation_generation
                .is_some_and(|g| g == 0 || g > MAX_SEQ)
            || self
                .fencing_token
                .as_ref()
                .is_some_and(|f| !(16..=256).contains(&f.len()))
        {
            return Err(SignalError::InvalidMessage);
        }
        Ok(())
    }
}
fn timestamp() -> Result<String, SignalError> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| SignalError::InvalidMessage)
}
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
struct Command {
    envelope: Envelope,
    completion: oneshot::Sender<Result<(), SignalError>>,
}
/// 发送与事件队列均为32。事件接收者停滞时断开，不能静默丢弃会话事件。
/// Drop 中止后台任务；需要握手退出时必须 await close()。
pub struct SignalClient {
    commands: mpsc::Sender<Command>,
    events: mpsc::Receiver<Result<Envelope, SignalError>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    clock: crate::lease::ServerClockBound,
}
impl SignalClient {
    pub async fn connect(
        identity_client: &IdentityClient,
        token: &SecretString,
    ) -> Result<Self, SignalError> {
        let mut url = identity_client
            .origin
            .join("/v1/device-signal")
            .map_err(|_| SignalError::InvalidMessage)?;
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme)
            .map_err(|_| SignalError::InvalidMessage)?;
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|_| SignalError::InvalidMessage)?;
        let mut auth = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&format!(
            "Bearer {}",
            token.expose()
        ))
        .map_err(|_| SignalError::InvalidMessage)?;
        auth.set_sensitive(true);
        request.headers_mut().insert("Authorization", auth);
        let config = WebSocketConfig::default()
            .read_buffer_size(4096)
            .write_buffer_size(0)
            .max_write_buffer_size(LIMIT + 1024)
            .max_message_size(Some(LIMIT))
            .max_frame_size(Some(LIMIT));
        // Reuse the HTTPS platform verifier, including OS trust policy. No separate
        // native-root fallback; configuration was initialized by IdentityClient.
        let connector = tokio_tungstenite::Connector::Rustls(identity_client.tls_config.clone());
        let (mut socket, _) = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::connect_async_tls_with_config(
                request,
                Some(config),
                false,
                Some(connector),
            ),
        )
        .await
        .map_err(|_| SignalError::Timeout)?
        .map_err(|error| match error {
            tokio_tungstenite::tungstenite::Error::Http(response)
                if matches!(response.status().as_u16(), 401 | 403) =>
            {
                SignalError::AuthorizationRejected
            }
            _ => SignalError::Transport,
        })?;
        let hello_started = std::time::Instant::now();
        let hello = Envelope::new("hello", json!({}))?;
        write(&mut socket, &hello).await?;
        let ack = tokio::time::timeout(Duration::from_secs(10), read(&mut socket))
            .await
            .map_err(|_| SignalError::Timeout)??;
        if ack.kind != "hello.ack"
            || ack.seq != 0
            || ack.request_id.as_deref() != Some(&hello.id)
            || ack.connection_generation.is_none()
            || ack.fencing_token.is_none()
        {
            return Err(SignalError::InvalidMessage);
        }
        let clock = crate::lease::ServerClockBound::from_hello(&ack.sent_at, hello_started)
            .map_err(|_| SignalError::InvalidMessage)?;
        let heartbeat = ack
            .payload
            .get("heartbeat_interval_seconds")
            .and_then(Value::as_u64)
            .filter(|n| (1..=60).contains(n))
            .ok_or(SignalError::InvalidMessage)?;
        let ttl = ack
            .payload
            .get("presence_ttl_seconds")
            .and_then(Value::as_u64)
            .filter(|n| *n > heartbeat && *n <= 300)
            .ok_or(SignalError::InvalidMessage)?;
        let (commands, command_rx) = mpsc::channel(32);
        let (events_tx, events) = mpsc::channel(32);
        let (stop, stop_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let result = drive(
                &mut socket,
                ack,
                heartbeat,
                ttl,
                command_rx,
                &events_tx,
                stop_rx,
            )
            .await;
            if let Err(error) = result {
                let _ = events_tx.try_send(Err(error));
            }
            let _ = tokio::time::timeout(Duration::from_secs(2), socket.close(None)).await;
        });
        Ok(Self {
            commands,
            events,
            stop: Some(stop),
            task: Some(task),
            clock,
        })
    }
    pub fn server_clock(&self) -> crate::lease::ServerClockBound {
        self.clock.clone()
    }
    /// 返回请求 UUID。取消等待不撤销已排队的帧；不得把取消误认为服务端未执行。
    pub async fn send(
        &self,
        kind: &str,
        session_id: Option<&str>,
        payload: Value,
    ) -> Result<String, SignalError> {
        self.send_generation(kind, session_id, payload, 1).await
    }
    pub async fn send_generation(
        &self,
        kind: &str,
        session_id: Option<&str>,
        payload: Value,
        generation: u64,
    ) -> Result<String, SignalError> {
        if !(1..=32).contains(&generation) {
            return Err(SignalError::InvalidMessage);
        }
        if !matches!(
            kind,
            "session.request"
                | "session.accept"
                | "session.reject"
                | "session.offer"
                | "session.answer"
                | "session.connected"
                | "session.reconnecting"
                | "session.renew"
                | "session.terminate"
                | "sync.request"
        ) {
            return Err(SignalError::InvalidMessage);
        }
        let mut envelope = Envelope::new(kind, payload)?;
        envelope.session_id = session_id.map(str::to_owned);
        if session_id.is_some() {
            envelope.negotiation_generation = Some(generation);
        }
        if matches!(kind, "session.offer" | "session.answer")
            && envelope
                .payload
                .get("sdp")
                .and_then(Value::as_str)
                .is_none_or(|s| s.is_empty() || s.len() > 65536)
        {
            return Err(SignalError::InvalidMessage);
        }
        envelope.validate()?;
        if serde_json::to_vec(&envelope)
            .map_err(|_| SignalError::InvalidMessage)?
            .len()
            > LIMIT - 1024
        {
            return Err(SignalError::InvalidMessage);
        }
        let id = envelope.id.clone();
        let (completion, result) = oneshot::channel();
        self.commands
            .try_send(Command {
                envelope,
                completion,
            })
            .map_err(|e| {
                if matches!(e, mpsc::error::TrySendError::Full(_)) {
                    SignalError::QueueFull
                } else {
                    SignalError::Closed
                }
            })?;
        result.await.map_err(|_| SignalError::Closed)??;
        Ok(id)
    }
    pub async fn receive(&mut self) -> Result<Envelope, SignalError> {
        self.events.recv().await.ok_or(SignalError::Closed)?
    }
    pub async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.as_mut()
            && tokio::time::timeout(Duration::from_secs(8), &mut *task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        self.task.take();
    }
}
impl Drop for SignalClient {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn write(socket: &mut Socket, envelope: &Envelope) -> Result<(), SignalError> {
    let data = serde_json::to_string(envelope).map_err(|_| SignalError::InvalidMessage)?;
    if data.len() > LIMIT {
        return Err(SignalError::InvalidMessage);
    }
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(data.into())),
    )
    .await
    .map_err(|_| SignalError::Timeout)?
    .map_err(|_| SignalError::Transport)
}
async fn read(socket: &mut Socket) -> Result<Envelope, SignalError> {
    loop {
        match socket
            .next()
            .await
            .ok_or(SignalError::Closed)?
            .map_err(|_| SignalError::Transport)?
        {
            Message::Text(text) => {
                let envelope: Envelope =
                    serde_json::from_str(&text).map_err(|_| SignalError::InvalidMessage)?;
                envelope.validate()?;
                return Ok(envelope);
            }
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(frame) => return Err(if frame.is_some_and(|frame| frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy) { SignalError::PolicyRejected } else { SignalError::Closed }),
            _ => return Err(SignalError::InvalidMessage),
        }
    }
}
async fn drive(
    socket: &mut Socket,
    ack: Envelope,
    heartbeat: u64,
    ttl: u64,
    mut commands: mpsc::Receiver<Command>,
    events: &mpsc::Sender<Result<Envelope, SignalError>>,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), SignalError> {
    let mut next_out = 1u64;
    let mut next_in = 1u64;
    let mut interval = tokio::time::interval(Duration::from_secs(heartbeat));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    let mut deadline = tokio::time::Instant::now() + Duration::from_secs(ttl);
    loop {
        let mut outgoing = tokio::select! {
            _=&mut stop=>return Ok(()),
            _=tokio::time::sleep_until(deadline)=>return Err(SignalError::Timeout),
            _=interval.tick()=>Some((Envelope::new("presence.heartbeat",json!({}))?,None)),
            command=commands.recv()=>{let command=command.ok_or(SignalError::Closed)?;Some((command.envelope,Some(command.completion)))},
            incoming=read(socket)=>{let incoming=incoming?;if incoming.seq!=next_in || incoming.connection_generation!=ack.connection_generation || incoming.fencing_token!=ack.fencing_token {return Err(SignalError::InvalidMessage);}next_in=next_in.checked_add(1).filter(|n|*n<=MAX_SEQ).ok_or(SignalError::InvalidMessage)?;deadline=tokio::time::Instant::now()+Duration::from_secs(ttl);if incoming.kind!="presence.ack" {events.try_send(Ok(incoming)).map_err(|_|SignalError::QueueFull)?;}None}
        };
        if let Some((ref mut envelope, completion)) = outgoing.take() {
            envelope.seq = next_out;
            envelope.connection_generation = ack.connection_generation;
            envelope.fencing_token = ack.fencing_token.clone();
            envelope.sent_at = timestamp()?;
            let result = write(socket, envelope).await;
            if let Some(completion) = completion {
                let _ = completion.send(result);
            }
            result?;
            next_out = next_out
                .checked_add(1)
                .filter(|n| *n <= MAX_SEQ)
                .ok_or(SignalError::InvalidMessage)?;
        }
    }
}
