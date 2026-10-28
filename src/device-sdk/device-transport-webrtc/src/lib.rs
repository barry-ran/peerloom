//! 真实 webrtc-rs 数据通道适配层。只负责传输，不代表已通过平台注册或会话授权。
//! 使用前必须由控制面验证 SDP 对端身份和会话权限；此处不实现业务授权。
//! 目前采用完整 ICE 收集的 SDP 交换；trickle ICE、重协商和自动重连尚未集成。

pub mod stream;
pub use stream::{ByteStream, StreamError};

use async_trait::async_trait;
use bytes::BytesMut;
use device_protocol::{ChannelMode, ConnectionPolicy};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, watch};
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceGatheringState, RTCIceTransportPolicy, RTCPeerConnectionState, SettingEngineBuilder,
};

pub use webrtc::peer_connection::{RTCIceServer, RTCSessionDescription as SessionDescription};

/// 只暴露实际选中候选的类别，不暴露地址、凭证或完整统计。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Unknown,
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
}
fn candidate_kind(value: rtc::peer_connection::transport::RTCIceCandidateType) -> CandidateKind {
    use rtc::peer_connection::transport::RTCIceCandidateType as T;
    match value {
        T::Host => CandidateKind::Host,
        T::Srflx => CandidateKind::ServerReflexive,
        T::Prflx => CandidateKind::PeerReflexive,
        T::Relay => CandidateKind::Relay,
        _ => CandidateKind::Unknown,
    }
}

/// 不实现 Debug，避免 TURN 凭证通过配置日志泄漏。
#[derive(Clone)]
pub struct TransportConfig {
    pub policy: ConnectionPolicy,
    pub ice_servers: Vec<RTCIceServer>,
    pub bind_address: SocketAddr,
    pub include_loopback: bool,
    /// 原生首版默认关闭 mDNS；浏览器 .local 候选互通需显式启用并单独验证。
    pub enable_mdns: bool,
    pub max_channels: usize,
    pub max_message_bytes: usize,
    pub send_buffer_bytes: usize,
    pub max_sdp_bytes: usize,
    pub operation_timeout: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            policy: ConnectionPolicy::Auto,
            ice_servers: Vec::new(),
            bind_address: SocketAddr::from(([0, 0, 0, 0], 0)),
            include_loopback: false,
            enable_mdns: false,
            max_channels: 8,
            max_message_bytes: 64 * 1024,
            send_buffer_bytes: 1024 * 1024,
            max_sdp_bytes: 64 * 1024,
            operation_timeout: Duration::from_secs(20),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    InvalidConfiguration,
    RelayRequired,
    RelayForbidden,
    InvalidCandidate,
    UnsupportedChannel,
    TooManyChannels,
    MessageTooLarge,
    SdpTooLarge,
    Timeout,
    Closed,
    /// 后端未提供可安全归类的错误；不包含 SDP、URL 或凭证原文。
    WebRtc,
    Io(std::io::ErrorKind),
    Crypto,
    Negotiation,
    Ice,
    Relay,
    Dtls,
    Sctp,
    NotReady,
    BufferFull,
    NegotiationAlreadyStarted,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TransportError {}

fn classify_backend(error: webrtc::error::Error) -> TransportError {
    use webrtc::error::Error;
    match error {
        Error::Io(error) => TransportError::Io(error.0.kind()),
        Error::Crypto(_) => TransportError::Crypto,
        Error::SdpInvalidSyntax(_) | Error::SdpInvalidValue(_) | Error::OtherSdpErr(_) => {
            TransportError::Negotiation
        }
        Error::OtherIceErr(_) => TransportError::Ice,
        Error::OtherTurnErr(_) => TransportError::Relay,
        Error::OtherDtlsErr(_) => TransportError::Dtls,
        Error::OtherSctpErr(_) => TransportError::Sctp,
        Error::ErrDataChannelClosed => TransportError::Closed,
        Error::ErrDataChannelNotOpen => TransportError::NotReady,
        Error::ErrSendBufferFull => TransportError::BufferFull,
        _ => TransportError::WebRtc,
    }
}

impl TransportConfig {
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.max_channels == 0
            || self.max_channels > 1024
            || self.max_message_bytes == 0
            || self.max_message_bytes > 64 * 1024
            || self.send_buffer_bytes < self.max_message_bytes
            || self.send_buffer_bytes > u32::MAX as usize
            || self.max_sdp_bytes == 0
            || self.max_sdp_bytes > 64 * 1024
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(300)
        {
            return Err(TransportError::InvalidConfiguration);
        }
        let has_turn = self
            .ice_servers
            .iter()
            .flat_map(|server| &server.urls)
            .any(|url| is_turn_url(url));
        if self.policy == ConnectionPolicy::RelayOnly && !has_turn {
            return Err(TransportError::RelayRequired);
        }
        if self.policy == ConnectionPolicy::DirectOnly && has_turn {
            return Err(TransportError::RelayForbidden);
        }
        Ok(())
    }
}

fn is_turn_url(url: &str) -> bool {
    url.split_once(':').is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("turn") || scheme.eq_ignore_ascii_case("turns")
    })
}

fn validate_remote_sdp(
    config: &TransportConfig,
    description: &SessionDescription,
) -> Result<(), TransportError> {
    if description.sdp.len() > config.max_sdp_bytes {
        return Err(TransportError::SdpTooLarge);
    }
    let mut candidate_count = 0;
    for line in description.sdp.lines() {
        let Some(raw) = line.trim().strip_prefix("a=candidate:") else {
            continue;
        };
        candidate_count += 1;
        // RFC ICE 使用 ASCII SP 分隔，先拒绝非规范字段，避免与后端 Unicode 分词差异。
        let fields: Vec<_> = raw.split_ascii_whitespace().collect();
        if candidate_count > 256
            || raw.len() > 2048
            || !raw.bytes().all(|byte| (32..=126).contains(&byte))
            || fields.len() < 8
            || fields[6] != "typ"
        {
            return Err(TransportError::InvalidCandidate);
        }
        let candidate = rtc::ice::candidate::unmarshal_candidate(raw)
            .map_err(|_| TransportError::InvalidCandidate)?;
        if config.policy == ConnectionPolicy::DirectOnly
            && candidate.candidate_type() == rtc::ice::candidate::CandidateType::Relay
        {
            return Err(TransportError::RelayForbidden);
        }
    }
    Ok(())
}

fn channel_options(mode: ChannelMode) -> Result<RTCDataChannelInit, TransportError> {
    match mode {
        ChannelMode::ReliableMessage => Ok(RTCDataChannelInit::default()),
        ChannelMode::LowLatencyMessage => Ok(RTCDataChannelInit {
            ordered: false,
            max_retransmits: Some(0),
            ..Default::default()
        }),
        // 不能把可靠消息通道冒充含流控/关闭语义的可靠字节流。
        ChannelMode::ReliableStream => Err(TransportError::UnsupportedChannel),
    }
}

/// 单个接收循环按元数据分派；不要并发调用不同 accept API 抢同一队列。
/// 不依据 label 猜测类型；流保留既有 peerloom.stream.v1 帧协议。
pub enum IncomingChannel {
    ReliableMessage(MessageChannel),
    ReliableStream(ByteStream),
    LowLatencyMessage(MessageChannel),
}

fn incoming_mode(
    protocol: &str,
    ordered: bool,
    max_retransmits: Option<u16>,
    max_packet_life_time: Option<u16>,
) -> Result<ChannelMode, TransportError> {
    match (protocol, ordered, max_retransmits, max_packet_life_time) {
        ("", true, None, None) => Ok(ChannelMode::ReliableMessage),
        ("", false, Some(0), None) => Ok(ChannelMode::LowLatencyMessage),
        (stream::PROTOCOL, true, None, None) => Ok(ChannelMode::ReliableStream),
        _ => Err(TransportError::UnsupportedChannel),
    }
}

struct IncomingQueue {
    receiver: mpsc::Receiver<Arc<dyn DataChannel>>,
    // Retain ownership across cancellable metadata awaits. A cancelled accept
    // resumes classification of this exact channel instead of abandoning it.
    pending: Option<Arc<dyn DataChannel>>,
}

#[cfg(feature = "test-diagnostics")]
#[derive(Default)]
struct IncomingDiagnostics {
    observed: AtomicUsize,
    enqueued: AtomicUsize,
    quota_rejected: AtomicUsize,
    queue_rejected: AtomicUsize,
}
#[cfg(feature = "test-diagnostics")]
#[derive(Debug)]
pub struct TransportDiagnostics {
    pub state: RTCPeerConnectionState,
    pub lifetime_channels: usize,
    pub incoming_observed: usize,
    pub incoming_enqueued: usize,
    pub quota_rejected: usize,
    pub queue_rejected: usize,
}

struct Handler {
    #[cfg(feature = "test-diagnostics")]
    diagnostics: Arc<IncomingDiagnostics>,
    gathered: watch::Sender<bool>,
    states: watch::Sender<RTCPeerConnectionState>,
    incoming: mpsc::Sender<Arc<dyn DataChannel>>,
    channel_count: Arc<AtomicUsize>,
    max_channels: usize,
}

fn reserve_channel(count: &AtomicUsize, max: usize) -> Result<(), TransportError> {
    count
        .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            (value < max).then_some(value + 1)
        })
        .map(|_| ())
        .map_err(|_| TransportError::TooManyChannels)
}

#[async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            self.gathered.send_replace(true);
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        self.states.send_replace(state);
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        #[cfg(feature = "test-diagnostics")]
        self.diagnostics.observed.fetch_add(1, Ordering::Relaxed);
        if reserve_channel(&self.channel_count, self.max_channels).is_err() {
            #[cfg(feature = "test-diagnostics")]
            self.diagnostics
                .quota_rejected
                .fetch_add(1, Ordering::Relaxed);
            let _ = channel.close().await;
            return;
        }
        if let Err(error) = self.incoming.try_send(channel) {
            #[cfg(feature = "test-diagnostics")]
            self.diagnostics
                .queue_rejected
                .fetch_add(1, Ordering::Relaxed);
            self.channel_count.fetch_sub(1, Ordering::AcqRel);
            let _ = error.into_inner().close().await;
        } else {
            #[cfg(feature = "test-diagnostics")]
            self.diagnostics.enqueued.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// 调用者必须显式 close().await，随后销毁；不在 Drop 内隐藏启动后台任务。
/// 会话生命周期内累计限制通道数量，关闭单个通道不回收名额；重新建连创建新实例。
pub struct PeerTransport {
    #[cfg(feature = "test-diagnostics")]
    diagnostics: Arc<IncomingDiagnostics>,
    peer: Arc<dyn PeerConnection>,
    config: TransportConfig,
    gathered: Mutex<watch::Receiver<bool>>,
    states: watch::Receiver<RTCPeerConnectionState>,
    incoming: Mutex<IncomingQueue>,
    channel_count: Arc<AtomicUsize>,
    closed: AtomicBool,
    negotiation: AtomicU8,
}

impl PeerTransport {
    /// Fixed enums/counts only. Never includes labels, SDP, addresses or credentials.
    #[cfg(feature = "test-diagnostics")]
    pub fn diagnostics(&self) -> TransportDiagnostics {
        TransportDiagnostics {
            state: self.state(),
            lifetime_channels: self.channel_count.load(Ordering::Relaxed),
            incoming_observed: self.diagnostics.observed.load(Ordering::Relaxed),
            incoming_enqueued: self.diagnostics.enqueued.load(Ordering::Relaxed),
            quota_rejected: self.diagnostics.quota_rejected.load(Ordering::Relaxed),
            queue_rejected: self.diagnostics.queue_rejected.load(Ordering::Relaxed),
        }
    }

    /// 直接读取底层 ICE transport 的真实选中对；未选中时为 None。
    /// 不依赖 0.21.1 stats 中缺失的 remote-candidate 条目或不一致的 ID 前缀。
    pub async fn selected_candidate_types(
        &self,
    ) -> Result<Option<(CandidateKind, CandidateKind)>, TransportError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportError::Closed);
        }
        tokio::time::timeout(self.config.operation_timeout, async {
            let Some(sctp) = self.peer.sctp().await else {
                return Ok(None);
            };
            let pair = sctp
                .transport()
                .ice_transport()
                .get_selected_candidate_pair()
                .await
                .map_err(classify_backend)?;
            Ok(pair.map(|pair| {
                (
                    candidate_kind(pair.local().typ),
                    candidate_kind(pair.remote().typ),
                )
            }))
        })
        .await
        .map_err(|_| TransportError::Timeout)?
    }

    pub async fn new(config: TransportConfig) -> Result<Self, TransportError> {
        config.validate()?;
        let (gather_tx, gather_rx) = watch::channel(false);
        let (state_tx, state_rx) = watch::channel(RTCPeerConnectionState::New);
        let (incoming_tx, incoming_rx) = mpsc::channel(config.max_channels);
        let count = Arc::new(AtomicUsize::new(0));
        #[cfg(feature = "test-diagnostics")]
        let diagnostics = Arc::new(IncomingDiagnostics::default());
        let handler = Handler {
            #[cfg(feature = "test-diagnostics")]
            diagnostics: diagnostics.clone(),
            gathered: gather_tx,
            states: state_tx,
            incoming: incoming_tx,
            channel_count: count.clone(),
            max_channels: config.max_channels,
        };
        let rtc_config = RTCConfigurationBuilder::new()
            .with_ice_servers(config.ice_servers.clone())
            .with_ice_transport_policy(if config.policy == ConnectionPolicy::RelayOnly {
                RTCIceTransportPolicy::Relay
            } else {
                RTCIceTransportPolicy::All
            })
            .build();
        let settings = SettingEngineBuilder::new()
            .with_include_loopback_candidate(config.include_loopback)
            .with_multicast_dns_mode(if config.enable_mdns {
                rtc::ice::mdns::MulticastDnsMode::QueryOnly
            } else {
                rtc::ice::mdns::MulticastDnsMode::Disabled
            })
            .with_sctp_max_message_size(
                rtc::peer_connection::configuration::setting_engine::SctpMaxMessageSize::Bounded(
                    config.max_message_bytes as u32,
                ),
            )
            .with_sctp_max_receive_buffer_size(config.send_buffer_bytes as u32)
            .build();
        let builder = PeerConnectionBuilder::new()
            .with_configuration(rtc_config)
            .with_setting_engine(settings)
            .with_data_channel_send_buffer_limit(config.send_buffer_bytes)
            .with_handler(Arc::new(handler))
            .with_udp_addrs(vec![config.bind_address]);
        let peer = tokio::time::timeout(config.operation_timeout, builder.build())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(classify_backend)?;
        Ok(Self {
            #[cfg(feature = "test-diagnostics")]
            diagnostics,
            peer: Arc::new(peer),
            config,
            gathered: Mutex::new(gather_rx),
            states: state_rx,
            incoming: Mutex::new(IncomingQueue {
                receiver: incoming_rx,
                pending: None,
            }),
            channel_count: count,
            closed: AtomicBool::new(false),
            negotiation: AtomicU8::new(0),
        })
    }

    pub fn state(&self) -> RTCPeerConnectionState {
        *self.states.borrow()
    }

    /// Observe a lost established path without depending on DataChannel close events.
    /// A transient ICE disconnect is recoverable, not an authorization extension.
    pub async fn wait_interrupted(&self) {
        let mut states = self.states.clone();
        loop {
            if matches!(
                *states.borrow_and_update(),
                RTCPeerConnectionState::Disconnected
                    | RTCPeerConnectionState::Failed
                    | RTCPeerConnectionState::Closed
            ) {
                return;
            }
            if states.changed().await.is_err() {
                return;
            }
        }
    }

    fn ensure_open(&self) -> Result<(), TransportError> {
        if self.closed.load(Ordering::Acquire) {
            Err(TransportError::Closed)
        } else {
            Ok(())
        }
    }

    async fn bounded<T>(
        &self,
        future: impl std::future::Future<Output = webrtc::error::Result<T>>,
    ) -> Result<T, TransportError> {
        self.ensure_open()?;
        tokio::time::timeout(self.config.operation_timeout, future)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(classify_backend)
    }

    pub async fn create_channel(
        &self,
        label: &str,
        mode: ChannelMode,
    ) -> Result<MessageChannel, TransportError> {
        self.ensure_open()?;
        let options = channel_options(mode)?;
        if label.len() > 128 {
            return Err(TransportError::InvalidConfiguration);
        }
        reserve_channel(&self.channel_count, self.config.max_channels)?;
        let result = self
            .bounded(self.peer.create_data_channel(label, Some(options)))
            .await;
        match result {
            Ok(channel) => Ok(self.wrap_channel(channel)),
            Err(error) => {
                if error != TransportError::Timeout {
                    self.channel_count.fetch_sub(1, Ordering::AcqRel);
                }
                Err(error)
            }
        }
    }

    fn wrap_channel(&self, channel: Arc<dyn DataChannel>) -> MessageChannel {
        MessageChannel {
            channel,
            max_message_bytes: self.config.max_message_bytes,
            timeout: self.config.operation_timeout,
            opened: false,
            pending: None,
        }
    }

    /// 混合通道唯一接收入口。调用者接收 enum 后交给各自有界驱动，不另起
    /// accept_stream/accept_channel 消费者。未知协议或不匹配可靠性失败关闭。
    pub async fn accept_incoming(&self) -> Result<IncomingChannel, TransportError> {
        self.ensure_open()?;
        let mut incoming =
            tokio::time::timeout(self.config.operation_timeout, self.incoming.lock())
                .await
                .map_err(|_| TransportError::Timeout)?;
        if incoming.pending.is_none() {
            incoming.pending = Some(
                tokio::time::timeout(self.config.operation_timeout, incoming.receiver.recv())
                    .await
                    .map_err(|_| TransportError::Timeout)?
                    .ok_or(TransportError::Closed)?,
            );
        }
        let channel = self.wrap_channel(
            incoming
                .pending
                .as_ref()
                .expect("pending receive populated")
                .clone(),
        );
        let mode = channel.metadata().await.and_then(|metadata| {
            incoming_mode(
                &metadata.protocol,
                metadata.ordered,
                metadata.max_retransmits,
                metadata.max_packet_life_time,
            )
        });
        match mode {
            Ok(ChannelMode::ReliableMessage) => {
                incoming.pending.take();
                Ok(IncomingChannel::ReliableMessage(channel))
            }
            Ok(ChannelMode::LowLatencyMessage) => {
                incoming.pending.take();
                Ok(IncomingChannel::LowLatencyMessage(channel))
            }
            Ok(ChannelMode::ReliableStream)
                if channel.max_message_bytes >= stream::MIN_MESSAGE_BYTES =>
            {
                incoming.pending.take();
                Ok(IncomingChannel::ReliableStream(ByteStream::new(channel)))
            }
            other => {
                let error = other.err().unwrap_or(TransportError::UnsupportedChannel);
                // Retain the slot while rejection closes the channel too: cancelling
                // this await must not abandon a live, unclassified channel.
                let _ = channel.close().await;
                incoming.pending.take();
                Err(error)
            }
        }
    }

    /// 兼容原始消息接口，不验证应用协议。混合通道应改用 accept_incoming。
    pub async fn accept_channel(&self) -> Result<MessageChannel, TransportError> {
        self.ensure_open()?;
        let channel = tokio::time::timeout(self.config.operation_timeout, async {
            let mut incoming = self.incoming.lock().await;
            match incoming.pending.take() {
                Some(channel) => Some(channel),
                None => incoming.receiver.recv().await,
            }
        })
        .await
        .map_err(|_| TransportError::Timeout)?
        .ok_or(TransportError::Closed)?;
        Ok(self.wrap_channel(channel))
    }

    async fn gathered_description(&self) -> Result<SessionDescription, TransportError> {
        tokio::time::timeout(self.config.operation_timeout, async {
            let mut gathered = self.gathered.lock().await;
            loop {
                if *gathered.borrow_and_update() {
                    break;
                }
                gathered
                    .changed()
                    .await
                    .map_err(|_| TransportError::Closed)?;
            }
            let description = self
                .peer
                .local_description()
                .await
                .ok_or(TransportError::WebRtc)?;
            validate_remote_sdp(&self.config, &description)?;
            Ok(description)
        })
        .await
        .map_err(|_| TransportError::Timeout)?
    }

    pub async fn create_offer(&self) -> Result<SessionDescription, TransportError> {
        self.ensure_open()?;
        self.negotiation
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| TransportError::NegotiationAlreadyStarted)?;
        let offer = self.bounded(self.peer.create_offer(None)).await?;
        self.bounded(self.peer.set_local_description(offer)).await?;
        let description = self.gathered_description().await?;
        self.negotiation.store(2, Ordering::Release);
        Ok(description)
    }

    pub async fn answer_offer(
        &self,
        offer: SessionDescription,
    ) -> Result<SessionDescription, TransportError> {
        self.ensure_open()?;
        validate_remote_sdp(&self.config, &offer)?;
        self.negotiation
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| TransportError::NegotiationAlreadyStarted)?;
        self.bounded(self.peer.set_remote_description(offer))
            .await?;
        let answer = self.bounded(self.peer.create_answer(None)).await?;
        self.bounded(self.peer.set_local_description(answer))
            .await?;
        self.gathered_description().await
    }

    pub async fn apply_answer(&self, answer: SessionDescription) -> Result<(), TransportError> {
        self.ensure_open()?;
        validate_remote_sdp(&self.config, &answer)?;
        self.negotiation
            .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| TransportError::NegotiationAlreadyStarted)?;
        self.bounded(self.peer.set_remote_description(answer)).await
    }

    pub async fn close(&self) -> Result<(), TransportError> {
        self.closed.store(true, Ordering::Release);
        tokio::time::timeout(self.config.operation_timeout, self.peer.close())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(classify_backend)
    }
}

/// 每条接收消息保留边界；该类型不是流，也不承诺业务确认或 exactly-once。
pub struct MessageChannel {
    channel: Arc<dyn DataChannel>,
    max_message_bytes: usize,
    timeout: Duration,
    opened: bool,
    pending: Option<Vec<u8>>,
}

/// 不含凭证的 DataChannel 协商元数据；用于拒绝错误通道语义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMetadata {
    pub label: String,
    pub protocol: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
    pub max_packet_life_time: Option<u16>,
}
impl ChannelMetadata {
    pub fn is_reliable_ordered(&self) -> bool {
        self.ordered && self.max_retransmits.is_none() && self.max_packet_life_time.is_none()
    }
}

impl MessageChannel {
    #[cfg(feature = "test-diagnostics")]
    pub async fn diagnostic_state(&self) -> Result<(usize, String), TransportError> {
        tokio::time::timeout(Duration::from_secs(1), async {
            let state = self.channel.ready_state().await.map_err(classify_backend)?;
            Ok((self.channel.id(), format!("{state:?}")))
        })
        .await
        .map_err(|_| TransportError::Timeout)?
    }

    pub async fn metadata(&self) -> Result<ChannelMetadata, TransportError> {
        tokio::time::timeout(self.timeout, async {
            Ok::<_, webrtc::error::Error>(ChannelMetadata {
                label: self.channel.label().await?,
                protocol: self.channel.protocol().await?,
                ordered: self.channel.ordered().await?,
                max_retransmits: self.channel.max_retransmits().await?,
                max_packet_life_time: self.channel.max_packet_life_time().await?,
            })
        })
        .await
        .map_err(|_| TransportError::Timeout)?
        .map_err(classify_backend)
    }
    pub async fn wait_open(&mut self) -> Result<(), TransportError> {
        if self.opened {
            return Ok(());
        }
        tokio::time::timeout(self.timeout, async {
            while let Some(event) = self.channel.poll().await {
                match event {
                    DataChannelEvent::OnOpen => {
                        self.opened = true;
                        return Ok(());
                    }
                    DataChannelEvent::OnMessage(message) => {
                        if message.data.len() > self.max_message_bytes {
                            let _ = self.channel.close().await;
                            return Err(TransportError::MessageTooLarge);
                        }
                        // 固定版本保证 OnOpen 先于 OnMessage；仍保留一个有界消息作为防御。
                        self.pending = Some(message.data.to_vec());
                        self.opened = true;
                        return Ok(());
                    }
                    DataChannelEvent::OnClose | DataChannelEvent::OnError => {
                        return Err(TransportError::Closed);
                    }
                    _ => {}
                }
            }
            Err(TransportError::Closed)
        })
        .await
        .map_err(|_| TransportError::Timeout)?
    }

    pub async fn send(&self, payload: &[u8]) -> Result<(), TransportError> {
        if payload.len() > self.max_message_bytes {
            return Err(TransportError::MessageTooLarge);
        }
        tokio::time::timeout(self.timeout, self.channel.try_send(BytesMut::from(payload)))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(classify_backend)
    }

    /// SCTP 尚未确认的有效载荷字节，用于背压观测；不代表进程总内存。
    pub async fn outstanding_bytes(&self) -> Result<usize, TransportError> {
        tokio::time::timeout(self.timeout, self.channel.outstanding_bytes())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(classify_backend)
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, TransportError> {
        if let Some(message) = self.pending.take() {
            return Ok(message);
        }
        tokio::time::timeout(self.timeout, async {
            while let Some(event) = self.channel.poll().await {
                match event {
                    DataChannelEvent::OnOpen => {
                        self.opened = true;
                    }
                    DataChannelEvent::OnMessage(message) => {
                        if message.data.len() > self.max_message_bytes {
                            let _ = self.channel.close().await;
                            return Err(TransportError::MessageTooLarge);
                        }
                        return Ok(message.data.to_vec());
                    }
                    DataChannelEvent::OnClose | DataChannelEvent::OnError => {
                        return Err(TransportError::Closed);
                    }
                    _ => {}
                }
            }
            Err(TransportError::Closed)
        })
        .await
        .map_err(|_| TransportError::Timeout)?
    }

    pub async fn close(&self) -> Result<(), TransportError> {
        tokio::time::timeout(self.timeout, self.channel.close())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(classify_backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrtc::peer_connection::RTCSdpType;

    #[test]
    fn zero_limits_cannot_enable_upstream_unbounded_send() {
        let invalid = TransportConfig {
            send_buffer_bytes: 0,
            ..TransportConfig::default()
        };
        assert_eq!(
            invalid.validate(),
            Err(TransportError::InvalidConfiguration)
        );
    }

    #[test]
    fn relay_policy_needs_explicit_server_and_direct_rejects_turn() {
        let mut config = TransportConfig {
            policy: ConnectionPolicy::RelayOnly,
            ..TransportConfig::default()
        };
        assert_eq!(config.validate(), Err(TransportError::RelayRequired));
        config.ice_servers.push(RTCIceServer {
            urls: vec!["turns:relay.example.invalid:5349".into()],
            ..Default::default()
        });
        assert_eq!(config.validate(), Ok(()));
        config.policy = ConnectionPolicy::DirectOnly;
        assert_eq!(config.validate(), Err(TransportError::RelayForbidden));
    }

    #[test]
    fn direct_rejects_remote_relay_candidates() {
        let config = TransportConfig {
            policy: ConnectionPolicy::DirectOnly,
            ..TransportConfig::default()
        };
        let mut description = SessionDescription::default();
        description.sdp_type = RTCSdpType::Offer;
        description.sdp = "v=0\r\na=candidate:1 1 udp 1 192.0.2.1 3478 typ relay\r\n".into();
        assert_eq!(
            validate_remote_sdp(&config, &description),
            Err(TransportError::RelayForbidden)
        );
    }

    #[test]
    fn stream_not_misrepresented_as_message_channel() {
        assert!(matches!(
            channel_options(ChannelMode::ReliableStream),
            Err(TransportError::UnsupportedChannel)
        ));
        let reliable = channel_options(ChannelMode::ReliableMessage).unwrap();
        assert!(reliable.ordered);
        assert!(reliable.max_retransmits.is_none());
        let lossy = channel_options(ChannelMode::LowLatencyMessage).unwrap();
        assert!(!lossy.ordered);
        assert_eq!(lossy.max_retransmits, Some(0));
    }

    #[tokio::test]
    #[ignore = "requires local UDP sockets"]
    async fn actual_dcep_metadata_preserves_all_six_wire_types() {
        let config = TransportConfig {
            policy: ConnectionPolicy::DirectOnly,
            include_loopback: true,
            bind_address: "127.0.0.1:0".parse().unwrap(),
            operation_timeout: Duration::from_secs(10),
            ..TransportConfig::default()
        };
        let a = Arc::new(PeerTransport::new(config.clone()).await.unwrap());
        let b = Arc::new(PeerTransport::new(config).await.unwrap());
        let source = a.clone();
        let target = b.clone();
        let mut task = tokio::spawn(async move {
            let mut channels = Vec::new();
            for (index, (ordered, retransmits, lifetime)) in [
                (true, None, None),
                (false, None, None),
                (true, Some(1), None),
                (false, Some(0), None),
                (true, None, Some(u16::MAX)),
                (false, None, Some(7)),
            ]
            .into_iter()
            .enumerate()
            {
                let channel = source
                    .peer
                    .create_data_channel(
                        "wire metadata",
                        Some(RTCDataChannelInit {
                            ordered,
                            max_retransmits: retransmits,
                            max_packet_life_time: lifetime,
                            ..Default::default()
                        }),
                    )
                    .await
                    .unwrap();
                if index == 0 {
                    let answer = target
                        .answer_offer(source.create_offer().await.unwrap())
                        .await
                        .unwrap();
                    source.apply_answer(answer).await.unwrap();
                }
                let received = target
                    .accept_channel()
                    .await
                    .unwrap_or_else(|error| panic!("DCEP type {index}: {error}"));
                let metadata = received.metadata().await.unwrap();
                assert_eq!(
                    (
                        metadata.ordered,
                        metadata.max_retransmits,
                        metadata.max_packet_life_time
                    ),
                    (ordered, retransmits, lifetime),
                    "DCEP type {index} lost metadata"
                );
                if retransmits.is_some() || lifetime.is_some() || !ordered {
                    assert_eq!(
                        incoming_mode(
                            stream::PROTOCOL,
                            metadata.ordered,
                            metadata.max_retransmits,
                            metadata.max_packet_life_time
                        ),
                        Err(TransportError::UnsupportedChannel)
                    );
                }
                let mut channel = source.wrap_channel(channel);
                channel.wait_open().await.unwrap();
                channels.push((channel, received));
            }
            for (channel, _) in channels {
                channel.close().await.unwrap();
            }
        });
        let outcome = tokio::time::timeout(Duration::from_secs(40), &mut task).await;
        if outcome.is_err() {
            task.abort();
            let _ = task.await;
        }
        a.close().await.unwrap();
        b.close().await.unwrap();
        outcome
            .expect("bounded metadata pair")
            .expect("metadata assertions");
    }

    #[test]
    fn typed_incoming_requires_exact_protocol_and_reliability() {
        assert_eq!(
            incoming_mode("", true, None, None),
            Ok(ChannelMode::ReliableMessage)
        );
        assert_eq!(
            incoming_mode("", false, Some(0), None),
            Ok(ChannelMode::LowLatencyMessage)
        );
        assert_eq!(
            incoming_mode(stream::PROTOCOL, true, None, None),
            Ok(ChannelMode::ReliableStream)
        );
        for (protocol, ordered, retransmits, lifetime) in [
            ("unknown", true, None, None),
            (stream::PROTOCOL, false, None, None),
            (stream::PROTOCOL, true, Some(0), None),
            (stream::PROTOCOL, true, None, Some(1)),
            ("", false, None, None),
            ("", true, Some(0), None),
            ("", false, Some(1), None),
            ("", false, Some(0), Some(1)),
        ] {
            assert_eq!(
                incoming_mode(protocol, ordered, retransmits, lifetime),
                Err(TransportError::UnsupportedChannel)
            );
        }
    }

    #[test]
    fn channel_reservations_are_hard_capped() {
        let count = AtomicUsize::new(0);
        assert_eq!(reserve_channel(&count, 1), Ok(()));
        assert_eq!(
            reserve_channel(&count, 1),
            Err(TransportError::TooManyChannels)
        );
        assert_eq!(count.load(Ordering::Acquire), 1);
    }
    #[test]
    fn oversized_sdp_rejected_before_backend_parse() {
        let config = TransportConfig {
            max_sdp_bytes: 8,
            ..TransportConfig::default()
        };
        let mut description = SessionDescription::default();
        description.sdp = "x".repeat(9);
        assert_eq!(
            validate_remote_sdp(&config, &description),
            Err(TransportError::SdpTooLarge)
        );
    }

    #[test]
    fn backend_categories_do_not_expose_secrets() {
        let error = classify_backend(webrtc::error::Error::OtherTurnErr(
            "secret-turn-credential".into(),
        ));
        assert_eq!(error, TransportError::Relay);
        assert!(!error.to_string().contains("secret"));
        assert_eq!(
            classify_backend(webrtc::error::Error::ErrDataChannelNotOpen),
            TransportError::NotReady
        );
    }
    #[test]
    fn noncanonical_relay_candidate_cannot_bypass_direct_policy() {
        let config = TransportConfig {
            policy: ConnectionPolicy::DirectOnly,
            ..TransportConfig::default()
        };
        for candidate in [
            "1 1 udp 1 192.0.2.1 3478 bogus relay",
            "1 1 udp 1 192.0.2.1 3478 typ\u{00a0}relay",
        ] {
            let mut description = SessionDescription::default();
            description.sdp = format!("v=0\r\na=candidate:{candidate}\r\n");
            assert_eq!(
                validate_remote_sdp(&config, &description),
                Err(TransportError::InvalidCandidate)
            );
        }
    }
}
