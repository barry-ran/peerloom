//! 增量候选传输：候选收集与 SDP 交换解耦，不取消慢接口或缩短 ICE 重试。
use super::*;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex as SyncMutex;
use tokio::sync::Notify;

const MAX_CANDIDATES: usize = 256;
const MAX_BYTES: usize = 256 * 1024;
const MAX_CANDIDATE_BYTES: usize = 4096;

/// 不实现 Debug，防止候选地址和 ICE 认证片段进入日志。
#[derive(Clone, PartialEq, Eq)]
pub struct IceCandidate {
    pub candidate: String,
    pub sdp_mid: String,
    pub sdp_mline_index: u16,
    pub username_fragment: String,
}

pub enum LocalIceEvent {
    Candidate(IceCandidate),
    Complete,
}

#[derive(Clone)]
pub(super) struct IceContext {
    mid: String,
    index: u16,
    ufrag: String,
}

fn token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|b| (33..=126).contains(&b))
}

// Peerloom 只承载 DataChannel，当前一个 BUNDLE application m-section。
// 明确拒绝不受支持的多媒体上下文，不将底层空 mid 当作真实值。
fn context(description: &SessionDescription) -> Result<IceContext, TransportError> {
    let mut session_ufrag = None;
    let mut media_ufrag = None;
    let mut mid = None;
    let mut media = false;
    for line in description.sdp.lines() {
        if let Some(value) = line.strip_prefix("m=") {
            if media || !value.starts_with("application ") {
                return Err(TransportError::Negotiation);
            }
            media = true;
        } else if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
            let slot = if media {
                &mut media_ufrag
            } else {
                &mut session_ufrag
            };
            if !token(value) || slot.replace(value.to_owned()).is_some() {
                return Err(TransportError::Negotiation);
            }
        } else if let Some(value) = line.strip_prefix("a=mid:")
            && (!media || !token(value) || mid.replace(value.to_owned()).is_some())
        {
            return Err(TransportError::Negotiation);
        }
    }
    Ok(IceContext {
        mid: mid.ok_or(TransportError::Negotiation)?,
        index: 0,
        ufrag: media_ufrag
            .or(session_ufrag)
            .ok_or(TransportError::Negotiation)?,
    })
}

// 新信令路径的候选只能进入有界增量入口，不能混用完整 SDP 绕过累计预算。
fn validate_initial_sdp(description: &SessionDescription) -> Result<(), TransportError> {
    for line in description.sdp.lines() {
        if let Some(attribute) = line.trim().strip_prefix("a=") {
            let name = attribute.split(':').next().unwrap_or("").trim();
            if matches!(name, "candidate" | "end-of-candidates") {
                return Err(TransportError::InvalidCandidate);
            }
        }
    }
    Ok(())
}

fn initial_sdp(
    description: &SessionDescription,
    offer: bool,
) -> Result<SessionDescription, TransportError> {
    let mut lines = Vec::new();
    let mut options = false;
    for line in description.sdp.lines() {
        if line.starts_with("a=candidate:") || line == "a=end-of-candidates" {
            continue;
        }
        if let Some(value) = line.strip_prefix("a=ice-options:") {
            options = true;
            let mut value = value.to_owned();
            if !value.split_ascii_whitespace().any(|v| v == "trickle") {
                value.push_str(" trickle");
            }
            lines.push(format!("a=ice-options:{value}"));
        } else {
            lines.push(line.to_owned());
        }
    }
    if !options {
        let at = lines
            .iter()
            .position(|line| line.starts_with("m="))
            .ok_or(TransportError::Negotiation)?;
        lines.insert(at, "a=ice-options:trickle".into());
    }
    let sdp = lines.join("\r\n") + "\r\n";
    if offer {
        SessionDescription::offer(sdp)
    } else {
        SessionDescription::answer(sdp)
    }
    .map_err(classify_backend)
}

#[derive(Default)]
struct Pending {
    candidates: VecDeque<String>,
    count: usize,
    bytes: usize,
    complete: bool,
    delivered_complete: bool,
    failed: bool,
}

#[derive(Default)]
pub(super) struct LocalIce {
    pending: SyncMutex<Pending>,
    changed: Notify,
}

impl LocalIce {
    pub(super) fn candidate(&self, candidate: Result<String, TransportError>) {
        if let Ok(mut pending) = self.pending.lock() {
            match candidate {
                Ok(candidate)
                    if !pending.complete
                        && !pending.failed
                        && candidate.len() <= MAX_CANDIDATE_BYTES
                        && pending.count < MAX_CANDIDATES
                        && pending.bytes.saturating_add(candidate.len() + 512) <= MAX_BYTES =>
                {
                    pending.count += 1;
                    // 预留 mid/ufrag 各 256 字节，不能仅约束队列原始字符串。
                    pending.bytes += candidate.len() + 512;
                    pending.candidates.push_back(candidate);
                }
                _ => pending.failed = true,
            }
        }
        self.changed.notify_one();
    }

    pub(super) fn complete(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.complete = true;
        }
        self.changed.notify_one();
    }
}

#[derive(Default)]
pub(super) struct RemoteIce {
    context: Option<IceContext>,
    count: usize,
    bytes: usize,
    seen: HashSet<String>,
    complete: bool,
}

fn validate(
    candidate: &IceCandidate,
    expected: &IceContext,
    policy: ConnectionPolicy,
) -> Result<(), TransportError> {
    if candidate.sdp_mid != expected.mid
        || candidate.sdp_mline_index != expected.index
        || candidate.username_fragment != expected.ufrag
        || candidate.candidate.is_empty()
        || candidate.candidate.len() > MAX_CANDIDATE_BYTES
    {
        return Err(TransportError::InvalidCandidate);
    }
    let value = candidate
        .candidate
        .strip_prefix("candidate:")
        .unwrap_or(&candidate.candidate);
    let fields: Vec<_> = value.split_ascii_whitespace().collect();
    if !value.bytes().all(|b| (32..=126).contains(&b)) || fields.len() < 8 || fields[6] != "typ" {
        return Err(TransportError::InvalidCandidate);
    }
    let parsed = rtc::ice::candidate::unmarshal_candidate(value)
        .map_err(|_| TransportError::InvalidCandidate)?;
    if policy == ConnectionPolicy::DirectOnly
        && parsed.candidate_type() == rtc::ice::candidate::CandidateType::Relay
    {
        return Err(TransportError::RelayForbidden);
    }
    Ok(())
}

impl PeerTransport {
    async fn initial_description(&self, offer: bool) -> Result<SessionDescription, TransportError> {
        let description =
            tokio::time::timeout(self.config.operation_timeout, self.peer.local_description())
                .await
                .map_err(|_| TransportError::Timeout)?
                .ok_or(TransportError::Negotiation)?;
        if description.sdp.len() > self.config.max_sdp_bytes {
            return Err(TransportError::SdpTooLarge);
        }
        let context = context(&description)?;
        let wire = initial_sdp(&description, offer)?;
        *self.local_ice_context.lock().await = Some(context);
        Ok(wire)
    }

    /// SDP 包含本代凭据和 DTLS 指纹，但不等待所有网络接口收集完成。
    pub async fn create_offer_trickle(&self) -> Result<SessionDescription, TransportError> {
        self.ensure_open()?;
        self.negotiation
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| TransportError::NegotiationAlreadyStarted)?;
        let offer = self.bounded(self.peer.create_offer(None)).await?;
        self.bounded(self.peer.set_local_description(offer)).await?;
        let description = self.initial_description(true).await?;
        self.negotiation.store(2, Ordering::Release);
        Ok(description)
    }

    pub async fn answer_offer_trickle(
        &self,
        offer: SessionDescription,
    ) -> Result<SessionDescription, TransportError> {
        self.ensure_open()?;
        validate_remote_sdp(&self.config, &offer)?;
        validate_initial_sdp(&offer)?;
        let remote_context = context(&offer)?;
        self.negotiation
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| TransportError::NegotiationAlreadyStarted)?;
        self.bounded(self.peer.set_remote_description(offer))
            .await?;
        self.remote_ice.lock().await.context = Some(remote_context);
        let answer = self.bounded(self.peer.create_answer(None)).await?;
        self.bounded(self.peer.set_local_description(answer))
            .await?;
        self.initial_description(false).await
    }

    pub async fn apply_answer_trickle(
        &self,
        answer: SessionDescription,
    ) -> Result<(), TransportError> {
        self.ensure_open()?;
        validate_remote_sdp(&self.config, &answer)?;
        validate_initial_sdp(&answer)?;
        let remote_context = context(&answer)?;
        self.negotiation
            .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| TransportError::NegotiationAlreadyStarted)?;
        self.bounded(self.peer.set_remote_description(answer))
            .await?;
        self.remote_ice.lock().await.context = Some(remote_context);
        Ok(())
    }

    /// 单个有序信令发送者消费；必须先发送 initial SDP。结束标记只返回一次。
    /// 关闭和候选溢出可中断等待；取消本次 future 不会丢失尚未返回的候选。
    pub async fn next_local_ice(&self) -> Result<LocalIceEvent, TransportError> {
        let context = self
            .local_ice_context
            .lock()
            .await
            .clone()
            .ok_or(TransportError::Negotiation)?;
        let mut closed = self.close_signal.subscribe();
        loop {
            self.ensure_open()?;
            let notified = self.local_ice.changed.notified();
            {
                let mut pending = self
                    .local_ice
                    .pending
                    .lock()
                    .map_err(|_| TransportError::WebRtc)?;
                if pending.failed {
                    return Err(TransportError::InvalidCandidate);
                }
                if let Some(candidate) = pending.candidates.pop_front() {
                    return Ok(LocalIceEvent::Candidate(IceCandidate {
                        candidate,
                        sdp_mid: context.mid.clone(),
                        sdp_mline_index: context.index,
                        username_fragment: context.ufrag.clone(),
                    }));
                }
                if pending.complete && !pending.delivered_complete {
                    pending.delivered_complete = true;
                    self.gathering_outcome.store(1, Ordering::Release);
                    return Ok(LocalIceEvent::Complete);
                }
            }
            tokio::select! {
                _ = notified => {},
                _ = closed.changed() => return Err(TransportError::Closed),
            }
        }
    }

    /// core 负责会话授权/代次及 pre-SDP 有界暂存；本层验证真实远端 SDP 上下文。
    /// 取消应用 future 后，调用方必须关闭本代连接，不能在同一连接重放此批候选。
    pub async fn add_remote_ice(
        &self,
        candidates: &[IceCandidate],
        complete: bool,
    ) -> Result<(), TransportError> {
        self.ensure_open()?;
        if candidates.len() > 16 || (candidates.is_empty() && !complete) {
            return Err(TransportError::InvalidCandidate);
        }
        let mut state = self.remote_ice.lock().await;
        let expected = state.context.clone().ok_or(TransportError::Negotiation)?;
        if state.complete && !candidates.is_empty() {
            return Err(TransportError::InvalidCandidate);
        }
        let bytes: usize = candidates
            .iter()
            .map(|c| c.candidate.len() + c.sdp_mid.len() + c.username_fragment.len())
            .sum();
        if state.count.saturating_add(candidates.len()) > MAX_CANDIDATES
            || state.bytes.saturating_add(bytes) > MAX_BYTES
        {
            return Err(TransportError::InvalidCandidate);
        }
        for candidate in candidates {
            validate(candidate, &expected, self.config.policy)?;
        }
        // 整批校验后再应用；重复也计入接收预算，不能用重放绕过资源上限。
        state.count += candidates.len();
        state.bytes += bytes;
        for candidate in candidates {
            if !state.seen.insert(candidate.candidate.clone()) {
                continue;
            }
            self.bounded(self.peer.add_ice_candidate(RTCIceCandidateInit {
                candidate: candidate.candidate.clone(),
                sdp_mid: Some(candidate.sdp_mid.clone()),
                sdp_mline_index: Some(candidate.sdp_mline_index),
                username_fragment: Some(candidate.username_fragment.clone()),
                url: None,
            }))
            .await?;
        }
        if complete {
            // rtc 0.21.1 的空 remote candidate 是 no-op，并无远端 EOC 状态入口。
            // 本层保持完整性/后续拒绝规则；不得将本地 gather 标记提前完成。
            state.complete = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn description() -> SessionDescription {
        SessionDescription::offer(
            concat!(
                "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
                "a=ice-ufrag:session123\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
                "c=IN IP4 0.0.0.0\r\na=mid:data\r\na=ice-ufrag:media123\r\n",
                "a=ice-pwd:synthetic-test-password\r\na=sctp-port:5000\r\n",
                "a=candidate:1 1 udp 2130706431 127.0.0.1 1234 typ host\r\na=end-of-candidates\r\n"
            )
            .into(),
        )
        .unwrap()
    }
    fn candidate() -> IceCandidate {
        IceCandidate {
            candidate: "candidate:1 1 udp 2130706431 127.0.0.1 1234 typ host".into(),
            sdp_mid: "data".into(),
            sdp_mline_index: 0,
            username_fragment: "media123".into(),
        }
    }
    #[test]
    fn initial_sdp_rejects_inline_candidates_and_completion() {
        let clean = initial_sdp(&description(), true).unwrap();
        assert_eq!(validate_initial_sdp(&clean), Ok(()));
        for attribute in [
            "a=candidate:1 1 udp 2130706431 127.0.0.1 1234 typ host",
            "a=end-of-candidates",
            "a=end-of-candidates:unexpected",
            "a=candidate",
        ] {
            let mut mixed = clean.clone();
            mixed.sdp.push_str(attribute);
            mixed.sdp.push_str("\r\n");
            assert_eq!(
                validate_initial_sdp(&mixed),
                Err(TransportError::InvalidCandidate)
            );
        }
    }

    #[test]
    fn uses_actual_mid_and_media_ufrag() {
        let value = context(&description()).unwrap();
        assert_eq!(value.mid, "data");
        assert_eq!(value.ufrag, "media123");
        let mut session = description();
        session.sdp = session.sdp.replace("a=ice-ufrag:media123\r\n", "");
        assert_eq!(context(&session).unwrap().ufrag, "session123");
    }
    #[test]
    fn initial_sdp_strips_candidates_but_keeps_credentials() {
        let value = initial_sdp(&description(), true).unwrap();
        assert!(!value.sdp.contains("a=candidate:"));
        assert!(!value.sdp.contains("a=end-of-candidates"));
        assert!(value.sdp.contains("a=ice-options:trickle"));
        assert!(value.sdp.contains("a=ice-pwd:synthetic-test-password"));
        assert_eq!(context(&value).unwrap().ufrag, "media123");
    }
    #[test]
    fn rejects_wrong_mid_index_ufrag_and_injection() {
        let ctx = context(&description()).unwrap();
        assert_eq!(validate(&candidate(), &ctx, ConnectionPolicy::Auto), Ok(()));
        for field in 0..4 {
            let mut value = candidate();
            match field {
                0 => value.sdp_mid = "other".into(),
                1 => value.sdp_mline_index = 1,
                2 => value.username_fragment = "old-generation".into(),
                _ => value.candidate.push_str("\r\na=ice-pwd:inject"),
            }
            assert_eq!(
                validate(&value, &ctx, ConnectionPolicy::Auto),
                Err(TransportError::InvalidCandidate)
            );
        }
    }
    #[test]
    fn rejects_ambiguous_context() {
        let mut value = description();
        value
            .sdp
            .push_str("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:other\r\n");
        assert!(context(&value).is_err());
        let mut value = description();
        value.sdp.push_str("a=mid:duplicate\r\n");
        assert!(context(&value).is_err());
    }
    #[test]
    fn local_overflow_and_after_completion_are_visible_errors() {
        let queue = LocalIce::default();
        for _ in 0..MAX_CANDIDATES {
            queue.candidate(Ok("small".into()));
        }
        assert!(!queue.pending.lock().unwrap().failed);
        queue.candidate(Ok("overflow".into()));
        assert!(queue.pending.lock().unwrap().failed);
        let queue = LocalIce::default();
        queue.complete();
        queue.candidate(Ok("late".into()));
        assert!(queue.pending.lock().unwrap().failed);
    }
    #[test]
    fn complete_preserves_all_queued_candidates_and_is_idempotent() {
        let queue = LocalIce::default();
        queue.candidate(Ok("first".into()));
        queue.candidate(Ok("second".into()));
        queue.complete();
        queue.complete();
        let mut value = queue.pending.lock().unwrap();
        assert_eq!(value.candidates.pop_front().as_deref(), Some("first"));
        assert_eq!(value.candidates.pop_front().as_deref(), Some("second"));
        assert!(value.complete);
        assert!(!value.failed);
    }
    #[test]
    fn direct_only_rejects_relay_candidates() {
        let mut value = candidate();
        value.candidate = value.candidate.replace("typ host", "typ relay");
        assert_eq!(
            validate(
                &value,
                &context(&description()).unwrap(),
                ConnectionPolicy::DirectOnly
            ),
            Err(TransportError::RelayForbidden)
        );
    }
}
