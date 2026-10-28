//! 会话授权的单调截止策略。调用方必须在 deadline/terminated 时关闭传输；
//! 这个纯策略对象自身不拥有 socket，也不宣称已实现完整 SDK 会话编排。
use crate::signaling::Envelope;
use std::time::{Duration, Instant};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
const CAP: Duration = Duration::from_secs(60);
const MARGIN: Duration = Duration::from_secs(1);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseError {
    InvalidUpdate,
    Expired,
    Closed,
}
#[derive(Clone)]
pub struct ServerClockBound {
    server_at_hello: OffsetDateTime,
    hello_started: Instant,
}
impl ServerClockBound {
    /// sent_at 由通过 TLS 与 hello correlation 验证的服务器 ack 提供。
    /// t0 在发送 hello 前记录；把整个往返延迟计入提前过期，不信任客户端墙钟。
    pub fn from_hello(sent_at: &str, hello_started: Instant) -> Result<Self, LeaseError> {
        Ok(Self {
            server_at_hello: OffsetDateTime::parse(sent_at, &Rfc3339)
                .map_err(|_| LeaseError::InvalidUpdate)?,
            hello_started,
        })
    }
    pub(crate) fn remaining_until(
        &self,
        expires: &str,
        received: Instant,
    ) -> Result<Duration, LeaseError> {
        let expires =
            OffsetDateTime::parse(expires, &Rfc3339).map_err(|_| LeaseError::InvalidUpdate)?;
        let elapsed = received
            .checked_duration_since(self.hello_started)
            .ok_or(LeaseError::InvalidUpdate)?;
        let upper = self
            .server_at_hello
            .checked_add(time::Duration::try_from(elapsed).map_err(|_| LeaseError::InvalidUpdate)?)
            .ok_or(LeaseError::InvalidUpdate)?;
        Duration::try_from(expires - upper).map_err(|_| LeaseError::Expired)
    }
    fn deadline(&self, expires: OffsetDateTime, received: Instant) -> Result<Instant, LeaseError> {
        let elapsed = received
            .checked_duration_since(self.hello_started)
            .ok_or(LeaseError::InvalidUpdate)?;
        let upper = self
            .server_at_hello
            .checked_add(time::Duration::try_from(elapsed).map_err(|_| LeaseError::InvalidUpdate)?)
            .ok_or(LeaseError::InvalidUpdate)?;
        let remaining = Duration::try_from(expires - upper)
            .map_err(|_| LeaseError::Expired)?
            .checked_sub(MARGIN)
            .ok_or(LeaseError::Expired)?
            .min(CAP);
        if remaining.is_zero() {
            return Err(LeaseError::Expired);
        }
        received
            .checked_add(remaining)
            .ok_or(LeaseError::InvalidUpdate)
    }
}
pub struct LeaseGuard {
    session_id: String,
    source: String,
    target: String,
    generation: u64,
    deadline: Option<Instant>,
    active: bool,
    closed: bool,
    pending_renewal: Option<String>,
}
impl LeaseGuard {
    pub fn new(session_id: String, source: String, target: String) -> Result<Self, LeaseError> {
        if [&session_id, &source, &target]
            .iter()
            .any(|id| uuid::Uuid::parse_str(id).is_err())
            || source == target
        {
            return Err(LeaseError::InvalidUpdate);
        }
        let session_id = uuid::Uuid::parse_str(&session_id)
            .map_err(|_| LeaseError::InvalidUpdate)?
            .to_string();
        let source = uuid::Uuid::parse_str(&source)
            .map_err(|_| LeaseError::InvalidUpdate)?
            .to_string();
        let target = uuid::Uuid::parse_str(&target)
            .map_err(|_| LeaseError::InvalidUpdate)?
            .to_string();
        if source == target {
            return Err(LeaseError::InvalidUpdate);
        }
        Ok(Self {
            session_id,
            source,
            target,
            generation: 0,
            deadline: None,
            active: false,
            closed: false,
            pending_renewal: None,
        })
    }
    /// 只标记已经由信令客户端提交的 session.renew 请求 UUID；发送本身不能延长期限。
    pub fn renewal_requested(&mut self, request_id: String) -> Result<(), LeaseError> {
        if self.closed {
            return Err(LeaseError::Closed);
        }
        if uuid::Uuid::parse_str(&request_id).is_err() {
            return Err(LeaseError::InvalidUpdate);
        }
        self.pending_renewal = Some(request_id);
        Ok(())
    }
    pub fn apply(
        &mut self,
        envelope: &Envelope,
        clock: &ServerClockBound,
        received: Instant,
    ) -> Result<(), LeaseError> {
        if self.closed {
            return Err(LeaseError::Closed);
        }
        if envelope.session_id.as_deref() != Some(&self.session_id)
            || !matches!(
                envelope.kind.as_str(),
                "session.pending" | "session.updated" | "session.terminated" | "sync.snapshot"
            )
        {
            return Err(LeaseError::InvalidUpdate);
        }
        if self.deadline.is_some_and(|d| received >= d) {
            self.invalidate();
            return Err(LeaseError::Expired);
        }
        let payload = &envelope.payload;
        if payload["session_id"].as_str() != Some(&self.session_id)
            || payload["source_device_id"].as_str() != Some(&self.source)
            || payload["target_device_id"].as_str() != Some(&self.target)
        {
            return Err(LeaseError::InvalidUpdate);
        }
        let state = payload["state"].as_str().ok_or(LeaseError::InvalidUpdate)?;
        if state == "closed" || envelope.kind == "session.terminated" {
            self.invalidate();
            return Ok(());
        }
        if !matches!(
            state,
            "authorizing" | "connecting" | "connected" | "reconnecting"
        ) {
            self.invalidate();
            return Err(LeaseError::InvalidUpdate);
        }
        let generation = payload["lease_generation"]
            .as_u64()
            .filter(|g| *g > 0)
            .ok_or(LeaseError::InvalidUpdate)?;
        if generation < self.generation {
            return Err(LeaseError::InvalidUpdate);
        }
        let mut expiry = None;
        for field in [
            "lease_expires_at",
            "source_lease_expires_at",
            "target_lease_expires_at",
        ] {
            let value = OffsetDateTime::parse(
                payload[field].as_str().ok_or(LeaseError::InvalidUpdate)?,
                &Rfc3339,
            )
            .map_err(|_| LeaseError::InvalidUpdate)?;
            expiry = Some(expiry.map_or(value, |old: OffsetDateTime| old.min(value)));
        }
        let deadline = match clock.deadline(expiry.ok_or(LeaseError::InvalidUpdate)?, received) {
            Ok(value) => value,
            Err(error) => {
                self.invalidate();
                return Err(error);
            }
        };
        let own_renewal = self.pending_renewal.is_some()
            && self.pending_renewal == envelope.request_id
            && envelope.kind == "session.updated";
        self.deadline = Some(match self.deadline {
            None => deadline,
            Some(_) if generation > self.generation && own_renewal => deadline,
            Some(old) => old.min(deadline),
        });
        if own_renewal {
            self.pending_renewal = None;
        }
        self.generation = generation;
        self.active = state != "authorizing";
        Ok(())
    }
    pub fn invalidate(&mut self) {
        self.closed = true;
        self.active = false;
        self.pending_renewal = None;
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub fn is_authorized(&self, now: Instant) -> bool {
        !self.closed && self.active && self.deadline.is_some_and(|deadline| now < deadline)
    }
}
