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
    continuous: Option<(device_clock::ContinuousClock, Duration)>,
}
impl ServerClockBound {
    /// sent_at 由通过 TLS 与 hello correlation 验证的服务器 ack 提供。
    /// t0 在发送 hello 前记录；把整个往返延迟计入提前过期，不信任客户端墙钟。
    pub fn from_hello(sent_at: &str, hello_started: Instant) -> Result<Self, LeaseError> {
        Ok(Self {
            server_at_hello: OffsetDateTime::parse(sent_at, &Rfc3339)
                .map_err(|_| LeaseError::InvalidUpdate)?,
            hello_started,
            continuous: None,
        })
    }
    pub(crate) fn with_continuous(
        mut self,
        clock: device_clock::ContinuousClock,
        started: Option<Duration>,
    ) -> Self {
        self.continuous = started.map(|started| (clock, started));
        self
    }
    pub(crate) fn continuous_deadline(
        &self,
        expires: OffsetDateTime,
    ) -> Result<(device_clock::ContinuousClock, Duration), LeaseError> {
        let (clock, started) = self.continuous.as_ref().ok_or(LeaseError::Expired)?;
        let now = clock.now().map_err(|_| LeaseError::Expired)?;
        let elapsed = now.checked_sub(*started).ok_or(LeaseError::Expired)?;
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
        Ok((
            clock.clone(),
            now.checked_add(remaining)
                .ok_or(LeaseError::InvalidUpdate)?,
        ))
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
#[derive(Clone)]
pub(crate) struct ContinuousGrant {
    pub epoch: u64,
    clock: device_clock::ContinuousClock,
    deadline: Duration,
}
impl ContinuousGrant {
    pub fn is_valid(&self) -> bool {
        self.clock.now().is_ok_and(|now| now < self.deadline)
    }
}
struct PendingRenewal {
    request_id: String,
    generation_at_request: u64,
}
pub struct LeaseGuard {
    session_id: String,
    source: String,
    target: String,
    generation: u64,
    deadline: Option<Instant>,
    active: bool,
    closed: bool,
    pending_renewal: Option<PendingRenewal>,
    latest_snapshot_bound: Option<Instant>,
    exclusive_epoch: Option<u64>,
    continuous: Option<ContinuousGrant>,
    latest_continuous_bound: Option<Duration>,
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
            latest_snapshot_bound: None,
            exclusive_epoch: None,
            continuous: None,
            latest_continuous_bound: None,
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
        self.pending_renewal = Some(PendingRenewal {
            request_id,
            generation_at_request: self.generation,
        });
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
        let exclusive =
            crate::exclusive::ExclusiveSnapshot::parse(envelope)?.map(|value| value.epoch);
        if self.exclusive_epoch.is_some() && self.exclusive_epoch != exclusive {
            return Err(LeaseError::InvalidUpdate);
        }
        self.exclusive_epoch = exclusive;
        if self.expired(received) {
            #[cfg(feature = "test-diagnostics")]
            self.trace_failure(
                "expired-before-update",
                envelope.payload["lease_generation"].as_u64().unwrap_or(0),
                self.matches_renewal(envelope),
                received,
            );
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
        let expiry = expiry.ok_or(LeaseError::InvalidUpdate)?;
        let stale = generation < self.generation;
        let own_renewal = self.matches_renewal(envelope)
            && self
                .pending_renewal
                .as_ref()
                .is_some_and(|pending| generation > pending.generation_at_request)
            && state != "authorizing";
        let (deadline, continuous) = match clock.deadline(expiry, received).and_then(|deadline| {
            let continuous = if exclusive.is_some() {
                Some(clock.continuous_deadline(expiry)?)
            } else {
                None
            };
            Ok((deadline, continuous))
        }) {
            Ok(value) => value,
            Err(LeaseError::Expired) if stale => {
                // A fully parsed older live snapshot can expire while a newer
                // authorized lease remains valid. It grants no new authority.
                if own_renewal {
                    self.pending_renewal = None;
                }
                return Ok(());
            }
            Err(error) => {
                #[cfg(feature = "test-diagnostics")]
                self.trace_failure(
                    "expiry-conversion",
                    generation,
                    self.matches_renewal(envelope),
                    received,
                );
                self.invalidate();
                return Err(error);
            }
        };
        // This upper bound is evidence, not permission: a peer's renewal alone
        // never extends the local authorization deadline. Same-generation replay
        // and a new hello clock can only tighten an existing snapshot bound.
        if !stale {
            self.latest_snapshot_bound = Some(match self.latest_snapshot_bound {
                Some(old) if generation == self.generation => old.min(deadline),
                _ => deadline,
            });
        }
        if let Some((_, bound)) = &continuous
            && !stale
        {
            self.latest_continuous_bound = Some(match self.latest_continuous_bound {
                Some(old) if generation == self.generation => old.min(*bound),
                _ => *bound,
            });
        }
        if stale && !own_renewal {
            return Ok(());
        }
        if let Some((clock, bound)) = continuous {
            let deadline = if own_renewal {
                bound.min(self.latest_continuous_bound.unwrap_or(bound))
            } else {
                self.continuous
                    .as_ref()
                    .map_or(bound, |old| old.deadline.min(bound))
            };
            self.continuous = Some(ContinuousGrant {
                epoch: exclusive.expect("exclusive clock"),
                clock,
                deadline,
            });
        }
        if own_renewal {
            self.deadline = Some(deadline.min(self.latest_snapshot_bound.unwrap_or(deadline)));
            self.pending_renewal = None;
        } else {
            self.deadline = Some(self.deadline.map_or(deadline, |old| old.min(deadline)));
        }
        if !stale {
            self.generation = generation;
            self.active = state != "authorizing";
        }
        Ok(())
    }
    fn matches_renewal(&self, envelope: &Envelope) -> bool {
        envelope.kind == "session.updated"
            && self
                .pending_renewal
                .as_ref()
                .is_some_and(|pending| Some(&pending.request_id) == envelope.request_id.as_ref())
    }
    #[cfg(feature = "test-diagnostics")]
    pub(crate) fn trace_failure(
        &self,
        stage: &'static str,
        incoming: u64,
        own_ack: bool,
        received: Instant,
    ) {
        if std::env::var_os("PEERLOOM_TEST_LEASE_DIAGNOSTICS").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        let remaining_ms = self
            .deadline
            .and_then(|deadline| deadline.checked_duration_since(received))
            .map_or(0, |value| value.as_millis());
        eprintln!(
            "PeerloomTestDiag lease stage={stage} current={} incoming={incoming} own_ack={own_ack} pending={} remaining_ms={remaining_ms}",
            self.generation,
            self.pending_renewal.is_some()
        );
    }
    pub fn invalidate(&mut self) {
        self.closed = true;
        self.active = false;
        self.pending_renewal = None;
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub(crate) fn bind_exclusive_epoch(&mut self, epoch: Option<u64>) -> Result<(), LeaseError> {
        if self.exclusive_epoch.is_some() && self.exclusive_epoch != epoch {
            return Err(LeaseError::InvalidUpdate);
        }
        self.exclusive_epoch = epoch;
        Ok(())
    }
    pub(crate) fn target_epoch(&self) -> Option<u64> {
        self.exclusive_epoch
    }
    pub(crate) fn continuous_grant(&self) -> Option<ContinuousGrant> {
        self.continuous.clone()
    }
    pub(crate) fn expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
            || self
                .continuous
                .as_ref()
                .is_some_and(|grant| !grant.is_valid())
    }
    pub fn is_authorized(&self, now: Instant) -> bool {
        !self.closed && self.active && !self.expired(now) && self.deadline.is_some()
    }
}

#[cfg(test)]
mod exclusive_tests {
    use super::*;
    fn guard(message: &Envelope) -> LeaseGuard {
        LeaseGuard::new(
            message.payload["session_id"].as_str().unwrap().into(),
            message.payload["source_device_id"].as_str().unwrap().into(),
            message.payload["target_device_id"].as_str().unwrap().into(),
        )
        .unwrap()
    }
    #[test]
    fn exclusive_late_own_ack_is_bounded_by_latest_continuous_authority() {
        let mut message = crate::exclusive::tests::message();
        message.payload["prepared"] = serde_json::json!(false);
        message.payload["state"] = serde_json::json!("connecting");
        let now = Instant::now();
        let system = device_clock::ContinuousClock::default();
        let started = system.now().unwrap();
        let clock = ServerClockBound::from_hello(&message.sent_at, now)
            .unwrap()
            .with_continuous(system, Some(started));
        let mut guard = guard(&message);
        guard.apply(&message, &clock, now).unwrap();
        let request = uuid::Uuid::new_v4().to_string();
        guard.renewal_requested(request.clone()).unwrap();
        let mut newer = message.clone();
        newer.kind = "session.updated".into();
        newer.payload["lease_generation"] = serde_json::json!(3);
        for key in [
            "lease_expires_at",
            "source_lease_expires_at",
            "target_lease_expires_at",
        ] {
            newer.payload[key] = serde_json::json!("2026-10-29T12:00:20Z");
        }
        guard.apply(&newer, &clock, now).unwrap();
        let bound = guard.latest_continuous_bound.unwrap();
        let mut own = message.clone();
        own.kind = "session.updated".into();
        own.request_id = Some(request);
        own.payload["lease_generation"] = serde_json::json!(2);
        for key in [
            "lease_expires_at",
            "source_lease_expires_at",
            "target_lease_expires_at",
        ] {
            own.payload[key] = serde_json::json!("2026-10-29T12:00:50Z");
        }
        guard.apply(&own, &clock, now).unwrap();
        assert_eq!(guard.generation, 3);
        assert!(guard.continuous.as_ref().unwrap().deadline <= bound);
        let deadline = guard.continuous.as_ref().unwrap().deadline;
        guard.apply(&own, &clock, now).unwrap();
        assert_eq!(guard.continuous.as_ref().unwrap().deadline, deadline);
    }
    #[test]
    fn exclusive_requires_continuous_clock_and_stable_epoch() {
        let message = crate::exclusive::tests::message();
        let now = Instant::now();
        let clock = ServerClockBound::from_hello(&message.sent_at, now).unwrap();
        assert_eq!(
            guard(&message).apply(&message, &clock, now),
            Err(LeaseError::Expired)
        );
        let system = device_clock::ContinuousClock::default();
        let started = system.now().unwrap();
        let clock = clock.with_continuous(system, Some(started));
        let mut guard = guard(&message);
        guard.apply(&message, &clock, now).unwrap();
        assert_eq!(guard.target_epoch(), Some(i64::MAX as u64));
        let mut changed = message.clone();
        changed.target_epoch = Some("1".into());
        changed.payload["target_epoch"] = serde_json::json!("1");
        assert_eq!(
            guard.apply(&changed, &clock, now),
            Err(LeaseError::InvalidUpdate)
        );
    }
    #[test]
    fn continuous_expiry_blocks_renewal_even_when_instant_has_not_advanced() {
        let mut message = crate::exclusive::tests::message();
        message.payload["prepared"] = serde_json::json!(false);
        message.payload["state"] = serde_json::json!("connecting");
        let now = Instant::now();
        let system = device_clock::ContinuousClock::default();
        let started = system.now().unwrap();
        let clock = ServerClockBound::from_hello(&message.sent_at, now)
            .unwrap()
            .with_continuous(system.clone(), Some(started));
        let mut guard = guard(&message);
        guard.apply(&message, &clock, now).unwrap();
        assert!(guard.is_authorized(now));
        // Model resume after the signed continuous deadline while the wake-up
        // scheduler's Instant remains unchanged. No wall time participates.
        guard.continuous.as_mut().unwrap().deadline = system.now().unwrap();
        assert!(guard.deadline().unwrap() > now);
        assert!(!guard.is_authorized(now));
        assert_eq!(guard.apply(&message, &clock, now), Err(LeaseError::Expired));
        guard.continuous.as_mut().unwrap().deadline += Duration::from_secs(60);
        assert!(!guard.is_authorized(now), "expired guard cannot revive");
    }
}
