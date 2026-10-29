//! 会话授权的单调截止策略。调用方必须在 deadline/terminated 时关闭传输；
//! 这个纯策略对象自身不拥有 socket，也不宣称已实现完整 SDK 会话编排。
use crate::{continuous_clock::ContinuousClock, signaling::Envelope};
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
/// Capture before writing hello. Unlike `Instant`, this anchor includes system sleep.
#[derive(Clone)]
pub struct HelloClockStart {
    clock: ContinuousClock,
    continuous: Duration,
    instant: Instant,
}
impl HelloClockStart {
    pub fn capture() -> Result<Self, LeaseError> {
        Self::with_clock(ContinuousClock::new())
    }
    fn with_clock(clock: ContinuousClock) -> Result<Self, LeaseError> {
        let continuous = clock.now().map_err(|_| LeaseError::Expired)?;
        Ok(Self {
            clock,
            continuous,
            instant: Instant::now(),
        })
    }
}

#[derive(Clone)]
pub(crate) struct ContinuousGrant {
    clock: ContinuousClock,
    expires: Duration,
}
impl ContinuousGrant {
    #[cfg(test)]
    pub(crate) fn for_test(clock: ContinuousClock, expires: Duration) -> Self {
        Self { clock, expires }
    }
    pub(crate) fn is_valid(&self) -> bool {
        self.clock.now().is_ok_and(|now| now < self.expires)
    }
}

#[derive(Clone)]
pub struct ServerClockBound {
    server_at_hello: OffsetDateTime,
    hello_started: Instant,
    continuous: Option<HelloClockStart>,
}
impl ServerClockBound {
    /// 兼容旧版纯 `Instant` 策略：不能保证系统休眠期间授权到期。
    /// 完整 SDK 使用 `from_hello_started`。低层调用方应在发送 hello 前
    /// 捕获 `HelloClockStart`，迁移到连续时钟入口。
    /// sent_at 由通过 TLS 与 hello correlation 验证的服务器 ack 提供。
    /// t0 在发送 hello 前记录；把整个往返延迟计入提前过期，不信任客户端墙钟。
    #[deprecated(
        note = "use HelloClockStart::capture before hello and from_hello_started for suspend-safe authorization"
    )]
    pub fn from_hello(sent_at: &str, hello_started: Instant) -> Result<Self, LeaseError> {
        Ok(Self {
            server_at_hello: OffsetDateTime::parse(sent_at, &Rfc3339)
                .map_err(|_| LeaseError::InvalidUpdate)?,
            hello_started,
            continuous: None,
        })
    }
    /// The caller must authenticate/correlate the hello ack before using its sent_at.
    pub fn from_hello_started(sent_at: &str, started: HelloClockStart) -> Result<Self, LeaseError> {
        started.clock.now().map_err(|_| LeaseError::Expired)?;
        Ok(Self {
            server_at_hello: OffsetDateTime::parse(sent_at, &Rfc3339)
                .map_err(|_| LeaseError::InvalidUpdate)?,
            hello_started: started.instant,
            continuous: Some(started),
        })
    }
    fn elapsed(&self, received: Instant) -> Result<Duration, LeaseError> {
        let scheduling = received
            .checked_duration_since(self.hello_started)
            .ok_or(LeaseError::InvalidUpdate)?;
        match &self.continuous {
            Some(started) => {
                let now = started.clock.now().map_err(|_| LeaseError::Expired)?;
                let elapsed = now
                    .checked_sub(started.continuous)
                    .ok_or(LeaseError::Expired)?;
                // Keep supplied Instant bounds conservative for low-level callers/tests.
                Ok(elapsed.max(scheduling))
            }
            None => Ok(scheduling),
        }
    }
    fn continuous_deadline(
        &self,
        expires: OffsetDateTime,
        received: Instant,
        continuous_received: Option<Duration>,
    ) -> Result<Option<ContinuousGrant>, LeaseError> {
        let Some(started) = &self.continuous else {
            return Ok(None);
        };
        let now = started.clock.now().map_err(|_| LeaseError::Expired)?;
        let elapsed = now
            .checked_sub(started.continuous)
            .ok_or(LeaseError::Expired)?
            .max(
                received
                    .checked_duration_since(self.hello_started)
                    .ok_or(LeaseError::InvalidUpdate)?,
            );
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
        let receive_cap = continuous_received
            .ok_or(LeaseError::InvalidUpdate)?
            .checked_add(CAP)
            .ok_or(LeaseError::InvalidUpdate)?;
        let expires = now
            .checked_add(remaining)
            .ok_or(LeaseError::InvalidUpdate)?
            .min(receive_cap);
        if now >= expires {
            return Err(LeaseError::Expired);
        }
        Ok(Some(ContinuousGrant {
            clock: started.clock.clone(),
            expires,
        }))
    }
    pub(crate) fn remaining_until(
        &self,
        expires: &str,
        received: Instant,
    ) -> Result<Duration, LeaseError> {
        let expires =
            OffsetDateTime::parse(expires, &Rfc3339).map_err(|_| LeaseError::InvalidUpdate)?;
        let elapsed = self.elapsed(received)?;
        let upper = self
            .server_at_hello
            .checked_add(time::Duration::try_from(elapsed).map_err(|_| LeaseError::InvalidUpdate)?)
            .ok_or(LeaseError::InvalidUpdate)?;
        Duration::try_from(expires - upper).map_err(|_| LeaseError::Expired)
    }
    fn deadline(&self, expires: OffsetDateTime, received: Instant) -> Result<Instant, LeaseError> {
        let elapsed = self.elapsed(received)?;
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
        // 本次快照的连续接收锚点只捕获一次；计算期间休眠不能重置 60 秒上限。
        let continuous_received = match clock
            .continuous
            .as_ref()
            .map(|started| started.clock.now())
            .transpose()
        {
            Ok(value) => value,
            Err(_) => {
                self.invalidate();
                return Err(LeaseError::Expired);
            }
        };
        if envelope.session_id.as_deref() != Some(&self.session_id)
            || !matches!(
                envelope.kind.as_str(),
                "session.pending" | "session.updated" | "session.terminated" | "sync.snapshot"
            )
        {
            return Err(LeaseError::InvalidUpdate);
        }
        if self.is_expired(received) {
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
        let stale = generation < self.generation;
        let own_renewal = self.matches_renewal(envelope)
            && self
                .pending_renewal
                .as_ref()
                .is_some_and(|pending| generation > pending.generation_at_request)
            && state != "authorizing";
        let expiry = expiry.ok_or(LeaseError::InvalidUpdate)?;
        let deadline = match clock.deadline(expiry, received) {
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
        let continuous = match clock.continuous_deadline(expiry, received, continuous_received) {
            Ok(value) => value,
            Err(error) => {
                self.invalidate();
                return Err(error);
            }
        };
        // 计算新截止时也可能发生休眠；首次授权也必须在提交前仍有效。
        // 最后确认旧授权，不能让在计算期间过期的旧 grant 被续约复活。
        if continuous.as_ref().is_some_and(|grant| !grant.is_valid()) || self.is_expired(received) {
            self.invalidate();
            return Err(LeaseError::Expired);
        }
        // A legacy clock must never replace a previously continuous authorization.
        if self.continuous.is_some() && continuous.is_none() {
            self.invalidate();
            return Err(LeaseError::InvalidUpdate);
        }
        // This upper bound is evidence, not permission: a peer's renewal alone
        // never extends the local authorization deadline. Same-generation replay
        // and a new hello clock can only tighten an existing snapshot bound.
        if !stale {
            self.latest_snapshot_bound = Some(match self.latest_snapshot_bound {
                Some(old) if generation == self.generation => old.min(deadline),
                _ => deadline,
            });
        }
        if stale && !own_renewal {
            return Ok(());
        }
        if let Some(mut grant) = continuous {
            if !stale {
                self.latest_continuous_bound = Some(match self.latest_continuous_bound {
                    Some(old) if generation == self.generation => old.min(grant.expires),
                    _ => grant.expires,
                });
            }
            grant.expires = if own_renewal {
                grant
                    .expires
                    .min(self.latest_continuous_bound.unwrap_or(grant.expires))
            } else {
                self.continuous
                    .as_ref()
                    .map_or(grant.expires, |old| old.expires.min(grant.expires))
            };
            self.continuous = Some(grant);
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
    pub(crate) fn continuous_grant(&self) -> Option<ContinuousGrant> {
        self.continuous.clone()
    }
    pub(crate) fn is_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
            || self
                .continuous
                .as_ref()
                .is_some_and(|grant| !grant.is_valid())
    }
    pub fn is_authorized(&self, now: Instant) -> bool {
        !self.closed && self.active && self.deadline.is_some() && !self.is_expired(now)
    }
}

#[cfg(test)]
mod continuous_tests {
    use super::*;
    use crate::continuous_clock::ClockError;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    const SERVER: &str = "2026-10-28T00:00:00Z";
    const SESSION: &str = "00000000-0000-4000-8000-000000000001";
    const SOURCE: &str = "00000000-0000-4000-8000-000000000002";
    const TARGET: &str = "00000000-0000-4000-8000-000000000003";

    struct FakeClock(Arc<Mutex<Result<Duration, ClockError>>>);
    impl FakeClock {
        fn new(value: Duration) -> (Self, ContinuousClock) {
            let state = Arc::new(Mutex::new(Ok(value)));
            let reader = state.clone();
            (
                Self(state),
                ContinuousClock::with_reader(move || *reader.lock().unwrap()),
            )
        }
        fn set(&self, seconds: u64) {
            *self.0.lock().unwrap() = Ok(Duration::from_secs(seconds));
        }
        fn fail(&self) {
            *self.0.lock().unwrap() = Err(ClockError);
        }
    }

    fn bound() -> (FakeClock, ServerClockBound, Instant) {
        let (fake, clock) = FakeClock::new(Duration::ZERO);
        let started = HelloClockStart::with_clock(clock).unwrap();
        let instant = started.instant;
        (
            fake,
            ServerClockBound::from_hello_started(SERVER, started).unwrap(),
            instant,
        )
    }
    fn guard() -> LeaseGuard {
        LeaseGuard::new(SESSION.into(), SOURCE.into(), TARGET.into()).unwrap()
    }
    fn update(generation: u64, seconds: u64) -> Envelope {
        let expires = format!("2026-10-28T00:{:02}:{:02}Z", seconds / 60, seconds % 60);
        serde_json::from_value(json!({
            "v": 1, "type": "session.updated", "id": uuid::Uuid::new_v4().to_string(),
            "session_id": SESSION, "seq": 1, "sent_at": SERVER,
            "payload": {
                "session_id": SESSION, "source_device_id": SOURCE,
                "target_device_id": TARGET, "state": "connecting",
                "lease_generation": generation, "lease_expires_at": expires,
                "source_lease_expires_at": expires, "target_lease_expires_at": expires
            }
        }))
        .unwrap()
    }
    fn renewal(guard: &mut LeaseGuard, generation: u64, seconds: u64) -> Envelope {
        let request_id = uuid::Uuid::new_v4().to_string();
        guard.renewal_requested(request_id.clone()).unwrap();
        let mut update = update(generation, seconds);
        update.request_id = Some(request_id);
        update
    }

    #[test]
    fn sleep_during_hello_counts_even_when_instant_does_not_advance() {
        let (fake, clock) = FakeClock::new(Duration::ZERO);
        let started = HelloClockStart::with_clock(clock).unwrap();
        let instant = started.instant;
        fake.set(120);
        let bound = ServerClockBound::from_hello_started(SERVER, started).unwrap();
        let mut guard = guard();
        assert_eq!(
            guard.apply(&update(1, 60), &bound, instant),
            Err(LeaseError::Expired)
        );
        assert!(!guard.is_authorized(instant));
    }

    #[test]
    fn sleep_expires_active_authorization_without_timer_progress() {
        let (fake, clock, instant) = bound();
        let mut guard = guard();
        guard.apply(&update(1, 60), &clock, instant).unwrap();
        assert!(guard.is_authorized(instant));
        fake.set(120);
        assert!(instant < guard.deadline().unwrap());
        assert!(!guard.is_authorized(instant));
        assert!(!guard.continuous_grant().unwrap().is_valid());
    }

    #[test]
    fn queued_renewal_after_sleep_cannot_resurrect_expired_authorization() {
        let (fake, clock, instant) = bound();
        let mut guard = guard();
        guard.apply(&update(1, 60), &clock, instant).unwrap();
        let renewal = renewal(&mut guard, 2, 240);
        fake.set(120);
        assert_eq!(
            guard.apply(&renewal, &clock, instant),
            Err(LeaseError::Expired)
        );
        assert_eq!(
            guard.apply(&renewal, &clock, instant),
            Err(LeaseError::Closed)
        );
        assert!(!guard.is_authorized(instant));
    }

    #[test]
    fn sleep_inside_renewal_conversion_cannot_resurrect_old_grant() {
        use std::collections::VecDeque;
        // Capture + hello + initial receive/deadline/grant/final check; renewal
        // enters while valid, then sleeps across the old grant but not its new cap.
        let reads = Mutex::new(VecDeque::from([0, 0, 0, 0, 0, 0, 10, 10, 65, 65, 65, 65]));
        let clock = ContinuousClock::with_reader(move || {
            Ok(Duration::from_secs(
                reads.lock().unwrap().pop_front().unwrap_or(120),
            ))
        });
        let started = HelloClockStart::with_clock(clock).unwrap();
        let instant = started.instant;
        let clock = ServerClockBound::from_hello_started(SERVER, started).unwrap();
        let mut guard = guard();
        guard.apply(&update(1, 60), &clock, instant).unwrap();
        let renewal = renewal(&mut guard, 2, 240);
        assert_eq!(
            guard.apply(&renewal, &clock, instant),
            Err(LeaseError::Expired)
        );
        assert!(!guard.is_authorized(instant));
    }

    #[test]
    fn first_grant_cannot_restart_receive_cap_after_sleep_during_conversion() {
        use std::collections::VecDeque;
        // Hello 0, receive 0, scheduling deadline 0; sleep before continuous deadline.
        let reads = Mutex::new(VecDeque::from([0, 0, 0, 0, 120]));
        let clock = ContinuousClock::with_reader(move || {
            Ok(Duration::from_secs(
                reads.lock().unwrap().pop_front().unwrap_or(120),
            ))
        });
        let started = HelloClockStart::with_clock(clock).unwrap();
        let instant = started.instant;
        let clock = ServerClockBound::from_hello_started(SERVER, started).unwrap();
        let mut guard = guard();
        assert_eq!(
            guard.apply(&update(1, 240), &clock, instant),
            Err(LeaseError::Expired)
        );
        assert!(!guard.is_authorized(instant));
    }

    #[test]
    fn valid_correlated_renewal_extends_both_bounds() {
        let (fake, clock, instant) = bound();
        let mut guard = guard();
        guard.apply(&update(1, 30), &clock, instant).unwrap();
        let renewal = renewal(&mut guard, 2, 60);
        fake.set(10);
        guard
            .apply(&renewal, &clock, instant + Duration::from_secs(10))
            .unwrap();
        assert_eq!(guard.deadline(), Some(instant + Duration::from_secs(59)));
        fake.set(30);
        assert!(guard.is_authorized(instant + Duration::from_secs(30)));
        fake.set(59);
        assert!(!guard.is_authorized(instant + Duration::from_secs(30)));
    }

    #[test]
    fn peer_update_and_replay_never_extend_continuous_grant() {
        let (fake, clock, instant) = bound();
        let mut guard = guard();
        guard.apply(&update(1, 30), &clock, instant).unwrap();
        fake.set(10);
        guard.apply(&update(1, 600), &clock, instant).unwrap();
        guard.apply(&update(2, 600), &clock, instant).unwrap();
        fake.set(29);
        assert!(!guard.is_authorized(instant));
    }

    #[test]
    fn deadline_equality_and_cap_fail_closed() {
        let (fake, clock, instant) = bound();
        let mut guard = guard();
        guard.apply(&update(1, 600), &clock, instant).unwrap();
        fake.set(59);
        assert!(guard.is_authorized(instant));
        fake.set(60);
        assert!(!guard.is_authorized(instant));
    }

    #[test]
    fn clock_errors_and_backwards_reads_are_sticky_for_authorization() {
        for fail in [true, false] {
            let (fake, clock, instant) = bound();
            let mut guard = guard();
            guard.apply(&update(1, 60), &clock, instant).unwrap();
            fake.set(10);
            assert!(guard.is_authorized(instant));
            if fail {
                fake.fail();
            } else {
                fake.set(9);
            }
            assert!(!guard.is_authorized(instant));
            fake.set(11);
            assert!(!guard.is_authorized(instant));
        }
    }

    #[test]
    fn failed_hello_clock_cannot_establish_bound() {
        let (fake, clock) = FakeClock::new(Duration::ZERO);
        let started = HelloClockStart::with_clock(clock.clone()).unwrap();
        fake.fail();
        assert!(matches!(
            ServerClockBound::from_hello_started(SERVER, started),
            Err(LeaseError::Expired)
        ));
        assert!(matches!(
            HelloClockStart::with_clock(clock),
            Err(LeaseError::Expired)
        ));
    }

    #[test]
    fn continuous_deadline_overflow_rejects_instead_of_wrapping() {
        let (_, clock) = FakeClock::new(Duration::MAX);
        let started = HelloClockStart::with_clock(clock).unwrap();
        let instant = started.instant;
        let clock = ServerClockBound::from_hello_started(SERVER, started).unwrap();
        let mut guard = guard();
        assert_eq!(
            guard.apply(&update(1, 60), &clock, instant),
            Err(LeaseError::InvalidUpdate)
        );
        assert!(!guard.is_authorized(instant));
    }

    #[test]
    #[allow(deprecated)] // Deliberately verify compatibility cannot weaken a safe grant.
    fn legacy_bound_cannot_downgrade_existing_continuous_authorization() {
        let (_, clock, instant) = bound();
        let mut guard = guard();
        guard.apply(&update(1, 60), &clock, instant).unwrap();
        let renewal = renewal(&mut guard, 2, 120);
        let legacy = ServerClockBound::from_hello(SERVER, instant).unwrap();
        assert_eq!(
            guard.apply(&renewal, &legacy, instant),
            Err(LeaseError::InvalidUpdate)
        );
        assert!(!guard.is_authorized(instant));
    }
}
