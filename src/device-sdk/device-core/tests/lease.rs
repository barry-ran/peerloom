use device_core::{
    lease::{LeaseError, LeaseGuard, ServerClockBound},
    signaling::Envelope,
};
use serde_json::json;
use std::time::{Duration, Instant};
const SESSION: &str = "00000000-0000-4000-8000-000000000001";
const SOURCE: &str = "00000000-0000-4000-8000-000000000002";
const TARGET: &str = "00000000-0000-4000-8000-000000000003";
fn update(generation: u64, seconds: u64) -> Envelope {
    let expires = format!("2026-10-28T00:{:02}:{:02}Z", seconds / 60, seconds % 60);
    serde_json::from_value(json!({"v":1,"type":"session.updated","id":uuid::Uuid::new_v4().to_string(),"session_id":SESSION,"seq":1,"sent_at":"2026-10-28T00:00:00Z","payload":{"session_id":SESSION,"source_device_id":SOURCE,"target_device_id":TARGET,"state":"connecting","lease_generation":generation,"lease_expires_at":expires,"source_lease_expires_at":expires,"target_lease_expires_at":expires}})).unwrap()
}
fn guard() -> LeaseGuard {
    LeaseGuard::new(SESSION.into(), SOURCE.into(), TARGET.into()).unwrap()
}
#[test]
fn handshake_delay_and_margin_make_expiry_early() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard
        .apply(&update(1, 60), &clock, start + Duration::from_secs(5))
        .unwrap();
    assert_eq!(guard.deadline(), Some(start + Duration::from_secs(59)));
    assert!(guard.is_authorized(start + Duration::from_secs(58)));
    assert!(!guard.is_authorized(start + Duration::from_secs(59)));
}
#[test]
fn forward_server_jump_is_hard_capped() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard.apply(&update(1, 600), &clock, start).unwrap();
    assert_eq!(guard.deadline(), Some(start + Duration::from_secs(60)));
}
#[test]
fn replay_and_reconnect_cannot_extend_old_lease() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard.apply(&update(1, 60), &clock, start).unwrap();
    let original = guard.deadline();
    let reconnect =
        ServerClockBound::from_hello("2026-10-28T00:00:00Z", start + Duration::from_secs(20))
            .unwrap();
    guard
        .apply(&update(1, 600), &reconnect, start + Duration::from_secs(20))
        .unwrap();
    assert_eq!(guard.deadline(), original);
    guard
        .apply(&update(2, 600), &reconnect, start + Duration::from_secs(21))
        .unwrap();
    assert_eq!(guard.deadline(), original);
}
#[test]
fn only_correlated_new_generation_renewal_extends() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard.apply(&update(1, 30), &clock, start).unwrap();
    let key = uuid::Uuid::new_v4().to_string();
    guard.renewal_requested(key.clone()).unwrap();
    let mut renewal = update(2, 60);
    renewal.request_id = Some(key);
    guard
        .apply(&renewal, &clock, start + Duration::from_secs(10))
        .unwrap();
    assert_eq!(guard.deadline(), Some(start + Duration::from_secs(59)));
}
#[test]
fn closed_or_expired_lease_never_resurrects() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard.apply(&update(1, 10), &clock, start).unwrap();
    assert_eq!(
        guard.apply(&update(2, 60), &clock, start + Duration::from_secs(9)),
        Err(LeaseError::Expired)
    );
    assert_eq!(
        guard.apply(&update(3, 60), &clock, start + Duration::from_secs(10)),
        Err(LeaseError::Closed)
    );
}
#[test]
fn authoritative_termination_immediately_revokes_and_peer_ids_are_checked() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard.apply(&update(1, 60), &clock, start).unwrap();
    let mut invalid = update(2, 60);
    invalid.payload["target_device_id"] = json!(SOURCE);
    assert_eq!(
        guard.apply(&invalid, &clock, start),
        Err(LeaseError::InvalidUpdate)
    );
    let mut closed = update(2, 60);
    closed.kind = "session.terminated".into();
    closed.payload["state"] = json!("closed");
    guard.apply(&closed, &clock, start).unwrap();
    assert!(!guard.is_authorized(start));
}
