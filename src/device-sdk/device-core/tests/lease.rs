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

#[test]
fn delayed_correlated_renewal_after_newer_peer_update_does_not_close_valid_lease() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard.apply(&update(2, 30), &clock, start).unwrap();
    let key = uuid::Uuid::new_v4().to_string();
    guard.renewal_requested(key.clone()).unwrap();
    // Concurrent peer renewal commits after our renewal but its publication
    // reaches this WSS first. Neither transaction is an authorization revocation.
    guard
        .apply(&update(4, 60), &clock, start + Duration::from_secs(10))
        .unwrap();
    let mut own_ack = update(3, 50);
    own_ack.request_id = Some(key);
    assert!(
        guard
            .apply(&own_ack, &clock, start + Duration::from_secs(11))
            .is_ok(),
        "authenticated older renewal response must not close a still-valid session"
    );
    assert!(guard.is_authorized(start + Duration::from_secs(30)));
    assert!(guard.deadline().unwrap() <= start + Duration::from_secs(49));
}

#[test]
fn stale_live_replay_cannot_extend_or_roll_back_active_state() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard.apply(&update(4, 60), &clock, start).unwrap();
    let deadline = guard.deadline();
    for expiry in [5, 600] {
        let mut old = update(3, expiry);
        old.payload["state"] = json!("authorizing");
        guard
            .apply(&old, &clock, start + Duration::from_secs(10))
            .unwrap();
        assert_eq!(guard.deadline(), deadline);
        assert!(guard.is_authorized(start + Duration::from_secs(10)));
    }
}
#[test]
fn stale_live_still_validates_identity_and_every_expiry_field() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    for field in [
        "session_id",
        "source_device_id",
        "target_device_id",
        "lease_expires_at",
        "source_lease_expires_at",
        "target_lease_expires_at",
        "state",
    ] {
        let mut guard = guard();
        guard.apply(&update(4, 60), &clock, start).unwrap();
        let mut old = update(3, 50);
        old.payload[field] = json!("invalid");
        assert_eq!(
            guard.apply(&old, &clock, start + Duration::from_secs(10)),
            Err(LeaseError::InvalidUpdate),
            "{field}"
        );
    }
}
#[test]
fn delayed_own_ack_is_capped_by_newer_stricter_snapshot_and_consumed_once() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard.apply(&update(2, 30), &clock, start).unwrap();
    let key = uuid::Uuid::new_v4().to_string();
    guard.renewal_requested(key.clone()).unwrap();
    guard
        .apply(&update(4, 40), &clock, start + Duration::from_secs(10))
        .unwrap();
    let mut own = update(3, 90);
    own.request_id = Some(key);
    guard
        .apply(&own, &clock, start + Duration::from_secs(11))
        .unwrap();
    assert_eq!(guard.deadline(), Some(start + Duration::from_secs(39)));
    own.payload["lease_generation"] = json!(5);
    for field in [
        "lease_expires_at",
        "source_lease_expires_at",
        "target_lease_expires_at",
    ] {
        own.payload[field] = update(5, 600).payload[field].clone();
    }
    guard
        .apply(&own, &clock, start + Duration::from_secs(12))
        .unwrap();
    assert_eq!(guard.deadline(), Some(start + Duration::from_secs(39)));
}
#[test]
fn stale_terminal_and_expired_current_lease_always_fail_closed() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    for terminal in [true, false] {
        let mut guard = guard();
        guard.apply(&update(4, 20), &clock, start).unwrap();
        let key = uuid::Uuid::new_v4().to_string();
        guard.renewal_requested(key.clone()).unwrap();
        let mut old = update(3, 60);
        old.request_id = Some(key);
        if terminal {
            old.kind = "session.terminated".into();
            old.payload["state"] = json!("closed");
            guard
                .apply(&old, &clock, start + Duration::from_secs(10))
                .unwrap();
        } else {
            assert_eq!(
                guard.apply(&old, &clock, start + Duration::from_secs(19)),
                Err(LeaseError::Expired)
            );
        }
        assert!(!guard.is_authorized(start + Duration::from_secs(19)));
        assert_eq!(
            guard.apply(&update(5, 120), &clock, start + Duration::from_secs(20)),
            Err(LeaseError::Closed)
        );
    }
}
#[test]
fn renewal_must_advance_from_request_generation_and_old_request_is_not_reused() {
    let start = Instant::now();
    let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", start).unwrap();
    let mut guard = guard();
    guard.apply(&update(4, 30), &clock, start).unwrap();
    let old_key = uuid::Uuid::new_v4().to_string();
    guard.renewal_requested(old_key.clone()).unwrap();
    let key = uuid::Uuid::new_v4().to_string();
    guard.renewal_requested(key.clone()).unwrap();
    let mut ack = update(5, 60);
    ack.request_id = Some(old_key);
    guard
        .apply(&ack, &clock, start + Duration::from_secs(10))
        .unwrap();
    assert_eq!(guard.deadline(), Some(start + Duration::from_secs(29)));
    ack.payload["lease_generation"] = json!(4);
    ack.request_id = Some(key.clone());
    guard
        .apply(&ack, &clock, start + Duration::from_secs(11))
        .unwrap();
    assert_eq!(guard.deadline(), Some(start + Duration::from_secs(29)));
    ack.payload["lease_generation"] = json!(5);
    guard
        .apply(&ack, &clock, start + Duration::from_secs(12))
        .unwrap();
    assert_eq!(guard.deadline(), Some(start + Duration::from_secs(59)));
}
