use super::*;
use crate::lease::ServerClockBound;
use time::OffsetDateTime;

#[tokio::test]
async fn target_closed_session_ignores_late_snapshot_and_offer() {
    target_terminal_session_ignores_late_snapshot_and_offer(false).await;
}
#[tokio::test]
async fn target_rejected_session_ignores_late_snapshot_and_offer() {
    target_terminal_session_ignores_late_snapshot_and_offer(true).await;
}
async fn target_terminal_session_ignores_late_snapshot_and_offer(reject: bool) {
    use device_storage::{IdentityScope, MemoryIdentityStore, SecretString};
    let app = uuid::Uuid::new_v4().to_string();
    let source = uuid::Uuid::new_v4().to_string();
    let target = uuid::Uuid::new_v4().to_string();
    let session_id = uuid::Uuid::new_v4().to_string();
    let config = SdkConfig::new("https://reset.example".into(), app.clone());
    let store = Arc::new(MemoryIdentityStore::default());
    let stored = StoredIdentity {
        device_id: target.clone(),
        device_credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
        expires_at: "2099-01-01T00:00:00Z".into(),
    };
    store
        .save(
            &IdentityScope {
                server_origin: "https://reset.example/".into(),
                application_id: app,
            },
            0,
            stored.clone(),
        )
        .await
        .unwrap();
    let identity = DeviceSdk::identity(&config, store).await.unwrap();
    let (commands, _command_rx) = mpsc::channel(32);
    let (events, _event_rx) = mpsc::channel(32);
    let mut actor = Actor::new(config, identity, stored, commands, events);
    let installation = actor.installation_closed.clone();
    let initial = Arc::new(Gate {
        installation_closed: installation.clone(),
        ..Gate::default()
    });
    actor
        .sessions
        .insert_incoming(
            session_id.clone(),
            Session {
                id: session_id.clone(),
                initial_request_id: None,
                source: source.clone(),
                target: target.clone(),
                guard: LeaseGuard::new(session_id.clone(), source.clone(), target.clone()).unwrap(),
                gate: initial.clone(),
                worker: None,
                authority: None,
                closing: false,
                renew_at: Instant::now(),
                ready: true,
                generation: 1,
                recovery_at: None,
                recovery_attempt: 0,
                sync_pending: false,
                sync_requested: false,
                requests: std::collections::VecDeque::new(),
            },
        )
        .unwrap();

    initial.update(Some(Instant::now() + Duration::from_secs(60)));
    if reject {
        let (done, _) = oneshot::channel();
        actor
            .command(Command::Respond(session_id.clone(), false, done))
            .await
            .unwrap();
    } else {
        actor
            .command(Command::CloseConnection(session_id.clone(), 1, None))
            .await
            .unwrap();
    }
    assert_eq!(actor.sessions.len(), 1);
    assert!(initial.closed.load(Ordering::Acquire));
    for generation in [1, 2] {
        let message: Envelope = serde_json::from_value(json!({
            "v":1,"type":"session.updated","id":uuid::Uuid::new_v4().to_string(),
            "session_id":session_id,"connection_generation":1,
            "fencing_token":"12345678901234567890123456789012","seq":generation,
            "sent_at":"2026-10-28T00:00:00Z",
            "payload":{"session_id":session_id,"source_device_id":source,
                "target_device_id":target,"state":"connecting","negotiation_generation":generation,
                "lease_generation":generation,"lease_expires_at":"2026-10-28T00:00:30Z"}
        }))
        .unwrap();
        actor.message(message.clone()).await.unwrap();
        let mut offer = message;
        offer.kind = "signal.offer".into();
        offer.payload = json!({"sdp":"late must never reach worker"});
        actor.message(offer).await.unwrap();
        assert_eq!(actor.sessions.len(), 1);
        assert!(actor.sessions.get(&session_id).unwrap().closing);
        assert!(initial.closed.load(Ordering::Acquire));
    }
}

#[tokio::test]
async fn queued_local_description_rechecks_generation_lease_and_reset_gate() {
    for invalidation in ["generation", "lease", "local", "installation", "valid"] {
        use device_storage::{IdentityScope, MemoryIdentityStore, SecretString};
        let app = uuid::Uuid::new_v4().to_string();
        let source = uuid::Uuid::new_v4().to_string();
        let target = uuid::Uuid::new_v4().to_string();
        let session_id = uuid::Uuid::new_v4().to_string();
        let config = SdkConfig::new("https://reset.example".into(), app.clone());
        let store = Arc::new(MemoryIdentityStore::default());
        let stored = StoredIdentity {
            device_id: target.clone(),
            device_credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
            expires_at: "2099-01-01T00:00:00Z".into(),
        };
        store
            .save(
                &IdentityScope {
                    server_origin: "https://reset.example/".into(),
                    application_id: app,
                },
                0,
                stored.clone(),
            )
            .await
            .unwrap();
        let identity = DeviceSdk::identity(&config, store).await.unwrap();
        let (commands, _command_rx) = mpsc::channel(32);
        let (events, _event_rx) = mpsc::channel(32);
        let mut actor = Actor::new(config, identity, stored, commands, events);
        let installation = actor.installation_closed.clone();
        let initial = Arc::new(Gate {
            installation_closed: installation.clone(),
            ..Gate::default()
        });
        actor
            .sessions
            .insert_incoming(
                session_id.clone(),
                Session {
                    id: session_id.clone(),
                    initial_request_id: None,
                    source: source.clone(),
                    target: target.clone(),
                    guard: LeaseGuard::new(session_id.clone(), source.clone(), target.clone())
                        .unwrap(),
                    gate: initial.clone(),
                    worker: None,
                    authority: None,
                    closing: false,
                    renew_at: Instant::now(),
                    ready: true,
                    generation: 1,
                    recovery_at: None,
                    recovery_attempt: 0,
                    sync_pending: false,
                    sync_requested: false,
                    requests: std::collections::VecDeque::new(),
                },
            )
            .unwrap();

        let now = Instant::now();
        #[allow(deprecated)] // 此测试显式推进 Instant，保留旧纯策略夹具。
        let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", now).unwrap();
        let message: Envelope = serde_json::from_value(json!({
            "v":1,"type":"session.updated","id":uuid::Uuid::new_v4().to_string(),
            "session_id":session_id,"connection_generation":1,
            "fencing_token":"12345678901234567890123456789012","seq":1,
            "sent_at":"2026-10-28T00:00:00Z",
            "payload":{"session_id":session_id,"source_device_id":source,
                "target_device_id":target,"state":"connecting","lease_generation":1,
                "lease_expires_at":"2026-10-28T00:01:00Z",
                "source_lease_expires_at":"2026-10-28T00:01:00Z",
                "target_lease_expires_at":"2026-10-28T00:01:00Z"}
        }))
        .unwrap();
        let session = actor.sessions.get_mut(&session_id).unwrap();
        session.guard.apply(&message, &clock, now).unwrap();
        initial.update(session.guard.deadline());
        match invalidation {
            "generation" => session.generation = 2,
            "lease" => session.guard.invalidate(),
            "local" => initial.close(),
            "installation" => installation.store(true, Ordering::Release),
            "valid" => {}
            _ => unreachable!(),
        }
        actor
            .internal(Internal::Description(
                session_id.clone(),
                1,
                "session.offer",
                "not logged".into(),
            ))
            .await
            .unwrap();
        // There is deliberately no WSS. A valid description attempts submission
        // and closes Offline; an invalid queued description must never submit.
        assert_eq!(
            actor
                .sessions
                .get(&session_id)
                .is_some_and(|session| session.closing),
            invalidation == "valid"
        );
    }
}

async fn capacity_actor(
    limit: usize,
) -> (
    Actor,
    mpsc::Receiver<SdkEvent>,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::Mutex<std::collections::HashMap<String, Envelope>>>,
) {
    use device_storage::{IdentityScope, MemoryIdentityStore, SecretString};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = uuid::Uuid::new_v4().to_string();
    let mut config = SdkConfig::new(origin.clone(), app.clone());
    config.development_loopback = true;
    config.max_connections = limit;
    let stored = StoredIdentity {
        device_id: uuid::Uuid::new_v4().to_string(),
        device_credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
        expires_at: "2099-01-01T00:00:00Z".into(),
    };
    let store = Arc::new(MemoryIdentityStore::default());
    store
        .save(
            &IdentityScope {
                server_origin: format!("{origin}/"),
                application_id: app,
            },
            0,
            stored.clone(),
        )
        .await
        .unwrap();
    let identity = DeviceSdk::identity(&config, store).await.unwrap();
    let authority = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        Envelope,
    >::new()));
    let server_authority = authority.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        socket.set_nodelay(true).unwrap();
        let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        let hello: Envelope =
            serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        ws.send(Message::Text(json!({"v":1,"type":"hello.ack","id":uuid::Uuid::new_v4().to_string(),"request_id":hello.id,"seq":0,
            "sent_at":OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
            "connection_generation":1,"fencing_token":"12345678901234567890123456789012",
            "payload":{"heartbeat_interval_seconds":10,"presence_ttl_seconds":30}}).to_string().into())).await.unwrap();
        let mut seq = 1u64;
        while let Some(Ok(message)) = ws.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
            let command: Envelope = serde_json::from_str(message.to_text().unwrap()).unwrap();
            if command.kind == "presence.heartbeat" {
                continue;
            }
            let id = command.session_id.as_ref().expect("session command");
            let mut response = {
                let mut map = server_authority.lock().unwrap();
                let snapshot = map.get_mut(id).expect("known authority");
                if command.kind == "session.terminate" || command.kind == "session.reject" {
                    snapshot.payload["state"] = json!("closed");
                }
                snapshot.clone()
            };
            response.kind = if command.kind == "sync.request" {
                "sync.snapshot"
            } else {
                "session.terminated"
            }
            .into();
            response.request_id = Some(command.id);
            response.connection_generation = Some(1);
            response.fencing_token = Some("12345678901234567890123456789012".into());
            response.seq = seq;
            seq += 1;
            ws.send(Message::Text(
                serde_json::to_string(&response).unwrap().into(),
            ))
            .await
            .unwrap();
        }
    });
    let (commands, _) = mpsc::channel(32);
    let (events, received) = mpsc::channel(256);
    let signal = SignalClient::connect(
        &IdentityClient::new(&origin, true, Duration::from_secs(2)).unwrap(),
        &stored.device_credential,
    )
    .await
    .unwrap();
    let mut actor = Actor::new(config, identity, stored, commands, events);
    actor.signal = Some(signal);
    (actor, received, server, authority)
}
fn capacity_snapshot(actor: &Actor, id: &str, terminal: bool) -> Envelope {
    let now = OffsetDateTime::now_utc();
    let stamp = |at: OffsetDateTime| {
        at.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let expiry = stamp(now + time::Duration::seconds(if terminal { 1 } else { 120 }));
    serde_json::from_value(json!({"v":1,"type":if terminal {"session.terminated"} else {"session.pending"},
        "id":uuid::Uuid::new_v4().to_string(),"session_id":id,"seq":1,"sent_at":stamp(now),
        "payload":{"session_id":id,"source_device_id":"00000000-0000-4000-8000-000000000001","target_device_id":actor.stored.device_id,
        "state":if terminal {"closed"} else {"authorizing"},"negotiation_generation":1,"lease_generation":1,
        "lease_expires_at":expiry,"source_lease_expires_at":expiry,"target_lease_expires_at":expiry}})).unwrap()
}

async fn apply_authority_reply(actor: &mut Actor) {
    let message = tokio::time::timeout(
        Duration::from_secs(2),
        actor.signal.as_mut().unwrap().receive(),
    )
    .await
    .unwrap()
    .unwrap();
    actor.message(message).await.unwrap();
}
#[tokio::test]
async fn authority_terminal_before_initial_never_delivers_incoming() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    let id = uuid::Uuid::new_v4().to_string();
    let initial = capacity_snapshot(&actor, &id, false);
    let terminal = capacity_snapshot(&actor, &id, true);
    authority
        .lock()
        .unwrap()
        .insert(id.clone(), terminal.clone());
    actor.message(terminal).await.unwrap();
    actor.message(initial).await.unwrap();
    assert!(actor.sessions.get(&id).unwrap().authority.is_some());
    assert!(events.try_recv().is_err());
    apply_authority_reply(&mut actor).await;
    assert_eq!(actor.sessions.len(), 0);
    assert!(events.try_recv().is_err());
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}
#[tokio::test]
async fn authority_healthy_churn_over_4096_has_no_history_floor() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    let mut first = None;
    for _ in 0..4100 {
        let id = uuid::Uuid::new_v4().to_string();
        let initial = capacity_snapshot(&actor, &id, false);
        first.get_or_insert(initial.clone());
        authority
            .lock()
            .unwrap()
            .insert(id.clone(), initial.clone());
        actor.message(initial).await.unwrap();
        apply_authority_reply(&mut actor).await;
        assert!(matches!(
            events.try_recv().unwrap(),
            SdkEvent::IncomingConnection { .. }
        ));
        actor.close_session(&id, SdkError::Closed, true).await;
        assert!(actor.sessions.get(&id).unwrap().closing);
        apply_authority_reply(&mut actor).await;
        assert_eq!(actor.sessions.len(), 0);
        assert!(matches!(
            events.try_recv().unwrap(),
            SdkEvent::ConnectionClosed { .. }
        ));
        assert!(events.try_recv().is_err());
    }
    actor.message(first.unwrap()).await.unwrap();
    apply_authority_reply(&mut actor).await;
    assert_eq!(actor.sessions.len(), 0);
    assert!(events.try_recv().is_err());
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}
#[tokio::test]
async fn authority_64_pending_sessions_use_only_32_inflight_without_dropping_rest() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    for _ in 0..64 {
        let id = uuid::Uuid::new_v4().to_string();
        let initial = capacity_snapshot(&actor, &id, false);
        authority.lock().unwrap().insert(id, initial.clone());
        actor.message(initial).await.unwrap();
    }
    assert_eq!(actor.sessions.len(), 64);
    assert_eq!(
        actor
            .sessions
            .iter()
            .filter(|(_, s)| s.authority.as_ref().is_some_and(|a| a.request.is_some()))
            .count(),
        32
    );
    assert!(
        actor
            .sessions
            .iter()
            .filter_map(|(_, session)| session.authority.as_ref())
            .filter(|pending| pending.request.is_none())
            .all(|pending| pending.deadline.is_none())
    );
    for _ in 0..32 {
        apply_authority_reply(&mut actor).await;
    }
    actor.control_remaining = actor.sessions.len();
    while actor.control_remaining > 0 {
        actor.maintenance_batch(false).await.unwrap();
    }
    for _ in 0..32 {
        apply_authority_reply(&mut actor).await;
    }
    assert!(actor.sessions.iter().all(|(_, s)| s.authority.is_none()));
    for _ in 0..64 {
        assert!(matches!(
            events.try_recv().unwrap(),
            SdkEvent::IncomingConnection { .. }
        ));
    }
    actor.close_all().await;
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}
#[tokio::test]
async fn authority_local_closed_cannot_be_revived_by_live_snapshot() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    let id = uuid::Uuid::new_v4().to_string();
    let initial = capacity_snapshot(&actor, &id, false);
    authority
        .lock()
        .unwrap()
        .insert(id.clone(), initial.clone());
    actor.message(initial.clone()).await.unwrap();
    apply_authority_reply(&mut actor).await;
    events.try_recv().unwrap();
    let gate = actor.sessions.get(&id).unwrap().gate.clone();
    actor.close_session(&id, SdkError::Closed, false).await;
    let mut live = initial;
    live.kind = "sync.snapshot".into();
    live.payload["state"] = json!("connected");
    live.payload["negotiation_generation"] = json!(33);
    live.payload["lease_generation"] = json!(2);
    actor.message(live).await.unwrap();
    assert!(actor.sessions.get(&id).unwrap().closing);
    assert!(gate.check().is_err());
    assert!(matches!(
        events.try_recv().unwrap(),
        SdkEvent::ConnectionClosed { .. }
    ));
    assert!(events.try_recv().is_err());
    actor.sessions.get_mut(&id).unwrap().renew_at = Instant::now();
    actor.maintenance_batch(true).await.unwrap();
    apply_authority_reply(&mut actor).await;
    assert_eq!(actor.sessions.len(), 0);
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn authority_offer_before_snapshot_stale_request_and_generation_are_not_consumed() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    let id = uuid::Uuid::new_v4().to_string();
    let initial = capacity_snapshot(&actor, &id, false);
    let mut live = initial.clone();
    live.payload["state"] = json!("connecting");
    live.payload["negotiation_generation"] = json!(33);
    live.payload["lease_generation"] = json!(2);
    authority.lock().unwrap().insert(id.clone(), live);
    actor.message(initial.clone()).await.unwrap();
    let old_request = actor
        .sessions
        .get(&id)
        .unwrap()
        .authority
        .as_ref()
        .unwrap()
        .request
        .clone();
    let mut offer = initial;
    offer.kind = "session.offer".into();
    offer.negotiation_generation = Some(1);
    offer.payload = json!({"sdp":"not parsed before authoritative admission"});
    actor.message(offer).await.unwrap();
    let session = actor.sessions.get(&id).unwrap();
    assert!(session.worker.is_none());
    assert!(session.gate.check().is_err());
    assert!(session.authority.as_ref().unwrap().offer.is_some());
    // A reconnect invalidates the old epoch's correlation without extending
    // this notification's total verification budget.
    let authority = actor
        .sessions
        .get_mut(&id)
        .unwrap()
        .authority
        .as_mut()
        .unwrap();
    authority.request = None;
    authority.requested_at = None;
    actor.request_authority(&id).await;
    assert_ne!(
        actor
            .sessions
            .get(&id)
            .unwrap()
            .authority
            .as_ref()
            .unwrap()
            .request,
        old_request
    );
    apply_authority_reply(&mut actor).await;
    assert!(actor.sessions.get(&id).unwrap().authority.is_some());
    apply_authority_reply(&mut actor).await;
    let session = actor.sessions.get(&id).unwrap();
    assert!(session.authority.is_none());
    assert_eq!(session.generation, 33);
    assert!(session.gate.check().is_ok());
    assert!(session.worker.is_none()); // the old generation's buffered offer was discarded
    assert!(events.try_recv().is_err());
    actor.close_all().await;
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn authority_matching_buffered_offer_is_processed_only_after_fresh_snapshot() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    let id = uuid::Uuid::new_v4().to_string();
    let mut initial = capacity_snapshot(&actor, &id, false);
    initial.kind = "session.updated".into();
    initial.payload["state"] = json!("connecting");
    authority
        .lock()
        .unwrap()
        .insert(id.clone(), initial.clone());
    actor.message(initial.clone()).await.unwrap();
    let mut offer = initial;
    offer.kind = "session.offer".into();
    offer.negotiation_generation = Some(1);
    offer.payload =
        json!({"sdp":"invalid SDP must fail only after authority admits this generation"});
    actor.message(offer).await.unwrap();
    let session = actor.sessions.get(&id).unwrap();
    assert!(!session.closing);
    assert!(session.worker.is_none());
    assert!(session.authority.as_ref().unwrap().offer.is_some());
    assert!(events.try_recv().is_err());
    apply_authority_reply(&mut actor).await;
    assert!(actor.sessions.get(&id).unwrap().closing);
    assert!(matches!(
        events.try_recv().unwrap(),
        SdkEvent::ConnectionClosed {
            reason: SdkError::Transport(TransportError::Negotiation),
            ..
        }
    ));
    apply_authority_reply(&mut actor).await;
    assert_eq!(actor.sessions.len(), 0);
    assert!(events.try_recv().is_err());
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}

fn authority_error(request: &str, code: &str) -> Envelope {
    serde_json::from_value(
        json!({"v":1,"type":"error","id":uuid::Uuid::new_v4().to_string(),
        "request_id":request,"seq":1,"sent_at":"2026-10-29T00:00:00Z","payload":{"code":code}}),
    )
    .unwrap()
}
#[tokio::test]
async fn authority_permanent_denials_release_only_unadmitted_slots() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    for code in [
        "AUTH_INVALID",
        "INVALID_INPUT",
        "SESSION_NOT_FOUND",
        "SESSION_CLOSED",
        "TARGET_NOT_FOUND",
        "DEVICE_REVOKED",
        "APPLICATION_DISABLED",
        "TARGET_NOT_CONNECTABLE",
        "GRANT_REQUIRED",
        "GRANT_REVOKED",
        "GRANT_EXPIRED",
        "LEASE_EXPIRED",
        "UNKNOWN_NEW_CODE",
    ] {
        let id = uuid::Uuid::new_v4().to_string();
        let initial = capacity_snapshot(&actor, &id, false);
        authority
            .lock()
            .unwrap()
            .insert(id.clone(), initial.clone());
        actor.message(initial).await.unwrap();
        let request = actor
            .sessions
            .get(&id)
            .unwrap()
            .authority
            .as_ref()
            .unwrap()
            .request
            .clone()
            .unwrap();
        actor
            .message(authority_error(&request, code))
            .await
            .unwrap();
        assert!(actor.sessions.get(&id).is_none(), "{code}");
        assert!(
            matches!(events.try_recv().unwrap(), SdkEvent::ConnectionClosed { reason: SdkError::Rejected(ref reason), .. } if reason == "AUTHORITY_DENIED")
        );
        assert!(events.try_recv().is_err());
        // Drain the mock server's already-issued live reply after the injected
        // denial/timeout. It must not resurrect the removed slot, and the server
        // must finish writing before the client closes its TCP connection.
        apply_authority_reply(&mut actor).await;
        assert!(actor.sessions.get(&id).is_none());
        assert!(events.try_recv().is_err());
    }
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}
#[tokio::test]
async fn authority_transient_retry_has_cooldown_and_total_operation_deadline() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    for code in ["DATABASE_UNAVAILABLE", "COMMIT_UNCERTAIN_RETRY_SAME_KEY"] {
        let id = uuid::Uuid::new_v4().to_string();
        let initial = capacity_snapshot(&actor, &id, false);
        authority
            .lock()
            .unwrap()
            .insert(id.clone(), initial.clone());
        actor.message(initial).await.unwrap();
        let pending = actor.sessions.get(&id).unwrap().authority.as_ref().unwrap();
        let request = pending.request.clone().unwrap();
        let deadline = pending.deadline;
        actor
            .message(authority_error(&request, code))
            .await
            .unwrap();
        actor.request_authority(&id).await;
        let pending = actor.sessions.get(&id).unwrap().authority.as_ref().unwrap();
        assert!(pending.request.is_none()); // no hot retry in the same actor turn
        assert_eq!(pending.deadline, deadline);
        assert!(events.try_recv().is_err());
        actor
            .sessions
            .get_mut(&id)
            .unwrap()
            .authority
            .as_mut()
            .unwrap()
            .deadline = Some(Instant::now());
        actor.request_authority(&id).await;
        assert!(actor.sessions.get(&id).is_none());
        assert!(matches!(
            events.try_recv().unwrap(),
            SdkEvent::ConnectionClosed {
                reason: SdkError::Transport(TransportError::Timeout),
                ..
            }
        ));
        assert!(events.try_recv().is_err());
        // Drain the mock server's already-issued live reply after the injected
        // denial/timeout. It must not resurrect the removed slot, and the server
        // must finish writing before the client closes its TCP connection.
        apply_authority_reply(&mut actor).await;
        assert!(actor.sessions.get(&id).is_none());
        assert!(events.try_recv().is_err());
    }
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}
#[tokio::test]
async fn authority_closing_auth_failure_is_fatal_without_reviving_or_forgetting_gate() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    let id = uuid::Uuid::new_v4().to_string();
    let initial = capacity_snapshot(&actor, &id, false);
    authority
        .lock()
        .unwrap()
        .insert(id.clone(), initial.clone());
    actor.message(initial).await.unwrap();
    let request = actor
        .sessions
        .get(&id)
        .unwrap()
        .authority
        .as_ref()
        .unwrap()
        .request
        .clone()
        .unwrap();
    apply_authority_reply(&mut actor).await;
    events.try_recv().unwrap();
    let gate = actor.sessions.get(&id).unwrap().gate.clone();
    actor.close_session(&id, SdkError::Closed, false).await;
    assert_eq!(
        actor
            .message(authority_error(&request, "AUTH_INVALID"))
            .await
            .unwrap_err(),
        SdkError::Signal(SignalError::AuthorizationRejected)
    );
    assert!(actor.sessions.get(&id).unwrap().closing);
    assert!(gate.check().is_err());
    actor.close_all().await;
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn local_close_releases_active_capacity_but_keeps_replay_fence_until_terminal() {
    let (mut actor, mut events, server, authority) = capacity_actor(1).await;
    let id = uuid::Uuid::new_v4().to_string();
    let initial = capacity_snapshot(&actor, &id, false);
    authority
        .lock()
        .unwrap()
        .insert(id.clone(), initial.clone());
    actor.message(initial).await.unwrap();
    apply_authority_reply(&mut actor).await;
    assert!(matches!(
        events.try_recv().unwrap(),
        SdkEvent::IncomingConnection { .. }
    ));
    actor.close_session(&id, SdkError::Closed, true).await;
    assert!(
        matches!(events.try_recv().unwrap(), SdkEvent::ConnectionClosed { session_id, .. } if session_id == id)
    );
    let old_gate = actor.sessions.get(&id).unwrap().gate.clone();
    assert!(old_gate.check().is_err());
    // The response may already be in the socket, but this actor has not applied
    // it. Local Closed already releases active capacity, while the old
    // identity and permanently closed gate remain pending the terminal ACK.
    assert_eq!(actor.sessions.len(), 1);
    let reservation = actor
        .sessions
        .reserve_outgoing(uuid::Uuid::new_v4().to_string())
        .unwrap();
    assert!(actor.sessions.release_reservation(reservation));
    apply_authority_reply(&mut actor).await;
    assert_eq!(actor.sessions.len(), 0);
    assert!(
        events.try_recv().is_err(),
        "terminal ACK must not duplicate Closed"
    );
    assert!(old_gate.check().is_err());
    let reservation = actor
        .sessions
        .reserve_outgoing(uuid::Uuid::new_v4().to_string())
        .unwrap();
    assert!(actor.sessions.release_reservation(reservation));
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}
