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
                ice_budget: IceBudget::default(),
                pending_ice: Vec::new(),
                closing: false,
                renew_at: Instant::now(),
                ready: true,
                ready_announced: true,
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
                    ice_budget: IceBudget::default(),
                    pending_ice: Vec::new(),
                    closing: false,
                    renew_at: Instant::now(),
                    ready: true,
                    ready_announced: true,
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
        actor
            .close_session(&id, SdkError::Closed, true)
            .await
            .unwrap();
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
    actor
        .close_session(&id, SdkError::Closed, false)
        .await
        .unwrap();
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
    actor
        .close_session(&id, SdkError::Closed, false)
        .await
        .unwrap();
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
    actor
        .close_session(&id, SdkError::Closed, true)
        .await
        .unwrap();
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

#[tokio::test]
async fn persisted_identity_has_no_periodic_credential_mutation() {
    use device_storage::{IdentityScope, MemoryIdentityStore, SecretString};
    let app = uuid::Uuid::new_v4().to_string();
    let config = SdkConfig::new("https://identity.example".into(), app.clone());
    let store = Arc::new(MemoryIdentityStore::default());
    let stored = StoredIdentity {
        device_id: uuid::Uuid::new_v4().to_string(),
        device_credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
    };
    let scope = IdentityScope {
        server_origin: "https://identity.example/".into(),
        application_id: app,
    };
    store.save(&scope, 0, stored.clone()).await.unwrap();
    let identity = DeviceSdk::identity(&config, store.clone()).await.unwrap();
    let (commands, _command_rx) = mpsc::channel(32);
    let (events, mut event_rx) = mpsc::channel(32);
    let mut actor = Actor::new(config, identity, stored.clone(), commands, events);
    // An elapsed maintenance deadline must not create a credential mutation job.
    actor.persist_at = Instant::now() - Duration::from_secs(48 * 3600);
    actor.retry_at = Instant::now() + Duration::from_secs(60);
    actor.tick().await.unwrap();
    assert!(actor.persist.is_none());
    actor.persist_needs_retry = true;
    actor
        .persisted(
            Err(IdentityError::Storage(
                device_storage::StorageError::Unavailable,
            )),
            Some(stored.clone()),
        )
        .await
        .unwrap();
    assert!(event_rx.try_recv().is_err());
    actor.persisted(Ok(()), Some(stored.clone())).await.unwrap();
    assert!(matches!(
        event_rx.try_recv().unwrap(),
        SdkEvent::IdentityPersisted
    ));
    actor.persisted(Ok(()), Some(stored.clone())).await.unwrap();
    assert!(event_rx.try_recv().is_err());
    let snapshot = store.load(&scope).await.unwrap();
    assert_eq!(snapshot.revision, 1);
    assert_eq!(
        snapshot.identity.unwrap().device_credential.expose(),
        stored.device_credential.expose()
    );
}

async fn pre_ready_actor() -> (Actor, mpsc::Receiver<SdkEvent>, String, String, String) {
    use device_storage::{IdentityScope, MemoryIdentityStore, SecretString};
    let app = uuid::Uuid::new_v4().to_string();
    let source = uuid::Uuid::new_v4().to_string();
    let target = uuid::Uuid::new_v4().to_string();
    let session_id = uuid::Uuid::new_v4().to_string();
    let request_id = uuid::Uuid::new_v4().to_string();
    let config = SdkConfig::new("https://reset.example".into(), app.clone());
    let store = Arc::new(MemoryIdentityStore::default());
    let stored = StoredIdentity {
        device_id: target.clone(),
        device_credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
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
    let (events, event_rx) = mpsc::channel(32);
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
                initial_request_id: Some(request_id.clone()),
                source: source.clone(),
                target: target.clone(),
                guard: LeaseGuard::new(session_id.clone(), source.clone(), target.clone()).unwrap(),
                gate: initial.clone(),
                worker: None,
                authority: None,
                ice_budget: IceBudget::default(),
                pending_ice: Vec::new(),
                closing: false,
                renew_at: Instant::now(),
                ready: false,
                ready_announced: false,
                generation: 1,
                recovery_at: None,
                recovery_attempt: 0,
                sync_pending: false,
                sync_requested: false,
                requests: std::collections::VecDeque::new(),
            },
        )
        .unwrap();

    (actor, event_rx, session_id, target, request_id)
}
#[tokio::test]
async fn accepted_request_closed_before_ready_keeps_request_correlation() {
    let (mut actor, mut event_rx, session_id, target, request_id) = pre_ready_actor().await;
    actor
        .close_session(&session_id, SdkError::Closed, false)
        .await
        .unwrap();
    match event_rx.try_recv().expect("terminal event") {
        SdkEvent::ConnectionRequestFailed {
            target_device_id,
            request_id: got,
            ..
        } => {
            assert_eq!(target_device_id, target);
            assert_eq!(got, request_id);
        }
        other => panic!("uncorrelated terminal event: {other:?}"),
    }
    actor
        .close_session(&session_id, SdkError::Closed, false)
        .await
        .unwrap();
    assert!(
        event_rx.try_recv().is_err(),
        "duplicate close must be silent"
    );
}

#[tokio::test]
async fn pre_ready_terminal_waits_for_worker_and_rejects_unknown_cleanup() {
    for fail in [false, true] {
        let (mut actor, mut events, id, _, _) = pre_ready_actor().await;
        let (control, _) = mpsc::channel(1);
        let (stop, stopped) = oneshot::channel();
        let joined = Arc::new(AtomicBool::new(false));
        let finished = joined.clone();
        actor.sessions.get_mut(&id).unwrap().worker = Some(Worker {
            control,
            stop: Some(stop),
            task: tokio::spawn(async move {
                stopped.await.unwrap();
                tokio::task::yield_now().await;
                finished.store(true, Ordering::Release);
                if fail {
                    Err(SdkError::RequestOutcomeUnknown)
                } else {
                    Ok(())
                }
            }),
        });
        let result = actor.close_session(&id, SdkError::Closed, false).await;
        assert!(joined.load(Ordering::Acquire));
        if fail {
            assert_eq!(result, Err(SdkError::RequestOutcomeUnknown));
            assert!(
                events.try_recv().is_err(),
                "unknown cleanup cannot claim request drain"
            );
        } else {
            result.unwrap();
            assert!(matches!(
                events.try_recv().unwrap(),
                SdkEvent::ConnectionRequestFailed { .. }
            ));
        }
    }
}

#[tokio::test]
async fn pre_ready_old_generation_close_cannot_fail_current_request() {
    let (mut actor, mut events, id, _, request_id) = pre_ready_actor().await;
    actor.sessions.get_mut(&id).unwrap().generation = 2;
    actor
        .internal(Internal::Closed(id.clone(), 1, SdkError::Closed))
        .await
        .unwrap();
    assert!(events.try_recv().is_err());
    assert!(!actor.sessions.get(&id).unwrap().closing);
    actor
        .internal(Internal::Closed(id.clone(), 2, SdkError::Closed))
        .await
        .unwrap();
    assert!(
        matches!(events.try_recv().unwrap(), SdkEvent::ConnectionRequestFailed {request_id: got, ..} if got == request_id)
    );
    actor
        .internal(Internal::Closed(id, 2, SdkError::Closed))
        .await
        .unwrap();
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn pre_ready_recovery_is_not_terminal_and_published_ready_survives_recovery() {
    for announced in [false, true] {
        let (mut actor, mut events, id, _, _) = pre_ready_actor().await;
        actor.sessions.get_mut(&id).unwrap().ready_announced = announced;
        actor.prepare_recovery(&id, SdkError::Closed).await.unwrap();
        if announced {
            assert!(matches!(
                events.try_recv().unwrap(),
                SdkEvent::ConnectionClosed { .. }
            ));
        } else {
            assert!(events.try_recv().is_err());
        }
        actor
            .close_session(&id, SdkError::Closed, false)
            .await
            .unwrap();
        let event = events.try_recv().unwrap();
        assert!(if announced {
            matches!(event, SdkEvent::ConnectionClosed { .. })
        } else {
            matches!(event, SdkEvent::ConnectionRequestFailed { .. })
        });
    }
}

#[tokio::test]
async fn pre_ready_publish_success_queue_failure_and_late_ready_are_distinct() {
    for full in [false, true] {
        let (mut actor, mut events, id, _, _) = pre_ready_actor().await;
        let now = Instant::now();
        #[allow(deprecated)]
        let clock = ServerClockBound::from_hello("2026-10-28T00:00:00Z", now).unwrap();
        let session = actor.sessions.get_mut(&id).unwrap();
        let message: Envelope = serde_json::from_value(json!({
            "v":1,"type":"session.updated","id":uuid::Uuid::new_v4().to_string(),
            "session_id":id,"connection_generation":1,
            "fencing_token":"12345678901234567890123456789012","seq":1,
            "sent_at":"2026-10-28T00:00:00Z",
            "payload":{"session_id":id,"source_device_id":session.source,
                "target_device_id":session.target,"state":"connecting","lease_generation":1,
                "lease_expires_at":"2026-10-28T00:01:00Z",
                "source_lease_expires_at":"2026-10-28T00:01:00Z",
                "target_lease_expires_at":"2026-10-28T00:01:00Z"}
        }))
        .unwrap();
        session.guard.apply(&message, &clock, now).unwrap();
        session.gate.update(session.guard.deadline());
        if full {
            for _ in 0..32 {
                actor.emit(SdkEvent::Online).unwrap();
            }
        }
        let (mut connection, _, _) = channels::test_connection();
        connection.session_id = id.clone();
        let result = actor
            .internal(Internal::Ready(id.clone(), 1, connection))
            .await;
        assert_eq!(actor.sessions.get(&id).unwrap().ready_announced, !full);
        if full {
            assert_eq!(result, Err(SdkError::QueueFull));
            for _ in 0..32 {
                assert!(matches!(events.try_recv().unwrap(), SdkEvent::Online));
            }
        } else {
            result.unwrap();
            assert!(matches!(
                events.try_recv().unwrap(),
                SdkEvent::ConnectionReady(_)
            ));
        }
        actor
            .close_session(&id, SdkError::Closed, false)
            .await
            .unwrap();
        let terminal = events.try_recv().unwrap();
        assert!(if full {
            matches!(terminal, SdkEvent::ConnectionRequestFailed { .. })
        } else {
            matches!(terminal, SdkEvent::ConnectionClosed { .. })
        });
        let (late, _, _) = channels::test_connection();
        actor.internal(Internal::Ready(id, 1, late)).await.unwrap();
        assert!(
            events.try_recv().is_err(),
            "late Ready cannot resurrect retired session"
        );
    }
}

#[tokio::test]
async fn pre_ready_transport_ready_without_published_event_stays_request_on_replacement() {
    let (mut actor, mut events, id, _, request_id) = pre_ready_actor().await;
    actor.sessions.get_mut(&id).unwrap().ready = true;
    actor.replace_generation(&id, 2).await.unwrap();
    assert!(events.try_recv().is_err());
    actor
        .close_session(&id, SdkError::Closed, false)
        .await
        .unwrap();
    assert!(
        matches!(events.try_recv().unwrap(), SdkEvent::ConnectionRequestFailed { request_id: got, .. } if got == request_id)
    );
}

#[tokio::test]
async fn pre_ready_stop_cancels_negotiation_without_unknown_drain() {
    let gate = Gate::default();
    let started = AtomicBool::new(false);
    struct DropMarker(Arc<AtomicBool>);
    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let marker = DropMarker(dropped.clone());
    let operation = async move {
        let _marker = marker;
        std::future::pending::<Result<(), SdkError>>().await
    };
    {
        tokio::pin!(operation);
        tokio::time::timeout(
            Duration::from_millis(100),
            wait_established_cleanup(operation.as_mut(), &gate, &started),
        )
        .await
        .expect("negotiation cancellation must not wait for an unanswered SDP");
    }
    assert!(
        dropped.load(Ordering::Acquire),
        "cancel before native peer close"
    );
    assert_eq!(gate.cleanup.merge_result(Ok(())), Ok(()));
    // A later native close failure still blocks success, even without workers.
    assert_eq!(
        gate.cleanup
            .merge_result(Err(SdkError::RequestOutcomeUnknown)),
        Err(SdkError::RequestOutcomeUnknown)
    );
}

#[tokio::test]
async fn pre_ready_stop_preserves_started_channel_cleanup_barrier() {
    let gate = Gate::default();
    let started = AtomicBool::new(true);
    let operation = std::future::pending::<Result<(), SdkError>>();
    tokio::pin!(operation);
    wait_established_cleanup(operation.as_mut(), &gate, &started).await;
    assert_eq!(
        gate.cleanup.merge_result(Ok(())),
        Err(SdkError::RequestOutcomeUnknown),
        "successful peer close cannot hide unfinished SDK channel workers"
    );
}

#[tokio::test]
async fn pre_ready_stop_waits_for_started_channel_cleanup() {
    let gate = Gate::default();
    let started = AtomicBool::new(true);
    let finished = AtomicBool::new(false);
    let operation = async {
        tokio::task::yield_now().await;
        finished.store(true, Ordering::Release);
        Ok(())
    };
    tokio::pin!(operation);
    wait_established_cleanup(operation.as_mut(), &gate, &started).await;
    assert!(finished.load(Ordering::Acquire));
    assert_eq!(gate.cleanup.merge_result(Ok(())), Ok(()));
}

fn ice_message(mut initial: Envelope, generation: u64, complete: bool) -> Envelope {
    initial.kind = "session.ice".into();
    initial.negotiation_generation = Some(generation);
    initial.payload = if complete {
        json!({"candidates":[],"complete":true})
    } else {
        json!({"candidates":[{"candidate":"candidate:1 1 UDP 1 192.0.2.1 1234 typ host",
            "sdp_mid":"0","sdp_mline_index":0,"username_fragment":"test"}],"complete":false})
    };
    initial
}

#[tokio::test]
async fn early_ice_waits_for_authority_and_old_generation_is_cleared() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    let id = uuid::Uuid::new_v4().to_string();
    let initial = capacity_snapshot(&actor, &id, false);
    let mut live = initial.clone();
    live.payload["state"] = json!("connecting");
    live.payload["negotiation_generation"] = json!(2);
    live.payload["lease_generation"] = json!(2);
    authority.lock().unwrap().insert(id.clone(), live);
    actor.message(initial.clone()).await.unwrap();
    actor
        .message(ice_message(initial.clone(), 1, false))
        .await
        .unwrap();
    actor
        .message(ice_message(initial.clone(), 1, true))
        .await
        .unwrap();
    actor
        .message(ice_message(initial.clone(), 1, true))
        .await
        .unwrap();
    let session = actor.sessions.get(&id).unwrap();
    assert_eq!(session.pending_ice.len(), 2);
    assert!(session.worker.is_none());
    assert!(session.gate.check().is_err());
    assert!(events.try_recv().is_err());
    apply_authority_reply(&mut actor).await;
    let session = actor.sessions.get(&id).unwrap();
    assert_eq!(session.generation, 2);
    assert!(session.pending_ice.is_empty());
    // Late old-generation traffic cannot consume the new generation's budget.
    for _ in 0..300 {
        actor
            .message(ice_message(initial.clone(), 1, false))
            .await
            .unwrap();
    }
    assert!(actor.sessions.get(&id).unwrap().pending_ice.is_empty());
    for _ in 0..256 {
        actor
            .message(ice_message(initial.clone(), 2, false))
            .await
            .unwrap();
    }
    assert_eq!(actor.sessions.get(&id).unwrap().pending_ice.len(), 1);
    actor
        .close_session(&id, SdkError::Closed, false)
        .await
        .unwrap();
    assert!(actor.sessions.get(&id).unwrap().pending_ice.is_empty());
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn pending_authority_ice_overflow_refuses_locally_without_remote_close() {
    let (mut actor, mut events, server, authority) = capacity_actor(0).await;
    let id = uuid::Uuid::new_v4().to_string();
    let initial = capacity_snapshot(&actor, &id, false);
    authority
        .lock()
        .unwrap()
        .insert(id.clone(), initial.clone());
    actor.message(initial.clone()).await.unwrap();
    for _ in 0..256 {
        actor
            .message(ice_message(initial.clone(), 1, false))
            .await
            .unwrap();
    }
    assert_eq!(actor.sessions.get(&id).unwrap().pending_ice.len(), 1);
    actor.message(ice_message(initial, 1, false)).await.unwrap();
    assert!(actor.sessions.get(&id).is_none());
    assert!(matches!(
        events.try_recv().unwrap(),
        SdkEvent::ConnectionClosed {
            reason: SdkError::Signal(SignalError::QueueFull),
            ..
        }
    ));
    assert!(events.try_recv().is_err());
    actor.signal.take().unwrap().close().await;
    server.await.unwrap();
}
