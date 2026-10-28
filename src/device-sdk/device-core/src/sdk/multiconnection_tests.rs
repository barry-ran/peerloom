use super::*;

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
                source: source.clone(),
                target: target.clone(),
                guard: LeaseGuard::new(session_id.clone(), source.clone(), target.clone()).unwrap(),
                gate: initial.clone(),
                worker: None,
                renew_at: Instant::now(),
                ready: true,
                generation: 1,
                recovery_at: None,
                recovery_attempt: 0,
                sync_pending: false,
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
    assert_eq!(actor.sessions.len(), 0);
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
        assert_eq!(actor.sessions.len(), 0);
        assert!(actor.sessions.has_seen(&session_id));
        assert!(initial.closed.load(Ordering::Acquire));
    }
}
