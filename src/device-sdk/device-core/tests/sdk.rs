use device_core::{
    sdk::{DeviceSdk, SdkConfig, SdkError, SdkEvent},
    signaling::SignalError,
};
use device_storage::{
    IdentityScope, IdentityStore, MemoryIdentityStore, SecretString, StoredIdentity,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_tungstenite::tungstenite::{
    Message,
    protocol::{CloseFrame, frame::coding::CloseCode},
};
const APP: &str = "00000000-0000-4000-8000-000000000001";
const DEVICE: &str = "00000000-0000-4000-8000-000000000002";
async fn setup() -> (TcpListener, SdkConfig, Arc<MemoryIdentityStore>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let store = Arc::new(MemoryIdentityStore::default());
    store
        .save(
            &IdentityScope {
                server_origin: origin.clone(),
                application_id: APP.into(),
            },
            0,
            StoredIdentity {
                device_id: DEVICE.into(),
                device_credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
                expires_at: "2027-01-01T00:00:00Z".into(),
            },
        )
        .await
        .unwrap();
    let mut config = SdkConfig::new(origin, APP.into());
    config.development_loopback = true;
    (listener, config, store)
}
async fn serve_self(listener: &TcpListener) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut bytes = [0u8; 4096];
    let n = socket.read(&mut bytes).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes[..n]).starts_with("GET /v1/device-self"));
    let body=json!({"device_id":DEVICE,"application_id":APP,"tenant_id":APP,"platform":"linux","metadata":{}}).to_string();
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
}
async fn handshake(
    listener: &TcpListener,
    generation: u64,
) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
    let (socket, _) = listener.accept().await.unwrap();
    let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
    let message = socket.next().await.unwrap().unwrap();
    let hello: serde_json::Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
    let ack = json!({"v":1,"type":"hello.ack","id":uuid::Uuid::new_v4().to_string(),"request_id":hello["id"],"connection_generation":generation,"fencing_token":"12345678901234567890123456789012","seq":0,"sent_at":"2026-10-28T00:00:00Z","payload":{"heartbeat_interval_seconds":15,"presence_ttl_seconds":45}});
    socket
        .send(Message::Text(ack.to_string().into()))
        .await
        .unwrap();
    socket
}
async fn next(sdk: &mut DeviceSdk) -> SdkEvent {
    tokio::time::timeout(Duration::from_secs(5), sdk.next_event())
        .await
        .unwrap()
        .unwrap()
}
#[tokio::test]
async fn network_loss_reconnects_by_default_and_explicit_close_stops() {
    let (listener, config, store) = setup().await;
    let server = tokio::spawn(async move {
        serve_self(&listener).await;
        drop(handshake(&listener, 1).await);
        let mut socket = handshake(&listener, 2).await;
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
        let _ = socket.flush().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    let mut sdk = DeviceSdk::load(config, store).await.unwrap();
    assert!(matches!(next(&mut sdk).await, SdkEvent::Online));
    assert!(matches!(next(&mut sdk).await, SdkEvent::Offline));
    assert!(matches!(next(&mut sdk).await, SdkEvent::Online));
    sdk.close().await;
    server.await.unwrap();
}
#[tokio::test]
async fn permanent_http_authorization_failure_stops_reconnect() {
    let (listener, config, store) = setup().await;
    let server = tokio::spawn(async move {
        serve_self(&listener).await;
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0u8; 4096];
        assert!(socket.read(&mut bytes).await.unwrap() > 0);
        socket
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
    });
    let mut sdk = DeviceSdk::load(config, store).await.unwrap();
    assert!(matches!(next(&mut sdk).await, SdkEvent::Offline));
    assert!(matches!(
        next(&mut sdk).await,
        SdkEvent::Stopped(SdkError::Signal(SignalError::AuthorizationRejected))
    ));
    sdk.close().await;
    server.await.unwrap();
}
#[tokio::test]
async fn policy_close_stops_instead_of_stealing_fence_back() {
    let (listener, config, store) = setup().await;
    let server = tokio::spawn(async move {
        serve_self(&listener).await;
        let mut socket = handshake(&listener, 1).await;
        socket
            .close(Some(CloseFrame {
                code: CloseCode::Policy,
                reason: "REPLACED".into(),
            }))
            .await
            .unwrap();
        let _ = socket.next().await;
    });
    let mut sdk = DeviceSdk::load(config, store).await.unwrap();
    assert!(matches!(next(&mut sdk).await, SdkEvent::Online));
    assert!(matches!(next(&mut sdk).await, SdkEvent::Offline));
    assert!(matches!(
        next(&mut sdk).await,
        SdkEvent::Stopped(SdkError::Signal(SignalError::PolicyRejected))
    ));
    sdk.close().await;
    server.await.unwrap();
}
#[tokio::test]
async fn capacity_above_bounded_multiconnection_limit_is_rejected() {
    let (_listener, mut config, store) = setup().await;
    config.max_connections = 33;
    assert!(matches!(
        DeviceSdk::load(config, store).await,
        Err(SdkError::InvalidConfiguration)
    ));
}
#[tokio::test]
async fn lost_request_response_does_not_leave_permanent_busy() {
    let (listener, config, store) = setup().await;
    let server = tokio::spawn(async move {
        serve_self(&listener).await;
        let mut first = handshake(&listener, 1).await;
        let request = first.next().await.unwrap().unwrap();
        assert!(request.to_text().unwrap().contains("session.request"));
        drop(first);
        let mut second = handshake(&listener, 2).await;
        let request = second.next().await.unwrap().unwrap();
        assert!(request.to_text().unwrap().contains("session.request"));
        let _ = second.next().await;
    });
    let mut sdk = DeviceSdk::load(config, store).await.unwrap();
    assert!(matches!(next(&mut sdk).await, SdkEvent::Online));
    sdk.connect("00000000-0000-4000-8000-000000000003")
        .await
        .unwrap();
    assert!(matches!(next(&mut sdk).await, SdkEvent::Offline));
    assert!(matches!(
        next(&mut sdk).await,
        SdkEvent::ConnectionRequestFailed {
            reason: SdkError::RequestOutcomeUnknown,
            ..
        }
    ));
    assert!(matches!(next(&mut sdk).await, SdkEvent::Online));
    sdk.connect("00000000-0000-4000-8000-000000000003")
        .await
        .unwrap();
    sdk.close().await;
    server.await.unwrap();
}
fn pending(session: &str, seq: u64) -> serde_json::Value {
    json!({"v":1,"type":"session.pending","id":uuid::Uuid::new_v4().to_string(),"session_id":session,"connection_generation":1,"fencing_token":"12345678901234567890123456789012","seq":seq,"sent_at":"2026-10-28T00:00:00Z","payload":{"session_id":session,"source_device_id":"00000000-0000-4000-8000-000000000003","target_device_id":DEVICE,"state":"authorizing","lease_generation":1,"lease_expires_at":"2026-10-28T00:00:30Z","source_lease_expires_at":"2026-10-28T00:00:30Z","target_lease_expires_at":"2026-10-28T00:00:30Z"}})
}
#[tokio::test]
async fn busy_rejection_does_not_echo_terminated_forever() {
    let (listener, config, store) = setup().await;
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    let server_a = a.clone();
    let (check_tx, check_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        serve_self(&listener).await;
        let mut socket = handshake(&listener, 1).await;
        socket
            .send(Message::Text(pending(&server_a, 1).to_string().into()))
            .await
            .unwrap();
        socket
            .send(Message::Text(pending(&b, 2).to_string().into()))
            .await
            .unwrap();
        let rejected = socket.next().await.unwrap().unwrap();
        assert!(rejected.to_text().unwrap().contains("session.reject"));
        let mut closed = pending(&b, 3);
        closed["type"] = json!("session.terminated");
        closed["payload"]["state"] = json!("closed");
        socket
            .send(Message::Text(closed.to_string().into()))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), socket.next())
                .await
                .is_err(),
            "must not reject already terminated session"
        );
        check_tx.send(()).unwrap();
        let accept = socket.next().await.unwrap().unwrap();
        assert!(accept.to_text().unwrap().contains("session.accept"));
        let _ = socket.next().await;
    });
    let mut sdk = DeviceSdk::load(config, store).await.unwrap();
    assert!(matches!(next(&mut sdk).await, SdkEvent::Online));
    assert!(matches!(
        next(&mut sdk).await,
        SdkEvent::IncomingConnection { .. }
    ));
    check_rx.await.unwrap();
    sdk.accept(&a).await.unwrap();
    sdk.close().await;
    server.await.unwrap();
}
struct FailingPersistence;
#[async_trait::async_trait]
impl IdentityStore for FailingPersistence {
    async fn load(
        &self,
        _: &IdentityScope,
    ) -> Result<device_storage::Snapshot, device_storage::StorageError> {
        Ok(Default::default())
    }
    async fn save(
        &self,
        _: &IdentityScope,
        _: u64,
        _: StoredIdentity,
    ) -> Result<u64, device_storage::StorageError> {
        Err(device_storage::StorageError::Unavailable)
    }
    async fn delete(&self, _: &IdentityScope, _: u64) -> Result<u64, device_storage::StorageError> {
        Err(device_storage::StorageError::Unavailable)
    }
}
#[tokio::test]
async fn registration_persistence_failure_keeps_usable_sdk_identity() {
    let (listener, config, _store) = setup().await;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0u8; 8192];
        let n = socket.read(&mut bytes).await.unwrap();
        assert!(String::from_utf8_lossy(&bytes[..n]).starts_with("POST /v1/device-registrations"));
        let body=json!({"device_id":DEVICE,"device_credential":format!("dev_{}","a".repeat(43)),"expires_at":"2027-01-01T00:00:00Z"}).to_string();
        socket.write_all(format!("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        drop(socket);
        let mut socket = handshake(&listener, 1).await;
        let _ = socket.next().await;
    });
    let request = device_core::identity::RegistrationRequest {
        application_id: APP.into(),
        platform: device_core::identity::Platform::Linux,
        installation_public_key: "test".into(),
        registration_grant: SecretString::new("reg_test".into()),
        sdk_version: "test".into(),
        metadata: Default::default(),
    };
    let mut sdk = DeviceSdk::register(
        config,
        Arc::new(FailingPersistence),
        request,
        device_core::identity::IdempotencyKey::random(),
    )
    .await
    .unwrap();
    assert_eq!(sdk.device_id(), DEVICE);
    assert!(matches!(
        next(&mut sdk).await,
        SdkEvent::IdentityPersistencePending
    ));
    assert!(matches!(next(&mut sdk).await, SdkEvent::Online));
    sdk.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn reset_stops_actor_and_preserves_tombstone_without_automatic_registration() {
    let (listener, config, store) = setup().await;
    let scope = IdentityScope {
        server_origin: config.origin.clone(),
        application_id: APP.into(),
    };
    let server = tokio::spawn(async move {
        serve_self(&listener).await;
        let mut socket = handshake(&listener, 1).await;
        let frame = tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap();
        assert!(matches!(frame, Some(Ok(Message::Close(_))) | None));
    });
    let mut sdk = DeviceSdk::load(config, store.clone()).await.unwrap();
    assert!(matches!(sdk.next_event().await, Some(SdkEvent::Online)));
    assert_eq!(sdk.reset(APP).await, Err(SdkError::InvalidConfiguration));
    assert!(!sdk.is_resetting());
    sdk.reset(DEVICE).await.unwrap();
    assert!(sdk.is_resetting());
    assert_eq!(sdk.connect(APP).await, Err(SdkError::Closed));
    assert_eq!(sdk.refresh_credentials().await, Err(SdkError::Closed));
    assert!(sdk.next_event().await.is_none());
    let snapshot = store.load(&scope).await.unwrap();
    assert_eq!(snapshot.revision, 2);
    assert!(snapshot.identity.is_none());
    sdk.retry_reset(DEVICE).await.unwrap();
    assert_eq!(store.load(&scope).await.unwrap().revision, 2);
    sdk.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn two_pending_requests_release_only_correlated_denial() {
    let (listener, mut config, store) = setup().await;
    config.max_connections = 2;
    let (both_tx, both_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        serve_self(&listener).await;
        let mut socket = handshake(&listener, 1).await;
        let mut requests = Vec::new();
        for _ in 0..2 {
            let frame = socket.next().await.unwrap().unwrap();
            let request: serde_json::Value =
                serde_json::from_str(frame.to_text().unwrap()).unwrap();
            assert_eq!(request["type"], "session.request");
            requests.push(request);
        }
        // Both requests have reached the server before either outcome is sent.
        both_tx.send(()).unwrap();
        let mut denied = pending(&uuid::Uuid::new_v4().to_string(), 1);
        denied["type"] = json!("error");
        denied.as_object_mut().unwrap().remove("session_id");
        denied["request_id"] = requests[0]["id"].clone();
        denied["payload"] = json!({"code":"GRANT_DENIED"});
        socket
            .send(Message::Text(denied.to_string().into()))
            .await
            .unwrap();
        let frame = socket.next().await.unwrap().unwrap();
        assert!(frame.to_text().unwrap().contains("session.request"));
        let _ = socket.next().await;
    });
    let mut sdk = DeviceSdk::load(config, store).await.unwrap();
    assert!(matches!(next(&mut sdk).await, SdkEvent::Online));
    let first = "00000000-0000-4000-8000-000000000003";
    let second = "00000000-0000-4000-8000-000000000004";
    let request = sdk.connect_with_request(first).await.unwrap();
    let sibling = sdk.connect_with_request(second).await.unwrap();
    assert_ne!(request, sibling);
    both_rx.await.unwrap();
    match next(&mut sdk).await {
        SdkEvent::ConnectionRequestFailed {
            target_device_id,
            request_id,
            reason,
        } => {
            assert_eq!(target_device_id, first);
            assert_eq!(request_id, request);
            assert_eq!(reason, SdkError::Rejected("GRANT_DENIED".into()));
        }
        other => panic!("uncorrelated failure: {other:?}"),
    }
    sdk.connect(first).await.unwrap();
    assert_eq!(sdk.connect(first).await, Err(SdkError::Busy));
    sdk.close().await;
    server.await.unwrap();
}
