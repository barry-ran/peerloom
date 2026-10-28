use device_core::identity::*;
use device_storage::*;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
const APP: &str = "00000000-0000-4000-8000-000000000001";
const DEVICE: &str = "00000000-0000-4000-8000-000000000002";
fn request() -> RegistrationRequest {
    RegistrationRequest {
        application_id: APP.into(),
        platform: Platform::Linux,
        installation_public_key: "test-key".into(),
        registration_grant: SecretString::new("reg_test".into()),
        sdk_version: "0.1.0".into(),
        metadata: Default::default(),
    }
}
fn body(token: char) -> String {
    format!(
        r#"{{"device_id":"{DEVICE}","device_credential":"dev_{}","expires_at":"2027-01-01T00:00:00Z"}}"#,
        token.to_string().repeat(43)
    )
}
async fn server(
    responses: Vec<(u16, String)>,
) -> (IdentityClient, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = IdentityClient::new(
        &format!("http://{}", listener.local_addr().unwrap()),
        true,
        Duration::from_secs(2),
    )
    .unwrap();
    let handle = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let len = headers
                        .lines()
                        .find_map(|s| s.strip_prefix("content-length: "))
                        .map(|s| s.parse::<usize>().unwrap())
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(bytes).unwrap());
            socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
        requests
    });
    (client, handle)
}
#[test]
fn tls_and_origin_policy() {
    for url in [
        "http://example.com",
        "http://localhost",
        "http://127.0.0.1.evil.test",
        "https://u:p@example.com",
        "https://example.com/path",
        "https://example.com?token=x",
    ] {
        assert!(
            IdentityClient::new(url, true, Duration::from_secs(2)).is_err(),
            "{url}"
        );
    }
    assert!(IdentityClient::new("http://127.0.0.1", false, Duration::from_secs(2)).is_err());
    assert!(IdentityClient::new("https://example.com", false, Duration::from_secs(2)).is_ok());
    assert!(IdentityClient::new("http://[::1]", true, Duration::from_secs(2)).is_ok());
    assert!(IdempotencyKey::new("contains\nnewline".into()).is_err());
}
#[tokio::test]
async fn registration_and_rotation_use_exact_contract() {
    let (client, handle) = server(vec![(201, body('a')), (200, body('b'))]).await;
    let store = Arc::new(MemoryIdentityStore::default());
    let mut session = IdentitySession::load(client, APP.into(), store)
        .await
        .unwrap();
    session
        .register(request(), IdempotencyKey::new("register-1".into()).unwrap())
        .await
        .unwrap();
    session
        .refresh(IdempotencyKey::new("refresh-1".into()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        session.identity().unwrap().device_credential.expose(),
        format!("dev_{}", "b".repeat(43))
    );
    let requests = handle.await.unwrap();
    assert!(requests[0].starts_with("POST /v1/device-registrations HTTP/1.1"));
    assert!(requests[0].contains("idempotency-key: register-1"));
    assert!(!requests[0].contains("authorization:"));
    assert!(requests[1].contains(&format!("authorization: Bearer dev_{}", "a".repeat(43))));
    assert!(requests[1].ends_with("{}"));
}
struct FailingStore;
#[async_trait::async_trait]
impl IdentityStore for FailingStore {
    async fn load(&self, _: &IdentityScope) -> Result<Snapshot, StorageError> {
        Ok(Snapshot::default())
    }
    async fn save(
        &self,
        _: &IdentityScope,
        _: u64,
        _: StoredIdentity,
    ) -> Result<u64, StorageError> {
        Err(StorageError::Unavailable)
    }
    async fn delete(&self, _: &IdentityScope, _: u64) -> Result<u64, StorageError> {
        Err(StorageError::Unavailable)
    }
}
#[tokio::test]
async fn persistence_failure_keeps_new_credential_and_blocks_rotation() {
    let (client, handle) = server(vec![(201, body('a'))]).await;
    let mut session = IdentitySession::load(client, APP.into(), Arc::new(FailingStore))
        .await
        .unwrap();
    assert_eq!(
        session.register(request(), IdempotencyKey::random()).await,
        Err(IdentityError::Storage(StorageError::Unavailable))
    );
    assert!(session.identity().is_some());
    assert!(session.needs_persistence());
    assert!(!session.has_pending_mutation());
    assert_eq!(
        session.refresh(IdempotencyKey::random()).await,
        Err(IdentityError::PendingMutation)
    );
    handle.await.unwrap();
}
#[tokio::test]
async fn uncertain_mutation_retries_same_body_and_key() {
    let (client, handle) = server(vec![
        (503, r#"{"code":"COMMIT_UNCERTAIN_RETRY_SAME_KEY"}"#.into()),
        (201, body('a')),
    ])
    .await;
    let mut session =
        IdentitySession::load(client, APP.into(), Arc::new(MemoryIdentityStore::default()))
            .await
            .unwrap();
    assert!(
        session
            .register(request(), IdempotencyKey::random())
            .await
            .is_err()
    );
    assert!(session.has_pending_mutation());
    assert_eq!(
        session.register(request(), IdempotencyKey::random()).await,
        Err(IdentityError::PendingMutation)
    );
    session.retry_pending().await.unwrap();
    let requests = handle.await.unwrap();
    assert_eq!(requests[0], requests[1]);
}
#[tokio::test]
async fn response_limits_and_error_redaction() {
    let (client, handle) = server(vec![
        (201, "x".repeat(65537)),
        (
            400,
            r#"{"code":"secret-dev_token","detail":"raw secret"}"#.into(),
        ),
    ])
    .await;
    assert!(matches!(
        client.register(&request(), &IdempotencyKey::random()).await,
        Err(IdentityError::ResponseTooLarge)
    ));
    let error = client
        .register(&request(), &IdempotencyKey::random())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        IdentityError::Server {
            status: 400,
            code: "UNKNOWN_SERVER_ERROR".into()
        }
    );
    assert!(!format!("{error:?}").contains("raw secret"));
    handle.await.unwrap();
}
#[tokio::test]
async fn cancellation_retains_exact_mutation_for_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = IdentityClient::new(
        &format!("http://{}", listener.local_addr().unwrap()),
        true,
        Duration::from_secs(2),
    )
    .unwrap();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let mut bytes = [0u8; 8192];
        let n = first.read(&mut bytes).await.unwrap();
        let original = String::from_utf8_lossy(&bytes[..n]).into_owned();
        seen_tx.send(()).unwrap();
        let (mut second, _) = listener.accept().await.unwrap();
        let n = second.read(&mut bytes).await.unwrap();
        let retry = String::from_utf8_lossy(&bytes[..n]).into_owned();
        assert_eq!(original, retry);
        let body = body('a');
        second.write_all(format!("HTTP/1.1 201 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    });
    let mut session =
        IdentitySession::load(client, APP.into(), Arc::new(MemoryIdentityStore::default()))
            .await
            .unwrap();
    {
        let mutation = session.register(request(), IdempotencyKey::random());
        tokio::pin!(mutation);
        tokio::select! { _=seen_rx=>{}, result=&mut mutation=>panic!("unexpected completion {result:?}") }
    }
    assert!(session.has_pending_mutation());
    session.retry_pending().await.unwrap();
    task.await.unwrap();
}
struct DelayedStore {
    saved: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl IdentityStore for DelayedStore {
    async fn load(&self, _: &IdentityScope) -> Result<Snapshot, StorageError> {
        Ok(Snapshot::default())
    }
    async fn save(
        &self,
        _: &IdentityScope,
        _: u64,
        _: StoredIdentity,
    ) -> Result<u64, StorageError> {
        self.saved.notify_one();
        std::future::pending().await
    }
    async fn delete(&self, _: &IdentityScope, _: u64) -> Result<u64, StorageError> {
        Err(StorageError::Unavailable)
    }
}
#[tokio::test]
async fn cancellation_during_storage_retains_new_identity() {
    let (client, handle) = server(vec![(201, body('a'))]).await;
    let store = Arc::new(DelayedStore {
        saved: tokio::sync::Notify::new(),
    });
    let mut session = IdentitySession::load(client, APP.into(), store.clone())
        .await
        .unwrap();
    {
        let mutation = session.register(request(), IdempotencyKey::random());
        tokio::pin!(mutation);
        tokio::select! { _=store.saved.notified()=>{}, result=&mut mutation=>panic!("unexpected completion {result:?}") }
    }
    assert!(session.identity().is_some());
    assert!(session.needs_persistence());
    assert!(!session.has_pending_mutation());
    handle.await.unwrap();
}
#[tokio::test]
async fn stale_owner_cannot_overwrite_new_persistent_identity() {
    let (client, handle) = server(vec![(201, body('a')), (201, body('b'))]).await;
    let store = Arc::new(MemoryIdentityStore::default());
    let mut first = IdentitySession::load(client.clone(), APP.into(), store.clone())
        .await
        .unwrap();
    let mut stale = IdentitySession::load(client, APP.into(), store)
        .await
        .unwrap();
    first
        .register(request(), IdempotencyKey::random())
        .await
        .unwrap();
    assert_eq!(
        stale.register(request(), IdempotencyKey::random()).await,
        Err(IdentityError::Storage(StorageError::Conflict))
    );
    assert!(stale.needs_persistence());
    assert!(
        stale
            .identity()
            .unwrap()
            .device_credential
            .expose()
            .ends_with(&"b".repeat(43))
    );
    handle.await.unwrap();
}
#[tokio::test]
async fn redirect_is_not_followed() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = IdentityClient::new(
        &format!("http://{}", listener.local_addr().unwrap()),
        true,
        Duration::from_secs(2),
    )
    .unwrap();
    let target_address = target.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0u8; 8192];
        assert!(socket.read(&mut bytes).await.unwrap() > 0);
        socket.write_all(format!("HTTP/1.1 307 Redirect\r\nLocation: http://{target_address}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    });
    assert!(
        client
            .register(&request(), &IdempotencyKey::random())
            .await
            .is_err()
    );
    task.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
}
struct CommitThenWaitStore {
    inner: MemoryIdentityStore,
    saved: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl IdentityStore for CommitThenWaitStore {
    async fn load(&self, scope: &IdentityScope) -> Result<Snapshot, StorageError> {
        self.inner.load(scope).await
    }
    async fn save(
        &self,
        scope: &IdentityScope,
        revision: u64,
        identity: StoredIdentity,
    ) -> Result<u64, StorageError> {
        self.inner.save(scope, revision, identity).await?;
        self.saved.notify_one();
        std::future::pending().await
    }
    async fn delete(&self, scope: &IdentityScope, revision: u64) -> Result<u64, StorageError> {
        self.inner.delete(scope, revision).await
    }
}
#[tokio::test]
async fn cancelled_committed_save_recovers_without_overwriting() {
    let (client, handle) = server(vec![(201, body('a'))]).await;
    let store = Arc::new(CommitThenWaitStore {
        inner: MemoryIdentityStore::default(),
        saved: tokio::sync::Notify::new(),
    });
    let mut session = IdentitySession::load(client, APP.into(), store.clone())
        .await
        .unwrap();
    {
        let mutation = session.register(request(), IdempotencyKey::random());
        tokio::pin!(mutation);
        tokio::select! {_=store.saved.notified()=>{}, result=&mut mutation=>panic!("unexpected {result:?}")}
    }
    assert!(session.needs_persistence());
    session.retry_persist().await.unwrap();
    assert!(!session.needs_persistence());
    handle.await.unwrap();
}
#[tokio::test]
async fn uppercase_application_uses_canonical_scope() {
    let lower = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let (client, handle) = server(vec![(201, body('a'))]).await;
    let store = Arc::new(MemoryIdentityStore::default());
    let mut session = IdentitySession::load(client.clone(), lower.to_uppercase(), store.clone())
        .await
        .unwrap();
    let mut registration = request();
    registration.application_id = lower.to_uppercase();
    session
        .register(registration, IdempotencyKey::random())
        .await
        .unwrap();
    let restored = IdentitySession::load(client, lower.into(), store)
        .await
        .unwrap();
    assert!(restored.identity().is_some());
    assert!(handle.await.unwrap()[0].contains(lower));
}

#[tokio::test]
async fn direct_registration_uses_secret_recovery_key_and_omits_grant() {
    let (client, server) = server(vec![(201, body('a')), (201, body('a'))]).await;
    let mut request = request();
    request.registration_grant = SecretString::new(String::new());
    let key = IdempotencyKey::recovery().unwrap();
    assert_eq!(key.expose().len(), 43);
    assert!(!format!("{key:?}").contains(key.expose()));
    assert!(key.expose() != IdempotencyKey::recovery().unwrap().expose());
    let first = client.register(&request, &key).await.unwrap();
    let retry = client.register(&request, &key).await.unwrap();
    assert_eq!(first.device_id, retry.device_id);
    let requests = server.await.unwrap();
    for raw in &requests {
        assert!(!raw.contains("registration_grant"));
        assert!(raw.contains(key.expose()));
    }
    assert!(requests[0] == requests[1]);
    assert_eq!(
        client
            .register(&request, &IdempotencyKey::random())
            .await
            .unwrap_err(),
        IdentityError::InvalidRequest
    );
    let malformed = IdempotencyKey::new("z".repeat(43)).unwrap();
    assert_eq!(
        client.register(&request, &malformed).await.unwrap_err(),
        IdentityError::InvalidRequest
    );
}
