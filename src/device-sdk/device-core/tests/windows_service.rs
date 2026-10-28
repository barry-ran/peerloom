//! Native Windows + CurrentUser DPAPI + real Go/PostgreSQL/Redis acceptance.
//! The supervisor runs the two phases in separate Windows processes.
#![cfg(target_os = "windows")]
use device_core::{
    identity::{IdempotencyKey, IdentityClient, IdentitySession, Platform, RegistrationRequest},
    sdk::{Connection, DeviceSdk, SdkConfig, SdkEvent},
};
use device_protocol::ConnectionPolicy;
use device_storage::{
    IdentityScope, IdentityStore, SecretString, StoredIdentity, WindowsDpapiStore,
};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
use zeroize::Zeroize;

#[derive(Deserialize)]
struct Device {
    application_id: String,
    device_id: String,
    device_credential: String,
    expires_at: String,
}
impl Drop for Device {
    fn drop(&mut self) {
        self.device_credential.zeroize();
    }
}
#[derive(Deserialize)]
struct Pair {
    source: Device,
    target: Device,
}
#[derive(Deserialize)]
struct Registration {
    application_id: String,
    registration_grant: String,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.registration_grant.zeroize();
    }
}
fn fixture<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = std::env::var(name).expect("native fixture path required");
    assert!(std::fs::metadata(&path).unwrap().len() <= 65536);
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    serde_json::from_slice(&bytes).expect("valid private fixture")
}
fn root() -> PathBuf {
    PathBuf::from(std::env::var("TEST_NATIVE_STORE_ROOT").unwrap())
}
fn store(role: &str) -> Arc<WindowsDpapiStore> {
    Arc::new(WindowsDpapiStore::new(root().join(role)).unwrap())
}
fn origin() -> String {
    std::env::var("TEST_IDENTITY_BASE_URL").unwrap()
}
fn scope(app: &str) -> IdentityScope {
    IdentityScope {
        server_origin: reqwest::Url::parse(&origin()).unwrap().to_string(),
        application_id: app.into(),
    }
}
async fn session(app: &str, role: &str) -> IdentitySession {
    IdentitySession::load(
        IdentityClient::new(&origin(), true, Duration::from_secs(10)).unwrap(),
        app.into(),
        store(role),
    )
    .await
    .unwrap()
}
async fn peer(device: &Device, role: &str) -> DeviceSdk {
    let storage = store(role);
    storage
        .save(
            &scope(&device.application_id),
            0,
            StoredIdentity {
                device_id: device.device_id.clone(),
                device_credential: SecretString::new(device.device_credential.clone()),
                expires_at: device.expires_at.clone(),
            },
        )
        .await
        .unwrap();
    let mut config = SdkConfig::new(origin(), device.application_id.clone());
    config.development_loopback = true;
    config.transport.policy = ConnectionPolicy::DirectOnly;
    config.transport.bind_address = "127.0.0.1:0".parse().unwrap();
    config.transport.include_loopback = true;
    DeviceSdk::load(config, storage).await.unwrap()
}
async fn next(sdk: &mut DeviceSdk) -> SdkEvent {
    tokio::time::timeout(Duration::from_secs(30), sdk.next_event())
        .await
        .expect("native SDK event deadline")
        .expect("native SDK event stream")
}
async fn ready(sdk: &mut DeviceSdk) -> Connection {
    loop {
        match next(sdk).await {
            SdkEvent::ConnectionReady(connection) => return connection,
            SdkEvent::Online => {}
            _ => panic!("unexpected native SDK event before ready"),
        }
    }
}

#[derive(Deserialize)]
struct LeaseSnapshot {
    source_lease_expires_at: String,
    target_lease_expires_at: String,
    lease_generation: u64,
}
impl LeaseSnapshot {
    fn deadlines(&self) -> (time::OffsetDateTime, time::OffsetDateTime) {
        let parse = |value: &str| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .expect("lease timestamp")
        };
        (
            parse(&self.source_lease_expires_at),
            parse(&self.target_lease_expires_at),
        )
    }
}
async fn lease_snapshot(origin: &str, session: &str, credential: &str) -> LeaseSnapshot {
    let origin = reqwest::Url::parse(origin).unwrap();
    assert!(
        origin.scheme() == "http"
            && matches!(origin.host_str(), Some("127.0.0.1" | "[::1]" | "::1"))
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {credential}")).unwrap();
    auth.set_sensitive(true);
    let mut response = client
        .get(origin.join(&format!("/v1/sessions/{session}")).unwrap())
        .header(reqwest::header::AUTHORIZATION, auth)
        .send()
        .await
        .expect("loopback lease probe request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "lease probe authorization/status"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.expect("lease probe body") {
        assert!(
            bytes.len() + chunk.len() <= 16 * 1024,
            "bounded lease snapshot"
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).expect("typed lease snapshot")
}
fn lease_probe_credential() -> zeroize::Zeroizing<String> {
    let path = std::env::var("TEST_LEASE_ADMIN_FIXTURE")
        .expect("native test requires private same-tenant lease probe fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600);
        assert!(metadata.len() <= 65536);
    }
    assert!(std::fs::metadata(&path).unwrap().len() <= 65536);
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    #[derive(Deserialize)]
    struct Admin {
        service_credential: String,
    }
    let value: Admin = serde_json::from_slice(&bytes).expect("lease probe fixture shape");
    assert!(value.service_credential.starts_with("svc_") && value.service_credential.len() == 47);
    zeroize::Zeroizing::new(value.service_credential)
}

#[tokio::test]
#[ignore = "requires native Windows + disposable Go/PG/Redis fixture"]
async fn native_registration_pair_rotation_and_close() {
    let registration: Registration = fixture("TEST_REGISTRATION_FIXTURE_FILE");
    let mut identity = session(&registration.application_id, "registered").await;
    identity
        .register(
            RegistrationRequest {
                application_id: registration.application_id.clone(),
                platform: Platform::Windows,
                installation_public_key: "native-windows-disposable-installation".into(),
                registration_grant: SecretString::new(registration.registration_grant.clone()),
                sdk_version: env!("CARGO_PKG_VERSION").into(),
                metadata: Default::default(),
            },
            IdempotencyKey::random(),
        )
        .await
        .unwrap();
    assert!(!identity.needs_persistence());
    let registered_id = identity.device_self().await.unwrap().device_id;
    // Private supervisor directory, never uploaded as a public artifact.
    std::fs::write(root().join("registered-device-id"), registered_id).unwrap();
    drop(identity);

    let pair: Pair = fixture("TEST_SIGNAL_FIXTURE_FILE");
    let mut a = peer(&pair.source, "source").await;
    let mut b = peer(&pair.target, "target").await;
    assert!(matches!(next(&mut a).await, SdkEvent::Online));
    assert!(matches!(next(&mut b).await, SdkEvent::Online));
    a.connect(b.device_id()).await.unwrap();
    let session_id = match next(&mut b).await {
        SdkEvent::IncomingConnection { session_id, .. } => session_id,
        _ => panic!("target approval required"),
    };
    b.accept(&session_id).await.unwrap();
    let mut ca = ready(&mut a).await;
    let mut cb = ready(&mut b).await;
    assert_eq!(ca.session_id(), cb.session_id());
    let lease_credential = lease_probe_credential();
    let initial = lease_snapshot(&origin(), ca.session_id(), &lease_credential).await;
    assert!(initial.lease_generation >= 1);
    ca.send(&[0, 255, 1, 0]).await.unwrap();
    assert_eq!(cb.receive().await.unwrap(), [0, 255, 1, 0]);
    cb.send("Windows 原生回显".as_bytes()).await.unwrap();
    assert_eq!(ca.receive().await.unwrap(), "Windows 原生回显".as_bytes());
    a.refresh_credentials().await.unwrap();
    assert!(matches!(next(&mut a).await, SdkEvent::Offline));
    assert!(matches!(next(&mut a).await, SdkEvent::Online));
    let saved = store("source")
        .load(&scope(&pair.source.application_id))
        .await
        .unwrap();
    assert!(saved.revision > 1);
    assert!(saved.identity.unwrap().device_credential.expose() != pair.source.device_credential);
    let (source_before, target_before) = initial.deadlines();
    let deadline = source_before.max(target_before);
    let remaining = deadline - time::OffsetDateTime::now_utc();
    let wait: Duration = remaining.try_into().expect("initial lease remains future");
    assert!(
        wait <= Duration::from_secs(90),
        "unexpected fixture lease duration"
    );
    tokio::time::sleep(wait + Duration::from_secs(2)).await;
    assert!(time::OffsetDateTime::now_utc() > deadline);
    let renewed = lease_snapshot(&origin(), ca.session_id(), &lease_credential).await;
    let (source_after, target_after) = renewed.deadlines();
    assert!(renewed.lease_generation > initial.lease_generation);
    assert!(source_after > source_before && target_after > target_before);
    assert!(
        source_after > time::OffsetDateTime::now_utc()
            && target_after > time::OffsetDateTime::now_utc()
    );
    println!(
        "Windows native persisted dual lease deadlines crossed; generation {} -> {}",
        initial.lease_generation, renewed.lease_generation
    );
    ca.send(b"after-rotation-and-renew").await.unwrap();
    assert_eq!(cb.receive().await.unwrap(), b"after-rotation-and-renew");
    cb.send(b"renewed-reverse").await.unwrap();
    assert_eq!(ca.receive().await.unwrap(), b"renewed-reverse");
    ca.close().await.unwrap();
    loop {
        if matches!(next(&mut b).await, SdkEvent::ConnectionClosed { .. }) {
            break;
        }
    }
    assert!(cb.send(b"closed").await.is_err());
    assert!(cb.receive().await.is_err());
    a.close().await;
    b.close().await;
}

#[tokio::test]
#[ignore = "supervisor must launch a new native process after the first phase"]
async fn native_secure_identity_survives_process_restart() {
    let registration: Registration = fixture("TEST_REGISTRATION_FIXTURE_FILE");
    let identity = session(&registration.application_id, "registered").await;
    let expected = std::fs::read_to_string(root().join("registered-device-id")).unwrap();
    assert_eq!(identity.device_self().await.unwrap().device_id, expected);
    let pair: Pair = fixture("TEST_SIGNAL_FIXTURE_FILE");
    let snapshot = store("source")
        .load(&scope(&pair.source.application_id))
        .await
        .unwrap();
    assert!(snapshot.revision > 1);
    assert!(snapshot.identity.unwrap().device_credential.expose() != pair.source.device_credential);
    // No fixture token import: new process loads the rotated credential through DPAPI.
    let source = session(&pair.source.application_id, "source").await;
    assert_eq!(
        source.device_self().await.unwrap().device_id,
        pair.source.device_id
    );
}
