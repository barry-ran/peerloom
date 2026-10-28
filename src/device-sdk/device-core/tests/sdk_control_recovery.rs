//! facade 真实端到端：应用只用 DeviceSdk/Connection，不复制 SDP/lease 编排。
use device_core::sdk::{Connection, DeviceSdk, SdkConfig, SdkEvent};
use device_protocol::ConnectionPolicy;
use device_storage::{
    IdentityScope, IdentityStore, MemoryIdentityStore, SecretString, StoredIdentity,
};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
#[derive(Deserialize)]
struct Device {
    application_id: String,
    device_id: String,
    device_credential: String,
    expires_at: String,
}
#[derive(Deserialize)]
struct Fixture {
    source: Device,
    target: Device,
}
async fn sdk(origin: &str, device: Device) -> DeviceSdk {
    let store = Arc::new(MemoryIdentityStore::default());
    let scope = IdentityScope {
        server_origin: reqwest::Url::parse(origin).unwrap().to_string(),
        application_id: device.application_id.clone(),
    };
    store
        .save(
            &scope,
            0,
            StoredIdentity {
                device_id: device.device_id,
                device_credential: SecretString::new(device.device_credential),
                expires_at: device.expires_at,
            },
        )
        .await
        .unwrap();
    let mut config = SdkConfig::new(origin.into(), device.application_id);
    config.max_connections = 2;
    config.development_loopback = true;
    config.transport.policy = if std::env::var("TEST_MANAGED_RELAY").as_deref() == Ok("1") {
        ConnectionPolicy::RelayOnly
    } else {
        ConnectionPolicy::DirectOnly
    };
    config.transport.bind_address = "127.0.0.1:0".parse().unwrap();
    config.transport.include_loopback = true;
    DeviceSdk::load(config, store).await.unwrap()
}
async fn next(sdk: &mut DeviceSdk) -> SdkEvent {
    tokio::time::timeout(Duration::from_secs(30), sdk.next_event())
        .await
        .expect("SDK event deadline")
        .expect("SDK event stream")
}
async fn ready(sdk: &mut DeviceSdk) -> Connection {
    loop {
        match next(sdk).await {
            SdkEvent::ConnectionReady(connection) => return connection,
            SdkEvent::Online => {}
            SdkEvent::Offline
            | SdkEvent::ConnectionClosed { .. }
            | SdkEvent::ConnectionRequestFailed { .. } => {}
            other => panic!("unexpected event {other:?}"),
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
        .expect("managed test requires private same-tenant lease probe fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600);
        assert!(metadata.len() <= 65536);
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    #[derive(Deserialize)]
    struct Admin {
        service_credential: String,
    }
    let value: Admin = serde_json::from_slice(&bytes).expect("lease probe fixture shape");
    assert!(value.service_credential.starts_with("svc_") && value.service_credential.len() == 47);
    zeroize::Zeroizing::new(value.service_credential)
}

async fn marker(control: &std::path::Path, name: &str) {
    tokio::time::timeout(Duration::from_secs(110), async {
        while !control.join(name).exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("owned fault controller deadline");
}
async fn establish(a: &mut DeviceSdk, b: &mut DeviceSdk) -> (Connection, Connection) {
    a.connect(b.device_id()).await.unwrap();
    let session = loop {
        match next(b).await {
            SdkEvent::IncomingConnection { session_id, .. } => break session_id,
            SdkEvent::Online
            | SdkEvent::Offline
            | SdkEvent::ConnectionClosed { .. }
            | SdkEvent::ConnectionRequestFailed { .. } => {}
            other => panic!("fresh authorization failed: {other:?}"),
        }
    };
    b.accept(&session).await.unwrap();
    let (ca, cb) = tokio::join!(ready(a), ready(b));
    assert_eq!(ca.session_id(), session);
    assert_eq!(cb.session_id(), session);
    (ca, cb)
}
async fn exchange(a: &mut Connection, b: &mut Connection) {
    tokio::time::timeout(Duration::from_secs(5), async {
        a.send(b"control-fault-probe").await.unwrap();
        assert_eq!(b.receive().await.unwrap(), b"control-fault-probe");
        b.send(b"reverse-probe").await.unwrap();
        assert_eq!(a.receive().await.unwrap(), b"reverse-probe");
    })
    .await
    .expect("real data exchange deadline");
}
async fn online_after_fault(sdk: &mut DeviceSdk) {
    loop {
        match next(sdk).await {
            SdkEvent::Online => return,
            SdkEvent::Offline
            | SdkEvent::ConnectionClosed { .. }
            | SdkEvent::ConnectionRequestFailed { .. } => {}
            other => panic!("temporary dependency outage must not permanently stop SDK: {other:?}"),
        }
    }
}
#[tokio::test]
#[ignore = "requires isolated Compose fault controller, fresh pair and private lease probe"]
async fn control_dependency_outage_and_fresh_authorization() {
    let path = std::env::var("TEST_SIGNAL_FIXTURE_FILE").unwrap();
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    let fixture: Fixture = serde_json::from_slice(&bytes).unwrap();
    let origin = std::env::var("TEST_IDENTITY_BASE_URL").unwrap();
    let mode = std::env::var("TEST_CONTROL_FAULT").unwrap();
    assert!(matches!(mode.as_str(), "device-server" | "redis"));
    let control = std::path::PathBuf::from(std::env::var("TEST_CONTROL_DIRECTORY").unwrap());
    let mut a = sdk(&origin, fixture.source).await;
    let mut b = sdk(&origin, fixture.target).await;
    assert!(matches!(next(&mut a).await, SdkEvent::Online));
    assert!(matches!(next(&mut b).await, SdkEvent::Online));
    let (mut old_a, mut old_b) = establish(&mut a, &mut b).await;
    exchange(&mut old_a, &mut old_b).await;
    let old_session = old_a.session_id().to_owned();
    let credential = lease_probe_credential();
    let snapshot = lease_snapshot(&origin, &old_session, &credential).await;
    assert!(snapshot.lease_generation > 0);
    let (left, right) = snapshot.deadlines();
    let remaining = left.max(right) - time::OffsetDateTime::now_utc();
    assert!(remaining.whole_seconds() >= 10 && remaining.whole_seconds() <= 90);
    let crossed = tokio::time::Instant::now()
        + Duration::from_millis(remaining.whole_milliseconds() as u64)
        + Duration::from_secs(2);
    std::fs::write(control.join("ready"), b"ready").unwrap();
    marker(&control, "down").await;
    if mode == "device-server" {
        // WSS loss alone must not destroy an authorized healthy direct data path.
        exchange(&mut old_a, &mut old_b).await;
        tokio::time::sleep_until(crossed).await;
        // A final renewal can race the pre-stop snapshot; this is a bounded
        // fail-closed test, not a claim about the last persisted deadline instant.
        tokio::time::timeout(Duration::from_secs(25), async {
            while old_a.validity().is_valid() || old_b.validity().is_valid() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("bounded invalidation after captured pre-stop deadlines");
        assert!(old_a.send(b"expired").await.is_err());
        assert!(old_b.receive().await.is_err());
        println!(
            "PASS: healthy data survived WSS loss; both old handles fenced within bounded post-snapshot window"
        );
        std::fs::write(control.join("expired"), b"expired").unwrap();
    } else {
        // Force an authenticated control frame through the real Redis ownership check.
        // An uncertain request outcome is allowed; a permanently stopped SDK is not.
        let _ = a.connect_with_request(b.device_id()).await;
        let _ = b.connect_with_request(a.device_id()).await;
    }
    marker(&control, "up").await;
    tokio::join!(online_after_fault(&mut a), online_after_fault(&mut b));
    if mode == "redis" {
        exchange(&mut old_a, &mut old_b).await;
    }
    old_a.close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while old_b.validity().is_valid() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("peer old gate close");
    assert!(old_b.send(b"old-handle").await.is_err());
    let (mut fresh_a, mut fresh_b) = establish(&mut a, &mut b).await;
    assert_ne!(fresh_a.session_id(), old_session);
    assert!(!old_b.validity().is_valid());
    exchange(&mut fresh_a, &mut fresh_b).await;
    fresh_a.close().await.unwrap();
    a.close().await;
    b.close().await;
    println!(
        "PASS: dependency restored, new consent/session exchanged data, old handle did not revive"
    );
}
