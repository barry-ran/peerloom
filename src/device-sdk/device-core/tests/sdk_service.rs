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

#[tokio::test]
#[ignore = "requires fresh authorized pair fixture and real Go/PG/Redis/UDP"]
async fn facade_connect_message_rotation_and_close() {
    let path = std::env::var("TEST_SIGNAL_FIXTURE_FILE").expect("pair fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    let fixture: Fixture = serde_json::from_slice(&bytes).unwrap();
    let origin = std::env::var("TEST_IDENTITY_BASE_URL").unwrap();
    if std::env::var("TEST_MANAGED_RELAY").as_deref() == Ok("1") {
        println!("facade integration mode: managed TURN, RelayOnly, no static ICE credentials");
    }
    let mut a = sdk(&origin, fixture.source).await;
    let mut b = sdk(&origin, fixture.target).await;
    assert!(matches!(next(&mut a).await, SdkEvent::Online));
    assert!(matches!(next(&mut b).await, SdkEvent::Online));
    a.connect(b.device_id()).await.unwrap();
    let session = match next(&mut b).await {
        SdkEvent::IncomingConnection { session_id, .. } => session_id,
        other => panic!("expected approval {other:?}"),
    };
    b.accept(&session).await.unwrap();
    let mut ca = ready(&mut a).await;
    let mut cb = ready(&mut b).await;
    assert_eq!(ca.session_id(), cb.session_id());
    let probe = if std::env::var("TEST_MANAGED_RELAY").as_deref() == Ok("1") {
        let credential = lease_probe_credential();
        let initial = lease_snapshot(&origin, ca.session_id(), &credential).await;
        assert!(initial.lease_generation >= 1);
        Some((credential, initial))
    } else {
        None
    };
    ca.send("facade 双向消息".as_bytes()).await.unwrap();
    assert_eq!(cb.receive().await.unwrap(), "facade 双向消息".as_bytes());
    cb.send(&[0, 255, 0]).await.unwrap();
    assert_eq!(ca.receive().await.unwrap(), [0, 255, 0]);
    // 真实 credential 轮换，旧WSS退出，新token连接+sync；原P2P不无故关闭。
    a.refresh_credentials().await.unwrap();
    assert!(matches!(next(&mut a).await, SdkEvent::Offline));
    assert!(matches!(next(&mut a).await, SdkEvent::Online));
    if let Some((credential, initial)) = probe {
        // ApprovalTimeout=30s is NOT LeaseTTL=60s. Observe persisted deadlines,
        // wait past both actual captured deadlines, then prove BOTH were renewed.
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
        let renewed = lease_snapshot(&origin, ca.session_id(), &credential).await;
        let (source_after, target_after) = renewed.deadlines();
        assert!(
            renewed.lease_generation > initial.lease_generation,
            "persisted lease generation did not advance"
        );
        assert!(
            source_after > source_before && target_after > target_before,
            "both peer leases must advance"
        );
        assert!(
            source_after > time::OffsetDateTime::now_utc()
                && target_after > time::OffsetDateTime::now_utc()
        );
        println!(
            "PASS: persisted dual lease deadlines crossed and advanced; lease_generation {} -> {}",
            initial.lease_generation, renewed.lease_generation
        );
    }
    ca.send(b"after-rotation").await.unwrap();
    assert_eq!(cb.receive().await.unwrap(), b"after-rotation");
    cb.send(b"renewed-reverse").await.unwrap();
    assert_eq!(ca.receive().await.unwrap(), b"renewed-reverse");
    ca.close().await.unwrap();
    loop {
        if matches!(next(&mut b).await, SdkEvent::ConnectionClosed { .. }) {
            break;
        }
    }
    assert!(cb.send(b"after-close").await.is_err());
    assert!(cb.receive().await.is_err());
    a.close().await;
    b.close().await;
}
