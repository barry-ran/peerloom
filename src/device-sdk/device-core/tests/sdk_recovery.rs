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
    tokio::time::timeout(Duration::from_secs(90), sdk.next_event())
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
#[tokio::test]
#[ignore = "requires fresh pair, Go schema8 and a runner-owned TURN outage"]
async fn facade_recovers_transport_with_fenced_new_handles() {
    let fixture_path = std::env::var("TEST_SIGNAL_FIXTURE_FILE").unwrap();
    let bytes = zeroize::Zeroizing::new(std::fs::read(fixture_path).unwrap());
    let fixture: Fixture = serde_json::from_slice(&bytes).unwrap();
    let origin = std::env::var("TEST_IDENTITY_BASE_URL").unwrap();
    assert_eq!(std::env::var("TEST_MANAGED_RELAY").unwrap(), "1");
    let mut a = sdk(&origin, fixture.source).await;
    let mut b = sdk(&origin, fixture.target).await;
    assert!(matches!(next(&mut a).await, SdkEvent::Online));
    assert!(matches!(next(&mut b).await, SdkEvent::Online));
    a.connect(b.device_id()).await.unwrap();
    let session = match next(&mut b).await {
        SdkEvent::IncomingConnection { session_id, .. } => session_id,
        other => panic!("expected initial consent {other:?}"),
    };
    b.accept(&session).await.unwrap();
    let old_a = ready(&mut a).await;
    let mut old_b = ready(&mut b).await;
    assert_eq!(old_a.negotiation_generation(), 1);
    old_a.send(b"before-outage").await.unwrap();
    assert_eq!(old_b.receive().await.unwrap(), b"before-outage");
    let control = std::path::PathBuf::from(std::env::var("TEST_RECOVERY_CONTROL_DIR").unwrap());
    std::fs::write(control.join("ready"), b"ready").unwrap();
    async fn recovered(sdk: &mut DeviceSdk) -> Connection {
        let mut closed = false;
        loop {
            match next(sdk).await {
                SdkEvent::ConnectionClosed { .. } => closed = true,
                SdkEvent::ConnectionReady(connection) => {
                    assert!(closed, "old handle must invalidate before new Ready");
                    assert!(connection.negotiation_generation() > 1);
                    return connection;
                }
                SdkEvent::Online | SdkEvent::Offline => {}
                other => panic!(
                    "recovery must retain original consent, not reopen a rejected session: {other:?}"
                ),
            }
        }
    }
    let (mut new_a, mut new_b) = tokio::join!(recovered(&mut a), recovered(&mut b));
    assert_eq!(new_a.session_id(), session);
    assert_eq!(new_b.session_id(), session);
    assert_eq!(
        new_a.negotiation_generation(),
        new_b.negotiation_generation()
    );
    assert!(!old_a.validity().is_valid());
    assert!(!old_b.validity().is_valid());
    assert!(old_a.send(b"stale").await.is_err());
    assert!(old_b.receive().await.is_err());
    // Closing or dropping an obsolete handle must not terminate the new generation.
    old_a.close().await.unwrap();
    drop(old_b);
    new_a.send(b"new-generation-source").await.unwrap();
    assert_eq!(new_b.receive().await.unwrap(), b"new-generation-source");
    new_b.send(b"new-generation-target").await.unwrap();
    assert_eq!(new_a.receive().await.unwrap(), b"new-generation-target");
    println!(
        "PASS: actual TURN outage recovered same session at generation {} with old handles fenced",
        new_a.negotiation_generation()
    );
    new_a.close().await.unwrap();
    assert!(matches!(
        next(&mut b).await,
        SdkEvent::ConnectionClosed { .. }
    ));
    assert!(new_b.send(b"after-explicit-close").await.is_err());
    a.close().await;
    b.close().await;
}
