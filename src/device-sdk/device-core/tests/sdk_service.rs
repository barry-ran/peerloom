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
    ca.send("facade 双向消息".as_bytes()).await.unwrap();
    assert_eq!(cb.receive().await.unwrap(), "facade 双向消息".as_bytes());
    cb.send(&[0, 255, 0]).await.unwrap();
    assert_eq!(ca.receive().await.unwrap(), [0, 255, 0]);
    // 真实 credential 轮换，旧WSS退出，新token连接+sync；原P2P不无故关闭。
    a.refresh_credentials().await.unwrap();
    assert!(matches!(next(&mut a).await, SdkEvent::Offline));
    assert!(matches!(next(&mut a).await, SdkEvent::Online));
    // 超过初始目标确认租约30s（守卫还提前1s），证明两个actor主动续租，
    // 而不是通过重连hello或仅在短暂happy-path内掩盖失效。
    tokio::time::sleep(Duration::from_secs(32)).await;
    ca.send(b"after-rotation").await.unwrap();
    assert_eq!(cb.receive().await.unwrap(), b"after-rotation");
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
