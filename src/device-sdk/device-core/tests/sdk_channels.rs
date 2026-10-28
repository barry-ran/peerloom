//! One authenticated identity/WSS owns two concurrent authorized peer sessions.
use device_core::QueueConfig;
use device_core::sdk::{Connection, DeviceSdk, SdkChannel, SdkConfig, SdkError, SdkEvent};
use device_protocol::{ChannelMode, ConnectionPolicy};
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
    third: Device,
}

async fn sdk(origin: &str, device: Device, capacity: usize) -> DeviceSdk {
    let store = Arc::new(MemoryIdentityStore::default());
    store
        .save(
            &IdentityScope {
                server_origin: reqwest::Url::parse(origin).unwrap().to_string(),
                application_id: device.application_id.clone(),
            },
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
    config.max_connections = capacity;
    config.max_channels_per_connection = 4;
    config.transport.max_channels = 5;
    config.transport.policy = ConnectionPolicy::DirectOnly;
    config.transport.bind_address = "127.0.0.1:0".parse().unwrap();
    config.transport.include_loopback = true;
    DeviceSdk::load(config, store).await.unwrap()
}
async fn next(sdk: &mut DeviceSdk) -> SdkEvent {
    tokio::time::timeout(Duration::from_secs(30), sdk.next_event())
        .await
        .expect("bounded event")
        .expect("live SDK")
}
async fn incoming(sdk: &mut DeviceSdk) -> String {
    match next(sdk).await {
        SdkEvent::IncomingConnection { session_id, .. } => session_id,
        other => panic!("expected authorized incoming: {other:?}"),
    }
}
async fn ready(sdk: &mut DeviceSdk) -> Connection {
    match next(sdk).await {
        SdkEvent::ConnectionReady(connection) => connection,
        other => panic!("expected ready: {other:?}"),
    }
}
async fn exchange(a: &mut Connection, b: &mut Connection, bytes: &[u8]) {
    a.send(bytes).await.unwrap();
    assert_eq!(b.receive().await.unwrap(), bytes);
    b.send(bytes).await.unwrap();
    assert_eq!(a.receive().await.unwrap(), bytes);
}

#[tokio::test]
#[ignore = "requires real Go/PG/Redis pair fixture and UDP"]
async fn hot_open_three_types_duplex_fin_and_parent_scope() {
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(std::env::var("TEST_MULTICONNECTION_FIXTURE_FILE").unwrap()).unwrap(),
    );
    let fixture: Fixture = serde_json::from_slice(&bytes).unwrap();
    let _ = fixture.third;
    let origin = std::env::var("TEST_IDENTITY_BASE_URL").unwrap();
    let mut a = sdk(&origin, fixture.source, 1).await;
    let mut b = sdk(&origin, fixture.target, 1).await;
    assert!(matches!(next(&mut a).await, SdkEvent::Online));
    assert!(matches!(next(&mut b).await, SdkEvent::Online));
    let request_id = a.connect_with_request(b.device_id()).await.unwrap();
    let id = incoming(&mut b).await;
    b.accept(&id).await.unwrap();
    let mut ac = ready(&mut a).await;
    let mut bc = ready(&mut b).await;
    assert_eq!(ac.peer_device_id(), b.device_id());
    assert_eq!(bc.peer_device_id(), a.device_id());
    assert_eq!(ac.request_id(), Some(request_id.as_str()));
    assert!(bc.request_id().is_none());
    let mut incoming_a = ac.take_incoming_channels().unwrap();
    let mut incoming_b = bc.take_incoming_channels().unwrap();
    exchange(&mut ac, &mut bc, b"legacy default still works").await;
    let mut reliable_a = ac
        .open_message(
            "same-label",
            ChannelMode::ReliableMessage,
            QueueConfig::default(),
        )
        .await
        .unwrap();
    let SdkChannel::Message(mut reliable_b) = incoming_b.receive().await.unwrap() else {
        panic!("typed reliable")
    };
    assert_eq!(reliable_b.mode(), ChannelMode::ReliableMessage);
    let mut fast_b = bc
        .open_message(
            "same-label",
            ChannelMode::LowLatencyMessage,
            QueueConfig::default(),
        )
        .await
        .unwrap();
    let SdkChannel::Message(mut fast_a) = incoming_a.receive().await.unwrap() else {
        panic!("typed low latency")
    };
    assert_eq!(fast_a.mode(), ChannelMode::LowLatencyMessage);
    reliable_a.send(&[0, 255, 0, 1]).await.unwrap();
    assert_eq!(reliable_b.receive().await.unwrap(), [0, 255, 0, 1]);
    reliable_b.send(b"reliable reply").await.unwrap();
    assert_eq!(reliable_a.receive().await.unwrap(), b"reliable reply");
    fast_b.send(b"fast").await.unwrap();
    assert_eq!(fast_a.receive().await.unwrap(), b"fast");
    fast_a.send(b"fast reply").await.unwrap();
    assert_eq!(fast_b.receive().await.unwrap(), b"fast reply");
    let stream_a = ac.open_stream("same-label").await.unwrap();
    let SdkChannel::Stream(stream_b) = incoming_b.receive().await.unwrap() else {
        panic!("typed stream")
    };
    let validity = stream_a.validity();
    assert!(matches!(
        ac.open_stream("over-active-limit").await,
        Err(SdkError::Busy)
    ));
    let (mut reader_a, writer_a) = stream_a.split();
    let (mut reader_b, writer_b) = stream_b.split();
    let awaiting_reply = tokio::spawn(async move {
        let mut bytes = [0; 5];
        let n = reader_a.read(&mut bytes).await.unwrap();
        (reader_a, bytes, n)
    });
    tokio::task::yield_now().await;
    let bytes = vec![71; 32000];
    let n = writer_a.write(&bytes).await.unwrap();
    assert!(n > 0 && n <= 16384 && n < bytes.len());
    let mut received = vec![0; n];
    let mut offset = 0;
    while offset < n {
        offset += reader_b.read(&mut received[offset..]).await.unwrap();
    }
    assert_eq!(received, bytes[..n]);
    // Pending read on A does not hold a lock preventing A->B write or B->A reply.
    writer_b.write(b"reply").await.unwrap();
    let (mut reader_a, reply, n) = awaiting_reply.await.unwrap();
    assert_eq!(&reply[..n], b"reply");
    writer_a.shutdown_write().await.unwrap();
    assert_eq!(
        writer_a.write(b"after own FIN").await,
        Err(SdkError::Closed)
    );
    assert!(writer_a.validity().is_valid());
    assert_eq!(reader_b.read(&mut [0; 1]).await.unwrap(), 0);
    writer_b.write(b"after FIN").await.unwrap();
    let mut after = [0; 9];
    assert_eq!(reader_a.read(&mut after).await.unwrap(), 9);
    assert_eq!(&after, b"after FIN");
    reliable_a.close().await.unwrap();
    reliable_b.close().await.unwrap();
    exchange(&mut ac, &mut bc, b"sibling survived child close").await;
    fast_b.send(b"another live child").await.unwrap();
    assert_eq!(fast_a.receive().await.unwrap(), b"another live child");
    // Active slot released, but total backend creation remains limited to five.
    let replacement = ac
        .open_message(
            "replacement",
            ChannelMode::ReliableMessage,
            QueueConfig::default(),
        )
        .await
        .unwrap();
    let SdkChannel::Message(_remote_replacement) = incoming_b.receive().await.unwrap() else {
        panic!("replacement")
    };
    replacement.close().await.unwrap();
    assert!(matches!(
        ac.open_stream("over-lifetime-limit").await,
        Err(SdkError::Transport(
            device_transport_webrtc::TransportError::TooManyChannels
        ))
    ));
    let identity = a.device_id().to_owned();
    a.reset(&identity).await.unwrap();
    assert!(!validity.is_valid());
    assert!(writer_a.write(b"after reset").await.is_err());
    assert!(reader_a.read(&mut [0; 1]).await.is_err());
    assert!(fast_a.send(b"after reset").await.is_err());
    a.close().await;
    b.close().await;
}
