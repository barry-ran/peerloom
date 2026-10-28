//! 需要 UDP socket 的网络集成；CI 显式运行 --ignored，与默认离线单测分开。
use device_protocol::{ChannelMode, ConnectionPolicy};
use device_transport_webrtc::{PeerTransport, TransportConfig, TransportError};
use std::time::Duration;

fn local_config() -> TransportConfig {
    TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        bind_address: "127.0.0.1:0".parse().unwrap(),
        include_loopback: true,
        operation_timeout: Duration::from_secs(15),
        ..TransportConfig::default()
    }
}

async fn exercise_pair(include_low_latency: bool) {
    let a = PeerTransport::new(local_config()).await.expect("create A");
    let b = match PeerTransport::new(local_config()).await {
        Ok(peer) => peer,
        Err(error) => {
            let _ = a.close().await;
            panic!("create B: {error}");
        }
    };
    let outcome = tokio::time::timeout(Duration::from_secs(45), async {
        let mut sender = a
            .create_channel("peerloom.echo", ChannelMode::ReliableMessage)
            .await?;
        let offer = a.create_offer().await?;
        assert!(
            offer.sdp.contains("a=fingerprint:"),
            "DTLS fingerprint required"
        );
        assert!(
            offer.sdp.contains("a=candidate:"),
            "real ICE candidates required"
        );
        assert!(
            !offer.sdp.contains("typ relay"),
            "direct policy cannot offer relay"
        );
        let answer = b.answer_offer(offer).await?;
        assert!(answer.sdp.contains("a=fingerprint:"));
        a.apply_answer(answer).await?;
        let mut receiver = b.accept_channel().await?;
        sender.wait_open().await?;
        receiver.wait_open().await?;
        sender.wait_open().await?; // 重复等待不得丢弃之后的数据。
        assert_eq!(
            sender.send(&vec![0; 65537]).await,
            Err(TransportError::MessageTooLarge)
        );
        for payload in [
            b"hello".as_slice(),
            "你好 Peerloom".as_bytes(),
            &[0, 1, 0, 255],
        ] {
            sender.send(payload).await?;
            assert_eq!(receiver.receive().await?, payload);
            receiver.send(payload).await?;
            assert_eq!(sender.receive().await?, payload);
        }
        if include_low_latency {
            let mut low_latency = a
                .create_channel("peerloom.low-latency", ChannelMode::LowLatencyMessage)
                .await?;
            let mut incoming = b.accept_channel().await?;
            low_latency.wait_open().await?;
            incoming.wait_open().await?;
            low_latency.send(b"low-latency").await?;
            assert_eq!(incoming.receive().await?, b"low-latency");
            incoming.send(b"reply").await?;
            assert_eq!(low_latency.receive().await?, b"reply");
            low_latency.close().await?;
        }
        assert!(matches!(
            a.create_offer().await,
            Err(TransportError::NegotiationAlreadyStarted)
        ));
        sender.close().await?;
        Ok::<(), TransportError>(())
    })
    .await;
    let a_close = a.close().await;
    let b_close = b.close().await;
    a_close.expect("A closes within bound");
    b_close.expect("B closes within bound");
    outcome
        .expect("whole exchange timeout")
        .expect("real native WebRTC exchange");
    assert!(matches!(
        a.create_channel("after-close", ChannelMode::ReliableMessage)
            .await,
        Err(TransportError::Closed)
    ));
}

#[tokio::test]
#[ignore = "真实 UDP 网络集成，CI 显式执行 --ignored"]
async fn native_direct_bidirectional_messages_and_graceful_close() {
    exercise_pair(true).await;
}

#[tokio::test]
#[ignore = "100 次真实 UDP 连接压力检查，CI 显式执行 --ignored"]
async fn native_direct_100_sequential_connections() {
    for iteration in 0..100 {
        exercise_pair(false).await;
        if iteration % 25 == 24 {
            eprintln!("已验证 {} 次原生直连建连和关闭", iteration + 1);
        }
    }
}
