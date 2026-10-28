//! 真实 UDP 集成；单一 typed incoming 消费者，不按通道类型抢收队列。
use device_protocol::{ChannelMode, ConnectionPolicy};
use device_transport_webrtc::{IncomingChannel, PeerTransport, TransportConfig, TransportError};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn mixed_hot_open_bidirectional_channels_keep_types_and_lifetime_budget() {
    let config = TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        include_loopback: true,
        bind_address: "127.0.0.1:0".parse().unwrap(),
        max_channels: 3,
        operation_timeout: Duration::from_secs(10),
        ..TransportConfig::default()
    };
    let a = Arc::new(PeerTransport::new(config.clone()).await.unwrap());
    let b = Arc::new(PeerTransport::new(config).await.unwrap());
    let left = a.clone();
    let right = b.clone();
    let mut task = tokio::spawn(async move {
        let a = left;
        let b = right;
        // One initial reliable channel creates the SCTP m-line. Other types are
        // opened in both directions after negotiation, without another SDP.
        let mut reliable_a = a
            .create_channel("same-label", ChannelMode::ReliableMessage)
            .await
            .unwrap();
        let answer = b
            .answer_offer(a.create_offer().await.unwrap())
            .await
            .unwrap();
        a.apply_answer(answer).await.unwrap();
        let IncomingChannel::ReliableMessage(mut reliable_b) = b.accept_incoming().await.unwrap()
        else {
            panic!("reliable message metadata misclassified");
        };
        reliable_a.wait_open().await.unwrap();
        reliable_b.wait_open().await.unwrap();
        reliable_a.send(b"before hot open").await.unwrap();
        assert_eq!(reliable_b.receive().await.unwrap(), b"before hot open");

        // Cancelling an idle accept must release the receive mutex, not create a
        // detached consumer which steals the next hot-opened channel.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), a.accept_incoming())
                .await
                .is_err()
        );

        // Same labels deliberately prove the dispatcher uses negotiated metadata.
        let mut low_b = b
            .create_channel("same-label", ChannelMode::LowLatencyMessage)
            .await
            .unwrap();
        let IncomingChannel::LowLatencyMessage(mut low_a) = a.accept_incoming().await.unwrap()
        else {
            panic!("low latency metadata misclassified");
        };
        low_b.wait_open().await.unwrap();
        low_a.wait_open().await.unwrap();
        let mut stream_a = a.create_stream("same-label").await.unwrap();
        let IncomingChannel::ReliableStream(mut stream_b) = b.accept_incoming().await.unwrap()
        else {
            panic!("stream protocol misclassified");
        };
        let (left, right) = tokio::join!(stream_a.wait_open(), stream_b.wait_open());
        left.unwrap();
        right.unwrap();

        // A stalled application stream reader does not consume the other channels.
        assert_eq!(stream_a.write(&[0, 255, 1, 0, 2]).await.unwrap(), 5);
        low_b.send(b"low forward").await.unwrap();
        assert_eq!(low_a.receive().await.unwrap(), b"low forward");
        low_a.send(b"low reverse").await.unwrap();
        assert_eq!(low_b.receive().await.unwrap(), b"low reverse");
        reliable_b.send("可靠消息".as_bytes()).await.unwrap();
        assert_eq!(reliable_a.receive().await.unwrap(), "可靠消息".as_bytes());
        stream_a.shutdown_write().await.unwrap();
        let mut output = Vec::new();
        let mut buffer = [0; 2];
        loop {
            let n = stream_b.read(&mut buffer).await.unwrap();
            if n == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(output, [0, 255, 1, 0, 2]);
        assert_eq!(stream_b.write(b"ok").await.unwrap(), 2);
        stream_b.shutdown_write().await.unwrap();
        assert_eq!(stream_a.read(&mut buffer).await.unwrap(), 2);
        assert_eq!(&buffer, b"ok");
        assert_eq!(stream_a.read(&mut buffer).await.unwrap(), 0);
        stream_a.close().await.unwrap();
        // A child's FIN/close leaves its sibling channel usable.
        reliable_a.send(b"after stream close").await.unwrap();
        assert_eq!(reliable_b.receive().await.unwrap(), b"after stream close");
        low_a.close().await.unwrap();
        reliable_a.close().await.unwrap();
        // Closing does not replenish the documented lifetime creation budget.
        assert!(matches!(
            a.create_channel("fourth", ChannelMode::ReliableMessage)
                .await,
            Err(TransportError::TooManyChannels)
        ));
        assert!(matches!(
            b.create_stream("fourth").await,
            Err(device_transport_webrtc::StreamError::Transport(
                TransportError::TooManyChannels
            ))
        ));
    });
    let outcome = tokio::time::timeout(Duration::from_secs(40), &mut task).await;
    if outcome.is_err() {
        task.abort();
        let _ = task.await;
    }
    let closed_a = a.close().await;
    let closed_b = b.close().await;
    closed_a.unwrap();
    closed_b.unwrap();
    outcome
        .expect("bounded mixed real pair")
        .expect("mixed channel assertions");
}
