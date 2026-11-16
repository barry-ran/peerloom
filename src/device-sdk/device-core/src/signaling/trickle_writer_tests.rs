//! Real local TCP/WSS-format writer tests. No remote server or credentials.
use super::*;
use device_protocol::ChannelMode;
use device_transport_webrtc::{LocalIceEvent, PeerTransport, TransportConfig};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::Role;

#[tokio::test]
async fn cancelled_generation_does_not_close_shared_signal_writer() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut socket =
            WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(client), Role::Client, None)
                .await;
        let mut server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let peer = Arc::new(
            PeerTransport::new(TransportConfig {
                include_loopback: true,
                bind_address: "127.0.0.1:0".parse().unwrap(),
                ..TransportConfig::default()
            })
            .await
            .unwrap(),
        );
        let _channel = peer
            .create_channel("test", ChannelMode::ReliableMessage)
            .await
            .unwrap();
        peer.create_offer_trickle().await.unwrap();
        let LocalIceEvent::Candidate(candidate) = peer.next_local_ice().await.unwrap() else {
            panic!("host candidate");
        };
        let payload = serde_json::to_value(IceBatch::local(Some(candidate))).unwrap();
        let mut ice = Envelope::new("session.ice", payload).unwrap();
        ice.session_id = Some(uuid::Uuid::new_v4().to_string());
        ice.negotiation_generation = Some(1);
        let (commands, received) = mpsc::channel(8);
        let (events, _event_rx) = mpsc::channel(8);
        let (stop, stopped) = oneshot::channel();
        let ack = Envelope::new("hello.ack", json!({})).unwrap();
        let task = tokio::spawn(async move {
            drive(&mut socket, ack, 60, 60, received, &events, stopped).await
        });
        let (completion, cancelled) = oneshot::channel();
        drop(cancelled);
        commands
            .send(Command {
                envelope: ice.clone(),
                completion,
                ice_peer: Some(peer.clone()),
            })
            .await
            .unwrap();
        let (completion, result) = oneshot::channel();
        commands
            .send(Command {
                envelope: ice,
                completion,
                ice_peer: Some(peer.clone()),
            })
            .await
            .unwrap();
        let frame = server.next().await.unwrap().unwrap();
        let Message::Text(frame) = frame else {
            panic!("ICE frame");
        };
        let frame: Envelope = serde_json::from_str(&frame).unwrap();
        assert_eq!(
            frame.seq, 1,
            "cancelled generation must not consume sequence"
        );
        let outcome = result.await.unwrap().unwrap();
        assert!(matches!(
            &outcome,
            IceConveyOutcome::Sent {
                generation: 1,
                ticket: Some(_)
            }
        ));
        // Losing the ticket after successful WSS delivery fails only this peer.
        drop(outcome);
        assert!(peer.wait_trickle_failure().await.is_err());
        let (completion, result) = oneshot::channel();
        let other = Envelope::new("session.renew", json!({})).unwrap();
        commands
            .send(Command {
                envelope: other,
                completion,
                ice_peer: None,
            })
            .await
            .unwrap();
        let Message::Text(frame) = server.next().await.unwrap().unwrap() else {
            panic!("other session frame");
        };
        let frame: Envelope = serde_json::from_str(&frame).unwrap();
        assert_eq!(frame.seq, 2);
        assert_eq!(frame.kind, "session.renew");
        assert!(result.await.unwrap().is_ok());
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        peer.close().await.unwrap();
    })
    .await
    .unwrap();
}
