use device_core::{
    identity::IdentityClient,
    signaling::{Envelope, SignalClient, SignalError},
};
use device_storage::SecretString;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::{
    Message,
    handshake::server::{Request, Response},
};
fn ack(hello: &Envelope) -> serde_json::Value {
    json!({"v":1,"type":"hello.ack","id":uuid::Uuid::new_v4().to_string(),"request_id":hello.id,"seq":0,"sent_at":"2026-10-28T00:00:00Z","connection_generation":1,"fencing_token":"12345678901234567890123456789012","payload":{"heartbeat_interval_seconds":1,"presence_ttl_seconds":3}})
}
async fn listener() -> (TcpListener, IdentityClient) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = IdentityClient::new(
        &format!("http://{}", listener.local_addr().unwrap()),
        true,
        Duration::from_secs(2),
    )
    .unwrap();
    (listener, client)
}
#[tokio::test]
#[allow(clippy::result_large_err)] // Upstream handshake callback fixes its error type.
async fn hello_heartbeat_command_and_graceful_close() {
    let (listener, identity) = listener().await;
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket =
            tokio_tungstenite::accept_hdr_async(socket, |request: &Request, response: Response| {
                assert_eq!(request.uri().path(), "/v1/device-signal");
                assert!(request.uri().query().is_none());
                assert!(request.headers().get("origin").is_none());
                assert_eq!(
                    request.headers().get("authorization").unwrap(),
                    "Bearer dev_test"
                );
                Ok(response)
            })
            .await
            .unwrap();
        let hello: Envelope =
            serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(hello.kind, "hello");
        assert_eq!(hello.seq, 0);
        assert!(hello.fencing_token.is_none());
        let ack = ack(&hello);
        socket
            .send(Message::Text(ack.to_string().into()))
            .await
            .unwrap();
        let command: Envelope =
            serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(command.kind, "session.request");
        assert_eq!(command.seq, 1);
        assert_eq!(command.connection_generation, Some(1));
        assert_eq!(
            command.fencing_token.as_deref(),
            Some("12345678901234567890123456789012")
        );
        let heartbeat: Envelope =
            serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(heartbeat.kind, "presence.heartbeat");
        assert_eq!(heartbeat.seq, 2);
        let mut response = ack.clone();
        response["type"] = json!("presence.ack");
        response["seq"] = json!(1);
        response["payload"] = json!({});
        socket
            .send(Message::Text(response.to_string().into()))
            .await
            .unwrap();
        response["type"] = json!("session.pending");
        response["seq"] = json!(2);
        response["payload"] = json!({"state":"authorizing"});
        socket
            .send(Message::Text(response.to_string().into()))
            .await
            .unwrap();
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
        let _ = socket.flush().await;
    });
    let mut client = SignalClient::connect(&identity, &SecretString::new("dev_test".into()))
        .await
        .unwrap();
    client
        .send(
            "session.request",
            None,
            json!({"target_device_id":uuid::Uuid::new_v4().to_string()}),
        )
        .await
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(3), client.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.kind, "session.pending");
    client.close().await;
    task.await.unwrap();
}
#[tokio::test]
async fn stale_fence_is_rejected_without_delivering_payload() {
    let (listener, identity) = listener().await;
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let hello: Envelope =
            serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        let mut message = ack(&hello);
        socket
            .send(Message::Text(message.to_string().into()))
            .await
            .unwrap();
        message["type"] = json!("session.pending");
        message["seq"] = json!(1);
        message["fencing_token"] = json!("00000000000000000000000000000000");
        socket
            .send(Message::Text(message.to_string().into()))
            .await
            .unwrap();
        let _ = socket.next().await;
    });
    let mut client = SignalClient::connect(&identity, &SecretString::new("dev_test".into()))
        .await
        .unwrap();
    assert_eq!(
        client.receive().await.unwrap_err(),
        SignalError::InvalidMessage
    );
    client.close().await;
    task.await.unwrap();
}
#[tokio::test]
async fn oversized_message_is_rejected_at_websocket_boundary() {
    let (listener, identity) = listener().await;
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let hello: Envelope =
            serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        socket
            .send(Message::Text(ack(&hello).to_string().into()))
            .await
            .unwrap();
        socket
            .send(Message::Text("x".repeat(128 * 1024 + 1).into()))
            .await
            .unwrap();
        let _ = socket.next().await;
    });
    let mut client = SignalClient::connect(&identity, &SecretString::new("dev_test".into()))
        .await
        .unwrap();
    assert_eq!(client.receive().await.unwrap_err(), SignalError::Transport);
    client.close().await;
    task.await.unwrap();
}
#[tokio::test]
async fn invalid_hello_correlation_is_rejected() {
    let (listener, identity) = listener().await;
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let hello: Envelope =
            serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        let mut message = ack(&hello);
        message["request_id"] = json!(uuid::Uuid::new_v4().to_string());
        socket
            .send(Message::Text(message.to_string().into()))
            .await
            .unwrap();
    });
    assert!(matches!(
        SignalClient::connect(&identity, &SecretString::new("dev_test".into())).await,
        Err(SignalError::InvalidMessage)
    ));
    task.await.unwrap();
}
#[tokio::test]
async fn slow_event_consumer_closes_instead_of_unbounded_queue() {
    let (listener, identity) = listener().await;
    let (finished, ready) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let hello: Envelope =
            serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        let mut message = ack(&hello);
        socket
            .send(Message::Text(message.to_string().into()))
            .await
            .unwrap();
        for seq in 1..=33 {
            message["type"] = json!("session.updated");
            message["seq"] = json!(seq);
            socket
                .send(Message::Text(message.to_string().into()))
                .await
                .unwrap();
        }
        let heartbeats = tokio::time::timeout(Duration::from_secs(4), async {
            let mut heartbeats = 0;
            loop {
                match socket.next().await.unwrap().unwrap() {
                    Message::Close(_) => break heartbeats,
                    Message::Text(text) => {
                        let event: Envelope = serde_json::from_str(&text).unwrap();
                        assert_eq!(event.kind, "presence.heartbeat");
                        heartbeats += 1;
                    }
                    _ => panic!("unexpected frame while bounded receiver is stalled"),
                }
            }
        })
        .await
        .unwrap();
        assert!(heartbeats >= 1);
        finished.send(()).unwrap();
    });
    let mut client = SignalClient::connect(&identity, &SecretString::new("dev_test".into()))
        .await
        .unwrap();
    ready.await.unwrap();
    for _ in 0..32 {
        assert_eq!(client.receive().await.unwrap().kind, "session.updated");
    }
    assert_eq!(client.receive().await.unwrap_err(), SignalError::Closed);
    client.close().await;
    task.await.unwrap();
}

#[tokio::test]
async fn full_incoming_queue_preserves_order_and_outgoing_command_progress() {
    let (listener, identity) = listener().await;
    let (sent, ready) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let hello: Envelope =
            serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        let mut message = ack(&hello);
        socket
            .send(Message::Text(message.to_string().into()))
            .await
            .unwrap();
        message["type"] = json!("session.pending");
        for seq in 1..=128 {
            message["seq"] = json!(seq);
            socket
                .send(Message::Text(message.to_string().into()))
                .await
                .unwrap();
        }
        sent.send(()).unwrap();
        let command: Envelope =
            serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(command.kind, "session.request");
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
    });
    let mut client = SignalClient::connect(&identity, &SecretString::new("dev_test".into()))
        .await
        .unwrap();
    ready.await.unwrap();
    // Let the fixed 32-slot receiver fill without consuming it. A pending event
    // must not block the same driver's independent outbound-command branch.
    tokio::time::sleep(Duration::from_millis(30)).await;
    tokio::time::timeout(
        Duration::from_secs(1),
        client.send(
            "session.request",
            None,
            json!({"target_device_id":uuid::Uuid::new_v4().to_string()}),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    for seq in 1..=128 {
        let message = tokio::time::timeout(Duration::from_secs(1), client.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(message.seq, seq);
    }
    client.close().await;
    task.await.unwrap();
}
