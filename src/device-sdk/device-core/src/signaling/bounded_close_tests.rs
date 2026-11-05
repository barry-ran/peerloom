//! Actual in-memory WebSocket protocol tests, not TCP/native-owner evidence.
use super::*;
use futures_util::poll;
use std::task::Poll;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio_tungstenite::tungstenite::protocol::Role;

type MemorySocket = WebSocketStream<DuplexStream>;
async fn pair() -> (MemorySocket, MemorySocket) {
    let (left, right) = tokio::io::duplex(4096);
    let client = WebSocketStream::from_raw_socket(left, Role::Client, None).await;
    let server = WebSocketStream::from_raw_socket(right, Role::Server, None).await;
    (client, server)
}

#[tokio::test]
async fn close_waits_for_reply_and_original_transport_release() {
    // Test-only observation bound; the production helper retains its single 2s budget.
    tokio::time::timeout(Duration::from_secs(5), async {
    let (mut client, mut server) = pair().await;
    let closing = close_socket_bounded(&mut client);
    tokio::pin!(closing);
    // Directly poll the real helper: the old send-only implementation returns
    // Ready here. No timer or scheduler inference is used for this control.
    assert_eq!(matches!(poll!(&mut closing), Poll::Pending), true,
        "CONTROL_SIGNAL_CLOSE_SEND_ONLY_IS_NOT_TERMINAL");
    assert!(matches!(server.next().await, Some(Ok(Message::Close(_)))));
    assert!(matches!(poll!(&mut closing), Poll::Pending),
        "CONTROL_SIGNAL_CLOSE_DELAYED_REPLY_REMAINS_PENDING");
    match server.flush().await {
        Ok(()) | Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed) => {},
        Err(error) => panic!("server close reply flush failed: {error:?}"),
    }
    // server remains owned in this stack frame: close-frame delivery is not EOF.
    assert!(matches!(poll!(&mut closing), Poll::Pending),
        "CONTROL_SIGNAL_CLOSE_REPLY_WITH_HELD_TRANSPORT_IS_NOT_TERMINAL");
    drop(server);
    closing.await.unwrap();

    }).await.expect("bounded protocol test observation expired");
}

#[tokio::test]
async fn close_handles_peer_first_without_send_after_closing() {
    // Test-only observation bound; the production helper retains its single 2s budget.
    tokio::time::timeout(Duration::from_secs(5), async {
    let (mut client, mut server) = pair().await;
    server.close(None).await.unwrap();
    assert!(matches!(client.next().await, Some(Ok(Message::Close(_)))));
    let closing = close_socket_bounded(&mut client);
    tokio::pin!(closing);
    assert!(matches!(poll!(&mut closing), Poll::Pending));
    // This polls the real server protocol through the client's automatic reply.
    assert!(matches!(server.next().await, Some(Ok(Message::Close(_)))));
    assert!(server.next().await.is_none());
    drop(server);
    closing.await.unwrap();

    }).await.expect("bounded protocol test observation expired");
}

#[tokio::test]
async fn close_handles_simultaneous_close() {
    // Test-only observation bound; the production helper retains its single 2s budget.
    tokio::time::timeout(Duration::from_secs(5), async {
    let (mut client, mut server) = pair().await;
    server.close(None).await.unwrap();
    let closing = close_socket_bounded(&mut client);
    tokio::pin!(closing);
    assert!(matches!(poll!(&mut closing), Poll::Pending));
    assert!(matches!(server.next().await, Some(Ok(Message::Close(_)))));
    assert!(server.next().await.is_none());
    drop(server);
    closing.await.unwrap();

    }).await.expect("bounded protocol test observation expired");
}

#[tokio::test]
async fn close_without_peer_response_exhausts_single_two_second_budget() {
    // Test-only observation bound; the production helper retains its single 2s budget.
    tokio::time::timeout(Duration::from_secs(5), async {
    let (mut client, _held_server) = pair().await;
    // No test-util feature or virtual time is required. The unchanged helper
    // budget is the only timer and covers both send and terminal draining.
    assert!(matches!(close_socket_bounded(&mut client).await, Err(SocketCloseError::Timeout)));

    }).await.expect("bounded protocol test observation expired");
}

#[tokio::test]
async fn close_preserves_abnormal_transport_failure() {
    // Test-only observation bound; the production helper retains its single 2s budget.
    tokio::time::timeout(Duration::from_secs(5), async {
    let (mut client, server) = pair().await;
    let closing = close_socket_bounded(&mut client);
    tokio::pin!(closing);
    assert!(matches!(poll!(&mut closing), Poll::Pending));
    drop(server);
    match closing.await {
        Err(SocketCloseError::WebSocket(error)) => {
            assert!(!matches!(error, tokio_tungstenite::tungstenite::Error::ConnectionClosed));
        }
        result => panic!("CONTROL_SIGNAL_CLOSE_ABNORMAL_EOF_MUST_REMAIN_ERROR: {result:?}"),
    }

    }).await.expect("bounded protocol test observation expired");
}

#[tokio::test]
async fn previously_consumed_protocol_error_cannot_become_clean_none() {
    // Test-only observation bound; the production helper retains its single 2s budget.
    tokio::time::timeout(Duration::from_secs(5), async {
    let (left, mut raw_peer) = tokio::io::duplex(4096);
    let mut client = WebSocketStream::from_raw_socket(left, Role::Client, None).await;
    // Reserved opcode is a deterministic real parser error, not a fake stream.
    raw_peer.write_all(&[0x83, 0x00]).await.unwrap();
    assert!(matches!(client.next().await, Some(Err(_))));
    assert!(client.is_terminated());
    assert!(matches!(close_socket_bounded(&mut client).await,
        Err(SocketCloseError::PreviouslyTerminated)),
        "CONTROL_SIGNAL_CLOSE_PRIOR_ERROR_IS_NOT_CLEAN_NONE");

    }).await.expect("bounded protocol test observation expired");
}

