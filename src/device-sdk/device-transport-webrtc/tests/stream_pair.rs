use device_protocol::ConnectionPolicy;
use device_transport_webrtc::{PeerTransport, StreamError, TransportConfig};

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn actual_byte_stream_preserves_bytes_and_half_close() {
    let config = TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        include_loopback: true,
        ..TransportConfig::default()
    };
    let source = PeerTransport::new(config.clone()).await.unwrap();
    let target = PeerTransport::new(config).await.unwrap();
    let mut outgoing = source.create_stream("bytes").await.unwrap();
    let offer = source.create_offer().await.unwrap();
    let answer = target.answer_offer(offer).await.unwrap();
    source.apply_answer(answer).await.unwrap();
    let mut incoming = target.accept_stream().await.unwrap();
    let (a, b) = tokio::join!(outgoing.wait_open(), incoming.wait_open());
    a.unwrap();
    b.unwrap();
    assert_eq!(
        incoming.wait_closed_after_fin().await,
        Err(StreamError::Transport(
            device_transport_webrtc::TransportError::NotReady
        ))
    );
    let input: Vec<u8> = (0..(256 << 10)).map(|i| (i % 251) as u8).collect();
    let mut sent = 0;
    while sent < input.len() {
        let n = outgoing.write(&input[sent..]).await.unwrap();
        assert!(n > 0 && n <= 16 << 10);
        sent += n;
    }
    outgoing.shutdown_write().await.unwrap();
    outgoing.shutdown_write().await.unwrap();
    assert_eq!(
        outgoing.write(b"after FIN").await,
        Err(StreamError::WriteClosed)
    );
    let mut received = Vec::new();
    let mut buffer = [0; 137];
    loop {
        let n = incoming.read(&mut buffer).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..n]);
    }
    assert_eq!(received, input);
    // Waiting for full close after FIN is cancellable and must not close the
    // reverse direction or consume/produce another EOF.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            incoming.wait_closed_after_fin()
        )
        .await
        .is_err()
    );
    // A FIN only closes one direction; the receiver can still send its response.
    assert_eq!(incoming.write("已接收".as_bytes()).await.unwrap(), 9);
    incoming.shutdown_write().await.unwrap();
    let n = outgoing.read(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..n], "已接收".as_bytes());
    assert_eq!(outgoing.read(&mut buffer).await.unwrap(), 0);
    outgoing.close().await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        incoming.wait_closed_after_fin(),
    )
    .await
    .unwrap()
    .unwrap();
    source.close().await.unwrap();
    target.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn stream_backpressure_does_not_skip_bytes_or_sequence() {
    let config = TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        include_loopback: true,
        send_buffer_bytes: 128,
        max_message_bytes: 128,
        ..TransportConfig::default()
    };
    let source = PeerTransport::new(config.clone()).await.unwrap();
    let target = PeerTransport::new(config).await.unwrap();
    let mut outgoing = source.create_stream("bounded").await.unwrap();
    let offer = source.create_offer().await.unwrap();
    let answer = target.answer_offer(offer).await.unwrap();
    source.apply_answer(answer).await.unwrap();
    let mut incoming = target.accept_stream().await.unwrap();
    let (a, b) = tokio::join!(outgoing.wait_open(), incoming.wait_open());
    a.unwrap();
    b.unwrap();
    let mut accepted = 0;
    let initial_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while accepted == 0 {
        match outgoing.write(&[7; 512]).await {
            Ok(n) => accepted += n,
            Err(StreamError::Transport(device_transport_webrtc::TransportError::BufferFull))
                if tokio::time::Instant::now() < initial_deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await
            }
            other => panic!("initial bounded send failed: {other:?}"),
        }
    }
    let mut full = false;
    for _ in 0..32 {
        match outgoing.write(&[7; 512]).await {
            Ok(n) => accepted += n,
            Err(StreamError::Transport(device_transport_webrtc::TransportError::BufferFull)) => {
                full = true;
                break;
            }
            other => panic!("unexpected send: {other:?}"),
        }
    }
    assert!(
        accepted > 0 && full,
        "bounded sender must apply backpressure"
    );
    let mut buffer = [0; 64];
    let mut received = 0;
    while received < accepted {
        let n = incoming.read(&mut buffer).await.unwrap();
        assert!(n > 0);
        assert!(buffer[..n].iter().all(|byte| *byte == 7));
        received += n;
    }
    assert_eq!(received, accepted);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match outgoing.write(b"one").await {
            Ok(3) => break,
            Err(StreamError::Transport(device_transport_webrtc::TransportError::BufferFull))
                if tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await
            }
            other => panic!("backpressure did not recover: {other:?}"),
        }
    }
    assert_eq!(incoming.read(&mut buffer).await.unwrap(), 3);
    assert_eq!(&buffer[..3], b"one");
    outgoing.close().await.unwrap();
    // Abrupt close must be an error, never a false orderly EOF.
    assert!(incoming.read(&mut buffer).await.is_err());
    source.close().await.unwrap();
    target.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn stream_rejects_plain_message_channel_protocol() {
    let config = TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        include_loopback: true,
        ..TransportConfig::default()
    };
    let source = PeerTransport::new(config.clone()).await.unwrap();
    let target = PeerTransport::new(config).await.unwrap();
    let _message = source
        .create_channel(
            "not-a-stream",
            device_protocol::ChannelMode::ReliableMessage,
        )
        .await
        .unwrap();
    let offer = source.create_offer().await.unwrap();
    let answer = target.answer_offer(offer).await.unwrap();
    source.apply_answer(answer).await.unwrap();
    assert!(matches!(
        target.accept_stream().await,
        Err(StreamError::Protocol)
    ));
    source.close().await.unwrap();
    target.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn stream_negotiates_different_receive_limits() {
    let large = TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        include_loopback: true,
        ..TransportConfig::default()
    };
    let small = TransportConfig {
        max_message_bytes: 128,
        ..large.clone()
    };
    let source = PeerTransport::new(large).await.unwrap();
    let target = PeerTransport::new(small).await.unwrap();
    let mut a = source.create_stream("different").await.unwrap();
    assert!(matches!(
        a.write(b"early").await,
        Err(StreamError::Transport(
            device_transport_webrtc::TransportError::NotReady
        ))
    ));
    let offer = source.create_offer().await.unwrap();
    let answer = target.answer_offer(offer).await.unwrap();
    source.apply_answer(answer).await.unwrap();
    let mut b = target.accept_stream().await.unwrap();
    let (left, right) = tokio::join!(a.wait_open(), b.wait_open());
    left.unwrap();
    right.unwrap();
    let payload = [42; 512];
    let mut offset = 0;
    while offset < payload.len() {
        let n = a.write(&payload[offset..]).await.unwrap();
        assert!(n <= 111);
        offset += n;
    }
    a.shutdown_write().await.unwrap();
    let mut received = Vec::new();
    let mut buffer = [0; 37];
    loop {
        let n = b.read(&mut buffer).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..n]);
    }
    assert_eq!(received, payload);
    a.close().await.unwrap();
    b.close().await.unwrap();
    source.close().await.unwrap();
    target.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn cancelling_peer_settings_wait_does_not_resend_local_settings() {
    let config = TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        include_loopback: true,
        ..TransportConfig::default()
    };
    let source = PeerTransport::new(config.clone()).await.unwrap();
    let target = PeerTransport::new(config).await.unwrap();
    let mut stream = source.create_stream("cancel-settings").await.unwrap();
    let offer = source.create_offer().await.unwrap();
    let answer = target.answer_offer(offer).await.unwrap();
    source.apply_answer(answer).await.unwrap();
    let mut raw = target.accept_channel().await.unwrap();
    raw.wait_open().await.unwrap();
    {
        let waiting = stream.wait_open();
        tokio::pin!(waiting);
        tokio::select! {
            received=raw.receive()=> {
                let frame=received.unwrap();
                assert_eq!(&frame[..5],b"PLS1\x03");
                assert_eq!(u64::from_be_bytes(frame[5..13].try_into().unwrap()),0);
            }
            _=&mut waiting => panic!("must await peer SETTINGS"),
            _=tokio::time::sleep(std::time::Duration::from_secs(3))=>panic!("settings send deadline"),
        }
        // Drop the pending receive future after the peer observed the local SETTINGS.
    }
    let mut settings = b"PLS1\x03".to_vec();
    settings.extend_from_slice(&0u64.to_be_bytes());
    settings.extend_from_slice(&4u32.to_be_bytes());
    settings.extend_from_slice(&16384u32.to_be_bytes());
    raw.send(&settings).await.unwrap();
    stream.wait_open().await.unwrap();
    assert_eq!(stream.write(b"one").await.unwrap(), 3);
    let data = raw.receive().await.unwrap();
    assert_eq!(&data[..5], b"PLS1\x01");
    assert_eq!(u64::from_be_bytes(data[5..13].try_into().unwrap()), 1);
    assert_eq!(&data[17..], b"one");
    stream.close().await.unwrap();
    source.close().await.unwrap();
    target.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn idle_read_timeout_preserves_sequence_partial_buffer_and_fin() {
    use device_transport_webrtc::TransportError;
    use std::{sync::Arc, time::Duration};
    let config = TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        include_loopback: true,
        operation_timeout: Duration::from_secs(2),
        ..TransportConfig::default()
    };
    let a = Arc::new(PeerTransport::new(config.clone()).await.unwrap());
    let b = Arc::new(PeerTransport::new(config).await.unwrap());
    let aa = a.clone();
    let bb = b.clone();
    let operation = tokio::spawn(async move {
        let mut source = aa.create_stream("idle").await.unwrap();
        let offer = aa.create_offer().await.unwrap();
        let answer = bb.answer_offer(offer).await.unwrap();
        aa.apply_answer(answer).await.unwrap();
        let mut target = bb.accept_stream().await.unwrap();
        let (x, y) = tokio::join!(source.wait_open(), target.wait_open());
        x.unwrap();
        y.unwrap();
        let mut bytes = [0; 2];
        assert_eq!(
            target.read(&mut bytes).await,
            Err(StreamError::Transport(TransportError::Timeout))
        );
        assert_eq!(source.write(b"abcd").await.unwrap(), 4);
        assert_eq!(target.read(&mut bytes).await.unwrap(), 2);
        assert_eq!(&bytes, b"ab");
        // Buffered remainder is retained even after an idle delay longer than the poll deadline.
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert_eq!(target.read(&mut bytes).await.unwrap(), 2);
        assert_eq!(&bytes, b"cd");
        assert_eq!(
            target.read(&mut bytes).await,
            Err(StreamError::Transport(TransportError::Timeout))
        );
        source.shutdown_write().await.unwrap();
        assert_eq!(target.read(&mut bytes).await.unwrap(), 0);
        assert_eq!(
            target.wait_closed_after_fin().await,
            Err(StreamError::Transport(TransportError::Timeout))
        );
        target.write(b"ok").await.unwrap();
        assert_eq!(source.read(&mut bytes).await.unwrap(), 2);
        assert_eq!(&bytes, b"ok");
        source.close().await.unwrap();
        target.close().await.unwrap();
    });
    let result = tokio::time::timeout(Duration::from_secs(20), operation).await;
    a.close().await.unwrap();
    b.close().await.unwrap();
    result.expect("bounded idle timeout regression").unwrap();
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn unidirectional_stream_notifications_do_not_starve_reverse_reliable_channel() {
    use device_protocol::ChannelMode;
    use device_transport_webrtc::{ByteStream, CandidateKind, MessageChannel, TransportError};
    use std::{sync::Arc, time::Duration};

    async fn write_frame(stream: &mut ByteStream, bytes: &[u8], sequence: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            match stream.write(bytes).await {
                Ok(n) => {
                    assert_eq!(n, bytes.len(), "8KiB fits the negotiated stream chunk");
                    return;
                }
                Err(StreamError::Transport(TransportError::BufferFull))
                    if tokio::time::Instant::now() < deadline =>
                {
                    // BufferFull means nothing was accepted; never retry an uncertain write.
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                other => panic!("unidirectional stream write frame {sequence}: {other:?}"),
            }
        }
    }

    async fn send_ack(channel: &MessageChannel, bytes: &[u8]) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            match channel.send(bytes).await {
                Ok(()) => return,
                Err(TransportError::BufferFull) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                other => panic!("independent reliable ACK send: {other:?}"),
            }
        }
    }

    async fn finish(stream: &mut ByteStream) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            match stream.shutdown_write().await {
                Ok(()) => return,
                Err(StreamError::Transport(TransportError::BufferFull))
                    if tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                other => panic!("unidirectional stream FIN: {other:?}"),
            }
        }
    }

    let config = TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        bind_address: "127.0.0.1:0".parse().unwrap(),
        include_loopback: true,
        operation_timeout: Duration::from_secs(3),
        ..TransportConfig::default()
    };
    let source = Arc::new(PeerTransport::new(config.clone()).await.unwrap());
    let target = match PeerTransport::new(config).await {
        Ok(peer) => Arc::new(peer),
        Err(error) => {
            let closed = source.close().await;
            assert!(closed.is_ok(), "source cleanup after target setup failure");
            panic!("target setup: {error:?}");
        }
    };
    let left = source.clone();
    let right = target.clone();
    // Isolate every assertion so both peers are closed even after panic or timeout.
    let mut operation = tokio::spawn(async move {
        let mut outgoing = left.create_stream("one-way-notifications").await.unwrap();
        let offer = left.create_offer().await.unwrap();
        assert!(offer.sdp.contains("a=fingerprint:"), "DTLS remains enabled");
        let answer = right.answer_offer(offer).await.unwrap();
        assert!(
            answer.sdp.contains("a=fingerprint:"),
            "DTLS remains enabled"
        );
        left.apply_answer(answer).await.unwrap();
        let mut incoming = right.accept_stream().await.unwrap();
        let (a, b) = tokio::join!(outgoing.wait_open(), incoming.wait_open());
        a.unwrap();
        b.unwrap();

        let mut ack_sender = right
            .create_channel("reverse-reliable-ack", ChannelMode::ReliableMessage)
            .await
            .unwrap();
        let mut ack_receiver = left.accept_channel().await.unwrap();
        ack_sender.wait_open().await.unwrap();
        ack_receiver.wait_open().await.unwrap();
        assert!(ack_sender.metadata().await.unwrap().is_reliable_ordered());
        assert!(ack_receiver.metadata().await.unwrap().is_reliable_ordered());
        for peer in [&left, &right] {
            assert_eq!(
                peer.selected_candidate_types().await.unwrap(),
                Some((CandidateKind::Host, CandidateKind::Host))
            );
        }

        let mut payload: Vec<_> = (0..8192).map(|offset| (offset % 251) as u8).collect();
        let mut received = vec![0_u8; payload.len()];
        let mut ack = [0xa5_u8; 64];
        // More than the backend's 256-event queue, without changing its capacity.
        // A receiver verifies the entire frame before sending its independent ACK.
        // No task reads outgoing or ack_sender to drain write-side notifications.
        for sequence in 0_u64..1152 {
            payload[..8].copy_from_slice(&sequence.to_be_bytes());
            ack[..8].copy_from_slice(&sequence.to_be_bytes());
            write_frame(&mut outgoing, &payload, sequence).await;
            let mut offset = 0;
            while offset < received.len() {
                let n = incoming
                    .read(&mut received[offset..])
                    .await
                    .unwrap_or_else(|error| {
                        panic!("stream receive frame {sequence} offset {offset}: {error:?}")
                    });
                assert!(n > 0, "frame {sequence} cannot end before all bytes arrive");
                offset += n;
            }
            assert_eq!(received, payload, "all bytes of frame {sequence}");
            send_ack(&ack_sender, &ack).await;
            assert_eq!(
                ack_receiver.receive().await.unwrap_or_else(|error| {
                    panic!("reverse reliable ACK frame {sequence}: {error:?}")
                }),
                ack,
                "reverse reliable ACK {sequence} must not be starved"
            );
            // Separate bursts so acknowledgments can lower SCTP outstanding bytes.
            // This pacing is not a performance assertion or a transport-setting change.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        finish(&mut outgoing).await;
        let mut eof = [0_u8; 1];
        assert_eq!(incoming.read(&mut eof).await.unwrap(), 0);
        finish(&mut incoming).await;
        // The first outgoing-stream read is deliberately AFTER every frame/ACK.
        assert_eq!(outgoing.read(&mut eof).await.unwrap(), 0);
        send_ack(&ack_sender, b"control survives both stream FINs").await;
        assert_eq!(
            ack_receiver.receive().await.unwrap(),
            b"control survives both stream FINs"
        );
    });
    let outcome = tokio::time::timeout(Duration::from_secs(15), &mut operation).await;
    if !outcome.as_ref().is_ok_and(|result| result.is_ok()) {
        operation.abort();
        if outcome.is_err() {
            let _ = operation.await;
        }
    }
    let (source_closed, target_closed) = tokio::join!(source.close(), target.close());
    outcome
        .expect("bounded unidirectional stream/reverse reliable regression")
        .expect("unidirectional notifications cannot block another channel");
    source_closed.unwrap();
    target_closed.unwrap();
}
