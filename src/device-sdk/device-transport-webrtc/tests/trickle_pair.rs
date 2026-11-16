//! Owned loopback socket acceptance: slow TURN must not serialize usable host ICE.
use device_protocol::{ChannelMode, ConnectionPolicy};
use device_transport_webrtc::{
    CandidateKind, LocalIceEvent, PeerTransport, RTCIceServer, TransportConfig, TransportError,
};
use std::{sync::Arc, time::Duration};
async fn pump(from: Arc<PeerTransport>, to: Arc<PeerTransport>) -> Result<(), TransportError> {
    loop {
        match from.next_local_ice().await? {
            LocalIceEvent::Candidate(candidate) => to.add_remote_ice(&[candidate], false).await?,
            LocalIceEvent::Complete => {
                to.add_remote_ice(&[], true).await?;
                return Ok(());
            }
        }
    }
}
#[tokio::test]
#[ignore = "real owned loopback UDP; explicit acceptance gate"]
async fn trickle_connects_before_unresponsive_turn_finishes() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let blackhole = tokio::spawn(async move {
        let mut b = [0u8; 4096];
        while socket.recv_from(&mut b).await.is_ok() {}
    });
    let config = TransportConfig {
        policy: ConnectionPolicy::Auto,
        include_loopback: true,
        bind_address: "127.0.0.1:0".parse().unwrap(),
        ice_servers: vec![RTCIceServer {
            urls: vec![format!("turn:127.0.0.1:{port}?transport=udp")],
            username: "test".into(),
            credential: "test-only".into(),
        }],
        ..Default::default()
    };
    let a = Arc::new(PeerTransport::new(config.clone()).await.unwrap());
    let b = Arc::new(PeerTransport::new(config).await.unwrap());
    let mut sender = a
        .create_channel("trickle", ChannelMode::ReliableMessage)
        .await
        .unwrap();
    let initial = tokio::time::Instant::now();
    let offer = a.create_offer_trickle().await.unwrap();
    assert!(!offer.sdp.contains("a=candidate:"));
    let answer = b.answer_offer_trickle(offer).await.unwrap();
    a.apply_answer_trickle(answer).await.unwrap();
    assert!(initial.elapsed() < Duration::from_secs(2));
    let mut ab = tokio::spawn(pump(a.clone(), b.clone()));
    let mut ba = tokio::spawn(pump(b.clone(), a.clone()));
    let outcome = tokio::time::timeout(Duration::from_secs(6), async {
        let mut receiver = b.accept_channel().await?;
        sender.wait_open().await?;
        receiver.wait_open().await?;
        sender.send(&[1, 2, 3]).await?;
        assert_eq!(receiver.receive().await?, [1, 2, 3]);
        receiver.send(&[4, 5]).await?;
        assert_eq!(sender.receive().await?, [4, 5]);
        assert_eq!(
            a.selected_candidate_types().await?,
            Some((CandidateKind::Host, CandidateKind::Host))
        );
        Ok::<_, TransportError>(())
    })
    .await;
    if matches!(outcome, Ok(Ok(()))) {
        // A slow branch may finish after data is already flowing: keep pumps alive.
        assert!(
            tokio::time::timeout(Duration::from_secs(10), &mut ab)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(10), &mut ba)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
        a.add_remote_ice(&[], true).await.unwrap(); // repeated completion is idempotent
        assert_eq!(
            a.gathering_outcome(),
            device_transport_webrtc::GatheringOutcome::Complete
        );
        assert_eq!(
            b.gathering_outcome(),
            device_transport_webrtc::GatheringOutcome::Complete
        );
    }
    a.close().await.unwrap();
    b.close().await.unwrap();
    ab.abort();
    ba.abort();
    if !matches!(outcome, Ok(Ok(()))) {
        let _ = ab.await;
        let _ = ba.await;
    }
    blackhole.abort();
    let _ = blackhole.await;
    assert!(matches!(outcome, Ok(Ok(()))), "{outcome:?}");
}

#[tokio::test]
#[ignore = "real owned loopback UDP; explicit acceptance gate"]
async fn trickle_relay_only_never_falls_back_and_close_wakes_pending_event() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let packets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = packets.clone();
    let blackhole = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        while socket.recv_from(&mut bytes).await.is_ok() {
            observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
    let config = TransportConfig {
        policy: ConnectionPolicy::RelayOnly,
        include_loopback: true,
        bind_address: "127.0.0.1:0".parse().unwrap(),
        ice_servers: vec![RTCIceServer {
            urls: vec![format!("turn:127.0.0.1:{port}?transport=udp")],
            username: "test".into(),
            credential: "test-only".into(),
        }],
        ..Default::default()
    };
    let a = Arc::new(PeerTransport::new(config.clone()).await.unwrap());
    let b = Arc::new(PeerTransport::new(config).await.unwrap());
    let mut channel = a
        .create_channel("must-relay", ChannelMode::ReliableMessage)
        .await
        .unwrap();
    let offer = a.create_offer_trickle().await.unwrap();
    let answer = b.answer_offer_trickle(offer).await.unwrap();
    a.apply_answer_trickle(answer).await.unwrap();
    // Cancelling a pending receive must neither consume nor fabricate Complete.
    assert!(
        tokio::time::timeout(Duration::from_millis(30), a.next_local_ice())
            .await
            .is_err()
    );
    let gather = tokio::time::timeout(Duration::from_secs(12), async {
        let (left, right) = tokio::join!(a.next_local_ice(), b.next_local_ice());
        assert!(matches!(left, Ok(LocalIceEvent::Complete)));
        assert!(matches!(right, Ok(LocalIceEvent::Complete)));
        a.add_remote_ice(&[], true).await.unwrap();
        b.add_remote_ice(&[], true).await.unwrap();
    })
    .await;
    assert!(packets.load(std::sync::atomic::Ordering::Relaxed) > 0);
    assert!(gather.is_ok());
    assert!(
        tokio::time::timeout(Duration::from_millis(200), channel.wait_open())
            .await
            .is_err()
    );
    assert_eq!(a.selected_candidate_types().await.unwrap(), None);
    let waiting = a.clone();
    let event = tokio::spawn(async move { waiting.next_local_ice().await });
    a.close().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), event)
            .await
            .unwrap()
            .unwrap(),
        Err(TransportError::Closed)
    ));
    b.close().await.unwrap();
    blackhole.abort();
    let _ = blackhole.await;
}
