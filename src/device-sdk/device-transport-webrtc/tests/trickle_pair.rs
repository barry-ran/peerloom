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
