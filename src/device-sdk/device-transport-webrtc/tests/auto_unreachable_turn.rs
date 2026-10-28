//! Real local UDP blackhole: no public TURN, no network configuration mutation.
//! Transport policy acceptance only; this does not substitute for SDK authorization.
use device_protocol::{ChannelMode, ConnectionPolicy};
use device_transport_webrtc::{
    CandidateKind, GatheringOutcome, PeerTransport, RTCIceServer, TransportConfig, TransportError,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

struct Blackhole {
    port: u16,
    packets: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Blackhole {
    async fn start() -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let packets = Arc::new(AtomicUsize::new(0));
        let count = packets.clone();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            while socket.recv_from(&mut bytes).await.is_ok() {
                count.fetch_add(1, Ordering::Relaxed);
                // Deliberately discard; no credential, address or payload logging.
            }
        });
        Self {
            port,
            packets,
            task,
        }
    }
    fn config(&self, policy: ConnectionPolicy) -> TransportConfig {
        TransportConfig {
            policy,
            include_loopback: true,
            bind_address: "127.0.0.1:0".parse().unwrap(),
            ice_servers: vec![RTCIceServer {
                urls: vec![format!("turn:127.0.0.1:{}?transport=udp", self.port)],
                username: "owned-test-only".into(),
                credential: "not-a-real-credential".into(),
            }],
            operation_timeout: Duration::from_secs(2),
            ..TransportConfig::default()
        }
    }
}
impl Drop for Blackhole {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
#[ignore = "real owned UDP blackhole; explicit acceptance gate"]
async fn auto_uses_reachable_host_when_turn_never_answers() {
    auto_pair(Duration::from_secs(2), Duration::from_secs(12)).await;
}

#[tokio::test]
#[ignore = "real default timeout and owned UDP blackhole; explicit acceptance gate"]
async fn default_twenty_second_gather_connects_within_forty_five_seconds() {
    let operation_timeout = TransportConfig::default().operation_timeout;
    assert_eq!(operation_timeout, Duration::from_secs(20));
    auto_pair(operation_timeout, Duration::from_secs(45)).await;
}

async fn auto_pair(operation_timeout: Duration, total: Duration) {
    let mut blackhole = Blackhole::start().await;
    let mut config = blackhole.config(ConnectionPolicy::Auto);
    config.operation_timeout = operation_timeout;
    let a = Arc::new(PeerTransport::new(config.clone()).await.unwrap());
    let b = match PeerTransport::new(config).await {
        Ok(peer) => Arc::new(peer),
        Err(error) => {
            let _ = a.close().await;
            panic!("second peer construction failed: {error:?}");
        }
    };
    let left = a.clone();
    let right = b.clone();
    let mut exchange = tokio::spawn(async move {
        let mut sender = left
            .create_channel("auto-host", ChannelMode::ReliableMessage)
            .await?;
        let offer = left.create_offer().await?;
        assert!(offer.sdp.contains("a=fingerprint:"));
        let answer = right.answer_offer(offer).await?;
        assert!(answer.sdp.contains("a=fingerprint:"));
        left.apply_answer(answer).await?;
        let mut receiver = right.accept_channel().await?;
        sender.wait_open().await?;
        receiver.wait_open().await?;
        for peer in [&left, &right] {
            assert_eq!(
                peer.gathering_outcome(),
                GatheringOutcome::PartialAtDeadline
            );
            assert_eq!(
                peer.selected_candidate_types().await?,
                Some((CandidateKind::Host, CandidateKind::Host))
            );
        }
        let payload = [0, 255, 1, 0, 2];
        sender.send(&payload).await?;
        assert_eq!(receiver.receive().await?, payload);
        receiver.send(&payload).await?;
        assert_eq!(sender.receive().await?, payload);
        Ok::<_, TransportError>(())
    });
    let outcome = tokio::time::timeout(total, &mut exchange).await;
    if outcome.is_err() {
        exchange.abort();
        let _ = exchange.await;
    }
    let _ = a.close().await;
    let _ = b.close().await;
    blackhole.task.abort();
    let _ = (&mut blackhole.task).await;
    assert!(
        blackhole.packets.load(Ordering::Relaxed) > 0,
        "TURN was actually attempted"
    );
    assert!(
        matches!(outcome, Ok(Ok(Ok(())))),
        "Auto must retain usable host candidates: {outcome:?}"
    );
}

#[tokio::test]
#[ignore = "real owned UDP blackhole; explicit acceptance gate"]
async fn relay_only_never_falls_back_to_host_when_turn_never_answers() {
    let mut blackhole = Blackhole::start().await;
    let peer = Arc::new(
        PeerTransport::new(blackhole.config(ConnectionPolicy::RelayOnly))
            .await
            .unwrap(),
    );
    let worker = peer.clone();
    let mut operation = tokio::spawn(async move {
        let _channel = worker
            .create_channel("relay-required", ChannelMode::ReliableMessage)
            .await?;
        worker.create_offer().await
    });
    let outcome = tokio::time::timeout(Duration::from_secs(6), &mut operation).await;
    if outcome.is_err() {
        operation.abort();
        let _ = operation.await;
    }
    let _ = peer.close().await;
    blackhole.task.abort();
    let _ = (&mut blackhole.task).await;
    assert!(
        blackhole.packets.load(Ordering::Relaxed) > 0,
        "TURN was actually attempted"
    );
    assert!(
        matches!(outcome, Ok(Ok(Err(TransportError::Timeout)))),
        "RelayOnly must not return host SDP"
    );
}

#[tokio::test]
#[ignore = "real owned UDP blackhole; explicit acceptance gate"]
async fn close_interrupts_pending_gather_without_returning_cached_sdp() {
    let mut blackhole = Blackhole::start().await;
    let mut config = blackhole.config(ConnectionPolicy::Auto);
    config.operation_timeout = Duration::from_secs(20);
    let peer = Arc::new(PeerTransport::new(config).await.unwrap());
    let worker = peer.clone();
    let mut operation = tokio::spawn(async move {
        let _channel = worker
            .create_channel("close-gather", ChannelMode::ReliableMessage)
            .await?;
        worker.create_offer().await
    });
    let attempted = tokio::time::timeout(Duration::from_secs(2), async {
        while blackhole.packets.load(Ordering::Acquire) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let closing_peer = peer.clone();
    let mut close_task = tokio::spawn(async move { closing_peer.close().await });
    let result = tokio::time::timeout(Duration::from_secs(1), &mut operation).await;
    if result.is_err() {
        operation.abort();
        let _ = operation.await;
    }
    blackhole.task.abort();
    let _ = (&mut blackhole.task).await;
    if tokio::time::timeout(Duration::from_secs(21), &mut close_task)
        .await
        .is_err()
    {
        close_task.abort();
        let _ = close_task.await;
        panic!("backend close exceeded its bounded cleanup");
    }
    assert!(attempted.is_ok(), "gather attempted TURN before close");
    assert!(matches!(result, Ok(Ok(Err(TransportError::Closed)))));
    assert_eq!(peer.gathering_outcome(), GatheringOutcome::Pending);
}
