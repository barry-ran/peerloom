//! Per-generation pumps are owned by the transport worker future. Dropping that
//! future cancels both pumps before peer.close; no detached task survives reset.
use super::*;
use device_transport_webrtc::LocalIceEvent;

pub(super) async fn send(
    peer: Arc<PeerTransport>,
    events: mpsc::Sender<Internal>,
    id: String,
    generation: u64,
    gate: Arc<Gate>,
) -> Result<(), SdkError> {
    let mut budget = IceBudget::default();
    loop {
        gate.check()?;
        let event = peer.next_local_ice().await.map_err(SdkError::Transport)?;
        let batch = match event {
            LocalIceEvent::Candidate(candidate) => IceBatch::local(Some(candidate)),
            LocalIceEvent::Complete => IceBatch::local(None),
        };
        // Validate our producer too, rather than sending malformed/oversized wire.
        let batch = IceBatch::parse(
            &serde_json::to_value(batch)
                .map_err(|_| SdkError::Signal(SignalError::InvalidMessage))?,
        )
        .map_err(SdkError::Signal)?;
        budget.admit(&batch).map_err(SdkError::Signal)?;
        let complete = batch.complete;
        gate.check()?;
        events
            .send(Internal::Ice(id.clone(), generation, batch))
            .await
            .map_err(|_| SdkError::Closed)?;
        if complete {
            // Gathering completion is not a connection-close event.
            return std::future::pending().await;
        }
    }
}

pub(super) async fn receive(
    peer: Arc<PeerTransport>,
    mut signals: mpsc::Receiver<RemoteSignal>,
    mut remote_sdp: bool,
    answer_ready: oneshot::Sender<()>,
    gate: Arc<Gate>,
) -> Result<(), SdkError> {
    let mut answer_ready = Some(answer_ready);
    let mut pending = Vec::new();
    let mut budget = IceBudget::default();
    while let Some(signal) = signals.recv().await {
        gate.check()?;
        match signal {
            RemoteSignal::Answer(answer) => {
                if remote_sdp {
                    return Err(SdkError::Signal(SignalError::InvalidMessage));
                }
                peer.apply_answer_trickle(*answer)
                    .await
                    .map_err(SdkError::Transport)?;
                remote_sdp = true;
                for batch in pending.drain(..) {
                    apply(&peer, batch).await?;
                }
                if let Some(ready) = answer_ready.take() {
                    let _ = ready.send(());
                }
            }
            RemoteSignal::Ice(mut batch) => {
                if !budget.admit(&batch).map_err(SdkError::Signal)? {
                    continue;
                }
                if remote_sdp {
                    apply(&peer, batch).await?;
                } else if batch.dedup_pending(&pending) {
                    pending.push(batch);
                }
            }
        }
    }
    Err(SdkError::Closed)
}
async fn apply(peer: &PeerTransport, batch: IceBatch) -> Result<(), SdkError> {
    peer.add_remote_ice(&batch.transport_candidates(), batch.complete)
        .await
        .map_err(SdkError::Transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestWorker = (
        mpsc::Sender<RemoteSignal>,
        oneshot::Sender<()>,
        mpsc::Receiver<Internal>,
        JoinHandle<Result<(), SdkError>>,
        Arc<Gate>,
        mpsc::Receiver<Command>,
    );
    fn worker(offer: Option<SessionDescription>, turn_port: u16) -> TestWorker {
        let gate = Arc::new(Gate::default());
        gate.update(Some(Instant::now() + Duration::from_secs(60)));
        let config = TransportConfig {
            policy: ConnectionPolicy::Auto,
            include_loopback: true,
            bind_address: "127.0.0.1:0".parse().unwrap(),
            ice_servers: vec![device_transport_webrtc::RTCIceServer {
                urls: vec![format!("turn:127.0.0.1:{turn_port}?transport=udp")],
                username: "test".into(),
                credential: "test-only".into(),
            }],
            ..TransportConfig::default()
        };
        let (control, received) = mpsc::channel(258);
        let (stop, stopped) = oneshot::channel();
        let (events, outputs) = mpsc::channel(32);
        let (sdk, commands) = mpsc::channel(32);
        let task = tokio::spawn(transport_worker(
            uuid::Uuid::new_v4().to_string(),
            1,
            gate.clone(),
            config,
            None,
            offer,
            received,
            stopped,
            events,
            sdk,
            4,
            OutboundBudget::new(1024 * 1024, 128).unwrap(),
            uuid::Uuid::new_v4().to_string(),
            None,
        ));
        (control, stop, outputs, task, gate, commands)
    }
    #[tokio::test]
    async fn real_workers_signal_sdp_first_accept_pre_answer_ice_and_cancel_after_ready() {
        // Keep an owned UDP port open without responding: host ICE succeeds
        // while this TURN interface reaches its genuine delayed terminal state.
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = blackhole.local_addr().unwrap().port();
        let (a_tx, a_stop, mut a_events, a_task, a_gate, _a_commands) = worker(None, port);
        let first = tokio::time::timeout(Duration::from_secs(5), a_events.recv())
            .await
            .unwrap()
            .unwrap();
        let Internal::Description(_, 1, "session.offer", sdp) = first else {
            panic!("initial event must be offer");
        };
        assert!(!sdp.contains("a=candidate:"));
        let (b_tx, b_stop, mut b_events, b_task, b_gate, _b_commands) =
            worker(Some(SessionDescription::offer(sdp).unwrap()), port);
        let first = tokio::time::timeout(Duration::from_secs(5), b_events.recv())
            .await
            .unwrap()
            .unwrap();
        let Internal::Description(_, 1, "session.answer", sdp) = first else {
            panic!("initial event must be answer");
        };
        assert!(!sdp.contains("a=candidate:"));
        // Intentionally deliver target candidates before its answer to exercise
        // the bounded remote pre-SDP queue, not just ideal WSS ordering.
        let first_ice = tokio::time::timeout(Duration::from_secs(5), b_events.recv())
            .await
            .unwrap()
            .unwrap();
        let Internal::Ice(_, 1, batch) = first_ice else {
            panic!("expected initial target candidate");
        };
        a_tx.send(RemoteSignal::Ice(batch)).await.unwrap();
        a_tx.send(RemoteSignal::Answer(Box::new(
            SessionDescription::answer(sdp).unwrap(),
        )))
        .await
        .unwrap();
        let mut connections = Vec::new();
        let mut completed = [false, false];
        tokio::time::timeout(Duration::from_secs(15), async {
            while connections.len() < 2 || !completed.iter().all(|v| *v) {
                let (side, event) = tokio::select! {
                    event=a_events.recv()=>(0,event.unwrap()),
                    event=b_events.recv()=>(1,event.unwrap()),
                };
                match event {
                    Internal::Ice(_, 1, batch) => {
                        completed[side] = batch.complete;
                        let tx = if side == 0 { &b_tx } else { &a_tx };
                        tx.send(RemoteSignal::Ice(batch)).await.unwrap();
                    }
                    Internal::Ready(_, 1, connection) => {
                        assert!(
                            !completed.iter().all(|done| *done),
                            "Ready must precede slow TURN gathering completion"
                        );
                        connections.push(connection);
                    }
                    Internal::Closed(_, _, error) => {
                        panic!("worker closed before ready: {error:?}")
                    }
                    _ => panic!("unexpected signal"),
                }
            }
        })
        .await
        .unwrap();
        // Ready does not discard the remote ICE receiver. Repeated terminal
        // markers remain harmless; a candidate after complete must still fail.
        a_tx.send(RemoteSignal::Ice(IceBatch::local(None)))
            .await
            .unwrap();
        b_tx.send(RemoteSignal::Ice(IceBatch::local(None)))
            .await
            .unwrap();
        let late = IceBatch::parse(&json!({"candidates":[{
            "candidate":"candidate:late 1 UDP 1 127.0.0.1 1234 typ host",
            "sdp_mid":"0","sdp_mline_index":0,"username_fragment":"late"
        }],"complete":false}))
        .unwrap();
        a_tx.send(RemoteSignal::Ice(late)).await.unwrap();
        let terminal = tokio::time::timeout(Duration::from_secs(5), a_events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            terminal,
            Internal::Closed(_, 1, SdkError::Signal(SignalError::InvalidMessage))
        ));
        let _ = a_stop.send(());
        let _ = b_stop.send(());
        tokio::time::timeout(Duration::from_secs(5), async {
            a_task.await.unwrap().unwrap();
            b_task.await.unwrap().unwrap();
        })
        .await
        .unwrap();
        assert!(a_gate.check().is_err());
        assert!(b_gate.check().is_err());
        drop(connections);
    }
}
