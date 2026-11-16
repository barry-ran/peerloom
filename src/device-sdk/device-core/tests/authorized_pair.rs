//! 注册由 identity_service 单独覆盖；本测试从开发 fixture 已注册凭证开始。
//! 验证真实 Go/PG/Redis 授权及初始 SDP 与增量 ICE 通过 WSS 转发，再跑真实 DTLS/SCTP。
use device_core::lease::LeaseGuard;
use device_core::{
    identity::IdentityClient,
    signaling::{Envelope, SignalClient},
};
use device_protocol::{ChannelMode, ConnectionPolicy};
use device_storage::{SecretString, StoredIdentity};
use device_transport_webrtc::{
    IceCandidate, LocalIceEvent, PeerTransport, SessionDescription, TransportConfig,
};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
#[derive(Deserialize)]
struct Device {
    application_id: String,
    device_id: String,
    device_credential: String,
}
impl Device {
    fn identity(self) -> (String, StoredIdentity) {
        (
            self.application_id,
            StoredIdentity {
                device_id: self.device_id,
                device_credential: SecretString::new(self.device_credential),
            },
        )
    }
}
#[derive(Deserialize)]
struct Fixture {
    source: Device,
    target: Device,
}
async fn event(client: &mut SignalClient, kind: &str) -> Envelope {
    let envelope = tokio::time::timeout(Duration::from_secs(15), client.receive())
        .await
        .expect("signal deadline")
        .expect("signal message");
    assert_eq!(envelope.kind, kind);
    envelope
}
fn transport_config() -> TransportConfig {
    TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        bind_address: "127.0.0.1:0".parse().unwrap(),
        include_loopback: true,
        operation_timeout: Duration::from_secs(15),
        ..TransportConfig::default()
    }
}
async fn exercise_pair(expire_after_disconnect: bool) {
    let path = std::env::var("TEST_SIGNAL_FIXTURE_FILE").expect("pair fixture path");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let data = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    let fixture: Fixture = serde_json::from_slice(&data).expect("pair fixture JSON");
    let (app_a, identity_a) = fixture.source.identity();
    let (app_b, identity_b) = fixture.target.identity();
    assert_ne!(
        app_a, app_b,
        "fixture must exercise same-tenant cross-application authorization"
    );
    let client = IdentityClient::new(
        &std::env::var("TEST_IDENTITY_BASE_URL").expect("test URL"),
        true,
        Duration::from_secs(10),
    )
    .unwrap();
    let self_a = client.device_self(&identity_a).await.unwrap();
    let self_b = client.device_self(&identity_b).await.unwrap();
    assert_eq!(self_a.tenant_id, self_b.tenant_id);
    assert_eq!(self_a.application_id, app_a);
    assert_eq!(self_b.application_id, app_b);
    let mut signal_a = SignalClient::connect(&client, &identity_a.device_credential)
        .await
        .unwrap();
    let mut signal_b = SignalClient::connect(&client, &identity_b.device_credential)
        .await
        .unwrap();
    let request_id = signal_a
        .send(
            "session.request",
            None,
            json!({"target_device_id":identity_b.device_id}),
        )
        .await
        .unwrap();
    let pending_a = event(&mut signal_a, "session.pending").await;
    let pending_b = event(&mut signal_b, "session.pending").await;
    assert_eq!(pending_a.request_id.as_deref(), Some(request_id.as_str()));
    assert_eq!(pending_a.session_id, pending_b.session_id);
    assert_eq!(pending_b.payload["state"], "authorizing");
    let session = pending_a.session_id.unwrap();
    // 目标同意之前不允许转发 SDP。
    signal_a
        .send("session.offer", Some(&session), json!({"sdp":"v=0\r\n"}))
        .await
        .unwrap();
    assert_eq!(
        event(&mut signal_a, "error").await.payload["code"],
        "TARGET_APPROVAL_REQUIRED"
    );
    signal_b
        .send("session.accept", Some(&session), json!({}))
        .await
        .unwrap();
    assert_eq!(
        event(&mut signal_a, "session.updated").await.payload["state"],
        "connecting"
    );
    assert_eq!(
        event(&mut signal_b, "session.updated").await.payload["state"],
        "connecting"
    );
    let peer_a = std::sync::Arc::new(PeerTransport::new(transport_config()).await.unwrap());
    let peer_b = std::sync::Arc::new(PeerTransport::new(transport_config()).await.unwrap());
    let mut outgoing = peer_a
        .create_channel("authorized.echo", ChannelMode::ReliableMessage)
        .await
        .unwrap();
    let offer = peer_a.create_offer_trickle().await.unwrap();
    assert!(offer.sdp.contains("a=fingerprint:"));
    assert!(!offer.sdp.contains("a=candidate:"));
    assert!(!offer.sdp.contains("a=end-of-candidates"));
    signal_a
        .send("session.offer", Some(&session), json!({"sdp":offer.sdp}))
        .await
        .unwrap();
    let routed = event(&mut signal_b, "session.offer").await;
    assert_eq!(routed.session_id.as_deref(), Some(session.as_str()));
    assert_eq!(routed.negotiation_generation, Some(1));
    let answer = peer_b
        .answer_offer_trickle(
            SessionDescription::offer(routed.payload["sdp"].as_str().unwrap().into()).unwrap(),
        )
        .await
        .unwrap();
    signal_b
        .send("session.answer", Some(&session), json!({"sdp":answer.sdp}))
        .await
        .unwrap();
    let routed = event(&mut signal_a, "session.answer").await;
    assert_eq!(routed.session_id.as_deref(), Some(session.as_str()));
    peer_a
        .apply_answer_trickle(
            SessionDescription::answer(routed.payload["sdp"].as_str().unwrap().into()).unwrap(),
        )
        .await
        .unwrap();
    let mut complete = [false, false];
    tokio::time::timeout(Duration::from_secs(15), async {
        while !complete.iter().all(|done| *done) {
            let (side, candidate) = tokio::select! {
                candidate = peer_a.next_local_ice(), if !complete[0] => (0,candidate.unwrap()),
                candidate = peer_b.next_local_ice(), if !complete[1] => (1,candidate.unwrap()),
            };
            let payload = match candidate {
                LocalIceEvent::Candidate(candidate) => json!({"candidates":[{
                    "candidate":candidate.candidate,"sdp_mid":candidate.sdp_mid,
                    "sdp_mline_index":candidate.sdp_mline_index,"username_fragment":candidate.username_fragment
                }],"complete":false}),
                LocalIceEvent::Complete => { complete[side]=true;json!({"candidates":[],"complete":true}) },
                LocalIceEvent::Nominated => continue,
            };
            let (from,to,peer) = if side==0 { (&signal_a,&mut signal_b,&peer_b) }
                else { (&signal_b,&mut signal_a,&peer_a) };
            let local = if side==0 { peer_a.clone() } else { peer_b.clone() };
            let (_, outcome) = from.send_ice_generation(&session,payload,1,local.clone()).await.unwrap();
            match outcome {
                device_core::signaling::IceConveyOutcome::SuppressedNomination => continue,
                device_core::signaling::IceConveyOutcome::Sent {generation, ticket} => {
                    assert_eq!(generation,1);
                    if let Some(ticket)=ticket { local.ack_local_ice_convey(ticket).await.unwrap(); }
                }
            }
            let routed=event(to,"session.ice").await;
            assert_eq!(routed.session_id.as_deref(),Some(session.as_str()));
            assert_eq!(routed.negotiation_generation,Some(1));
            let candidates:Vec<IceCandidate>=routed.payload["candidates"].as_array().unwrap().iter().map(|c|IceCandidate {
                candidate:c["candidate"].as_str().unwrap().into(),
                sdp_mid:c["sdp_mid"].as_str().unwrap().into(),
                sdp_mline_index:u16::try_from(c["sdp_mline_index"].as_u64().unwrap()).unwrap(),
                username_fragment:c["username_fragment"].as_str().unwrap().into(),
            }).collect();
            peer.add_remote_ice(&candidates,routed.payload["complete"].as_bool().unwrap()).await.unwrap();
        }
    }).await.unwrap();
    let mut incoming = peer_b.accept_channel().await.unwrap();
    outgoing.wait_open().await.unwrap();
    incoming.wait_open().await.unwrap();
    for bytes in ["已授权跨应用直连".as_bytes(), &[0, 255, 0, 128]] {
        outgoing.send(bytes).await.unwrap();
        assert_eq!(incoming.receive().await.unwrap(), bytes);
        incoming.send(bytes).await.unwrap();
        assert_eq!(outgoing.receive().await.unwrap(), bytes);
    }
    signal_a
        .send("session.connected", Some(&session), json!({}))
        .await
        .unwrap();
    signal_b
        .send("session.connected", Some(&session), json!({}))
        .await
        .unwrap();
    let mut guards = [
        LeaseGuard::new(
            session.clone(),
            identity_a.device_id.clone(),
            identity_b.device_id.clone(),
        )
        .unwrap(),
        LeaseGuard::new(
            session.clone(),
            identity_a.device_id.clone(),
            identity_b.device_id.clone(),
        )
        .unwrap(),
    ];
    for (index, signal) in [&mut signal_a, &mut signal_b].into_iter().enumerate() {
        event(signal, "session.updated").await;
        let connected = event(signal, "session.updated").await;
        assert_eq!(connected.payload["state"], "connected");
        guards[index]
            .apply(
                &connected,
                &signal.server_clock(),
                std::time::Instant::now(),
            )
            .unwrap();
        assert!(guards[index].is_authorized(std::time::Instant::now()));
    }
    if expire_after_disconnect {
        signal_a.close().await;
        signal_b.close().await;
        // WSS 中断不自动破坏可用 P2P，也绝不能隐式延长授权。
        outgoing.send(b"before-lease-expiry").await.unwrap();
        assert_eq!(incoming.receive().await.unwrap(), b"before-lease-expiry");
        let deadline = guards
            .iter()
            .map(|guard| guard.deadline().unwrap())
            .min()
            .unwrap();
        assert!(deadline.duration_since(std::time::Instant::now()) <= Duration::from_secs(60));
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        // 编排调用方在期限到达时执行关闭；LeaseGuard 本身是无 socket 的策略对象。
        for guard in &mut guards {
            guard.invalidate();
        }
        peer_a.close().await.unwrap();
        peer_b.close().await.unwrap();
        assert!(outgoing.send(b"after-lease-expiry").await.is_err());
        assert!(
            guards
                .iter()
                .all(|guard| !guard.is_authorized(std::time::Instant::now()))
        );
        return;
    }
    signal_a
        .send("session.terminate", Some(&session), json!({}))
        .await
        .unwrap();
    assert_eq!(
        event(&mut signal_a, "session.terminated").await.payload["state"],
        "closed"
    );
    assert_eq!(
        event(&mut signal_b, "session.terminated").await.payload["state"],
        "closed"
    );
    outgoing.close().await.unwrap();
    peer_a.close().await.unwrap();
    peer_b.close().await.unwrap();
    signal_a.close().await;
    signal_b.close().await;
}

#[tokio::test]
#[ignore = "requires disposable authorized pair fixture, real UDP and ~60s lease expiry"]
async fn actual_authorized_signaling_and_webrtc_pair() {
    exercise_pair(false).await;
    exercise_pair(true).await;
}
