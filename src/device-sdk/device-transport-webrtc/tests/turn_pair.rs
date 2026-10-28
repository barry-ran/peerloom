//! 真实本机 TURN：凭证由受控测试进程注入，禁止使用公网服务或日志打印秘密。
use device_protocol::{ChannelMode, ConnectionPolicy};
use device_transport_webrtc::{CandidateKind, PeerTransport, TransportConfig, TransportError};
use std::time::Duration;
use webrtc::peer_connection::RTCIceServer;

fn relay_config(wrong_password: bool) -> TransportConfig {
    let path = std::env::var("TEST_TURN_CREDENTIAL_FILE").expect("TURN credential file required");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut credential = std::fs::read_to_string(path).expect("read test credential");
    if wrong_password {
        credential.push_str("-intentionally-invalid");
    }
    TransportConfig {
        policy: ConnectionPolicy::RelayOnly,
        ice_servers: vec![RTCIceServer {
            urls: vec![std::env::var("TEST_TURN_URL").expect("TURN URL required")],
            username: std::env::var("TEST_TURN_USERNAME").expect("TURN username required"),
            credential,
        }],
        bind_address: "127.0.0.1:0".parse().unwrap(),
        include_loopback: true,
        operation_timeout: Duration::from_secs(10),
        ..TransportConfig::default()
    }
}

fn assert_relay_sdp(sdp: &str) {
    assert!(sdp.contains("a=fingerprint:"), "DTLS must remain enabled");
    let candidates: Vec<_> = sdp
        .lines()
        .filter(|line| line.starts_with("a=candidate:"))
        .collect();
    assert!(!candidates.is_empty(), "actual TURN allocation required");
    for candidate in candidates {
        let fields: Vec<_> = candidate.split_whitespace().collect();
        assert_eq!(fields.get(6), Some(&"typ"));
        assert_eq!(fields.get(7), Some(&"relay"), "relay-only cannot fall back");
        let port: u16 = fields[5].parse().unwrap();
        assert!(
            (55000..=55031).contains(&port),
            "relay port outside bounded fixture range"
        );
    }
}

type PairKinds = Option<(CandidateKind, CandidateKind)>;

async fn successful_pair(phase: &'static str) -> (PairKinds, PairKinds) {
    let a = PeerTransport::new(relay_config(false))
        .await
        .expect("TURN A");
    let b = match PeerTransport::new(relay_config(false)).await {
        Ok(peer) => peer,
        Err(error) => {
            let _ = a.close().await;
            panic!("TURN B: {error}");
        }
    };
    let a = std::sync::Arc::new(a);
    let b = std::sync::Arc::new(b);
    let task_a = a.clone();
    let task_b = b.clone();
    // 子任务隔离断言 panic，父任务在任何失败路径仍主动关闭双方。
    let result = tokio::spawn(async move {
        let a = task_a;
        let b = task_b;
        tokio::time::timeout(Duration::from_secs(40), async {
            let mut sender = a
                .create_channel("relay.echo", ChannelMode::ReliableMessage)
                .await?;
            eprintln!("TURN {phase} stage=gather-offer");
            let offer = a.create_offer().await?;
            assert_relay_sdp(&offer.sdp);
            eprintln!("TURN {phase} stage=gather-answer");
            let answer = b.answer_offer(offer).await?;
            assert_relay_sdp(&answer.sdp);
            eprintln!("TURN {phase} stage=apply-answer");
            a.apply_answer(answer).await?;
            eprintln!("TURN {phase} stage=accept-reliable");
            let mut receiver = b.accept_channel().await?;
            eprintln!("TURN {phase} stage=open-reliable");
            sender.wait_open().await?;
            eprintln!("TURN {phase} stage=open-remote-reliable");
            receiver.wait_open().await?;
            for payload in ["真实中继双向消息".as_bytes(), &[0, 255, 1, 0]] {
                eprintln!("TURN {phase} stage=send-reliable");
                sender.send(payload).await?;
                eprintln!("TURN {phase} stage=receive-reliable");
                assert_eq!(receiver.receive().await?, payload);
                eprintln!("TURN {phase} stage=reply-reliable");
                receiver.send(payload).await?;
                eprintln!("TURN {phase} stage=receive-reliable-reply");
                assert_eq!(sender.receive().await?, payload);
            }
            eprintln!("TURN {phase} stage=create-low-latency");
            let mut fast = a
                .create_channel("relay.low-latency", ChannelMode::LowLatencyMessage)
                .await?;
            eprintln!("TURN {phase} stage=accept-low-latency");
            let mut incoming = match b.accept_channel().await {
                Ok(channel) => channel,
                Err(error) => {
                    #[cfg(feature = "test-diagnostics")]
                    {
                        // Observe only AFTER the unchanged failed 10s accept. No retry,
                        // polling of channel events, SDP, packet capture or arbitrary logs.
                        eprintln!(
                            "TURN {phase} diagnostic=hot-open-source {:?}",
                            a.diagnostics()
                        );
                        eprintln!(
                            "TURN {phase} diagnostic=hot-open-target {:?}",
                            b.diagnostics()
                        );
                        eprintln!(
                            "TURN {phase} diagnostic=source-channel-state {:?}",
                            fast.diagnostic_state().await
                        );
                    }
                    return Err(error);
                }
            };
            eprintln!("TURN {phase} stage=open-low-latency");
            fast.wait_open().await?;
            eprintln!("TURN {phase} stage=open-remote-low-latency");
            incoming.wait_open().await?;
            eprintln!("TURN {phase} stage=echo-low-latency");
            fast.send(b"fast").await?;
            eprintln!("TURN {phase} stage=receive-low-latency");
            assert_eq!(incoming.receive().await?, b"fast");
            eprintln!("TURN {phase} stage=reply-low-latency");
            incoming.send(b"reply").await?;
            eprintln!("TURN {phase} stage=receive-low-latency-reply");
            assert_eq!(fast.receive().await?, b"reply");
            eprintln!("TURN {phase} stage=selected-pair");
            Ok::<_, TransportError>((
                a.selected_candidate_types().await?,
                b.selected_candidate_types().await?,
            ))
        })
        .await
    })
    .await;
    eprintln!("TURN {phase} stage=close-a");
    let a_close = a.close().await;
    eprintln!("TURN {phase} stage=close-b");
    let b_close = b.close().await;
    a_close.expect("close TURN A");
    b_close.expect("close TURN B");
    let (a_pair, b_pair) = result
        .expect("TURN exchange task")
        .expect("TURN exchange deadline")
        .expect("actual relay exchange");
    (a_pair, b_pair)
}

#[tokio::test]
#[ignore = "requires isolated real coturn with bounded loopback relay ports"]
async fn relay_only_bidirectional_and_invalid_credentials_fail_closed() {
    // 正向对照排除服务未运行导致的假阴性。
    let before = successful_pair("before-invalid-credential").await;
    let invalid = PeerTransport::new(relay_config(true))
        .await
        .expect("invalid credential peer");
    let outcome = tokio::time::timeout(Duration::from_secs(15), async {
        let _channel = invalid
            .create_channel("must.not.connect", ChannelMode::ReliableMessage)
            .await?;
        invalid.create_offer().await
    })
    .await;
    invalid.close().await.expect("close invalid peer");
    match outcome {
        Ok(Ok(description)) => assert!(
            !description
                .sdp
                .lines()
                .any(|line| line.starts_with("a=candidate:")),
            "invalid credentials must not yield any relay or fallback candidate"
        ),
        Ok(Err(TransportError::Relay | TransportError::Timeout)) => {}
        Ok(Err(error)) => panic!("unexpected invalid credential error: {error}"),
        Err(_) => panic!("transport operation exceeded its configured timeout"),
    }
    // 拒绝以后再次正向验证服务可用，不能以服务退出冒充凭证拒绝。
    let after = successful_pair("after-invalid-credential").await;
    for selected in [before.0, before.1, after.0, after.1] {
        assert_eq!(selected, Some((CandidateKind::Relay, CandidateKind::Relay)));
    }
}
