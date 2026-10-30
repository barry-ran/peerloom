// 私有真实传输 worker 回归与显式性能夹具。
// fixture() 提供测试授权，不等于完整控制面验收，不进入产品构建。
#[cfg(target_os = "linux")]
mod worker_performance {
    use super::*;
    use device_protocol::ConnectionPolicy;
    use device_transport_webrtc::{CandidateKind, PeerTransport, TransportConfig};
    use std::future::Future;
    use std::sync::atomic::AtomicU64;
    use tokio::task::JoinHandle;

    const BLOCKS: usize = 5;

    struct LiveWorker<const BYTES: usize> {
        id: usize,
        source: PeerTransport,
        target: PeerTransport,
        remote: ByteStream,
        sdk: Option<SdkByteStream>,
        parent: Arc<Gate>,
        budget: OutboundBudget,
        active: Arc<ActiveChannels>,
        task: Option<JoinHandle<Result<(), SdkError>>>,
        polls: Arc<AtomicU64>,
        retries: u64,
    }

    fn payload<const BYTES: usize>(id: usize, round: usize, block: usize) -> [u8; BYTES] {
        let mut result = std::array::from_fn(|i| (i % 251) as u8);
        result[..8].copy_from_slice(&(id as u64).to_be_bytes());
        result[8..16].copy_from_slice(&(round as u64).to_be_bytes());
        result[16..24].copy_from_slice(&(block as u64).to_be_bytes());
        result
    }

    async fn real_worker<const BYTES: usize>(id: usize) -> LiveWorker<BYTES> {
        let config = TransportConfig {
            policy: ConnectionPolicy::DirectOnly,
            bind_address: "127.0.0.1:0".parse().unwrap(),
            include_loopback: true,
            ..TransportConfig::default()
        };
        let source = PeerTransport::new(config.clone()).await.unwrap();
        let target = PeerTransport::new(config).await.unwrap();
        let mut remote = source.create_stream("worker-performance").await.unwrap();
        let offer = source.create_offer().await.unwrap();
        assert!(offer.sdp.contains("a=fingerprint:"));
        let answer = target.answer_offer(offer).await.unwrap();
        assert!(answer.sdp.contains("a=fingerprint:"));
        source.apply_answer(answer).await.unwrap();
        let mut raw = target.accept_stream().await.unwrap();
        let (a, b) = tokio::join!(remote.wait_open(), raw.wait_open());
        a.unwrap();
        b.unwrap();
        for peer in [&source, &target] {
            assert_eq!(
                peer.selected_candidate_types().await.unwrap(),
                Some((CandidateKind::Host, CandidateKind::Host))
            );
        }
        let (sdk, worker, budget, parent) = fixture();
        // fixture原60s授权不足以覆盖大批建立；仅测试本地授权，不绕产品权限。
        parent.update(Some(Instant::now() + Duration::from_secs(600)));
        let active = Arc::new(ActiveChannels {
            used: AtomicUsize::new(0),
            limit: 1,
        });
        let permit = active.reserve().unwrap();
        let polls = Arc::new(AtomicU64::new(0));
        let count = polls.clone();
        let count_polls = std::env::var_os("PEERLOOM_PERF_POLL_COUNTS").is_some();
        let task = tokio::spawn(async move {
            if count_polls {
                // 单独profile才计数；正式CPU/时延测量不加每次poll的原子计数开销。
                let mut operation = Box::pin(worker.run(raw, permit));
                std::future::poll_fn(|cx| {
                    count.fetch_add(1, Ordering::Relaxed);
                    operation.as_mut().poll(cx)
                })
                .await
            } else {
                worker.run(raw, permit).await
            }
        });
        LiveWorker {
            id,
            source,
            target,
            remote,
            sdk: Some(sdk),
            parent,
            budget,
            active,
            task: Some(task),
            polls,
            retries: 0,
        }
    }

    impl<const BYTES: usize> LiveWorker<BYTES> {
        fn extend_test_grant(&self) {
            self.parent
                .update(Some(Instant::now() + Duration::from_secs(600)));
        }

        async fn fill(&mut self, round: usize) {
            for block in 0..BLOCKS {
                let bytes = payload::<BYTES>(self.id, round, block);
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match self.remote.write(&bytes).await {
                        Ok(n) => {
                            assert_eq!(n, BYTES);
                            break;
                        }
                        Err(StreamError::Transport(TransportError::BufferFull))
                            if Instant::now() < deadline =>
                        {
                            self.retries += 1;
                            tokio::task::yield_now().await;
                        }
                        other => panic!("bounded fill failed: {other:?}"),
                    }
                }
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let sdk = self.sdk.as_ref().unwrap();
                    assert!(sdk.validity().is_valid());
                    let len = sdk.reader.received.len();
                    assert!(len <= 4);
                    if len == 4 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("real delivery queue reached four slots");
        }

        async fn drain(&mut self, round: usize) {
            let sdk = self.sdk.as_mut().unwrap();
            for block in 0..BLOCKS {
                let mut actual = [0; BYTES];
                let mut offset = 0;
                while offset < actual.len() {
                    let n = sdk.read(&mut actual[offset..]).await.unwrap();
                    assert!(n > 0, "premature EOF under backpressure");
                    offset += n;
                }
                assert_eq!(
                    actual,
                    payload::<BYTES>(self.id, round, block),
                    "connection, round, block and all bytes must match"
                );
            }
        }

        async fn joined(&mut self) -> Result<(), SdkError> {
            let result = tokio::time::timeout(Duration::from_secs(5), self.task.take().unwrap())
                .await
                .expect("worker drain deadline")
                .expect("worker panicked");
            assert_eq!(self.active.used.load(Ordering::Acquire), 0);
            assert_eq!(self.budget.usage(), (0, 0));
            result
        }

        async fn close_peers(self) {
            self.source.close().await.unwrap();
            self.target.close().await.unwrap();
        }

        async fn orderly_close(mut self) -> u64 {
            self.remote.shutdown_write().await.unwrap();
            assert_eq!(
                self.sdk.as_mut().unwrap().read(&mut [0; 1]).await.unwrap(),
                0
            );
            // EOF只关闭接收方向，仍可反向写并精确交付。
            assert_eq!(
                self.sdk
                    .as_ref()
                    .unwrap()
                    .write(b"reverse-after-fin")
                    .await
                    .unwrap(),
                17
            );
            let mut reverse = [0; 17];
            let mut offset = 0;
            while offset < reverse.len() {
                let n = self.remote.read(&mut reverse[offset..]).await.unwrap();
                assert!(n > 0);
                offset += n;
            }
            assert_eq!(&reverse, b"reverse-after-fin");
            self.sdk.as_ref().unwrap().shutdown_write().await.unwrap();
            assert_eq!(self.remote.read(&mut [0; 1]).await.unwrap(), 0);
            self.sdk.take().unwrap().close().await.unwrap();
            let result = self.joined().await;
            assert!(matches!(result, Ok(()) | Err(SdkError::Closed)));
            let retries = self.retries;
            self.close_peers().await;
            retries
        }
    }

    fn cpu_ticks() -> (u64, u64) {
        let text = std::fs::read_to_string("/proc/self/stat").unwrap();
        let fields: Vec<_> = text
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        (fields[11].parse().unwrap(), fields[12].parse().unwrap())
    }

    fn env_usize(name: &str, default: usize) -> usize {
        std::env::var(name)
            .map(|v| v.parse().unwrap())
            .unwrap_or(default)
    }

    async fn benchmark<const BYTES: usize>() {
        let connections = env_usize("PEERLOOM_PERF_CONNECTIONS", 1);
        let rounds = env_usize("PEERLOOM_PERF_RESUME_ROUNDS", 200);
        assert!((1..=500).contains(&connections) && rounds > 0);
        let ticks_per_second = env_usize("CLK_TCK", 100) as f64;
        let mut fixtures = Vec::with_capacity(connections);
        for start in (0..connections).step_by(8) {
            let mut setup = tokio::task::JoinSet::new();
            for id in start..(start + 8).min(connections) {
                setup.spawn(real_worker::<BYTES>(id));
            }
            while let Some(fixture) = setup.join_next().await {
                fixtures.push(fixture.unwrap());
            }
        }
        let mut fill = tokio::task::JoinSet::new();
        for mut fixture in fixtures {
            fill.spawn(async move {
                fixture.fill(0).await;
                fixture
            });
        }
        let mut fixtures = Vec::with_capacity(connections);
        while let Some(fixture) = fill.join_next().await {
            fixtures.push(fixture.unwrap());
        }
        for fixture in &fixtures {
            fixture.extend_test_grant();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            fixtures
                .iter()
                .all(|f| f.sdk.as_ref().unwrap().reader.received.len() == 4)
        );
        let before_polls: u64 = fixtures
            .iter()
            .map(|f| f.polls.load(Ordering::Relaxed))
            .sum();
        let before_cpu = cpu_ticks();
        let start = Instant::now();
        tokio::time::sleep(Duration::from_secs(5)).await;
        let idle_wall = start.elapsed().as_secs_f64();
        let after_cpu = cpu_ticks();
        let after_polls: u64 = fixtures
            .iter()
            .map(|f| f.polls.load(Ordering::Relaxed))
            .sum();
        let user = (after_cpu.0 - before_cpu.0) as f64 / ticks_per_second;
        let sys = (after_cpu.1 - before_cpu.1) as f64 / ticks_per_second;
        assert!(
            fixtures
                .iter()
                .all(|f| f.sdk.as_ref().unwrap().reader.received.len() == 4)
        );

        // 单独恢复测量，包含同样的四次立即读取及完整payload核对。
        // 与idle不同，多个实例恢复测试并发，因此其负载随connections增加。
        let ready = Arc::new(tokio::sync::Barrier::new(connections + 1));
        let start = Arc::new(tokio::sync::Barrier::new(connections + 1));
        let mut resuming = tokio::task::JoinSet::new();
        for mut fixture in fixtures {
            fixture.extend_test_grant();
            let ready = ready.clone();
            let start = start.clone();
            resuming.spawn(async move {
                fixture.drain(0).await;
                let mut samples = Vec::with_capacity(rounds);
                ready.wait().await;
                start.wait().await;
                for round in 1..=rounds {
                    fixture.fill(round).await;
                    // 可复现但错开的timer相位；不计入恢复时延。
                    let pause_us = 500 + ((round * 137 + fixture.id * 53) % 7000) as u64;
                    tokio::time::sleep(Duration::from_micros(pause_us)).await;
                    let start = Instant::now();
                    fixture.drain(round).await;
                    samples.push(start.elapsed().as_nanos() as u64);
                }
                (fixture, samples)
            });
        }
        let mut completed = Vec::with_capacity(connections);
        ready.wait().await;
        let transfer_cpu_before = cpu_ticks();
        let transfer_start = Instant::now();
        start.wait().await;
        while let Some(result) = resuming.join_next().await {
            completed.push(result.unwrap());
        }
        let transfer_wall_s = transfer_start.elapsed().as_secs_f64();
        let transfer_cpu_after = cpu_ticks();
        let transfer_user_s =
            (transfer_cpu_after.0 - transfer_cpu_before.0) as f64 / ticks_per_second;
        let transfer_sys_s =
            (transfer_cpu_after.1 - transfer_cpu_before.1) as f64 / ticks_per_second;
        let transfer_payload_bytes = connections * rounds * BLOCKS * BYTES;
        let mut samples = Vec::with_capacity(connections * rounds);
        let mut finished = Vec::with_capacity(connections);
        for (fixture, mut part) in completed {
            samples.append(&mut part);
            finished.push(fixture);
        }
        samples.sort_unstable();
        let q = |pct: usize| samples[(samples.len() - 1) * pct / 100] as f64 / 1000.0;
        let (p50, p95, p99) = (q(50), q(95), q(99));
        let mut closing = tokio::task::JoinSet::new();
        for fixture in finished {
            closing.spawn(fixture.orderly_close());
        }
        let mut retries = 0;
        while let Some(result) = closing.join_next().await {
            retries += result.unwrap();
        }
        // 所有内容/FIN/清理成功后才打印成功记录。外层runner仍须要求exit0。
        println!(
            concat!(
                "{{\"kind\":\"sdk_worker_backpressure\",\"connections\":{},",
                "\"bytes\":{},\"resume_rounds\":{},\"idle_wall_s\":{:.6},\"idle_user_s\":{:.6},",
                "\"idle_sys_s\":{:.6},\"idle_cpu_ns_per_worker_s\":{:.6},",
                "\"poll_counting\":{},\"worker_polls\":{},\"polls_per_worker_s\":{:.6},",
                "\"resume_p50_us\":{:.3},\"resume_p95_us\":{:.3},\"resume_p99_us\":{:.3},",
                "\"raw_buffer_full_retries\":{},",
                "\"transfer_payload_bytes\":{},\"transfer_wall_s\":{:.6},",
                "\"transfer_user_s\":{:.6},\"transfer_sys_s\":{:.6},",
                "\"transfer_cpu_ns_per_byte\":{:.6},\"paced_mib_per_s\":{:.6}}}"
            ),
            connections,
            BYTES,
            rounds,
            idle_wall,
            user,
            sys,
            (user + sys) * 1e9 / idle_wall / connections as f64,
            std::env::var_os("PEERLOOM_PERF_POLL_COUNTS").is_some(),
            after_polls - before_polls,
            (after_polls - before_polls) as f64 / idle_wall / connections as f64,
            p50,
            p95,
            p99,
            retries,
            transfer_payload_bytes,
            transfer_wall_s,
            transfer_user_s,
            transfer_sys_s,
            (transfer_user_s + transfer_sys_s) * 1e9 / transfer_payload_bytes as f64,
            transfer_payload_bytes as f64 / transfer_wall_s / 1048576.0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires real loopback UDP; explicit release performance experiment"]
    async fn sdk_worker_backpressure_performance() {
        tokio::time::timeout(Duration::from_secs(600), async {
            match env_usize("PEERLOOM_PERF_BYTES", 64) {
                64 => benchmark::<64>().await,
                16384 => benchmark::<16384>().await,
                _ => panic!("supported payload sizes: 64, 16384"),
            }
        })
        .await
        .expect("bounded complete performance case");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires real loopback UDP"]
    async fn full_delivery_queue_keeps_reverse_write_and_parent_expiry_live() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut fixture = real_worker::<64>(0).await;
            fixture.fill(0).await;
            assert_eq!(
                fixture
                    .sdk
                    .as_ref()
                    .unwrap()
                    .write(b"reverse")
                    .await
                    .unwrap(),
                7
            );
            let mut reverse = [0; 7];
            let mut offset = 0;
            while offset < reverse.len() {
                let n = fixture.remote.read(&mut reverse[offset..]).await.unwrap();
                assert!(n > 0);
                offset += n;
            }
            assert_eq!(&reverse, b"reverse");
            assert_eq!(fixture.sdk.as_ref().unwrap().reader.received.len(), 4);
            fixture.parent.update(Some(Instant::now()));
            assert!(fixture.joined().await.is_err());
            assert!(!fixture.sdk.as_ref().unwrap().validity().is_valid());
            let mut untouched = [0x55; 64];
            assert!(
                fixture
                    .sdk
                    .as_mut()
                    .unwrap()
                    .read(&mut untouched)
                    .await
                    .is_err()
            );
            assert_eq!(untouched, [0x55; 64]);
            fixture.close_peers().await;
        })
        .await
        .expect("bounded full queue reverse/expiry");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires real loopback UDP"]
    async fn full_delivery_queue_reader_drop_releases_worker_and_budget() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut fixture = real_worker::<64>(0).await;
            fixture.fill(0).await;
            let (reader, writer) = fixture.sdk.take().unwrap().split();
            drop(reader);
            assert!(fixture.joined().await.is_err());
            assert_eq!(writer.write(b"closed").await, Err(SdkError::Closed));
            drop(writer);
            fixture.close_peers().await;
        })
        .await
        .expect("bounded full queue reader drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires real loopback UDP"]
    async fn full_delivery_queue_receiver_closed_does_not_spin() {
        // 私有测试直接close接收端，专门检查reserve Err分支；不新增生产API。
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut fixture = real_worker::<64>(0).await;
            fixture.fill(0).await;
            fixture.sdk.as_mut().unwrap().reader.received.close();
            assert!(fixture.joined().await.is_err());
            fixture.close_peers().await;
        })
        .await
        .expect("bounded directly closed receiver");
    }

    async fn wait_for_empty_read_reservation(fixture: &LiveWorker<64>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let received = &fixture.sdk.as_ref().unwrap().reader.received;
                assert_eq!(received.len(), 0);
                if received.capacity() == 3 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle raw read holds one of four capacity slots");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires real loopback UDP and the original 20s raw-read timeout"]
    async fn reserved_empty_queue_receiver_close_survives_raw_timeout() {
        let mut fixture = real_worker::<64>(0).await;
        wait_for_empty_read_reservation(&fixture).await;
        // Private close without gate notification exercises the retained permit.
        // Keep the original raw-read timeout; this is not a new public close API.
        fixture.sdk.as_mut().unwrap().reader.received.close();
        let result = tokio::time::timeout(Duration::from_secs(25), fixture.task.take().unwrap())
            .await
            .expect("receiver closure must be observed after one raw-read timeout")
            .expect("worker panicked");
        assert_eq!(result, Err(SdkError::Closed));
        assert_eq!(fixture.active.used.load(Ordering::Acquire), 0);
        assert_eq!(fixture.budget.usage(), (0, 0));
        fixture.close_peers().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires real loopback UDP"]
    async fn reserved_empty_queue_reader_drop_releases_worker_and_budget() {
        let mut fixture = real_worker::<64>(0).await;
        wait_for_empty_read_reservation(&fixture).await;
        let (reader, writer) = fixture.sdk.take().unwrap().split();
        drop(reader);
        assert!(fixture.joined().await.is_err());
        assert_eq!(writer.write(b"closed").await, Err(SdkError::Closed));
        drop(writer);
        fixture.close_peers().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires real loopback UDP"]
    async fn full_delivery_queue_observes_unnotified_continuous_expiry() {
        let mut fixture = real_worker::<64>(0).await;
        fixture.fill(0).await;
        let ticks = Arc::new(AtomicU64::new(0));
        let reading = ticks.clone();
        test_continuous_grant(&fixture.parent, move || {
            Ok(Duration::from_secs(reading.load(Ordering::SeqCst)))
        });
        // No parent update/close/notify after the continuous clock crosses expiry.
        ticks.store(120, Ordering::SeqCst);
        let mut untouched = [0x55; 64];
        assert_eq!(
            fixture.sdk.as_mut().unwrap().read(&mut untouched).await,
            Err(SdkError::AuthorizationExpired)
        );
        assert_eq!(untouched, [0x55; 64]);
        assert_eq!(
            fixture.sdk.as_ref().unwrap().write(b"forbidden").await,
            Err(SdkError::AuthorizationExpired)
        );
        tokio::time::timeout(Duration::from_millis(100), fixture.joined())
            .await
            .expect("original 5ms backstop remains live under full-queue backpressure")
            .expect_err("expired worker must fail closed");
        fixture.close_peers().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires real loopback UDP"]
    async fn full_delivery_queue_observes_unnotified_installation_close() {
        let mut fixture = real_worker::<64>(0).await;
        fixture.fill(0).await;
        fixture
            .parent
            .installation_closed
            .store(true, Ordering::Release);
        let mut untouched = [0x55; 64];
        assert_eq!(
            fixture.sdk.as_mut().unwrap().read(&mut untouched).await,
            Err(SdkError::Closed)
        );
        assert_eq!(untouched, [0x55; 64]);
        assert_eq!(
            fixture.sdk.as_ref().unwrap().write(b"forbidden").await,
            Err(SdkError::Closed)
        );
        tokio::time::timeout(Duration::from_millis(100), fixture.joined())
            .await
            .expect("installation close cannot depend on capacity or a notification")
            .expect_err("closed installation must fail closed");
        fixture.close_peers().await;
    }
}
