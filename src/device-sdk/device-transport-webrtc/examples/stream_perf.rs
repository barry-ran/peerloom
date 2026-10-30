//! 可复现的真实环回 DTLS/SCTP 字节流测量；不包含控制面/FFI，也不冒充公网。
//! 参数：连接数、消息字节数、每连接往返次数、预热次数。
use device_protocol::ConnectionPolicy;
use device_transport_webrtc::{
    ByteStream, CandidateKind, PeerTransport, StreamError, TransportConfig, TransportError,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
static RETRIES: AtomicU64 = AtomicU64::new(0);
use std::time::{Duration, Instant};
use tokio::sync::Barrier;

async fn write_all(stream: &mut ByteStream, mut data: &[u8]) {
    while !data.is_empty() {
        match stream.write(data).await {
            Ok(n) => {
                assert!(n > 0);
                data = &data[n..];
            }
            Err(StreamError::Transport(TransportError::BufferFull)) => {
                RETRIES.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await
            }
            other => panic!("write: {other:?}"),
        }
    }
}
async fn read_exact(stream: &mut ByteStream, data: &mut [u8]) {
    let mut offset = 0;
    while offset < data.len() {
        let n = stream.read(&mut data[offset..]).await.expect("read");
        assert!(n > 0, "premature EOF");
        offset += n;
    }
}
async fn pair() -> (PeerTransport, PeerTransport, ByteStream, ByteStream) {
    let config = TransportConfig {
        policy: ConnectionPolicy::DirectOnly,
        bind_address: "127.0.0.1:0".parse().unwrap(),
        include_loopback: true,
        ..TransportConfig::default()
    };
    let a = PeerTransport::new(config.clone()).await.expect("peer A");
    let b = PeerTransport::new(config).await.expect("peer B");
    let mut tx = a.create_stream("performance").await.expect("stream");
    let offer = a.create_offer().await.unwrap();
    assert!(offer.sdp.contains("a=fingerprint:"));
    let answer = b.answer_offer(offer).await.unwrap();
    a.apply_answer(answer).await.unwrap();
    let mut rx = b.accept_stream().await.unwrap();
    let (x, y) = tokio::join!(tx.wait_open(), rx.wait_open());
    x.unwrap();
    y.unwrap();
    assert_eq!(
        a.selected_candidate_types().await.unwrap(),
        Some((CandidateKind::Host, CandidateKind::Host))
    );
    (a, b, tx, rx)
}
fn cpu_ticks() -> (u64, u64) {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    (fields[11].parse().unwrap(), fields[12].parse().unwrap())
}
fn quantile(v: &[u64], percentile: usize) -> u64 {
    v[((v.len() - 1) * percentile) / 100]
}
fn main() {
    let threads = std::env::var("PEERLOOM_PERF_THREADS")
        .unwrap_or_else(|_| "4".into())
        .parse::<usize>()
        .unwrap();
    let mut builder = if threads == 0 {
        tokio::runtime::Builder::new_current_thread()
    } else {
        let mut b = tokio::runtime::Builder::new_multi_thread();
        b.worker_threads(threads);
        b
    };
    builder.enable_all().build().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(180), run())
            .await
            .expect("performance case deadline");
    });
}
async fn run() {
    let args: Vec<_> = std::env::args()
        .skip(1)
        .map(|s| s.parse::<usize>().unwrap())
        .collect();
    assert_eq!(args.len(), 4, "connections bytes rounds warmup");
    let (connections, size, rounds, warmup) = (args[0], args[1], args[2], args[3]);
    assert!(connections > 0 && size > 0 && rounds > 0);
    let ticks_per_second: f64 = std::env::var("CLK_TCK")
        .unwrap_or_else(|_| "100".into())
        .parse()
        .unwrap();
    let mut peers = Vec::new();
    let mut streams = Vec::new();
    for base in (0..connections).step_by(8) {
        let mut pending = tokio::task::JoinSet::new();
        for _ in base..(base + 8).min(connections) {
            pending.spawn(pair());
        }
        while let Some(p) = pending.join_next().await {
            let (a, b, tx, rx) = p.unwrap();
            peers.push((a, b));
            streams.push((tx, rx));
        }
    }
    let ready = Arc::new(Barrier::new(connections + 1));
    let start = Arc::new(Barrier::new(connections + 1));
    let mut clients = tokio::task::JoinSet::new();
    for (connection_id, (mut tx, mut rx)) in streams.into_iter().enumerate() {
        let ready = ready.clone();
        let start = start.clone();
        clients.spawn(async move {
            let server = tokio::spawn(async move {
                let mut data = vec![0; size];
                for _ in 0..warmup + rounds {
                    read_exact(&mut rx, &mut data).await;
                    write_all(&mut rx, &data).await;
                }
                rx
            });
            let mut payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut received = vec![0; size];
            let mut samples = Vec::with_capacity(rounds);
            for i in 0..warmup + rounds {
                if i == warmup {
                    ready.wait().await;
                    start.wait().await;
                }
                for (dst, byte) in payload.iter_mut().zip(
                    (connection_id as u64)
                        .to_le_bytes()
                        .into_iter()
                        .chain((i as u64).to_le_bytes()),
                ) {
                    *dst = byte;
                }
                let before = Instant::now();
                write_all(&mut tx, &payload).await;
                read_exact(&mut tx, &mut received).await;
                assert_eq!(payload, received, "all bytes and round sequence must match");
                if i >= warmup {
                    samples.push(before.elapsed().as_nanos() as u64);
                }
            }
            (samples, tx, server.await.unwrap())
        });
    }
    let mut completed = Vec::with_capacity(connections);
    ready.wait().await;
    eprintln!("PERF_MEASURE_BEGIN connections={connections} bytes={size} rounds={rounds}");
    let retries_before = RETRIES.load(Ordering::Relaxed);
    let cpu_before = cpu_ticks();
    let wall = Instant::now();
    start.wait().await;

    while let Some(result) = clients.join_next().await {
        completed.push(result.unwrap());
    }
    let elapsed = wall.elapsed().as_secs_f64();
    let cpu_after = cpu_ticks();
    let retries = RETRIES.load(Ordering::Relaxed) - retries_before;
    eprintln!("PERF_MEASURE_END retries={retries}");
    let mut samples = Vec::with_capacity(connections * rounds);
    let mut finished = Vec::with_capacity(connections);
    for (s, a, b) in completed {
        samples.extend(s);
        finished.push((a, b));
    }
    samples.sort_unstable();
    let bytes = 2 * connections * size * rounds;
    let user = (cpu_after.0 - cpu_before.0) as f64 / ticks_per_second;
    let sys = (cpu_after.1 - cpu_before.1) as f64 / ticks_per_second;
    println!(
        "{{\"connections\":{connections},\"size\":{size},\"rounds\":{rounds},\"payload_bytes\":{bytes},\"wall_s\":{elapsed:.6},\"user_s\":{user:.6},\"sys_s\":{sys:.6},\"cpu_ns_per_byte\":{:.6},\"mib_per_s\":{:.6},\"rtt_p50_us\":{:.3},\"rtt_p95_us\":{:.3},\"rtt_p99_us\":{:.3}}}",
        (user + sys) * 1e9 / bytes as f64,
        bytes as f64 / elapsed / 1048576.0,
        quantile(&samples, 50) as f64 / 1000.0,
        quantile(&samples, 95) as f64 / 1000.0,
        quantile(&samples, 99) as f64 / 1000.0
    );
    for (mut a, mut b) in finished {
        a.shutdown_write().await.unwrap();
        let mut byte = [0];
        assert_eq!(b.read(&mut byte).await.unwrap(), 0);
        b.shutdown_write().await.unwrap();
        assert_eq!(a.read(&mut byte).await.unwrap(), 0);
        a.close().await.unwrap();
    }
    for (a, b) in peers {
        a.close().await.unwrap();
        b.close().await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
}
