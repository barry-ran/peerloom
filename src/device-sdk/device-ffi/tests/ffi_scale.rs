// MIT — Copyright (c) 2026 Peerloom contributors.
//! Real C-host capacity. The PC never calls Rust DeviceSdk; only peers do.
#![cfg(peerloom_capacity_c_host)]
#![allow(unsafe_code)]
#![recursion_limit = "256"]
#[path = "../../device-core/tests/support/capacity.rs"]
mod capacity;
use capacity::*;
use device_core::sdk::{
    Connection, SdkChannel, SdkError, SdkEvent, SdkStreamReader, SdkStreamWriter,
};
use device_ffi as _; // Link the real Rust ABI definitions reached by the C object.
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::{Notify, mpsc};

const OK: u32 = 0;
const CLOSED: u32 = 5;
const FULL: u32 = 6;
const CANCELLED: u32 = 9;
const BUSY: u32 = 11;
const BULK: usize = 256 * 1024;
const RESERVATION: usize = 65536;
const BUDGET: usize = 128 * 1024 * 1024;
type Sink = extern "C" fn(u64, u32, u64, u64, u32, u64, *const u8, usize);
#[link(name = "capacity_host", kind = "static")]
unsafe extern "C" {
    fn capacity_create(json: *const u8, len: usize, sink: Sink, context: u64, out: *mut u64)
    -> u32;
    fn capacity_submit(
        sdk: u64,
        op: u32,
        connection: u64,
        input: *const u8,
        len: usize,
        out: *mut u64,
    ) -> u32;
    fn capacity_channel(
        sdk: u64,
        connection: u64,
        channel: u64,
        op: u32,
        input: *const u8,
        len: usize,
        out: *mut u64,
    ) -> u32;
    fn capacity_cancel(sdk: u64, request: u64) -> u32;
    fn capacity_storage(sdk: u64, request: u64, status: u32, input: *const u8, len: usize) -> u32;
    fn capacity_shutdown(sdk: u64, out: *mut u64) -> u32;
    fn capacity_release(sdk: u64) -> u32;
    fn capacity_state(sdk: u64) -> u32;
    fn capacity_connection_valid(sdk: u64, connection: u64) -> u32;
    fn capacity_channel_valid(sdk: u64, connection: u64, channel: u64) -> u32;
    fn capacity_pending_reads(sdk: u64) -> u64;
    fn capacity_resource_bytes(sdk: u64, field: u32) -> u64;
}
#[derive(Clone)]
struct Event {
    kind: u32,
    request: u64,
    connection: u64,
    status: u32,
    channel: u64,
    bytes: Vec<u8>,
}
#[derive(Default)]
struct State {
    events: VecDeque<Event>,
    completions: BTreeMap<u64, Event>,
    accepted: BTreeSet<u64>,
    completed: BTreeSet<u64>,
    callbacks: usize,
    shutdown: usize,
    failed: bool,
}
#[derive(Default)]
struct Collector {
    state: Mutex<State>,
    changed: Notify,
}
static COLLECTOR: OnceLock<Arc<Collector>> = OnceLock::new();
extern "C" fn collect(
    context: u64,
    kind: u32,
    request: u64,
    connection: u64,
    status: u32,
    channel: u64,
    bytes: *const u8,
    len: usize,
) {
    // The C trampoline validated ABI, null/length and quiescent rules first.
    // Borrowed payload is copied before callback return; no Rust panic crosses C.
    let Some(collector) = COLLECTOR.get() else {
        std::process::abort()
    };
    if context != 1 || len > 65536 || (len != 0 && bytes.is_null()) {
        std::process::abort();
    }
    let bytes = if len == 0 {
        Vec::new()
    } else {
        // SAFETY: canonical C callback contract and trampoline validated view.
        unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec()
    };
    let Ok(mut state) = collector.state.lock() else {
        std::process::abort()
    };
    state.callbacks += 1;
    if state.shutdown != 0 {
        state.failed = true;
    }
    let event = Event {
        kind,
        request,
        connection,
        status,
        channel,
        bytes,
    };
    if kind == 1 {
        if request == 0 || !state.completed.insert(request) || state.completions.len() >= 2048 {
            state.failed = true;
        }
        state.completions.insert(request, event);
    } else {
        if kind == 9 {
            state.shutdown += 1;
        }
        if state.events.len() >= 4096 {
            state.failed = true;
        } else {
            state.events.push_back(event);
        }
    }
    drop(state);
    collector.changed.notify_one();
}
struct Host {
    sdk: u64,
    collector: Arc<Collector>,
    revision: u64,
    identity: Value,
}
impl Host {
    fn new(f: &Fixture) -> Self {
        let collector = Arc::new(Collector::default());
        assert!(
            COLLECTOR.set(collector.clone()).is_ok(),
            "exactly one PC host"
        );
        let config = serde_json::to_vec(&json!({"abi_version":1,"origin":f.origin,
            "application_id":f.registrations[0].application_id,"storage":"external",
            "development_loopback":true}))
        .unwrap();
        let mut sdk = 0;
        // SAFETY: inputs and output live throughout the synchronous C adapter call.
        assert_eq!(
            unsafe { capacity_create(config.as_ptr(), config.len(), collect, 1, &mut sdk) },
            OK
        );
        assert_ne!(sdk, 0);
        Self {
            sdk,
            collector,
            revision: 0,
            identity: Value::Null,
        }
    }
    fn admit(&self, status: u32, request: u64) -> u64 {
        assert_eq!(status, OK, "C ABI operation admission");
        assert_ne!(request, 0);
        let mut state = self.collector.state.lock().unwrap();
        assert!(state.accepted.insert(request), "unique accepted operation");
        assert!(!state.failed);
        request
    }
    fn submit(&self, op: u32, connection: u64, input: &[u8]) -> u64 {
        let mut request = 0;
        // No collector mutex is held: callback may complete before this returns.
        let status = unsafe {
            capacity_submit(
                self.sdk,
                op,
                connection,
                input.as_ptr(),
                input.len(),
                &mut request,
            )
        };
        self.admit(status, request)
    }
    fn child_status(&self, connection: u64, channel: u64, op: u32, input: &[u8]) -> (u32, u64) {
        let mut request = 0;
        let status = unsafe {
            capacity_channel(
                self.sdk,
                connection,
                channel,
                op,
                input.as_ptr(),
                input.len(),
                &mut request,
            )
        };
        if status == OK {
            self.admit(status, request);
        } else {
            assert_eq!(request, 0);
        }
        (status, request)
    }
    async fn child(&self, connection: u64, channel: u64, op: u32, input: &[u8]) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (status, id) = self.child_status(connection, channel, op, input);
            if status == OK {
                return id;
            }
            // An observed COMPLETE may precede callback return by a few CPU
            // instructions. The old per-stream ticket is still held then.
            // Only unaccepted BUSY/FULL (id=0) may retry. Accepted completions,
            // UNKNOWN, and already-written prefixes are never resubmitted.
            assert!(
                matches!(status, BUSY | FULL) && id == 0,
                "stream admission rejected"
            );
            assert!(
                Instant::now() < deadline,
                "bounded unaccepted admission retry"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    async fn read(&self, connection: u64, channel: u64, maximum: usize) -> u64 {
        self.child(
            connection,
            channel,
            2,
            format!("{{\"max_bytes\":{maximum}}}").as_bytes(),
        )
        .await
    }
    fn storage(&mut self, event: &Event) {
        assert_eq!(event.kind, 10);
        let value: Value = serde_json::from_slice(&event.bytes).unwrap();
        let response = match value["operation"].as_str().unwrap() {
            "load" => json!({"revision":self.revision,"identity":self.identity}),
            "save" | "delete" => {
                assert_eq!(value["expected_revision"].as_u64(), Some(self.revision));
                self.revision = self.revision.checked_add(1).unwrap();
                self.identity = if value["operation"] == "save" {
                    value["identity"].clone()
                } else {
                    Value::Null
                };
                json!({"revision":self.revision})
            }
            _ => panic!("unexpected CAS operation"),
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            unsafe { capacity_storage(self.sdk, event.request, OK, bytes.as_ptr(), bytes.len()) },
            OK
        );
    }
    async fn next(&mut self) -> Event {
        let deadline = Instant::now() + Duration::from_secs(50);
        loop {
            let collector = self.collector.clone();
            let notified = collector.changed.notified();
            let event = {
                let mut state = self.collector.state.lock().unwrap();
                assert!(!state.failed);
                state.events.pop_front()
            };
            if let Some(event) = event {
                return event;
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), notified)
                .await
                .expect("bounded C event");
        }
    }
    async fn completion(&mut self, request: u64) -> Event {
        let deadline = Instant::now() + Duration::from_secs(50);
        loop {
            let collector = self.collector.clone();
            let notified = collector.changed.notified();
            let (completion, storage) = {
                let mut state = self.collector.state.lock().unwrap();
                assert!(!state.failed);
                let completion = state.completions.remove(&request);
                let storage = state
                    .events
                    .iter()
                    .position(|event| event.kind == 10)
                    .and_then(|i| state.events.remove(i));
                (completion, storage)
            };
            if let Some(event) = storage {
                self.storage(&event);
            }
            if let Some(event) = completion {
                return event;
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), notified)
                .await
                .expect("bounded C completion");
        }
    }
    async fn ok(&mut self, request: u64) -> Event {
        let result = self.completion(request).await;
        assert_eq!(result.status, OK, "C operation completed successfully");
        result
    }
    fn check(&self) {
        assert!(!self.collector.state.lock().unwrap().failed);
    }
}
struct Pair {
    connection: u64,
    channel: u64,
    remote: Connection,
    stream: Option<(SdkStreamReader, SdkStreamWriter)>,
    session: String,
}
fn byte_at(index: usize, direction: u8, offset: usize) -> u8 {
    // The prefix is injective across all 500 peers (a modulo-251 pattern alone
    // would collide for peers 1 and 252). The rest also verifies byte offsets.
    if offset < 4 {
        (index as u32).to_le_bytes()[offset]
    } else if offset == 4 {
        direction
    } else {
        ((offset * 17 + index * 31 + usize::from(direction)) % 251) as u8
    }
}
fn bytes(index: usize, direction: u8, count: usize) -> Vec<u8> {
    (0..count)
        .map(|offset| byte_at(index, direction, offset))
        .collect()
}
async fn snapshot(
    api: &Api,
    pairs: &BTreeMap<usize, Pair>,
    source: &str,
    peers: &BTreeMap<usize, Driver>,
) -> BTreeMap<String, Lease> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let rows = api.sessions().await;
        let live: BTreeMap<_, _> = rows
            .into_iter()
            .filter(|(_, r)| r.state != "closed")
            .collect();
        assert_eq!(live.len(), pairs.len(), "no unexpected pending sessions");
        if pairs.iter().all(|(i, p)| {
            live.get(&p.session).is_some_and(|r| {
                r.state == "connected"
                    && r.source_device_id == source
                    && r.target_device_id == peers[i].id
            })
        }) {
            return live;
        }
        assert!(Instant::now() < deadline, "connected session snapshot");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
fn valid(host: &Host, pairs: &BTreeMap<usize, Pair>) {
    for pair in pairs.values() {
        assert_eq!(
            unsafe { capacity_connection_valid(host.sdk, pair.connection) },
            OK
        );
        assert_eq!(
            unsafe { capacity_channel_valid(host.sdk, pair.connection, pair.channel) },
            OK
        );
        assert!(pair.remote.validity().is_valid());
    }
    host.check();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires real Go/PG/Redis grants, C adapter and 501 registered installations"]
async fn one_c_pc_five_hundred_real_native_streams() {
    let started = Instant::now();
    let path = std::env::var("TEST_CAPACITY_FIXTURE").expect("private capacity fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let info = std::fs::symlink_metadata(&path).unwrap();
        assert!(
            info.is_file()
                && info.permissions().mode() & 0o777 == 0o600
                && info.len() <= 1024 * 1024
        );
    }
    let input = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    let f: Fixture = serde_json::from_slice(&input).unwrap();
    assert!((1..=500).contains(&f.peer_count) && f.registrations.len() == f.peer_count + 1);
    assert!(
        !f.debug_close_only && f.hold_seconds >= 120,
        "FFI stress never skips lease hold"
    );
    let api = Api::new(&f.origin, &f.service_credential);
    let mut host = Host::new(&f);
    phase("register", started);
    let registration = &f.registrations[0];
    let request = json!({"registration":{"platform":"linux","installation_public_key":format!("capacity-c-public-label-{}",uuid::Uuid::new_v4()),"registration_grant":registration.grant,"sdk_version":env!("CARGO_PKG_VERSION"),"metadata":{}},"idempotency_key":uuid::Uuid::new_v4().to_string()});
    let start = host.submit(1, 0, &serde_json::to_vec(&request).unwrap());
    // Real external-store load deliberately remains outstanding, which keeps the
    // serial START in flight. A subsequent REFRESH is provably queued, not racing
    // an already-running asynchronous read or remote credential mutation.
    let load = host.next().await;
    assert_eq!(load.kind, 10);
    assert_eq!(
        serde_json::from_slice::<Value>(&load.bytes).unwrap()["operation"],
        "load"
    );
    let queued = host.submit(5, 0, &[]);
    assert_eq!(unsafe { capacity_cancel(host.sdk, queued) }, OK);
    host.storage(&load);
    let complete = host.ok(start).await;
    let source = serde_json::from_slice::<Value>(&complete.bytes).unwrap()["device_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(host.completion(queued).await.status, CANCELLED);
    assert_eq!(host.next().await.kind, 2);
    let (send, mut events) = mpsc::channel(64);
    let mut peers = BTreeMap::new();
    for i in 1..=f.peer_count {
        peers.insert(
            i,
            register(&f, &f.registrations[i], i, send.clone(), started).await,
        );
        let (index, event) = next(&mut events).await;
        assert_eq!(index, i);
        assert!(matches!(event, SdkEvent::Online));
    }
    assert_eq!(
        peers.values().map(|p| &p.id).collect::<BTreeSet<_>>().len(),
        f.peer_count
    );
    assert!(peers.values().all(|p| p.id != source));
    phase("authorize", started);
    for peer in peers.values() {
        let grant=api.request("/v1/connection-grants",Some(json!({"source_device_id":source,"target_device_id":peer.id,"expires_in_seconds":3600,"expiry_action":"terminate"}))).await;
        assert_eq!(grant["max_sessions"], -1);
    }
    phase("connect", started);
    let indices: Vec<_> = (1..=f.peer_count).collect();
    let mut pairs = BTreeMap::new();
    let mut latency = Vec::new();
    for wave in indices.chunks(10) {
        let mut beginnings = BTreeMap::new();
        for i in wave {
            beginnings.insert(*i, Instant::now());
            let id = host.submit(
                2,
                0,
                &serde_json::to_vec(&json!({"target_device_id":peers[i].id})).unwrap(),
            );
            host.ok(id).await;
        }
        let mut pc = BTreeMap::new();
        let mut targets = BTreeMap::new();
        while pc.len() != wave.len() || targets.len() != wave.len() {
            tokio::select! {
                event=host.next()=>{
                    assert_eq!(event.kind,5,"PC must receive real connection Ready");assert_eq!(event.status,OK);
                    let payload:Value=serde_json::from_slice(&event.bytes).unwrap();
                    let index=*wave.iter().find(|i|payload["peer_device_id"]==peers[i].id).unwrap();
                    let session=payload["session_id"].as_str().unwrap().to_owned();
                    assert!(pc.insert(index,(event.connection,session)).is_none());
                },
                event=next(&mut events)=>{
                    let(index,event)=event;assert!(wave.contains(&index));
                    let SdkEvent::ConnectionReady(connection)=event else { panic!("peer real Ready required") };
                    assert_eq!(connection.peer_device_id(),source);assert!(targets.insert(index,connection).is_none());
                }
            }
        }
        for i in wave {
            latency.push(beginnings[i].elapsed().as_secs_f64() * 1000.0);
            let (connection, session) = pc.remove(i).unwrap();
            let mut remote = targets.remove(i).unwrap();
            assert_eq!(remote.session_id(), session);
            let mut incoming = remote.take_incoming_channels().unwrap();
            let open = host.submit(
                8,
                connection,
                &serde_json::to_vec(
                    &json!({"mode":"reliable_stream","label":format!("capacity-stream-{i}")}),
                )
                .unwrap(),
            );
            let opened = host.ok(open).await;
            assert_eq!(opened.connection, connection);
            assert_ne!(opened.channel, 0);
            let SdkChannel::Stream(stream) =
                tokio::time::timeout(Duration::from_secs(30), incoming.receive())
                    .await
                    .unwrap()
                    .unwrap()
            else {
                panic!("real incoming stream")
            };
            assert_eq!(stream.session_id(), session);
            pairs.insert(
                *i,
                Pair {
                    connection,
                    channel: opened.channel,
                    remote,
                    stream: Some(stream.split()),
                    session,
                },
            );
        }
        println!("capacity ready_pairs={}", pairs.len());
    }
    assert_eq!(
        pairs
            .values()
            .map(|p| &p.session)
            .collect::<BTreeSet<_>>()
            .len(),
        f.peer_count
    );
    valid(&host, &pairs);
    // All peer writers are still owned and untouched: no peer can produce data
    // before the entire 500-admission and running-read barrier is established.
    let mut pending = BTreeMap::new();
    for (index, pair) in &pairs {
        let (status, id) =
            host.child_status(pair.connection, pair.channel, 2, b"{\"max_bytes\":65536}");
        let admitted = pending.len() + usize::from(status == OK);
        if admitted <= 33 || admitted.is_multiple_of(100) || status != OK {
            println!("capacity ffi_reads_accepted={admitted} status={status}");
        }
        assert_eq!(
            status, OK,
            "all 500 C READ admissions; legacy 32 must fail at 33"
        );
        pending.insert(*index, id);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let running = unsafe { capacity_pending_reads(host.sdk) };
        assert!(running <= f.peer_count as u64);
        assert!(
            pending
                .values()
                .all(|id| !host.collector.state.lock().unwrap().completed.contains(id)),
            "no read completion before peer data"
        );
        if running == f.peer_count as u64 {
            break;
        }
        assert!(Instant::now() < deadline, "all C reads running");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    println!("capacity ffi_pending_reads={}", pending.len());
    // Query real logical charges only after admission/running barriers. The
    // legacy-32 RED must fail at admission 33, before any unsupported observer.
    let resource_budget = unsafe { capacity_resource_bytes(host.sdk, 0) };
    let read_charged = unsafe { capacity_resource_bytes(host.sdk, 1) };
    let critical_charged = unsafe { capacity_resource_bytes(host.sdk, 2) };
    assert_eq!(
        resource_budget, BUDGET as u64,
        "actual default logical budget"
    );
    assert!(read_charged >= (f.peer_count * RESERVATION) as u64);
    assert!(read_charged.checked_add(critical_charged).unwrap() <= resource_budget);

    for id in pending.values() {
        assert_eq!(
            unsafe { capacity_cancel(host.sdk, *id) },
            BUSY,
            "running READ cannot cancel"
        );
    }
    let first = &pairs[&1];
    let (duplicate, id) =
        host.child_status(first.connection, first.channel, 2, b"{\"max_bytes\":65536}");
    assert!(matches!(duplicate, FULL | BUSY));
    assert_eq!(id, 0, "rejected duplicate READ has no request ID");
    phase("baseline", started);
    let snapshot_started = Instant::now();
    let initial = snapshot(&api, &pairs, &source, &peers).await;
    let baseline_time = time::OffsetDateTime::now_utc();
    let initial_deadline = initial
        .values()
        .map(|r| {
            let (a, b) = r.deadlines();
            assert!(a > baseline_time && b > baseline_time);
            a.max(b)
        })
        .max()
        .unwrap();
    println!(
        "capacity baseline_complete elapsed_ms={} snapshot_elapsed_ms={} sessions={}",
        started.elapsed().as_millis(),
        snapshot_started.elapsed().as_millis(),
        initial.len()
    );
    write_json(
        &f.directory.join("baseline.json"),
        json!({"case":"ffi","simultaneous_ready":pairs.len(),"sdk_instances":peers.len()+1,"pc_sdk_instances":1,"snapshot_complete_at":baseline_time.to_string(),"sessions":initial,"pending_c_reads":pending.len()}),
    );
    phase("hold", started);
    let hold = Instant::now();
    while hold.elapsed() < Duration::from_secs(f.hold_seconds)
        || time::OffsetDateTime::now_utc() <= initial_deadline
    {
        valid(&host, &pairs);
        assert_eq!(
            unsafe { capacity_pending_reads(host.sdk) },
            f.peer_count as u64
        );
        assert!(
            host.collector.state.lock().unwrap().events.is_empty(),
            "unexpected PC event during pending-read hold"
        );
        assert!(
            pending
                .values()
                .all(|id| !host.collector.state.lock().unwrap().completed.contains(id))
        );
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
            panic!("unexpected peer event during hold")
        }
        assert!(hold.elapsed() < Duration::from_secs(180));
    }
    phase("renewal-proof", started);
    let renewed = snapshot(&api, &pairs, &source, &peers).await;
    let now = time::OffsetDateTime::now_utc();
    for (id, before) in &initial {
        let after = &renewed[id];
        let (a, b) = before.deadlines();
        let (c, d) = after.deadlines();
        assert!(
            after.lease_generation > before.lease_generation
                && c > a
                && d > b
                && c > now
                && d > now
        );
    }
    write_json(
        &f.directory.join("renewed.json"),
        json!({"sessions":renewed,"hold_seconds":hold.elapsed().as_secs_f64(),"simultaneous_ready":pairs.len()}),
    );
    // Real streams, not a callback-count mock: both directions independently
    // validate a deterministic byte position/pattern and partial API results.
    // Keep every stream alive and all initial READs admitted, but bound active
    // data producers to eight peers. PC WRITE is one-at-a-time; no whole-buffer
    // retry can duplicate bytes after a partial write or uncertain completion.
    phase("ffi-bulk", started);
    let bulk_started = Instant::now();
    let mut partial_write = false;
    let mut partial_read = false;
    for wave in indices.chunks(8) {
        let mut transfers = BTreeMap::new();
        for index in wave {
            let index = *index;
            let pair = pairs.get_mut(&index).unwrap();
            let (mut reader, writer) = pair.stream.take().unwrap();
            transfers.insert(
                index,
                tokio::spawn(async move {
                    let outgoing = tokio::spawn(async move {
                        let mut offset = 0;
                        while offset < BULK {
                            let chunk: Vec<_> = (offset..(offset + 65536).min(BULK))
                                .map(|at| byte_at(index, 1, at))
                                .collect();
                            let n = writer.write(&chunk).await.expect("peer stream write");
                            assert!(n > 0 && n <= chunk.len());
                            offset += n;
                        }
                        writer
                    });
                    let mut offset = 0;
                    let mut chunk = [0u8; 4093];
                    while offset < BULK {
                        let n = reader.read(&mut chunk).await.expect("peer stream read");
                        assert!(n > 0 && n <= BULK - offset);
                        for (i, value) in chunk[..n].iter().enumerate() {
                            assert_eq!(*value, byte_at(index, 2, offset + i));
                        }
                        offset += n;
                    }
                    (reader, outgoing.await.unwrap())
                }),
            );
        }
        for index in wave {
            let pair = pairs.get_mut(index).unwrap();
            let forward = bytes(*index, 2, BULK);
            let reverse = bytes(*index, 1, BULK);
            let mut sent = 0;
            while sent < BULK {
                let end = (sent + 65536).min(BULK);
                let request = host
                    .child(pair.connection, pair.channel, 3, &forward[sent..end])
                    .await;
                let complete = host.ok(request).await;
                let n = serde_json::from_slice::<Value>(&complete.bytes).unwrap()["written"]
                    .as_u64()
                    .unwrap() as usize;
                assert!(n > 0 && n <= end - sent);
                partial_write |= n < end - sent;
                sent += n;
            }
            let first = host.ok(pending.remove(index).unwrap()).await;
            assert!(!first.bytes.is_empty() && first.bytes.len() <= RESERVATION);
            assert_eq!(first.bytes, reverse[..first.bytes.len()]);
            partial_read |= first.bytes.len() < RESERVATION;
            let mut received = first.bytes.len();
            while received < BULK {
                let maximum = 4093.min(BULK - received);
                let request = host.read(pair.connection, pair.channel, maximum).await;
                let part = host.ok(request).await;
                assert!(!part.bytes.is_empty() && part.bytes.len() <= maximum);
                assert_eq!(part.bytes, reverse[received..received + part.bytes.len()]);
                received += part.bytes.len();
            }
            pair.stream = Some(
                tokio::time::timeout(Duration::from_secs(30), transfers.remove(index).unwrap())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
    }
    let bulk_seconds = bulk_started.elapsed().as_secs_f64();
    assert!(
        partial_write && partial_read,
        "stream partial progress must be observed"
    );
    assert!(pending.is_empty());
    valid(&host, &pairs);
    // Control-plane termination must wake already-running C reads as CLOSED,
    // without requiring any peer payload or disrupting an authorized sibling.
    phase("ffi-terminate", started);
    let terminated = f.peer_count.saturating_sub(1).min(20);
    let terminated_indices = indices[..terminated].to_vec();
    for index in &terminated_indices {
        let p = &pairs[index];
        pending.insert(
            *index,
            host.read(p.connection, p.channel, RESERVATION).await,
        );
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while unsafe { capacity_pending_reads(host.sdk) } != terminated as u64 {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for index in &terminated_indices {
        let pair = &pairs[index];
        api.request_status(
            &format!("/v1/sessions/{}/terminate", pair.session),
            Some(json!({})),
            200,
        )
        .await;
    }
    for index in &terminated_indices {
        assert_eq!(
            host.completion(pending.remove(index).unwrap()).await.status,
            CLOSED
        );
    }
    let mut terminal = BTreeSet::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while terminal.len() < terminated {
        let (index, event) = next(&mut events).await;
        assert!(
            terminated_indices.contains(&index),
            "termination cannot swallow sibling event"
        );
        match event {
            SdkEvent::ConnectionClosed {
                reason: SdkError::Rejected(_),
                ..
            } => {
                terminal.insert(index);
            }
            SdkEvent::ConnectionClosed {
                reason: SdkError::Transport(_),
                ..
            } => {}
            _ => panic!("target authority termination"),
        }
        assert!(Instant::now() < deadline);
    }
    let mut pc_terminal = BTreeSet::new();
    while pc_terminal.len() < terminated {
        let event = host.next().await;
        if event.kind == 7 {
            assert!(
                terminated_indices
                    .iter()
                    .any(|i| pairs[i].connection == event.connection)
            );
            pc_terminal.insert(event.connection);
        } else {
            assert_eq!(
                event.kind, 13,
                "only child/parent closure during authorized termination"
            );
        }
    }
    for index in &terminated_indices {
        let pair = pairs.remove(index).unwrap();
        assert_ne!(
            unsafe { capacity_connection_valid(host.sdk, pair.connection) },
            OK
        );
        assert_ne!(
            unsafe { capacity_channel_valid(host.sdk, pair.connection, pair.channel) },
            OK
        );
        assert!(!pair.remote.validity().is_valid());
    }
    assert_eq!(pairs.len(), f.peer_count - terminated);
    valid(&host, &pairs);
    // All unaffected streams complete an additional bidirectional exchange and
    // real FIN half-close. The reverse direction remains writable after PC FIN.
    phase("ffi-fin", started);
    let mut fin_count = 0;
    for (index, pair) in &mut pairs {
        let (mut reader, writer) = pair.stream.take().unwrap();
        let forward = bytes(*index, 3, 137);
        let reverse = bytes(*index, 4, 193);
        let request = host.child(pair.connection, pair.channel, 3, &forward).await;
        let complete = host.ok(request).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&complete.bytes).unwrap()["written"],
            forward.len()
        );
        let mut got = vec![0; forward.len()];
        let mut offset = 0;
        while offset < got.len() {
            let n = reader.read(&mut got[offset..]).await.unwrap();
            assert!(n > 0);
            offset += n;
        }
        assert_eq!(got, forward);
        let finish = host.child(pair.connection, pair.channel, 4, &[]).await;
        host.ok(finish).await;
        assert_eq!(reader.read(&mut [0u8; 1]).await.unwrap(), 0);
        let (status, rejected) = host.child_status(pair.connection, pair.channel, 3, b"after-fin");
        assert_eq!(status, CLOSED);
        assert_eq!(rejected, 0);
        let read = host.read(pair.connection, pair.channel, RESERVATION).await;
        assert_eq!(writer.write(&reverse).await.unwrap(), reverse.len());
        assert_eq!(host.ok(read).await.bytes, reverse);
        writer.shutdown_write().await.unwrap();
        let eof = host.read(pair.connection, pair.channel, 4093).await;
        assert!(host.ok(eof).await.bytes.is_empty());
        pair.stream = Some((reader, writer));
        fin_count += 1;
    }
    assert_eq!(fin_count, pairs.len());
    // Flush optional child close notifications before reset; no completion is
    // ever discarded, and the accepted/completed sets remain independently held.
    {
        let mut state = host.collector.state.lock().unwrap();
        assert!(state.events.iter().all(|e| e.kind == 13));
        state.events.clear();
    }
    phase("ffi-reset", started);
    let reset = host.submit(
        7,
        0,
        &serde_json::to_vec(&json!({"expected_device_id":source,"retry":false})).unwrap(),
    );
    let reset_result = host.ok(reset).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reset_result.bytes).unwrap()["identity_reset"],
        true
    );
    assert!(
        host.identity.is_null(),
        "actual external CAS tombstone after reset"
    );
    assert_eq!(
        unsafe { capacity_pending_reads(host.sdk) },
        0,
        "all real read workers drained before RESET completion"
    );
    for pair in pairs.values() {
        assert_ne!(
            unsafe { capacity_connection_valid(host.sdk, pair.connection) },
            OK
        );
        assert_ne!(
            unsafe { capacity_channel_valid(host.sdk, pair.connection, pair.channel) },
            OK
        );
    }
    // Reset fences local SDK delivery; it is not server revocation. Explicitly
    // terminate remaining rows before final shutdown, rather than claiming WSS
    // loss closes the authoritative session immediately.
    for pair in pairs.values() {
        api.request_status(
            &format!("/v1/sessions/{}/terminate", pair.session),
            Some(json!({})),
            200,
        )
        .await;
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let rows = api.sessions().await;
        if rows.len() == f.peer_count && rows.values().all(|r| r.state == "closed") {
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    phase("shutdown", started);
    let mut shutdown = 0;
    assert_eq!(unsafe { capacity_shutdown(host.sdk, &mut shutdown) }, OK);
    assert_ne!(shutdown, 0);
    loop {
        let event = host.next().await;
        if event.kind == 10 {
            host.storage(&event);
            continue;
        }
        if event.kind == 9 {
            assert_eq!(event.request, shutdown);
            assert_eq!(event.status, OK);
            break;
        }
        assert!(
            matches!(event.kind, 3 | 7 | 13),
            "only reset/close notifications precede shutdown"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = unsafe { capacity_release(host.sdk) };
        if status == OK {
            break;
        }
        assert_eq!(status, BUSY);
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(unsafe { capacity_state(host.sdk) }, 3);
    let callbacks = host.collector.state.lock().unwrap().callbacks;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (accepted_count, completed_count) = {
        let state = host.collector.state.lock().unwrap();
        assert_eq!(state.callbacks, callbacks);
        assert_eq!(state.shutdown, 1);
        assert!(!state.failed);
        assert_eq!(
            state.accepted, state.completed,
            "every accepted ID exactly one terminal callback"
        );
        assert!(state.completions.is_empty());
        (state.accepted.len(), state.completed.len())
    };
    for peer in peers.values() {
        peer.commands.send(Command::Stop).await.unwrap();
    }
    let done = futures_util::future::join_all(peers.into_values().map(|peer| peer.task));
    tokio::pin!(done);
    tokio::time::timeout(Duration::from_secs(40),async{loop{tokio::select!{result=&mut done=>{for r in result{r.unwrap();}break;},_=events.recv()=>{}}}}).await.unwrap();
    assert!(pairs.values().all(|p| !p.remote.validity().is_valid()));
    drop(pairs);
    latency.sort_by(f64::total_cmp);
    write_json(
        &f.directory.join("sdk-proof.json"),
        json!({
            "case":"ffi","status":"passed","peer_count":f.peer_count,"pc_identity_count":1,"pc_sdk_instances":1,"pc_c_abi_instances":1,
            "c_adapter_validated":true,"native_simulated_peer_instances":f.peer_count,"simultaneous_ready":f.peer_count,"ffi_streams_ready":f.peer_count,
            "peak_pending_reads":f.peer_count,"all_500_reads_accepted_before_peer_payload":f.peer_count==500,"read_reservation_bytes":RESERVATION,
            "resource_budget_bytes":resource_budget,"pending_read_charged_bytes":read_charged,"pending_critical_charged_bytes":critical_charged,"bulk_bytes_per_peer_per_direction":BULK,
            "bulk_send_window":8,"bulk_bytes_total":2*f.peer_count*BULK,"bulk_elapsed_seconds":bulk_seconds,"bulk_bytes_per_second":(2*f.peer_count*BULK) as f64/bulk_seconds,"queued_cancel_verified":true,"running_read_cancel_busy":true,
            "terminated_pending_reads":terminated,"siblings_survive_termination":fin_count==f.peer_count-terminated,
            "partial_read_verified":partial_read,"partial_write_verified":partial_write,"fin_half_close_verified":fin_count>0,
            "reset_verified":true,"pending_reads_after_reset":0,"exactly_once_completions":true,
            "ffi_operations_accepted":accepted_count,"ffi_operation_completions":completed_count,"no_callbacks_after_shutdown":true,"real_registration":true,
            "real_webrtc_bidirectional_unique_payloads":true,"all_initial_dual_deadlines_crossed_and_renewed":true,"hold_seconds":f.hold_seconds,
            "manual_new_session_count":0,"all_session_rows_closed":true,"all_local_gates_closed":true,"explicit_session_close_before_sdk_shutdown":true,
            "physical_android_devices":false,"video_tested":false,"errors":0,
            "connection_latency_ms":{"count":latency.len(),"min":latency[0],"p50":latency[latency.len()/2],"p95":latency[(latency.len()-1)*95/100],"max":latency.last()}
        }),
    );
}
