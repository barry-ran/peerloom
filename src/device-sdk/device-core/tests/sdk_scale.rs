//! Real native capacity acceptance: one PC installation / one DeviceSdk / one WSS.
//! Peers are simulated native SDK instances, not Android devices or video streams.
use device_core::{
    identity::{IdempotencyKey, Platform, RegistrationRequest},
    sdk::{Connection, DeviceSdk, SdkConfig, SdkError, SdkEvent},
};
use device_protocol::ConnectionPolicy;
use device_storage::{MemoryIdentityStore, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

#[derive(Deserialize)]
struct Registration {
    application_id: String,
    grant: String,
}
#[derive(Deserialize)]
struct Fixture {
    origin: String,
    registrations: Vec<Registration>,
    service_credential: String,
    directory: PathBuf,
    peer_count: usize,
    hold_seconds: u64,
    #[serde(default)]
    debug_close_only: bool,
}
#[derive(Clone, Deserialize, Serialize)]
struct Lease {
    id: String,
    source_device_id: String,
    target_device_id: String,
    state: String,
    lease_generation: u64,
    source_lease_expires_at: Option<String>,
    target_lease_expires_at: Option<String>,
}
impl Lease {
    fn deadlines(&self) -> (time::OffsetDateTime, time::OffsetDateTime) {
        let parse = |value: &Option<String>| {
            time::OffsetDateTime::parse(
                value.as_ref().expect("dual lease required"),
                &time::format_description::well_known::Rfc3339,
            )
            .expect("valid server timestamp")
        };
        (
            parse(&self.source_lease_expires_at),
            parse(&self.target_lease_expires_at),
        )
    }
}
struct Api {
    client: reqwest::Client,
    origin: reqwest::Url,
    token: reqwest::header::HeaderValue,
}
impl Api {
    fn new(origin: &str, credential: &str) -> Self {
        let origin = reqwest::Url::parse(origin).expect("origin");
        assert_eq!(origin.scheme(), "http");
        assert_eq!(origin.host_str(), Some("127.0.0.1"));
        assert!(
            origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
        );
        let mut token = reqwest::header::HeaderValue::from_str(&format!("Bearer {credential}"))
            .expect("secret header");
        token.set_sensitive(true);
        Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            origin,
            token,
        }
    }
    async fn request(&self, path: &str, body: Option<Value>) -> Value {
        let url = self.origin.join(path).expect("fixed management route");
        let mut request = match &body {
            Some(_) => self.client.post(url),
            None => self.client.get(url),
        }
        .header(reqwest::header::AUTHORIZATION, self.token.clone());
        let expected = if body.is_some() { 201 } else { 200 };
        if let Some(body) = body {
            request = request
                .header("Idempotency-Key", uuid::Uuid::new_v4().to_string())
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(&body).unwrap());
        }
        let mut response = request.send().await.expect("management HTTP transport");
        assert_eq!(
            response.status().as_u16(),
            expected,
            "management HTTP status"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.expect("management body") {
            assert!(
                bytes.len() + chunk.len() <= 256 * 1024,
                "management response bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).expect("management JSON")
    }
    async fn sessions(&self) -> BTreeMap<String, Lease> {
        let mut found = BTreeMap::new();
        let mut cursor = String::new();
        let mut cursors = BTreeSet::new();
        for _ in 0..20 {
            let mut url = self.origin.join("/v1/sessions").unwrap();
            url.query_pairs_mut().append_pair("limit", "100");
            if !cursor.is_empty() {
                url.query_pairs_mut().append_pair("cursor", &cursor);
            }
            let page = self
                .request(&format!("{}?{}", url.path(), url.query().unwrap()), None)
                .await;
            let items: Vec<Lease> =
                serde_json::from_value(page["items"].clone()).expect("session page");
            assert!(items.len() <= 100);
            for row in items {
                assert!(
                    found.insert(row.id.clone(), row).is_none(),
                    "duplicate session page"
                );
            }
            cursor = page["next_cursor"].as_str().unwrap_or("").to_owned();
            if cursor.is_empty() {
                return found;
            }
            assert!(
                cursor.len() <= 1024 && cursors.insert(cursor.clone()),
                "cursor bound/loop"
            );
        }
        panic!("session page limit");
    }
}

enum Command {
    Connect(String, oneshot::Sender<()>),
    Refresh(oneshot::Sender<()>),
    Stop,
}
struct Driver {
    id: String,
    commands: mpsc::Sender<Command>,
    task: tokio::task::JoinHandle<()>,
}
async fn register(
    f: &Fixture,
    registration: &Registration,
    index: usize,
    events: mpsc::Sender<(usize, SdkEvent)>,
) -> Driver {
    let mut config = SdkConfig::new(f.origin.clone(), registration.application_id.clone());
    // Test the production default unlimited count, NOT a special high test cap.
    assert_eq!(
        config.max_connections, 0,
        "default SDK connection count must be unlimited"
    );
    config.development_loopback = true;
    config.transport.policy = ConnectionPolicy::DirectOnly;
    config.transport.bind_address = "127.0.0.1:0".parse().unwrap();
    config.transport.include_loopback = true;
    let mut sdk = DeviceSdk::register(
        config,
        Arc::new(MemoryIdentityStore::default()),
        RegistrationRequest {
            application_id: registration.application_id.clone(),
            platform: Platform::Linux,
            installation_public_key: format!("capacity-public-label-{}", uuid::Uuid::new_v4()),
            registration_grant: SecretString::new(registration.grant.clone()),
            sdk_version: env!("CARGO_PKG_VERSION").into(),
            metadata: serde_json::Map::new(),
        },
        IdempotencyKey::random(),
    )
    .await
    .expect("real SDK registration");
    let id = sdk.device_id().to_owned();
    let (commands, mut requests) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                command = requests.recv() => match command {
                    Some(Command::Connect(target, done)) => { sdk.connect(&target).await.expect("connect admitted"); let _ = done.send(()); }
                    Some(Command::Refresh(done)) => { sdk.refresh_credentials().await.expect("credential refresh"); let _ = done.send(()); }
                    Some(Command::Stop) | None => break,
                },
                event = sdk.next_event() => {
                    let event = event.expect("SDK event stream remains live");
                    if let SdkEvent::ConnectionClosed { ref session_id, ref reason } = event {
                        let reason = match reason {
                            SdkError::Closed => "closed",
                            SdkError::Rejected(_) => "rejected",
                            SdkError::AuthorizationExpired => "authorization_expired",
                            SdkError::Transport(_) => "transport",
                            _ => "other",
                        };
                        let mut hash = std::hash::DefaultHasher::new();
                        std::hash::Hash::hash(session_id, &mut hash);
                        let tag = std::hash::Hasher::finish(&hash);
                        println!("capacity event=closed endpoint={index} reason={reason} session_tag={tag:016x}");
                    }
                    if let SdkEvent::IncomingConnection { ref session_id, .. } = event {
                        assert_ne!(index, 0, "PC must be sole initiator");
                        sdk.accept(session_id).await.expect("explicit target acceptance");
                    } else if events.send((index, event)).await.is_err() { break; }
                }
            }
        }
        sdk.close().await;
    });
    Driver { id, commands, task }
}
async fn connect(source: &Driver, target: &str) {
    let (done, result) = oneshot::channel();
    source
        .commands
        .send(Command::Connect(target.into(), done))
        .await
        .expect("driver live");
    tokio::time::timeout(Duration::from_secs(10), result)
        .await
        .expect("connect admission deadline")
        .expect("driver acknowledgement");
}
async fn next(events: &mut mpsc::Receiver<(usize, SdkEvent)>) -> (usize, SdkEvent) {
    tokio::time::timeout(Duration::from_secs(50), events.recv())
        .await
        .expect("Ready deadline")
        .expect("driver stream live")
}
type Pair = (Connection, Connection);
async fn gather(
    indices: &[usize],
    drivers: &[Driver],
    events: &mut mpsc::Receiver<(usize, SdkEvent)>,
    starts: &BTreeMap<usize, Instant>,
    latencies: &mut Vec<f64>,
) -> BTreeMap<usize, Pair> {
    let mut pc = BTreeMap::new();
    let mut peers = BTreeMap::new();
    while pc.len() != indices.len() || peers.len() != indices.len() {
        let (endpoint, event) = next(events).await;
        let SdkEvent::ConnectionReady(connection) = event else {
            panic!("unexpected event during connection establishment at endpoint {endpoint}");
        };
        let index = if endpoint == 0 {
            indices
                .iter()
                .copied()
                .find(|i| drivers[*i].id == connection.peer_device_id())
                .expect("PC ready belongs to current wave")
        } else {
            assert!(indices.contains(&endpoint));
            assert_eq!(connection.peer_device_id(), drivers[0].id);
            endpoint
        };
        assert!(connection.validity().is_valid());
        if endpoint == 0 {
            assert!(pc.insert(index, connection).is_none());
        } else {
            assert!(peers.insert(index, connection).is_none());
        }
        if pc.contains_key(&index) && peers.contains_key(&index) {
            latencies.push(starts[&index].elapsed().as_secs_f64() * 1000.0);
        }
    }
    pc.into_iter()
        .map(|(index, source)| {
            let target = peers.remove(&index).unwrap();
            assert_eq!(source.session_id(), target.session_id());
            assert_eq!(
                source.negotiation_generation(),
                target.negotiation_generation()
            );
            (index, (source, target))
        })
        .collect()
}
async fn close_wave(
    indices: &[usize],
    pairs: &mut BTreeMap<usize, Pair>,
    events: &mut mpsc::Receiver<(usize, SdkEvent)>,
) -> BTreeSet<String> {
    let mut expected = BTreeSet::new();
    let mut retained = Vec::new();
    let mut ids = BTreeSet::new();
    for index in indices {
        let (source, target) = pairs.remove(index).expect("live pair to close");
        let id = source.session_id().to_owned();
        source.close().await.expect("explicit source close");
        expected.insert((0, id.clone()));
        expected.insert((*index, id.clone()));
        ids.insert(id);
        // Do not drop the target handle before authoritative server termination:
        // a recoverable transport Closed event may legitimately precede it.
        retained.push(target);
    }
    while !expected.is_empty() {
        let (endpoint, event) = next(events).await;
        match event {
            SdkEvent::ConnectionClosed { session_id, reason } => {
                assert!(
                    ids.contains(&session_id),
                    "close wave cannot swallow sibling transitions"
                );
                assert!(endpoint == 0 || indices.contains(&endpoint));
                if (endpoint == 0 && reason == SdkError::Closed)
                    || (endpoint != 0 && matches!(reason, SdkError::Rejected(_)))
                {
                    expected.remove(&(endpoint, session_id));
                } else {
                    assert!(
                        matches!(reason, SdkError::Transport(_)),
                        "only transient transport closure may precede terminal"
                    );
                }
            }
            _ => panic!("unexpected event during explicit close wave"),
        }
    }
    for target in retained {
        assert!(!target.validity().is_valid());
        drop(target);
    }
    ids
}

async fn exchange(pairs: &mut BTreeMap<usize, Pair>, phase: &str) {
    for (index, (source, target)) in pairs {
        let forward = format!(
            "capacity-{phase}-{index}-PC-to-peer-{}",
            source.session_id()
        )
        .into_bytes();
        let reverse = format!(
            "capacity-{phase}-{index}-peer-to-PC-{}",
            source.session_id()
        )
        .into_bytes();
        tokio::time::timeout(Duration::from_secs(5), async {
            source.send(&forward).await.expect("forward send");
            assert_eq!(target.receive().await.expect("forward receive"), forward);
            target.send(&reverse).await.expect("reverse send");
            assert_eq!(source.receive().await.expect("reverse receive"), reverse);
        })
        .await
        .expect("bidirectional exchange deadline");
    }
}
fn write_json(path: &Path, value: Value) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("exclusive nonsecret evidence");
    file.write_all(serde_json::to_string_pretty(&value).unwrap().as_bytes())
        .unwrap();
    file.sync_all().unwrap();
}
fn all_valid(pairs: &BTreeMap<usize, Pair>, count: usize) {
    assert_eq!(pairs.len(), count, "simultaneous pair count");
    assert_eq!(
        pairs
            .values()
            .map(|pair| pair.0.session_id())
            .collect::<BTreeSet<_>>()
            .len(),
        count
    );
    for (a, b) in pairs.values() {
        assert!(
            a.validity().is_valid() && b.validity().is_valid(),
            "every live endpoint remains authorized"
        );
    }
}
async fn snapshot(
    api: &Api,
    pairs: &BTreeMap<usize, Pair>,
    source: &str,
    peers: &[Driver],
) -> BTreeMap<String, Lease> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let rows = api.sessions().await;
        let live: BTreeMap<_, _> = rows
            .into_iter()
            .filter(|(_, row)| row.state != "closed")
            .collect();
        assert_eq!(live.len(), pairs.len(), "no pending or unexpected sessions");
        let ready = pairs.iter().all(|(i, (a, _))| {
            live.get(a.session_id()).is_some_and(|row| {
                row.state == "connected"
                    && row.source_device_id == source
                    && row.target_device_id == peers[*i].id
            })
        });
        if ready {
            return live;
        }
        assert!(
            Instant::now() < deadline,
            "all DB sessions must be connected"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires capacity controller, real Go/PG/Redis and 501 registered native SDKs"]
async fn one_pc_five_hundred_real_native_peers() {
    let path = std::env::var("TEST_CAPACITY_FIXTURE").expect("private fixture");
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
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    let f: Fixture = serde_json::from_slice(&bytes).expect("capacity fixture shape");
    assert!((1..=500).contains(&f.peer_count));
    assert!(
        (f.debug_close_only && f.peer_count <= 20 && f.hold_seconds == 0)
            || (!f.debug_close_only && f.hold_seconds >= 120)
    );
    assert_eq!(f.registrations.len(), f.peer_count + 1);
    let api = Api::new(&f.origin, &f.service_credential);
    let (events_tx, mut events) = mpsc::channel(64);
    let mut drivers = Vec::new();
    println!("capacity phase=register");
    for (index, registration) in f.registrations.iter().enumerate() {
        drivers.push(register(&f, registration, index, events_tx.clone()).await);
        let (actual, event) = next(&mut events).await;
        assert_eq!(actual, index);
        assert!(matches!(event, SdkEvent::Online));
    }
    assert_eq!(
        drivers.iter().map(|d| &d.id).collect::<BTreeSet<_>>().len(),
        f.peer_count + 1
    );
    println!("capacity phase=authorize");
    for peer in drivers.iter().skip(1) {
        let result=api.request("/v1/connection-grants", Some(json!({"source_device_id":drivers[0].id,"target_device_id":peer.id,"expires_in_seconds":3600,"expiry_action":"terminate"}))).await;
        assert_eq!(
            result["max_sessions"], -1,
            "server default grants unlimited"
        );
    }
    println!("capacity phase=connect");
    let mut pairs = BTreeMap::new();
    let mut latency = Vec::new();
    let indices: Vec<_> = (1..=f.peer_count).collect();
    for wave in indices.chunks(10) {
        let mut starts = BTreeMap::new();
        for i in wave {
            starts.insert(*i, Instant::now());
            connect(&drivers[0], &drivers[*i].id).await;
        }
        pairs.extend(gather(wave, &drivers, &mut events, &starts, &mut latency).await);
        println!("capacity ready_pairs={}", pairs.len());
    }
    all_valid(&pairs, f.peer_count);
    exchange(&mut pairs, "initial").await;
    println!("capacity phase=baseline");
    let initial = snapshot(&api, &pairs, &drivers[0].id, &drivers).await;
    let baseline_time = time::OffsetDateTime::now_utc();
    let initial_deadline = initial
        .values()
        .map(|row| {
            let (a, b) = row.deadlines();
            assert!(a > baseline_time && b > baseline_time);
            a.max(b)
        })
        .max()
        .unwrap();
    write_json(
        &f.directory.join("baseline.json"),
        json!({"simultaneous_ready":pairs.len(),"sdk_instances":drivers.len(),"pc_sdk_instances":1,"snapshot_complete_at":baseline_time.to_string(),"sessions":initial}),
    );
    println!("capacity phase=hold");
    let hold = Instant::now();
    while !f.debug_close_only
        && (hold.elapsed() < Duration::from_secs(f.hold_seconds)
            || time::OffsetDateTime::now_utc() <= initial_deadline)
    {
        all_valid(&pairs, f.peer_count);
        if let Ok(Some((endpoint, _))) =
            tokio::time::timeout(Duration::from_secs(1), events.recv()).await
        {
            panic!("unexpected live-session transition during hold endpoint {endpoint}");
        }
        assert!(
            hold.elapsed() < Duration::from_secs(180),
            "lease hold bound"
        );
    }
    all_valid(&pairs, f.peer_count);
    exchange(&mut pairs, "post-deadline").await;
    println!("capacity phase=renewal-proof");
    let renewed = snapshot(&api, &pairs, &drivers[0].id, &drivers).await;
    let now = time::OffsetDateTime::now_utc();
    for (id, before) in initial.iter().filter(|_| !f.debug_close_only) {
        let after = &renewed[id];
        let (a, b) = before.deadlines();
        let (c, d) = after.deadlines();
        assert!(
            after.lease_generation > before.lease_generation
                && c > a
                && d > b
                && c > now
                && d > now,
            "both persisted leases renewed across initial deadlines"
        );
    }
    write_json(
        &f.directory.join("renewed.json"),
        json!({"sessions":renewed,"hold_seconds":hold.elapsed().as_secs_f64(),"simultaneous_ready":pairs.len()}),
    );
    println!("capacity phase=pc-wss-reconnect");
    // Credential rotation exercises control-plane reconnect without claiming an ICE outage.
    let (tx, rx) = oneshot::channel();
    drivers[0]
        .commands
        .send(Command::Refresh(tx))
        .await
        .unwrap();
    rx.await.unwrap();
    let mut offline = false;
    loop {
        let (i, e) = next(&mut events).await;
        assert_eq!(i, 0);
        match e {
            SdkEvent::Offline => offline = true,
            SdkEvent::Online => {
                assert!(offline);
                break;
            }
            _ => panic!("rotation changed live data session"),
        }
    }
    all_valid(&pairs, f.peer_count);
    exchange(&mut pairs, "pc-wss-reconnected").await;
    println!("capacity phase=manual-new-sessions");
    let reconnect_count = f.peer_count.min(20);
    let mut closed_ids = BTreeSet::new();
    for wave in indices[..reconnect_count].chunks(10) {
        closed_ids.extend(close_wave(wave, &mut pairs, &mut events).await);
        exchange(&mut pairs, "unaffected-siblings").await;
        let mut starts = BTreeMap::new();
        for i in wave {
            starts.insert(*i, Instant::now());
            connect(&drivers[0], &drivers[*i].id).await;
        }
        let added = gather(wave, &drivers, &mut events, &starts, &mut latency).await;
        assert!(
            added
                .values()
                .all(|pair| !closed_ids.contains(pair.0.session_id()))
        );
        pairs.extend(added);
        all_valid(&pairs, f.peer_count);
    }
    exchange(&mut pairs, "all-reestablished").await;
    let final_live = snapshot(&api, &pairs, &drivers[0].id, &drivers).await;
    write_json(
        &f.directory.join("reestablished.json"),
        json!({"sessions":final_live,"manual_new_session_count":reconnect_count,"transport_fault_auto_recovery_tested":false}),
    );
    let validity: Vec<_> = pairs
        .values()
        .flat_map(|(a, b)| [a.validity(), b.validity()])
        .collect();
    println!("capacity phase=explicit-session-close");
    // DeviceSdk.close() fences local resources, but WSS loss alone is not a
    // server-side revocation. Explicitly terminate each session before shutdown.
    for wave in indices.chunks(10) {
        close_wave(wave, &mut pairs, &mut events).await;
    }
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        let rows = api.sessions().await;
        if rows.len() == f.peer_count + reconnect_count
            && rows.values().all(|row| row.state == "closed")
        {
            break;
        }
        assert!(Instant::now() < end, "all persisted sessions closed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("capacity phase=shutdown");
    for driver in &drivers {
        driver.commands.send(Command::Stop).await.unwrap();
    }
    // Keep draining terminal events while joining; 500 drivers must not deadlock
    // on the bounded host-event channel during an installation-wide shutdown.
    let completion = futures_util::future::join_all(drivers.into_iter().map(|driver| driver.task));
    tokio::pin!(completion);
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            tokio::select! {
                results = &mut completion => { for result in results { result.expect("driver succeeded"); } break; }
                event = events.recv() => { assert!(event.is_some(), "terminal events remain drainable"); }
            }
        }
    }).await.expect("all driver shutdown bound");
    assert!(validity.iter().all(|gate| !gate.is_valid()));
    drop(pairs);
    latency.sort_by(f64::total_cmp);
    write_json(
        &f.directory.join("sdk-proof.json"),
        json!({"status":if f.debug_close_only { "debug-only" } else { "passed" },"peer_count":f.peer_count,"pc_identity_count":1,"pc_sdk_instances":1,"native_simulated_peer_instances":f.peer_count,"simultaneous_ready":f.peer_count,"real_registration":true,"real_webrtc_bidirectional_unique_payloads":true,"all_initial_dual_deadlines_crossed_and_renewed":!f.debug_close_only,"hold_seconds":f.hold_seconds,"manual_new_session_count":reconnect_count,"pc_credential_rotation_wss_reconnect":true,"all_session_rows_closed":true,"all_local_gates_closed":true,"explicit_session_close_before_sdk_shutdown":true,"physical_android_devices":false,"video_tested":false,"connection_latency_ms":{"count":latency.len(),"min":latency[0],"p50":latency[latency.len()/2],"p95":latency[(latency.len()-1)*95/100],"max":latency.last()},"errors":0}),
    );
}
