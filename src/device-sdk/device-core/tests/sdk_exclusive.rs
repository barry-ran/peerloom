//! Three real SDK identities against isolated Go/PG/Redis; no fake sessions.
use device_core::{
    identity::{IdempotencyKey, Platform, RegistrationRequest},
    sdk::{Connection, DeviceSdk, SdkChannel, SdkConfig, SdkError, SdkEvent},
};
use device_protocol::ConnectionPolicy;
use device_storage::{MemoryIdentityStore, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
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
}
struct Api {
    client: reqwest::Client,
    origin: reqwest::Url,
    token: reqwest::header::HeaderValue,
}
impl Api {
    async fn request(&self, path: &str, body: Option<Value>, key: &str) -> (u16, Value) {
        let mut req = if body.is_some() {
            self.client.post(self.origin.join(path).unwrap())
        } else {
            self.client.get(self.origin.join(path).unwrap())
        };
        req = req.header(reqwest::header::AUTHORIZATION, self.token.clone());
        if let Some(v) = body {
            req = req
                .header("Idempotency-Key", key)
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(&v).unwrap())
        }
        let mut res = req.send().await.expect("public HTTP");
        let status = res.status().as_u16();
        let mut b = Vec::new();
        while let Some(c) = res.chunk().await.expect("HTTP body") {
            assert!(b.len() + c.len() <= 65536);
            b.extend(c)
        }
        (status, serde_json::from_slice(&b).expect("bounded JSON"))
    }
    async fn prepare(&self, source: &str, target: &str, key: &str) -> (u16, Value) {
        self.request("/v1/exclusive-sessions/prepare",Some(json!({"source_device_id":source,"target_device_id":target,"expires_in_seconds":600})),key).await
    }
}
enum Command {
    Prepared(String, oneshot::Sender<String>),
    Refresh(oneshot::Sender<()>),
    Stop,
}
struct Driver {
    id: String,
    commands: mpsc::Sender<Command>,
    task: tokio::task::JoinHandle<()>,
}
async fn driver(
    f: &Fixture,
    r: &Registration,
    index: usize,
    events: mpsc::Sender<(usize, SdkEvent)>,
) -> Driver {
    let mut c = SdkConfig::new(f.origin.clone(), r.application_id.clone());
    c.development_loopback = true;
    c.transport.policy = ConnectionPolicy::DirectOnly;
    c.transport.bind_address = "127.0.0.1:0".parse().unwrap();
    c.transport.include_loopback = true;
    let mut sdk = DeviceSdk::register(
        c,
        Arc::new(MemoryIdentityStore::default()),
        RegistrationRequest {
            application_id: r.application_id.clone(),
            platform: Platform::Linux,
            installation_public_key: format!("exclusive-public-fixture-{}", uuid::Uuid::new_v4()),
            registration_grant: SecretString::new(r.grant.clone()),
            sdk_version: env!("CARGO_PKG_VERSION").into(),
            metadata: serde_json::Map::new(),
        },
        IdempotencyKey::random(),
    )
    .await
    .expect("real registration");
    let id = sdk.device_id().to_owned();
    let (commands, mut requests) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
             cmd=requests.recv()=>match cmd{Some(Command::Prepared(id,done))=>{let correlation=sdk.connect_prepared(&id).await.expect("prepared admission");let _=done.send(correlation);},Some(Command::Refresh(done))=>{sdk.refresh_credentials().await.expect("target credential refresh");let _=done.send(());},Some(Command::Stop)|None=>break},
             event=sdk.next_event()=>{let e=event.expect("SDK live");if let SdkEvent::IncomingConnection{ref session_id,..}=e{assert_eq!(index,2,"only target receives incoming");sdk.accept(session_id).await.expect("epoch target acceptance");}else if events.send((index,e)).await.is_err(){break}}
            }
        }
        sdk.close().await;
    });
    Driver { id, commands, task }
}
async fn event(events: &mut mpsc::Receiver<(usize, SdkEvent)>) -> (usize, SdkEvent) {
    tokio::time::timeout(Duration::from_secs(30), events.recv())
        .await
        .expect("bounded event")
        .expect("event stream")
}
async fn connected(
    source: &Driver,
    id: &str,
    index: usize,
    previous: Option<&str>,
    events: &mut mpsc::Receiver<(usize, SdkEvent)>,
) -> (Connection, Connection) {
    let (tx, rx) = oneshot::channel();
    source
        .commands
        .send(Command::Prepared(id.into(), tx))
        .await
        .unwrap();
    assert!(!rx.await.unwrap().is_empty());
    let (mut a, mut b) = (None, None);
    while a.is_none() || b.is_none() {
        let (i, e) = event(events).await;
        match e {
            SdkEvent::ConnectionReady(c) => {
                assert_eq!(c.session_id(), id);
                if i == index {
                    assert!(a.replace(c).is_none())
                } else {
                    assert_eq!(i, 2);
                    assert!(b.replace(c).is_none())
                }
            }
            SdkEvent::ConnectionClosed { session_id, reason } => panic!(
                "unexpected close endpoint={i} expected_session={} previous_session={} reason={reason:?}",
                session_id == id,
                previous == Some(session_id.as_str())
            ),
            other => panic!("unexpected connection event {other:?}"),
        }
    }
    (a.unwrap(), b.unwrap())
}
async fn exchange(a: &Connection, b: &mut Connection) {
    a.send(b"exclusive-forward").await.unwrap();
    assert_eq!(b.receive().await.unwrap(), b"exclusive-forward");
    b.send(b"exclusive-reverse").await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated actual Go/PG/Redis and three registered SDKs"]
async fn prepared_target_competition_renewal_fence_and_handoff() {
    let path = std::env::var("TEST_EXCLUSIVE_FIXTURE").expect("private fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::symlink_metadata(&path).unwrap();
        assert!(m.is_file() && m.permissions().mode() & 0o777 == 0o600);
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    let f: Fixture = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(f.registrations.len(), 3);
    let origin = reqwest::Url::parse(&f.origin).unwrap();
    assert_eq!(origin.scheme(), "http");
    assert_eq!(origin.host_str(), Some("127.0.0.1"));
    let mut token =
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", f.service_credential))
            .unwrap();
    token.set_sensitive(true);
    let api = Api {
        origin,
        token,
        client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap(),
    };
    let (tx, mut events) = mpsc::channel(32);
    let mut peers = Vec::new();
    for (i, r) in f.registrations.iter().enumerate() {
        peers.push(driver(&f, r, i, tx.clone()).await)
    }
    let mut online = [false; 3];
    while !online.iter().all(|x| *x) {
        let (i, e) = event(&mut events).await;
        assert!(matches!(e, SdkEvent::Online));
        assert!(!online[i]);
        online[i] = true;
    }
    eprintln!("exclusive-stage=all-online");
    let k0 = uuid::Uuid::new_v4().to_string();
    let k1 = uuid::Uuid::new_v4().to_string();
    let (r0, r1) = tokio::join!(
        api.prepare(&peers[0].id, &peers[2].id, &k0),
        api.prepare(&peers[1].id, &peers[2].id, &k1)
    );
    assert!(
        (r0.0 == 201 && r1.0 == 409) || (r1.0 == 201 && r0.0 == 409),
        "exactly one authoritative winner"
    );
    let (winner, first, key) = if r0.0 == 201 {
        (0, r0.1, k0)
    } else {
        (1, r1.1, k1)
    };
    eprintln!("exclusive-stage=single-winner");
    let loser = 1 - winner;
    let id = first["session_id"].as_str().unwrap().to_owned();
    let epoch = first["target_epoch"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(first["prepared"].as_bool().unwrap());
    let (mut a, mut b) = connected(&peers[winner], &id, winner, None, &mut events).await;
    exchange(&a, &mut b).await;
    assert_eq!(a.receive().await.unwrap(), b"exclusive-reverse");
    let (_, before) = api.request(&format!("/v1/sessions/{id}"), None, "").await;
    let initial = before["lease_generation"].as_u64().unwrap();
    eprintln!("exclusive-stage=lease-hold");
    tokio::time::sleep(Duration::from_secs(65)).await;
    let (status, after) = api.request(&format!("/v1/sessions/{id}"), None, "").await;
    assert_eq!(status, 200);
    assert_eq!(after["state"], "connected");
    assert!(after["lease_generation"].as_u64().unwrap() > initial);
    for field in ["source_lease_expires_at", "target_lease_expires_at"] {
        let parse = |v: &Value| {
            time::OffsetDateTime::parse(
                v[field].as_str().unwrap(),
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap()
        };
        assert!(
            parse(&after) > parse(&before),
            "both actual lease deadlines must advance"
        );
    }
    exchange(&a, &mut b).await;
    assert_eq!(a.receive().await.unwrap(), b"exclusive-reverse");
    eprintln!("exclusive-stage=leases-renewed");
    let mut incoming = b.take_incoming_channels().unwrap();
    let stream_a = a.open_stream("exclusive-stream").await.unwrap();
    let SdkChannel::Stream(stream_b) = incoming.receive().await.unwrap() else {
        panic!("typed stream")
    };
    let (_read_a, write_a) = stream_a.split();
    let (mut read_b, _write_b) = stream_b.split();
    let data = vec![37u8; 32000];
    let n = write_a.write(&data).await.unwrap();
    assert!(n > 0 && n < data.len());
    let mut got = vec![0; n];
    let mut at = 0;
    while at < n {
        at += read_b.read(&mut got[at..]).await.unwrap();
    }
    assert_eq!(got, data[..n]);
    let pending_read = tokio::spawn(async move { read_b.read(&mut [0; 1]).await });
    tokio::task::yield_now().await;
    eprintln!("exclusive-stage=close-fence");
    a.close().await.unwrap();
    let terminal = tokio::time::timeout(Duration::from_secs(10), pending_read)
        .await
        .expect("close wakes old stream")
        .unwrap();
    assert!(
        terminal.is_err() || terminal == Ok(0),
        "old stream cannot deliver after close"
    );
    assert!(write_a.write(b"stale epoch").await.is_err());
    let mut closed = [false; 3];
    let mut target_transport_closed = false;
    while !closed[winner] || !closed[2] {
        let (i, e) = event(&mut events).await;
        match e {
            SdkEvent::ConnectionClosed { session_id, reason } => {
                assert_eq!(session_id, id);
                assert!(i == winner || i == 2);
                eprintln!("exclusive-close endpoint={i} reason={reason:?}");
                if i == 2 && matches!(reason, SdkError::Transport(_)) {
                    // Published recovery contract: an old transport can fail
                    // before the authoritative session terminal arrives.
                    assert!(!target_transport_closed && !closed[i]);
                    target_transport_closed = true;
                } else {
                    assert!(!closed[i], "duplicate authoritative terminal");
                    if i == 2 {
                        assert!(matches!(reason, SdkError::Rejected(_)));
                    } else {
                        assert!(matches!(reason, SdkError::Closed));
                    }
                    closed[i] = true;
                }
            }
            other => panic!("unexpected close {other:?}"),
        }
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (s, v) = api.request(&format!("/v1/sessions/{id}"), None, "").await;
            assert_eq!(s, 200);
            if v["exclusive_release_state"] == "released" {
                assert_eq!(v["target_fenced"], true);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await
        }
    })
    .await
    .expect("target ACK releases without waiting lease");
    eprintln!("exclusive-stage=target-fenced");
    let (s, replay) = api.prepare(&peers[winner].id, &peers[2].id, &key).await;
    assert_eq!(s, 201);
    assert_eq!(replay["session_id"], id);
    assert_eq!(replay["state"], "closed");
    let (s, next) = api
        .prepare(
            &peers[loser].id,
            &peers[2].id,
            &uuid::Uuid::new_v4().to_string(),
        )
        .await;
    assert_eq!(s, 201);
    assert!(
        next["target_epoch"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > epoch
    );
    let next_id = next["session_id"].as_str().unwrap();
    let (mut c, mut d) = connected(&peers[loser], next_id, loser, Some(&id), &mut events).await;
    exchange(&c, &mut d).await;
    assert_eq!(c.receive().await.unwrap(), b"exclusive-reverse");
    eprintln!("exclusive-stage=higher-epoch-data-passed");
    let (done, refreshed) = oneshot::channel();
    peers[2]
        .commands
        .send(Command::Refresh(done))
        .await
        .unwrap();
    refreshed.await.unwrap();
    // Previous Online events were consumed before either prepare. Require the
    // target's new Offline -> Online handshake, not merely refresh completion.
    let mut offline = false;
    loop {
        let (index, value) = event(&mut events).await;
        assert_eq!(index, 2, "only refreshed target may change WSS here");
        match value {
            SdkEvent::Offline => {
                assert!(!offline);
                offline = true;
            }
            SdkEvent::Online => {
                assert!(offline);
                break;
            }
            other => panic!("unexpected target reconnect event {other:?}"),
        }
    }
    exchange(&c, &mut d).await;
    assert_eq!(c.receive().await.unwrap(), b"exclusive-reverse");
    eprintln!("exclusive-stage=new-target-wss-online");
    c.close().await.unwrap();
    let mut terminal = [false; 3];
    let mut transport = false;
    while !terminal[loser] || !terminal[2] {
        let (index, value) = event(&mut events).await;
        match value {
            SdkEvent::ConnectionClosed { session_id, reason } => {
                assert_eq!(session_id, next_id);
                assert!(index == loser || index == 2);
                if index == 2 && matches!(reason, SdkError::Transport(_)) {
                    assert!(!transport && !terminal[index]);
                    transport = true;
                } else {
                    assert!(!terminal[index]);
                    if index == 2 {
                        assert!(matches!(reason, SdkError::Rejected(_)));
                    } else {
                        assert!(matches!(reason, SdkError::Closed));
                    }
                    terminal[index] = true;
                }
            }
            other => panic!("unexpected new-runtime close {other:?}"),
        }
    }
    let (status, closing) = api
        .request(&format!("/v1/sessions/{next_id}"), None, "")
        .await;
    assert_eq!(status, 200);
    assert_eq!(closing["state"], "closed");
    assert_eq!(
        closing["target_fenced"], false,
        "new WSS cannot ACK old accepted runtime"
    );
    assert_eq!(closing["exclusive_release_state"], "closing");
    let not_before = time::OffsetDateTime::parse(
        closing["release_not_before"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert!(not_before > time::OffsetDateTime::now_utc());
    let (denied, _) = api
        .prepare(
            &peers[winner].id,
            &peers[2].id,
            &uuid::Uuid::new_v4().to_string(),
        )
        .await;
    assert_eq!(
        denied, 409,
        "source close/new runtime must not steal occupied target"
    );
    tokio::time::timeout(Duration::from_secs(75), async {
        loop {
            let (status, current) = api
                .request(&format!("/v1/sessions/{next_id}"), None, "")
                .await;
            assert_eq!(status, 200);
            assert_eq!(current["target_fenced"], false);
            assert_eq!(current["release_not_before"], closing["release_not_before"]);
            if current["exclusive_release_state"] == "released" {
                assert!(time::OffsetDateTime::now_utc() >= not_before);
                break;
            }
            assert_eq!(current["exclusive_release_state"], "closing");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("public persisted deadline bounds safe takeover");
    let (status, final_session) = api
        .prepare(
            &peers[winner].id,
            &peers[2].id,
            &uuid::Uuid::new_v4().to_string(),
        )
        .await;
    assert_eq!(status, 201);
    assert!(
        final_session["target_epoch"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > next["target_epoch"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
    );
    let final_id = final_session["session_id"].as_str().unwrap();
    let (mut e, mut f) =
        connected(&peers[winner], final_id, winner, Some(next_id), &mut events).await;
    exchange(&e, &mut f).await;
    assert_eq!(e.receive().await.unwrap(), b"exclusive-reverse");
    e.close().await.unwrap();
    eprintln!("exclusive-stage=new-runtime-deadline-handoff-passed");
    for p in &peers {
        p.commands.send(Command::Stop).await.unwrap()
    }
    for p in peers {
        tokio::time::timeout(Duration::from_secs(10), p.task)
            .await
            .unwrap()
            .unwrap()
    }
    println!(
        "exclusive acceptance: 3 real identities; one winner; renewed 65s; target fence; handoff; bidirectional messages; quiescent shutdown"
    );
}
