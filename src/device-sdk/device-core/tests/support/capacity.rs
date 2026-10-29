// MIT — Copyright (c) 2026 Peerloom contributors.
//! Shared test-only real registration, management and evidence support.
#![allow(dead_code)]
use device_core::{
    identity::{IdempotencyKey, Platform, RegistrationRequest},
    sdk::{DeviceSdk, SdkConfig, SdkError, SdkEvent},
};
use device_protocol::ConnectionPolicy;
use device_storage::{MemoryIdentityStore, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
#[derive(Deserialize)]
pub struct Registration {
    pub application_id: String,
    pub grant: String,
}
#[derive(Deserialize)]
pub struct Fixture {
    pub origin: String,
    pub registrations: Vec<Registration>,
    pub service_credential: String,
    pub directory: PathBuf,
    pub peer_count: usize,
    pub hold_seconds: u64,
    #[serde(default)]
    pub debug_close_only: bool,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Lease {
    pub id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub state: String,
    pub lease_generation: u64,
    pub source_lease_expires_at: Option<String>,
    pub target_lease_expires_at: Option<String>,
}
impl Lease {
    pub fn deadlines(&self) -> (time::OffsetDateTime, time::OffsetDateTime) {
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
pub struct Api {
    pub client: reqwest::Client,
    pub origin: reqwest::Url,
    pub token: reqwest::header::HeaderValue,
}
impl Api {
    pub fn new(origin: &str, credential: &str) -> Self {
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
    pub async fn request(&self, path: &str, body: Option<Value>) -> Value {
        let expected = if body.is_some() { 201 } else { 200 };
        self.request_status(path, body, expected).await
    }
    pub async fn request_status(&self, path: &str, body: Option<Value>, expected: u16) -> Value {
        let url = self.origin.join(path).expect("fixed management route");
        let mut request = match &body {
            Some(_) => self.client.post(url),
            None => self.client.get(url),
        }
        .header(reqwest::header::AUTHORIZATION, self.token.clone());
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
    pub async fn sessions(&self) -> BTreeMap<String, Lease> {
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

pub enum Command {
    Connect(String, oneshot::Sender<()>),
    Refresh(oneshot::Sender<()>),
    Stop,
}
pub struct Driver {
    pub id: String,
    pub commands: mpsc::Sender<Command>,
    pub task: tokio::task::JoinHandle<()>,
}
pub fn session_tag(id: &str) -> u64 {
    let mut hash = std::hash::DefaultHasher::new();
    std::hash::Hash::hash(id, &mut hash);
    std::hash::Hasher::finish(&hash)
}
pub fn phase(name: &str, started: Instant) {
    println!(
        "capacity phase={name} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}
pub async fn register(
    f: &Fixture,
    registration: &Registration,
    index: usize,
    events: mpsc::Sender<(usize, SdkEvent)>,
    started: Instant,
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
                        let tag = session_tag(session_id);
                        println!("capacity event=closed endpoint={index} reason={reason} session_tag={tag:016x} elapsed_ms={}", started.elapsed().as_millis());
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
pub async fn connect(source: &Driver, target: &str) {
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
pub async fn next(events: &mut mpsc::Receiver<(usize, SdkEvent)>) -> (usize, SdkEvent) {
    tokio::time::timeout(Duration::from_secs(50), events.recv())
        .await
        .expect("Ready deadline")
        .expect("driver stream live")
}
pub fn write_json(path: &Path, value: Value) {
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
