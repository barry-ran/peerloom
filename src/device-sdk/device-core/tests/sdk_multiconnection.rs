//! One authenticated identity/WSS owns two concurrent authorized peer sessions.
use device_core::sdk::{Connection, DeviceSdk, SdkConfig, SdkError, SdkEvent};
use device_protocol::ConnectionPolicy;
use device_storage::{
    IdentityScope, IdentityStore, MemoryIdentityStore, SecretString, StoredIdentity,
};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Deserialize)]
struct Device {
    application_id: String,
    device_id: String,
    device_credential: String,
    expires_at: String,
}
#[derive(Deserialize)]
struct Fixture {
    source: Device,
    target: Device,
    third: Device,
}

async fn sdk(origin: &str, device: Device, capacity: usize) -> DeviceSdk {
    let store = Arc::new(MemoryIdentityStore::default());
    store
        .save(
            &IdentityScope {
                server_origin: reqwest::Url::parse(origin).unwrap().to_string(),
                application_id: device.application_id.clone(),
            },
            0,
            StoredIdentity {
                device_id: device.device_id,
                device_credential: SecretString::new(device.device_credential),
                expires_at: device.expires_at,
            },
        )
        .await
        .unwrap();
    let mut config = SdkConfig::new(origin.into(), device.application_id);
    config.development_loopback = true;
    config.max_connections = capacity;
    config.transport.policy = ConnectionPolicy::DirectOnly;
    config.transport.bind_address = "127.0.0.1:0".parse().unwrap();
    config.transport.include_loopback = true;
    DeviceSdk::load(config, store).await.unwrap()
}
async fn next(sdk: &mut DeviceSdk) -> SdkEvent {
    tokio::time::timeout(Duration::from_secs(30), sdk.next_event())
        .await
        .expect("bounded event")
        .expect("live SDK")
}
async fn incoming(sdk: &mut DeviceSdk) -> String {
    match next(sdk).await {
        SdkEvent::IncomingConnection { session_id, .. } => session_id,
        other => panic!("expected authorized incoming: {other:?}"),
    }
}
async fn ready(sdk: &mut DeviceSdk) -> Connection {
    match next(sdk).await {
        SdkEvent::ConnectionReady(connection) => connection,
        other => panic!("expected ready: {other:?}"),
    }
}
async fn exchange(a: &mut Connection, b: &mut Connection, bytes: &[u8]) {
    a.send(bytes).await.unwrap();
    assert_eq!(b.receive().await.unwrap(), bytes);
    b.send(bytes).await.unwrap();
    assert_eq!(a.receive().await.unwrap(), bytes);
}

#[derive(Deserialize)]
struct LeaseSnapshot {
    source_lease_expires_at: String,
    target_lease_expires_at: String,
    lease_generation: u64,
}
impl LeaseSnapshot {
    fn deadlines(&self) -> (time::OffsetDateTime, time::OffsetDateTime) {
        let parse = |value: &str| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .expect("lease timestamp")
        };
        (
            parse(&self.source_lease_expires_at),
            parse(&self.target_lease_expires_at),
        )
    }
}
async fn lease_snapshot(origin: &str, session: &str, credential: &str) -> LeaseSnapshot {
    let origin = reqwest::Url::parse(origin).unwrap();
    assert!(
        origin.scheme() == "http"
            && matches!(origin.host_str(), Some("127.0.0.1" | "[::1]" | "::1"))
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {credential}")).unwrap();
    auth.set_sensitive(true);
    let mut response = client
        .get(origin.join(&format!("/v1/sessions/{session}")).unwrap())
        .header(reqwest::header::AUTHORIZATION, auth)
        .send()
        .await
        .expect("loopback lease probe request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "lease probe authorization/status"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.expect("lease probe body") {
        assert!(
            bytes.len() + chunk.len() <= 16 * 1024,
            "bounded lease snapshot"
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).expect("typed lease snapshot")
}
fn lease_probe_credential() -> zeroize::Zeroizing<String> {
    let path = std::env::var("TEST_LEASE_ADMIN_FIXTURE")
        .expect("managed test requires private same-tenant lease probe fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600);
        assert!(metadata.len() <= 65536);
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    #[derive(Deserialize)]
    struct Admin {
        service_credential: String,
    }
    let value: Admin = serde_json::from_slice(&bytes).expect("lease probe fixture shape");
    assert!(value.service_credential.starts_with("svc_") && value.service_credential.len() == 47);
    zeroize::Zeroizing::new(value.service_credential)
}

#[tokio::test]
#[ignore = "requires fresh three-device fixture and real Go/PG/Redis/UDP"]
async fn three_devices_share_one_wss_with_bounded_admission_and_reset() {
    let path =
        std::env::var("TEST_MULTICONNECTION_FIXTURE_FILE").expect("private three-device fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).unwrap());
    let fixture: Fixture = serde_json::from_slice(&bytes).unwrap();
    let origin = std::env::var("TEST_IDENTITY_BASE_URL").unwrap();
    let mut a = sdk(&origin, fixture.source, 2).await;
    let mut b = sdk(&origin, fixture.target, 1).await;
    let mut c = sdk(&origin, fixture.third, 1).await;
    for value in [&mut a, &mut b, &mut c] {
        assert!(matches!(next(value).await, SdkEvent::Online));
    }
    // Two overlapping requests: denial must identify and release ONLY its own slot.
    let absent = uuid::Uuid::new_v4().to_string();
    let denied_request = a.connect_with_request(&absent).await.unwrap();
    let surviving_request = a.connect_with_request(c.device_id()).await.unwrap();
    assert_ne!(denied_request, surviving_request);
    match next(&mut a).await {
        SdkEvent::ConnectionRequestFailed {
            target_device_id,
            request_id,
            reason,
        } => {
            assert_eq!(target_device_id, absent);
            assert_eq!(request_id, denied_request);
            assert!(matches!(reason, SdkError::Rejected(_)));
        }
        event => panic!("expected precisely correlated denial: {event:?}"),
    }
    a.connect(b.device_id()).await.unwrap();
    // Neither peer has approved or created a transport. Pending authorization
    // must already consume both local slots, rather than overbooking capacity.
    assert_eq!(a.connect(b.device_id()).await, Err(SdkError::Busy));
    let ab = incoming(&mut b).await;
    let ac = incoming(&mut c).await;
    b.accept(&ab).await.unwrap();
    c.accept(&ac).await.unwrap();
    let mut outgoing = BTreeMap::new();
    for _ in 0..2 {
        let connection = ready(&mut a).await;
        outgoing.insert(connection.session_id().to_owned(), connection);
    }
    let mut a_b = outgoing.remove(&ab).expect("A-B ready");
    let mut a_c = outgoing.remove(&ac).expect("A-C ready");
    let mut b_a = ready(&mut b).await;
    let mut c_a = ready(&mut c).await;
    assert_eq!(b_a.session_id(), ab);
    assert_eq!(c_a.session_id(), ac);
    exchange(&mut a_b, &mut b_a, &[0, 255, 1, 0]).await;
    exchange(&mut a_c, &mut c_a, "第三个设备".as_bytes()).await;
    assert_eq!(a.connect(c.device_id()).await, Err(SdkError::Busy));
    let probe = lease_probe_credential();
    let initial_ab = lease_snapshot(&origin, &ab, &probe).await;
    let initial_ac = lease_snapshot(&origin, &ac, &probe).await;
    // One credential rotation reconnects the one WSS and syncs BOTH leases.
    a.refresh_credentials().await.unwrap();
    assert!(matches!(next(&mut a).await, SdkEvent::Offline));
    assert!(matches!(next(&mut a).await, SdkEvent::Online));
    let (ab_source, ab_target) = initial_ab.deadlines();
    let (ac_source, ac_target) = initial_ac.deadlines();
    let deadline = ab_source.max(ab_target).max(ac_source).max(ac_target);
    let remaining: Duration = (deadline - time::OffsetDateTime::now_utc())
        .try_into()
        .unwrap();
    assert!(remaining <= Duration::from_secs(90));
    tokio::time::sleep(remaining + Duration::from_secs(2)).await;
    assert!(time::OffsetDateTime::now_utc() > deadline);
    for (id, initial) in [(&ab, &initial_ab), (&ac, &initial_ac)] {
        let after = lease_snapshot(&origin, id, &probe).await;
        let (before_source, before_target) = initial.deadlines();
        let (after_source, after_target) = after.deadlines();
        assert!(after.lease_generation > initial.lease_generation);
        assert!(after_source > before_source && after_target > before_target);
        assert!(
            after_source > time::OffsetDateTime::now_utc()
                && after_target > time::OffsetDateTime::now_utc()
        );
        println!(
            "PASS: session persisted dual deadlines crossed and advanced, generation {} -> {}",
            initial.lease_generation, after.lease_generation
        );
    }
    exchange(&mut a_b, &mut b_a, b"both leases renewed AB").await;
    exchange(&mut a_c, &mut c_a, b"both leases renewed AC").await;
    let old_ab = a_b.validity();
    a_b.close().await.unwrap();
    assert!(!old_ab.is_valid());
    exchange(&mut a_c, &mut c_a, b"sibling survives AB close").await;
    // The peer may first report transport interruption before authoritative teardown.
    // Wait for terminal server closure, not a recoverable-generation notification.
    loop {
        match next(&mut b).await {
            SdkEvent::ConnectionClosed { session_id, reason } if session_id == ab => {
                if matches!(reason, SdkError::Rejected(_)) {
                    break;
                }
            }
            event => panic!("unexpected sibling/terminal event: {event:?}"),
        }
    }
    assert!(b_a.send(b"closed AB").await.is_err());
    assert!(
        matches!(next(&mut a).await,SdkEvent::ConnectionClosed {session_id,..} if session_id==ab)
    );
    // Released capacity can admit another independently authorized session.
    a.connect(b.device_id()).await.unwrap();
    let new_ab = incoming(&mut b).await;
    assert_ne!(new_ab, ab);
    b.accept(&new_ab).await.unwrap();
    let mut reopened = ready(&mut a).await;
    let mut b_reopened = ready(&mut b).await;
    exchange(&mut reopened, &mut b_reopened, b"reused slot, new session").await;
    let new_ab_validity = reopened.validity();
    // Reset is a single installation-wide fence, not a per-connection cleanup.
    let old_ac = a_c.validity();
    let identity = a.device_id().to_owned();
    a.reset(&identity).await.unwrap();
    assert!(!old_ab.is_valid() && !old_ac.is_valid() && !new_ab_validity.is_valid());
    assert!(
        reopened
            .send(b"second live session after reset")
            .await
            .is_err()
    );
    assert!(a_c.send(b"after reset").await.is_err());
    assert!(a_c.receive().await.is_err());
    assert!(a.connect(c.device_id()).await.is_err());
    a.close().await;
    b.close().await;
    c.close().await;
}
