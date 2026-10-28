//! 显式临时 Go 服务联调。fixture 只能使用测试 grant，不得传入生产身份。
use device_core::identity::{
    IdempotencyKey, IdentityClient, IdentitySession, Platform, RegistrationRequest,
};
use device_storage::{MemoryIdentityStore, SecretString};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
#[derive(Deserialize)]
struct Fixture {
    application_id: String,
    registration_grant: String,
}
#[tokio::test]
#[ignore = "requires disposable Go identity service and TEST_IDENTITY_FIXTURE_FILE JSON path"]
async fn actual_go_registration_self_and_rotation() {
    let path = std::env::var("TEST_IDENTITY_FIXTURE_FILE").expect("test fixture path required");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(path).expect("read disposable fixture"));
    let fixture: Fixture = serde_json::from_slice(&bytes).expect("valid disposable fixture");
    let client = IdentityClient::new(
        &std::env::var("TEST_IDENTITY_BASE_URL").expect("loopback test URL"),
        true,
        Duration::from_secs(10),
    )
    .unwrap();
    let mut session = IdentitySession::load(
        client.clone(),
        fixture.application_id.clone(),
        Arc::new(MemoryIdentityStore::default()),
    )
    .await
    .unwrap();
    let registration = RegistrationRequest {
        application_id: fixture.application_id,
        platform: Platform::Linux,
        installation_public_key: "integration-test-installation-key".into(),
        registration_grant: SecretString::new(fixture.registration_grant),
        sdk_version: "0.1.0-integration".into(),
        metadata: Default::default(),
    };
    let register_key = IdempotencyKey::random();
    let registered = client.register(&registration, &register_key).await.unwrap();
    let replay = client.register(&registration, &register_key).await.unwrap();
    assert_eq!(registered.device_id, replay.device_id);
    assert!(registered.device_credential.expose() == replay.device_credential.expose());
    session.register(registration, register_key).await.unwrap();
    let before = session.device_self().await.unwrap();
    let old = session.identity().unwrap().device_credential.clone();
    session.refresh(IdempotencyKey::random()).await.unwrap();
    let after = session.device_self().await.unwrap();
    assert_eq!(before.device_id, after.device_id);
    assert_eq!(before.application_id, after.application_id);
    assert!(old.expose() != session.identity().unwrap().device_credential.expose());
    assert!(!session.needs_persistence());
}
