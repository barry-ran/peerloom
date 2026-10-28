//! Only runs against scripts/test-secret-service.sh disposable bus/keyring.
#![cfg(target_os = "linux")]
use device_storage::{
    IdentityScope, IdentityStore, LinuxSecretServiceStore, SecretString, StorageError,
    StoredIdentity,
};
use secret_service::{EncryptionType, SecretService};
use std::{path::PathBuf, time::Duration};
fn fixture() -> (LinuxSecretServiceStore, IdentityScope) {
    assert_eq!(
        std::env::var("PEERLOOM_DISPOSABLE_KEYRING").as_deref(),
        Ok("yes"),
        "never use a real user keyring for these tests"
    );
    let dir = PathBuf::from(std::env::var("PEERLOOM_TEST_LOCK_DIR").unwrap());
    (
        LinuxSecretServiceStore::new(dir).unwrap(),
        IdentityScope {
            server_origin: "https://example.invalid".into(),
            application_id: "secret-service-integration".into(),
        },
    )
}
fn identity() -> StoredIdentity {
    StoredIdentity {
        device_id: "device-test".into(),
        device_credential: SecretString::new(
            "dev_never_write_this_credential_to_a_plain_file".into(),
        ),
        expires_at: "2030-01-01T00:00:00Z".into(),
    }
}
#[tokio::test]
#[ignore = "requires a disposable D-Bus session and unlocked test keyring"]
async fn keyring_write_cas_cancel() {
    let (store, scope) = fixture();
    assert_eq!(store.load(&scope).await.unwrap().revision, 0);
    assert_eq!(store.save(&scope, 0, identity()).await.unwrap(), 1);
    let second = fixture().0;
    let (a, b) = tokio::join!(
        store.save(&scope, 1, identity()),
        second.save(&scope, 1, identity())
    );
    assert!(matches!(
        (a, b),
        (Ok(2), Err(StorageError::Conflict)) | (Err(StorageError::Conflict), Ok(2))
    ));
    assert_eq!(store.delete(&scope, 2).await.unwrap(), 3);
    assert!(store.load(&scope).await.unwrap().identity.is_none());
    assert_eq!(
        store.save(&scope, 0, identity()).await,
        Err(StorageError::Conflict)
    );
    // Cancel while waiting for the OS lock, not after the operation already finished.
    let lock_path = std::fs::read_dir(std::env::var("PEERLOOM_TEST_LOCK_DIR").unwrap())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    held.lock().unwrap();
    let cancelled_store = store.clone();
    let cancelled_scope = scope.clone();
    let pending =
        tokio::spawn(async move { cancelled_store.save(&cancelled_scope, 3, identity()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!pending.is_finished());
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    drop(held);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let loaded = store.load(&scope).await.unwrap();
        if loaded.revision == 4 {
            break;
        }
        assert_eq!(loaded.revision, 3);
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        store
            .load(&scope)
            .await
            .unwrap()
            .identity
            .unwrap()
            .device_credential
            .expose(),
        identity().device_credential.expose()
    );
    for item in std::fs::read_dir(std::env::var("PEERLOOM_TEST_LOCK_DIR").unwrap()).unwrap() {
        assert_eq!(
            std::fs::read(item.unwrap().path()).unwrap(),
            b"0",
            "only commit markers may be on disk outside the keyring"
        );
    }
}
#[tokio::test]
#[ignore = "run in second process after keyring_write_cas_cancel"]
async fn keyring_restart_reads_same_identity() {
    let (store, scope) = fixture();
    let loaded = store.load(&scope).await.unwrap();
    assert_eq!(loaded.revision, 4);
    assert_eq!(
        loaded.identity.unwrap().device_credential.expose(),
        identity().device_credential.expose()
    );
}
#[tokio::test]
#[ignore = "locks only the disposable test collection; run after restart test"]
async fn keyring_locked_fails_without_unlock_or_prompt() {
    let (store, scope) = fixture();
    let service = SecretService::connect(EncryptionType::Dh).await.unwrap();
    let collection = service.get_default_collection().await.unwrap();
    collection.lock().await.unwrap();
    assert!(collection.is_locked().await.unwrap());
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), store.load(&scope))
            .await
            .unwrap(),
        Err(StorageError::Unavailable)
    ));
    assert_eq!(
        store.save(&scope, 4, identity()).await,
        Err(StorageError::Unavailable)
    );
    assert!(
        collection.is_locked().await.unwrap(),
        "adapter must not unlock the collection"
    );
}
#[tokio::test]
#[ignore = "run on a disposable bus without any secret-service provider"]
async fn unavailable_service_fails_closed() {
    let (store, scope) = fixture();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(8), store.load(&scope))
            .await
            .unwrap(),
        Err(StorageError::Unavailable)
    ));
}

#[tokio::test]
#[ignore = "disposable unlocked keyring only; run after restart before lock test"]
async fn duplicate_and_missing_items_fail_closed() {
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    let (store, scope) = fixture();
    let service = SecretService::connect(EncryptionType::Dh).await.unwrap();
    let collection = service.get_default_collection().await.unwrap();
    for suffix in ["-duplicate", "-missing"] {
        let mut scoped = scope.clone();
        scoped.application_id.push_str(suffix);
        store.save(&scoped, 0, identity()).await.unwrap();
        let mut digest = Sha256::new();
        digest.update(b"peerloom-identity-scope-v1\0");
        for value in [&scoped.server_origin, &scoped.application_id] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        let hash: String = digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let attributes = HashMap::from([("peerloom.scope.v1", hash.as_str())]);
        let items = collection.search_items(attributes.clone()).await.unwrap();
        assert_eq!(items.len(), 1);
        if suffix == "-duplicate" {
            collection
                .create_item(
                    "test duplicate",
                    attributes,
                    b"invalid",
                    false,
                    "text/plain",
                )
                .await
                .unwrap();
        } else {
            items[0].delete().await.unwrap();
        }
        assert!(matches!(
            store.load(&scoped).await,
            Err(StorageError::Unavailable)
        ));
        assert_eq!(
            store.save(&scoped, 0, identity()).await,
            Err(StorageError::Unavailable)
        );
    }
}

struct HungService;
#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl HungService {
    async fn open_session(
        &self,
        _algorithm: &str,
        _input: zbus::zvariant::OwnedValue,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedValue, zbus::zvariant::OwnedObjectPath)> {
        std::future::pending().await
    }
}
#[tokio::test]
#[ignore = "disposable bus with no real keyring; deliberately hangs mock OpenSession"]
async fn hung_service_has_bounded_shutdown() {
    let (store, scope) = fixture();
    let _server = zbus::connection::Builder::session()
        .unwrap()
        .name("org.freedesktop.secrets")
        .unwrap()
        .serve_at("/org/freedesktop/secrets", HungService)
        .unwrap()
        .build()
        .await
        .unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(6), store.load(&scope))
            .await
            .unwrap(),
        Err(StorageError::Unavailable)
    ));
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "must exercise hung IPC, not fail before connecting"
    );
    assert!(started.elapsed() < Duration::from_secs(6));
}
