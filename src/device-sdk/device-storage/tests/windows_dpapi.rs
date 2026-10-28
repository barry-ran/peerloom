//! Real Windows user-profile DPAPI and filesystem tests. No Wine/mocks.
#![cfg(target_os = "windows")]
use device_storage::{
    IdentityScope, IdentityStore, SecretString, StorageError, StoredIdentity, WindowsDpapiStore,
};
use std::{path::PathBuf, process::Command, time::Duration};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(format!("peerloom-dpapi-{suffix}"));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("private")
    }
    fn store(&self) -> WindowsDpapiStore {
        WindowsDpapiStore::new(self.path()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn scope() -> IdentityScope {
    IdentityScope {
        server_origin: "https://example.invalid".into(),
        application_id: "app".into(),
    }
}
fn identity() -> StoredIdentity {
    StoredIdentity {
        device_id: "device-test".into(),
        device_credential: SecretString::new(
            "dev_windows_synthetic_credential_not_plaintext".into(),
        ),
        expires_at: "2030-01-01T00:00:00Z".into(),
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn child(mode: &str, path: &std::path::Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "windows_child", "--nocapture"])
        .env("PEERLOOM_WINDOWS_TEST_MODE", mode)
        .env("PEERLOOM_WINDOWS_TEST_DIR", path);
    command
}
#[test]
fn windows_child() {
    let Ok(mode) = std::env::var("PEERLOOM_WINDOWS_TEST_MODE") else {
        return;
    };
    let store = WindowsDpapiStore::new(
        std::env::var_os("PEERLOOM_WINDOWS_TEST_DIR")
            .unwrap()
            .into(),
    )
    .unwrap();
    runtime().block_on(async {
        if mode == "read" {
            let loaded = store.load(&scope()).await.unwrap();
            assert_eq!(loaded.revision, 1);
            assert_eq!(
                loaded.identity.unwrap().device_credential.expose(),
                identity().device_credential.expose()
            );
        } else if mode == "race" {
            match store.save(&scope(), 1, identity()).await {
                Ok(2) => (),
                Err(StorageError::Conflict) => std::process::exit(2),
                other => panic!("unexpected CAS result {other:?}"),
            }
        } else {
            panic!("unknown test mode");
        }
    });
}
#[test]
fn restart_cross_process_cas_and_tombstone() {
    let fixture = Fixture::new();
    runtime().block_on(async {
        assert_eq!(
            fixture.store().save(&scope(), 0, identity()).await.unwrap(),
            1
        );
    });
    assert!(child("read", &fixture.path()).status().unwrap().success());
    let mut a = child("race", &fixture.path()).spawn().unwrap();
    let mut b = child("race", &fixture.path()).spawn().unwrap();
    let codes = (a.wait().unwrap().code(), b.wait().unwrap().code());
    assert!(matches!(codes, (Some(0), Some(2)) | (Some(2), Some(0))));
    runtime().block_on(async {
        let store = fixture.store();
        assert_eq!(store.delete(&scope(), 2).await.unwrap(), 3);
        assert!(store.load(&scope()).await.unwrap().identity.is_none());
        assert_eq!(
            store.save(&scope(), 0, identity()).await,
            Err(StorageError::Conflict)
        );
    });
    for entry in std::fs::read_dir(fixture.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let secret = identity();
        let secret = secret.device_credential.expose().as_bytes();
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
    }
}
#[tokio::test]
async fn cancellation_after_admission_finishes_atomic_transaction() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store.save(&scope(), 0, identity()).await.unwrap();
    let lock = std::fs::read_dir(fixture.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "lock"))
        .unwrap();
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock)
        .unwrap();
    held.lock().unwrap();
    let writer = store.clone();
    let (admitted_tx, admitted_rx) = tokio::sync::oneshot::channel();
    let pending = tokio::spawn(async move {
        let scope = scope();
        let mut operation = Box::pin(writer.save(&scope, 1, identity()));
        let mut signal = Some(admitted_tx);
        std::future::poll_fn(|context| {
            // First poll reaches the spawn_blocking acceptance point. Dropping its
            // JoinHandle detaches, rather than aborting, even if the worker is queued.
            let result = std::future::Future::poll(operation.as_mut(), context);
            if let Some(signal) = signal.take() {
                let _ = signal.send(());
            }
            result
        })
        .await
    });
    admitted_rx.await.unwrap();
    assert!(!pending.is_finished());
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    drop(held);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let loaded = store.load(&scope()).await.unwrap();
        if loaded.revision == 2 {
            break;
        }
        assert_eq!(loaded.revision, 1);
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
#[tokio::test]
async fn scope_copy_corruption_missing_blob_and_pending_fail_closed() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store.save(&scope(), 0, identity()).await.unwrap();
    let original = std::fs::read_dir(fixture.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "bin"))
        .unwrap();
    let bytes = std::fs::read(&original).unwrap();
    let mut other_scope = scope();
    other_scope.application_id = "other-app".into();
    store.save(&other_scope, 0, identity()).await.unwrap();
    let other = std::fs::read_dir(fixture.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "bin") && p != &original)
        .unwrap();
    std::fs::write(&other, &bytes).unwrap();
    assert!(matches!(
        store.load(&other_scope).await,
        Err(StorageError::Unavailable)
    ));
    let mut corrupt = bytes;
    let end = corrupt.len() - 1;
    corrupt[end] ^= 1;
    std::fs::write(&original, corrupt).unwrap();
    assert!(matches!(
        store.load(&scope()).await,
        Err(StorageError::Unavailable)
    ));
    std::fs::remove_file(&original).unwrap();
    assert!(matches!(
        store.load(&scope()).await,
        Err(StorageError::Unavailable)
    ));
    let lock = original.with_extension("lock");
    std::fs::write(lock, b"1").unwrap();
    assert!(matches!(
        store.load(&scope()).await,
        Err(StorageError::Unavailable)
    ));
}
