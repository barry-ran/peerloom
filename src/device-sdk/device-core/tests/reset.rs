use async_trait::async_trait;
use device_core::identity::{IdentityClient, IdentityError, IdentitySession};
use device_storage::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
const APP: &str = "00000000-0000-4000-8000-000000000001";
const DEVICE: &str = "00000000-0000-4000-8000-000000000002";
fn scope() -> IdentityScope {
    IdentityScope {
        server_origin: "https://reset.example.invalid/".into(),
        application_id: APP.into(),
    }
}
fn identity(id: &str) -> StoredIdentity {
    StoredIdentity {
        device_id: id.into(),
        device_credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
        expires_at: "2030-01-01T00:00:00Z".into(),
    }
}
async fn session(store: Arc<dyn IdentityStore>) -> IdentitySession {
    IdentitySession::load(
        IdentityClient::new(
            "https://reset.example.invalid",
            false,
            Duration::from_secs(1),
        )
        .unwrap(),
        APP.into(),
        store,
    )
    .await
    .unwrap()
}
#[derive(Default)]
struct FaultStore {
    memory: MemoryIdentityStore,
    mode: AtomicU8,
    deletes: AtomicUsize,
}
#[async_trait]
impl IdentityStore for FaultStore {
    async fn load(&self, scope: &IdentityScope) -> Result<Snapshot, StorageError> {
        self.memory.load(scope).await
    }
    async fn save(
        &self,
        scope: &IdentityScope,
        expected: u64,
        value: StoredIdentity,
    ) -> Result<u64, StorageError> {
        self.memory.save(scope, expected, value).await
    }
    async fn delete(&self, scope: &IdentityScope, expected: u64) -> Result<u64, StorageError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == 1 {
            return Err(StorageError::Unavailable);
        }
        let next = self.memory.delete(scope, expected).await?;
        match mode {
            2 => Err(StorageError::Unavailable),
            3 => std::future::pending().await,
            _ => Ok(next),
        }
    }
}
#[tokio::test]
async fn explicit_confirmation_tombstone_and_new_identity_scope() {
    let store = Arc::new(FaultStore::default());
    store.save(&scope(), 0, identity(DEVICE)).await.unwrap();
    let mut owner = session(store.clone()).await;
    assert_eq!(owner.reset(APP).await, Err(IdentityError::InvalidRequest));
    assert!(owner.identity().is_some());
    assert_eq!(store.deletes.load(Ordering::SeqCst), 0);
    owner.reset(DEVICE).await.unwrap();
    assert!(owner.identity().is_none());
    assert!(!owner.has_pending_reset());
    let snapshot = store.load(&scope()).await.unwrap();
    assert_eq!(snapshot.revision, 2);
    assert!(snapshot.identity.is_none());
    // Another explicit registration would save against revision2, never recreate revision0.
    let next_device = "00000000-0000-4000-8000-000000000003";
    store
        .save(&scope(), 2, identity(next_device))
        .await
        .unwrap();
    let next = session(store.clone()).await;
    assert_eq!(next.identity().unwrap().device_id, next_device);
    assert_ne!(next.identity().unwrap().device_id, DEVICE);
}
#[tokio::test]
async fn unknown_delete_retains_gate_and_retry_never_repeats_committed_delete() {
    for mode in [1, 2, 3] {
        let store = Arc::new(FaultStore::default());
        store.save(&scope(), 0, identity(DEVICE)).await.unwrap();
        let mut owner = session(store.clone()).await;
        store.mode.store(mode, Ordering::SeqCst);
        if mode == 3 {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), owner.reset(DEVICE))
                    .await
                    .is_err()
            );
        } else {
            assert_eq!(
                owner.reset(DEVICE).await,
                Err(IdentityError::Storage(StorageError::Unavailable))
            );
        }
        assert!(owner.has_pending_reset());
        assert!(owner.identity().is_none());
        assert_eq!(
            owner.reset(DEVICE).await,
            Err(IdentityError::PendingMutation)
        );
        assert_eq!(
            owner
                .refresh(device_core::identity::IdempotencyKey::random())
                .await,
            Err(IdentityError::PendingMutation)
        );
        store.mode.store(0, Ordering::SeqCst);
        owner.retry_reset().await.unwrap();
        assert!(!owner.has_pending_reset());
        assert_eq!(store.load(&scope()).await.unwrap().revision, 2);
        assert_eq!(
            store.deletes.load(Ordering::SeqCst),
            if mode == 1 { 2 } else { 1 }
        );
    }
}
#[tokio::test]
async fn concurrent_writer_and_later_tombstone_are_not_overwritten_or_claimed() {
    for later_tombstone in [false, true] {
        let store = Arc::new(FaultStore::default());
        store.save(&scope(), 0, identity(DEVICE)).await.unwrap();
        let mut owner = session(store.clone()).await;
        store.save(&scope(), 1, identity(APP)).await.unwrap();
        if later_tombstone {
            store.delete(&scope(), 2).await.unwrap();
        }
        let before = store.deletes.load(Ordering::SeqCst);
        assert_eq!(
            owner.reset(DEVICE).await,
            Err(IdentityError::Storage(StorageError::Conflict))
        );
        assert!(owner.has_pending_reset());
        assert!(owner.identity().is_none());
        assert_eq!(store.deletes.load(Ordering::SeqCst), before);
        assert_eq!(
            store.load(&scope()).await.unwrap().revision,
            if later_tombstone { 3 } else { 2 }
        );
    }
}
