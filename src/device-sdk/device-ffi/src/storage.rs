use crate::state::*;
use async_trait::async_trait;
use device_storage::{
    IdentityScope, IdentityStore, SecretString, Snapshot, StorageError, StoredIdentity,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    sync::{Arc, Weak},
    time::Duration,
};

pub struct ExternalStore(pub Weak<Instance>);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    revision: u64,
    #[serde(default)]
    identity: Option<Identity>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device_id: String,
    device_credential: String,
    expires_at: String,
}
struct Pending {
    instance: Arc<Instance>,
    id: u64,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.instance.storage.lock() {
            pending.remove(&self.id);
        }
    }
}
impl ExternalStore {
    async fn call(
        &self,
        scope: &IdentityScope,
        kind: &str,
        expected: Option<u64>,
        identity: Option<StoredIdentity>,
    ) -> Result<Reply, StorageError> {
        if expected == Some(u64::MAX) {
            return Err(StorageError::RevisionOverflow);
        }
        let instance = self.0.upgrade().ok_or(StorageError::Unavailable)?;
        let id = next_id().map_err(|_| StorageError::Unavailable)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut pending = instance
                .storage
                .lock()
                .map_err(|_| StorageError::Unavailable)?;
            if pending.len() >= 8 {
                return Err(StorageError::Unavailable);
            }
            pending.insert(id, tx);
        }
        let _pending = Pending {
            instance: instance.clone(),
            id,
        };
        let payload = json!({
            "operation": kind,
            "scope": {
                "server_origin": scope.server_origin,
                "application_id": scope.application_id,
            },
            "expected_revision": expected,
            "identity": identity.as_ref().map(|identity| json!({
                "device_id": identity.device_id,
                "device_credential": identity.device_credential.expose(),
                "expires_at": identity.expires_at,
            })),
        });
        if !instance.emit(Event::new(
            STORAGE,
            id,
            0,
            OK,
            serde_json::to_vec(&payload).map_err(|_| StorageError::Unavailable)?,
        )) {
            return Err(StorageError::Unavailable);
        }
        let result = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| StorageError::Unavailable)?
            .map_err(|_| StorageError::Unavailable)?;
        match result.status {
            OK => {}
            BUSY => return Err(StorageError::Conflict),
            _ => return Err(StorageError::Unavailable),
        }
        let reply: Reply =
            serde_json::from_slice(&result.payload).map_err(|_| StorageError::Unavailable)?;
        if let Some(expected) = expected
            && (reply.revision
                != expected
                    .checked_add(1)
                    .ok_or(StorageError::RevisionOverflow)?
                || reply.identity.is_some())
        {
            return Err(StorageError::Unavailable);
        }
        Ok(reply)
    }
}
#[async_trait]
impl IdentityStore for ExternalStore {
    async fn load(&self, scope: &IdentityScope) -> Result<Snapshot, StorageError> {
        let reply = self.call(scope, "load", None, None).await?;
        Ok(Snapshot {
            revision: reply.revision,
            identity: reply.identity.map(|i| StoredIdentity {
                device_id: i.device_id,
                device_credential: SecretString::new(i.device_credential),
                expires_at: i.expires_at,
            }),
        })
    }
    async fn save(
        &self,
        scope: &IdentityScope,
        expected_revision: u64,
        identity: StoredIdentity,
    ) -> Result<u64, StorageError> {
        Ok(self
            .call(scope, "save", Some(expected_revision), Some(identity))
            .await?
            .revision)
    }
    async fn delete(
        &self,
        scope: &IdentityScope,
        expected_revision: u64,
    ) -> Result<u64, StorageError> {
        Ok(self
            .call(scope, "delete", Some(expected_revision), None)
            .await?
            .revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize},
    };
    fn setup() -> (Arc<Instance>, std::sync::mpsc::Receiver<Event>) {
        let (commands, _) = tokio::sync::mpsc::channel(32);
        let (events, rx) = std::sync::mpsc::sync_channel(97);
        (
            Arc::new(Instance {
                commands,
                events,
                operations: Mutex::new(Default::default()),
                storage: Mutex::new(Default::default()),
                shutting: AtomicBool::new(false),
                stop: Default::default(),
                runtime_done: AtomicBool::new(false),
                callback_done: AtomicBool::new(false),
                shutdown_id: AtomicU64::new(0),
                connection_id: AtomicU64::new(0),
                connection_validity: Mutex::new(None),
                closing_connection: AtomicU64::new(0),
                data_count: AtomicUsize::new(0),
                control_count: AtomicUsize::new(0),
                threads: Mutex::new(Vec::new()),
            }),
            rx,
        )
    }
    fn scope() -> IdentityScope {
        IdentityScope {
            server_origin: "https://example.test/".into(),
            application_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        }
    }
    fn identity() -> StoredIdentity {
        StoredIdentity {
            device_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            device_credential: SecretString::new("dev_example_not_logged".into()),
            expires_at: "2030-01-01T00:00:00Z".into(),
        }
    }
    async fn event(rx: &std::sync::mpsc::Receiver<Event>) -> Event {
        for _ in 0..1000 {
            if let Ok(e) = rx.try_recv() {
                return e;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        panic!("storage event deadline");
    }
    fn reply(instance: &Instance, event: &Event, status: u32, json: &str) {
        instance
            .storage
            .lock()
            .unwrap()
            .remove(&event.request)
            .unwrap()
            .send(StorageReply {
                status,
                payload: json.as_bytes().to_vec(),
            })
            .unwrap_or_else(|_| panic!("receiver missing"));
        instance.release_credit(event);
    }
    #[tokio::test]
    async fn async_cas_load_save_delete_and_conflict() {
        let (i, rx) = setup();
        let store = Arc::new(ExternalStore(Arc::downgrade(&i)));
        let s = store.clone();
        let t = tokio::spawn(async move { s.load(&scope()).await });
        let e = event(&rx).await;
        let body: serde_json::Value = serde_json::from_slice(&e.payload).unwrap();
        assert_eq!(body["operation"], "load");
        assert_eq!(body["scope"]["application_id"], scope().application_id);
        reply(&i, &e, OK, r#"{"revision":0,"identity":null}"#);
        assert_eq!(t.await.unwrap().unwrap().revision, 0);
        let s = store.clone();
        let t = tokio::spawn(async move { s.save(&scope(), 0, identity()).await });
        let e = event(&rx).await;
        let body: serde_json::Value = serde_json::from_slice(&e.payload).unwrap();
        assert_eq!(body["operation"], "save");
        assert_eq!(body["expected_revision"], 0);
        reply(&i, &e, OK, r#"{"revision":1}"#);
        assert_eq!(t.await.unwrap(), Ok(1));
        let s = store.clone();
        let t = tokio::spawn(async move { s.delete(&scope(), 1).await });
        let e = event(&rx).await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&e.payload).unwrap()["operation"],
            "delete"
        );
        reply(&i, &e, OK, r#"{"revision":2}"#);
        assert_eq!(t.await.unwrap(), Ok(2));
        let s = store.clone();
        let t = tokio::spawn(async move { s.save(&scope(), 0, identity()).await });
        let e = event(&rx).await;
        reply(&i, &e, BUSY, "{}");
        assert_eq!(t.await.unwrap(), Err(StorageError::Conflict));
    }
    #[tokio::test]
    async fn revision_must_be_exact_cas_successor() {
        for revision in [0, 1, 3, u64::MAX] {
            let (i, rx) = setup();
            let store = ExternalStore(Arc::downgrade(&i));
            let t = tokio::spawn(async move { store.delete(&scope(), 1).await });
            let e = event(&rx).await;
            reply(&i, &e, OK, &format!(r#"{{"revision":{revision}}}"#));
            assert_eq!(t.await.unwrap(), Err(StorageError::Unavailable));
        }
    }
    #[tokio::test]
    async fn overflowing_revision_is_rejected_before_host_mutation() {
        let (instance, events) = setup();
        let store = ExternalStore(Arc::downgrade(&instance));
        assert_eq!(
            store.delete(&scope(), u64::MAX).await,
            Err(StorageError::RevisionOverflow)
        );
        assert!(events.try_recv().is_err());
        assert!(instance.storage.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn cancelled_external_wait_does_not_retain_reply_slot() {
        let (i, rx) = setup();
        let store = ExternalStore(Arc::downgrade(&i));
        let t = tokio::spawn(async move { store.save(&scope(), 0, identity()).await });
        let e = event(&rx).await;
        assert!(i.storage.lock().unwrap().contains_key(&e.request));
        t.abort();
        let _ = t.await;
        assert!(!i.storage.lock().unwrap().contains_key(&e.request));
        // The host may already have atomically committed: dropping this wait does not roll it back.
        i.release_credit(&e);
    }
}
