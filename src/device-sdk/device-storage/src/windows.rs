//! Windows CurrentUser DPAPI + protected SID DACL + same-volume encrypted snapshots.
//! No plaintext/MemoryIdentityStore fallback. Same-user malicious processes are not isolated.
use crate::{IdentityScope, IdentityStore, SecretString, Snapshot, StorageError, StoredIdentity};
use async_trait::async_trait;
use device_storage_windows::{ProtectedDirectory, protect, unprotect};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use zeroize::{Zeroize, Zeroizing};
static OPERATIONS: OnceLock<Arc<Semaphore>> = OnceLock::new();
const MAX_SNAPSHOT: usize = 64 * 1024;

/// Windows native only. The final directory is created with a protected DACL granting
/// only the current process token's user SID full access. Existing weaker ACLs are rejected.
///
/// All processes must use the same directory. Only absolute local NTFS drive paths are
/// supported; every reparse-point ancestor/leaf is rejected. Parent directories must exist.
/// Cancellation does not kill a DPAPI/Win32 call: an accepted transaction keeps its OS
/// lock until completion. Lock contention is bounded to two seconds; kernel/profile I/O
/// is not safely interruptible. Runtime owners must not claim hard-deadline OS shutdown.
#[derive(Clone)]
pub struct WindowsDpapiStore {
    directory: Arc<PathBuf>,
}
impl WindowsDpapiStore {
    pub fn new(directory: PathBuf) -> Result<Self, StorageError> {
        if !directory.is_absolute() {
            return Err(StorageError::Unavailable);
        }
        Ok(Self {
            directory: Arc::new(directory),
        })
    }
    async fn run(
        &self,
        scope: &IdentityScope,
        mutation: Option<(u64, Option<StoredIdentity>)>,
    ) -> Result<Snapshot, StorageError> {
        let hash = scope_hash(scope)?;
        let permit = OPERATIONS
            .get_or_init(|| Arc::new(Semaphore::new(16)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| StorageError::Unavailable)?;
        let directory = self.directory.clone();
        // No timeout pretending to stop an in-flight OS operation. A cancelled caller
        // leaves this bounded-concurrency worker alive until its atomic transaction ends.
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            transaction(&directory, &hash, mutation)
        })
        .await
        .map_err(|_| StorageError::Unavailable)?
    }
}
#[async_trait]
impl IdentityStore for WindowsDpapiStore {
    async fn load(&self, scope: &IdentityScope) -> Result<Snapshot, StorageError> {
        self.run(scope, None).await
    }
    async fn save(
        &self,
        scope: &IdentityScope,
        expected_revision: u64,
        identity: StoredIdentity,
    ) -> Result<u64, StorageError> {
        Ok(self
            .run(scope, Some((expected_revision, Some(identity))))
            .await?
            .revision)
    }
    async fn delete(
        &self,
        scope: &IdentityScope,
        expected_revision: u64,
    ) -> Result<u64, StorageError> {
        Ok(self
            .run(scope, Some((expected_revision, None)))
            .await?
            .revision)
    }
}
fn scope_hash(scope: &IdentityScope) -> Result<String, StorageError> {
    if scope.server_origin.is_empty()
        || scope.server_origin.len() > 2048
        || scope.application_id.is_empty()
        || scope.application_id.len() > 128
    {
        return Err(StorageError::Unavailable);
    }
    let mut digest = Sha256::new();
    digest.update(b"peerloom-windows-scope-v1\0");
    for value in [&scope.server_origin, &scope.application_id] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn transaction(
    path: &std::path::Path,
    hash: &str,
    mutation: Option<(u64, Option<StoredIdentity>)>,
) -> Result<Snapshot, StorageError> {
    transaction_inner(path, hash, mutation, || {})
}
// Private injection point is callable only inside this module's unit tests. The
// production entry always supplies a no-op; no environment-controlled crash hook.
fn transaction_inner(
    path: &std::path::Path,
    hash: &str,
    mutation: Option<(u64, Option<StoredIdentity>)>,
    before_journal_clear: impl FnOnce(),
) -> Result<Snapshot, StorageError> {
    let directory = ProtectedDirectory::open(path).map_err(|_| StorageError::Unavailable)?;
    let mut lock = directory
        .open_lock(&format!("{hash}.lock"))
        .map_err(|_| StorageError::Unavailable)?;
    let started = Instant::now();
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock)
                if started.elapsed() < Duration::from_secs(2) =>
            {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(_) => return Err(StorageError::Unavailable),
        }
    }
    let mut marker = [0; 2];
    let count = lock
        .read(&mut marker)
        .map_err(|_| StorageError::Unavailable)?;
    if count != 0 && (count != 1 || marker[0] != b'0') {
        return Err(StorageError::Unavailable);
    }
    let ciphertext = directory
        .read(&format!("{hash}.bin"))
        .map_err(|_| StorageError::Unavailable)?;
    let current = match ciphertext {
        Some(bytes) => decode(
            &unprotect(&bytes, hash.as_bytes()).map_err(|_| StorageError::Unavailable)?,
            hash,
        )?,
        None if count == 0 => Snapshot::default(),
        None => return Err(StorageError::Unavailable),
    };
    let Some((expected, identity)) = mutation else {
        return Ok(current);
    };
    if current.revision != expected {
        return Err(StorageError::Conflict);
    }
    let next = Snapshot {
        revision: expected
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow)?,
        identity,
    };
    let plaintext = encode(&next, hash)?;
    let ciphertext = protect(&plaintext, hash.as_bytes()).map_err(|_| StorageError::Unavailable)?;
    journal(&mut lock, true)?;
    directory
        .replace(&format!("{hash}.bin"), &ciphertext)
        .map_err(|_| StorageError::Unavailable)?;
    before_journal_clear();
    journal(&mut lock, false)?;
    Ok(next)
}
fn journal(file: &mut File, pending: bool) -> Result<(), StorageError> {
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(if pending { b"1" } else { b"0" }))
        .and_then(|()| file.set_len(1))
        .and_then(|()| file.sync_all())
        .map_err(|_| StorageError::Unavailable)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskSnapshot {
    version: u32,
    scope: String,
    revision: u64,
    identity: Option<DiskIdentity>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskIdentity {
    device_id: String,
    device_credential: String,
    expires_at: String,
}
impl Drop for DiskIdentity {
    fn drop(&mut self) {
        self.device_credential.zeroize();
    }
}
fn encode(snapshot: &Snapshot, hash: &str) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let wire = DiskSnapshot {
        version: 1,
        scope: hash.into(),
        revision: snapshot.revision,
        identity: snapshot.identity.as_ref().map(|i| DiskIdentity {
            device_id: i.device_id.clone(),
            device_credential: i.device_credential.expose().to_owned(),
            expires_at: i.expires_at.clone(),
        }),
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&wire).map_err(|_| StorageError::Unavailable)?);
    if bytes.len() > MAX_SNAPSHOT {
        return Err(StorageError::Unavailable);
    }
    Ok(bytes)
}
fn decode(bytes: &[u8], hash: &str) -> Result<Snapshot, StorageError> {
    if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT {
        return Err(StorageError::Unavailable);
    }
    let wire: DiskSnapshot =
        serde_json::from_slice(bytes).map_err(|_| StorageError::Unavailable)?;
    if wire.version != 1 || wire.revision == 0 || wire.scope != hash {
        return Err(StorageError::Unavailable);
    }
    Ok(Snapshot {
        revision: wire.revision,
        identity: wire.identity.map(|mut i| StoredIdentity {
            device_id: std::mem::take(&mut i.device_id),
            device_credential: SecretString::new(std::mem::take(&mut i.device_credential)),
            expires_at: std::mem::take(&mut i.expires_at),
        }),
    })
}

#[cfg(test)]
#[path = "../tests/support/fixture_directory.rs"]
mod test_fixture_directory;

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> IdentityScope {
        IdentityScope {
            server_origin: "https://crash.example.invalid".into(),
            application_id: "crash-test".into(),
        }
    }
    fn identity(value: &str) -> StoredIdentity {
        StoredIdentity {
            device_id: "crash-device".into(),
            device_credential: SecretString::new(value.into()),
            expires_at: "2030-01-01T00:00:00Z".into(),
        }
    }
    #[test]
    fn crash_after_replace_child() {
        let Some(path) = std::env::var_os("PEERLOOM_DPAPI_CRASH_CHILD_PATH") else {
            return;
        };
        let path = PathBuf::from(path);
        let hash = scope_hash(&scope()).unwrap();
        transaction_inner(
            &path,
            &hash,
            Some((1, Some(identity("new-synthetic-secret")))),
            || std::process::exit(79),
        )
        .unwrap();
        panic!("crashpoint did not execute");
    }
    #[test]
    fn committed_replace_before_journal_clear_crash_stays_fail_closed() {
        let root = test_fixture_directory::new_directory().unwrap();
        let path = root.join("private");
        let hash = scope_hash(&scope()).unwrap();
        transaction(
            &path,
            &hash,
            Some((0, Some(identity("old-synthetic-secret")))),
        )
        .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::tests::crash_after_replace_child",
                "--nocapture",
            ])
            .env("PEERLOOM_DPAPI_CRASH_CHILD_PATH", &path)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(79));
        assert!(matches!(
            transaction(&path, &hash, None),
            Err(StorageError::Unavailable)
        ));
        assert!(matches!(
            transaction(&path, &hash, Some((0, Some(identity("must-not-reset"))))),
            Err(StorageError::Unavailable)
        ));
        let directory = ProtectedDirectory::open(&path).unwrap();
        let ciphertext = directory.read(&format!("{hash}.bin")).unwrap().unwrap();
        let snapshot = decode(&unprotect(&ciphertext, hash.as_bytes()).unwrap(), &hash).unwrap();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(
            snapshot.identity.unwrap().device_credential.expose(),
            "new-synthetic-secret"
        );
        assert_eq!(
            std::fs::read(path.join(format!("{hash}.lock"))).unwrap(),
            b"1"
        );
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }
}
