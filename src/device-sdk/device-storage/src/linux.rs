//! Linux Secret Service 适配：只使用已解锁的 default collection，不执行 Prompt/Unlock。
//! 系统服务之外仅存 0600 锁/不确定提交标记，不存身份或凭证。
use crate::{IdentityScope, IdentityStore, SecretString, Snapshot, StorageError, StoredIdentity};
use async_trait::async_trait;
use nix::{
    fcntl::{OFlag, open, openat},
    sys::stat::{Mode, mkdirat},
    unistd::geteuid,
};
use secret_service::{EncryptionType, SecretService};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    future::Future,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use zbus::{
    Connection, Proxy,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "org.freedesktop.secrets";
const ROOT: &str = "/org/freedesktop/secrets";
const CONTENT_TYPE: &str = "application/vnd.peerloom.identity+json";
const IPC_TIMEOUT: Duration = Duration::from_secs(3);
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SNAPSHOT: usize = 64 * 1024;

/// 所有访问同一用户 Secret Service 的 Peerloom 进程必须传入相同绝对锁目录。
/// 最后一级目录自动以 0700 创建；父目录必须已存在，路径不允许 symlink/`..`。
/// 不可把锁目录放入网络文件系统。不同目录的实例之间不承诺 CAS。
///
/// 调用者取消不取消内部有界事务；已开始的 SetSecret 可完整提交。
/// IPC 超时或进程崩溃留下 pending 标记时，后续操作失败关闭，不能删锁自动恢复。
/// 应停止所有写入者并由应用进行显式修复；此版本不猜测远端提交状态。
#[derive(Clone)]
pub struct LinuxSecretServiceStore {
    directory: Arc<PathBuf>,
    operations: Arc<Semaphore>,
}
impl LinuxSecretServiceStore {
    pub fn new(lock_directory: PathBuf) -> Result<Self, StorageError> {
        if !lock_directory.is_absolute()
            || !lock_directory
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            || lock_directory == Path::new("/")
        {
            return Err(StorageError::Unavailable);
        }
        Ok(Self {
            directory: Arc::new(lock_directory),
            operations: Arc::new(Semaphore::new(16)),
        })
    }
    async fn run(
        &self,
        scope: &IdentityScope,
        mutation: Option<(u64, Option<StoredIdentity>)>,
    ) -> Result<Snapshot, StorageError> {
        let hash = scope_hash(scope)?;
        let permit = self
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| StorageError::Unavailable)?;
        let directory = self.directory.clone();
        // The detached-on-caller-cancellation task is bounded; it retains the OS lock
        // until acknowledgement or fail-closed pending marker. No blocking DBus calls.
        tokio::spawn(async move {
            let _permit = permit;
            let lock_hash = hash.clone();
            let lock = tokio::task::spawn_blocking(move || acquire_lock(&directory, &lock_hash))
                .await
                .map_err(|_| StorageError::Unavailable)??;
            tokio::time::timeout(TRANSACTION_TIMEOUT, transaction(lock, &hash, mutation))
                .await
                .map_err(|_| StorageError::Unavailable)?
        })
        .await
        .map_err(|_| StorageError::Unavailable)?
    }
}
#[async_trait]
impl IdentityStore for LinuxSecretServiceStore {
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
    let mut hash = Sha256::new();
    hash.update(b"peerloom-identity-scope-v1\0");
    for value in [&scope.server_origin, &scope.application_id] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
// A writable non-sticky ancestor lets another UID rename our private leaf and
// split the lock namespace. NOFOLLOW alone does not prevent that attack.
fn trusted_ancestor(uid: u32, mode: u32) -> bool {
    (uid == 0 || uid == geteuid().as_raw()) && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}
fn acquire_lock(directory: &Path, hash: &str) -> Result<File, StorageError> {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut dir = open("/", flags, Mode::empty()).map_err(|_| StorageError::Unavailable)?;
    let names: Vec<_> = directory
        .components()
        .filter_map(|c| {
            if let Component::Normal(n) = c {
                Some(n)
            } else {
                None
            }
        })
        .collect();
    for (index, name) in names.iter().enumerate() {
        let ancestor = nix::sys::stat::fstat(&dir).map_err(|_| StorageError::Unavailable)?;
        if !trusted_ancestor(ancestor.st_uid, ancestor.st_mode) {
            return Err(StorageError::Unavailable);
        }
        if index + 1 == names.len() {
            match mkdirat(&dir, *name, Mode::S_IRWXU) {
                Ok(()) | Err(nix::errno::Errno::EEXIST) => (),
                Err(_) => return Err(StorageError::Unavailable),
            }
        }
        nix::unistd::fsync(&dir).map_err(|_| StorageError::Unavailable)?;
        dir = openat(&dir, *name, flags, Mode::empty()).map_err(|_| StorageError::Unavailable)?;
    }
    let directory = File::from(dir);
    let metadata = directory
        .metadata()
        .map_err(|_| StorageError::Unavailable)?;
    if metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o777 != 0o700 {
        return Err(StorageError::Unavailable);
    }
    let lock = openat(
        &directory,
        format!("{hash}.lock").as_str(),
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|_| StorageError::Unavailable)?;
    directory
        .sync_all()
        .map_err(|_| StorageError::Unavailable)?;
    let mut lock = File::from(lock);
    let metadata = lock.metadata().map_err(|_| StorageError::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(StorageError::Unavailable);
    }
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
    Ok(lock)
}
async fn journal(lock: &File, pending: bool) -> Result<(), StorageError> {
    let mut file = lock.try_clone().map_err(|_| StorageError::Unavailable)?;
    tokio::task::spawn_blocking(move || {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(if pending { b"1" } else { b"0" })?;
        file.set_len(1)?;
        file.sync_all()
    })
    .await
    .map_err(|_| StorageError::Unavailable)?
    .map_err(|_| StorageError::Unavailable)
}
async fn bounded<T, E>(future: impl Future<Output = Result<T, E>>) -> Result<T, StorageError> {
    tokio::time::timeout(IPC_TIMEOUT, future)
        .await
        .map_err(|_| StorageError::Unavailable)?
        .map_err(|_| StorageError::Unavailable)
}
async fn transaction(
    lock: File,
    hash: &str,
    mutation: Option<(u64, Option<StoredIdentity>)>,
) -> Result<Snapshot, StorageError> {
    let connection = bounded(
        zbus::connection::Builder::session()
            .map_err(|_| StorageError::Unavailable)?
            .method_timeout(IPC_TIMEOUT)
            .build(),
    )
    .await?;
    let service = bounded(SecretService::connect_with_existing(
        EncryptionType::Dh,
        connection.clone(),
    ))
    .await?;
    let collection = bounded(service.get_default_collection()).await?;
    if bounded(collection.is_locked()).await? {
        return Err(StorageError::Unavailable);
    }
    let attributes = HashMap::from([("peerloom.scope.v1", hash)]);
    let mut items = bounded(collection.search_items(attributes.clone())).await?;
    if items.len() > 1 {
        return Err(StorageError::Unavailable);
    }
    let had_committed = lock
        .metadata()
        .map_err(|_| StorageError::Unavailable)?
        .len()
        != 0;
    if items.is_empty() && had_committed {
        return Err(StorageError::Unavailable);
    }
    let current = if let Some(item) = items.first() {
        if bounded(item.is_locked()).await? {
            return Err(StorageError::Unavailable);
        }
        let bytes = Zeroizing::new(bounded(item.get_secret()).await?);
        if bytes.is_empty() && had_committed {
            return Err(StorageError::Unavailable);
        }
        decode(&bytes)?
    } else {
        Snapshot::default()
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
    let bytes = encode(&next)?;
    // Fail-closed marker also covers create timeout: never race a delayed initial
    // CreateItem against another writer and silently select a duplicate item.
    journal(&lock, true).await?;
    if items.is_empty() {
        create_empty_without_prompt(&connection, &collection.collection_path, attributes.clone())
            .await?;
        items = bounded(collection.search_items(attributes)).await?;
        if items.len() != 1 {
            return Err(StorageError::Unavailable);
        }
    }
    let item = items.first().ok_or(StorageError::Unavailable)?;
    if bounded(item.is_locked()).await? {
        return Err(StorageError::Unavailable);
    }
    bounded(item.set_secret(&bytes, CONTENT_TYPE)).await?;
    journal(&lock, false).await?;
    Ok(next)
}
/// Only empty bytes use the plain session; real credentials always use library DH.
/// Reject returned prompts without invoking Prompt, Unlock or UI interaction.
async fn create_empty_without_prompt(
    connection: &Connection,
    path: &OwnedObjectPath,
    attributes: HashMap<&str, &str>,
) -> Result<(), StorageError> {
    let service = bounded(Proxy::new(
        connection,
        SERVICE,
        ROOT,
        "org.freedesktop.Secret.Service",
    ))
    .await?;
    let (_, session): (OwnedValue, OwnedObjectPath) =
        bounded(service.call("OpenSession", &("plain", Value::from("")))).await?;
    let collection = bounded(Proxy::new(
        connection,
        SERVICE,
        path.as_str(),
        "org.freedesktop.Secret.Collection",
    ))
    .await?;
    let properties = HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label",
            Value::from("Peerloom identity"),
        ),
        (
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(attributes),
        ),
    ]);
    let empty_secret = (
        session.clone(),
        Vec::<u8>::new(),
        Vec::<u8>::new(),
        CONTENT_TYPE,
    );
    let (item, prompt): (OwnedObjectPath, OwnedObjectPath) =
        bounded(collection.call("CreateItem", &(properties, empty_secret, false))).await?;
    if let Ok(proxy) = bounded(Proxy::new(
        connection,
        SERVICE,
        session.as_str(),
        "org.freedesktop.Secret.Session",
    ))
    .await
    {
        let _: Result<(), _> = bounded(proxy.call("Close", &())).await;
    }
    if item.as_str() == "/" || prompt.as_str() != "/" {
        return Err(StorageError::Unavailable);
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskSnapshot {
    version: u32,
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
fn encode(snapshot: &Snapshot) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let wire = DiskSnapshot {
        version: 1,
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
fn decode(bytes: &[u8]) -> Result<Snapshot, StorageError> {
    if bytes.is_empty() {
        return Ok(Snapshot::default());
    }
    if bytes.len() > MAX_SNAPSHOT {
        return Err(StorageError::Unavailable);
    }
    let wire: DiskSnapshot =
        serde_json::from_slice(bytes).map_err(|_| StorageError::Unavailable)?;
    if wire.version != 1 || wire.revision == 0 {
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
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "peerloom-storage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
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
    #[test]
    fn opaque_scope_is_length_delimited_and_scoped() {
        let one = scope_hash(&scope()).unwrap();
        assert_eq!(one.len(), 64);
        assert!(!one.contains("app"));
        let mut other = scope();
        other.application_id.push('2');
        assert_ne!(one, scope_hash(&other).unwrap());
        assert_ne!(
            scope_hash(&IdentityScope {
                server_origin: "ab".into(),
                application_id: "c".into()
            })
            .unwrap(),
            scope_hash(&IdentityScope {
                server_origin: "a".into(),
                application_id: "bc".into()
            })
            .unwrap()
        );
    }
    #[test]
    fn codec_tombstone_and_corruption_fail_closed() {
        let snapshot = Snapshot {
            revision: 4,
            identity: Some(StoredIdentity {
                device_id: "id".into(),
                device_credential: SecretString::new("secret".into()),
                expires_at: "later".into(),
            }),
        };
        let decoded = decode(&encode(&snapshot).unwrap()).unwrap();
        assert_eq!(decoded.revision, 4);
        assert_eq!(
            decoded.identity.unwrap().device_credential.expose(),
            "secret"
        );
        assert_eq!(
            decode(
                &encode(&Snapshot {
                    revision: 5,
                    identity: None
                })
                .unwrap()
            )
            .unwrap()
            .revision,
            5
        );
        assert!(decode(b"not-json").is_err());
        assert!(decode(br#"{"version":2,"revision":1,"identity":null}"#).is_err());
        assert!(decode(br#"{"version":1,"revision":0,"identity":null}"#).is_err());
        assert!(decode(&vec![0; MAX_SNAPSHOT + 1]).is_err());
        assert_eq!(decode(&[]).unwrap().revision, 0);
    }
    #[test]
    fn private_lock_rejects_symlinks_permissions_and_hardlinks() {
        let root = Directory::new();
        let directory = root.0.join("locks");
        drop(acquire_lock(&directory, "scope").unwrap());
        let link = root.0.join("symlink");
        symlink(&directory, &link).unwrap();
        assert!(acquire_lock(&link, "scope").is_err());
        let nested = link.join("child");
        assert!(acquire_lock(&nested, "scope").is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(acquire_lock(&directory, "scope").is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::hard_link(directory.join("scope.lock"), directory.join("other.lock")).unwrap();
        assert!(acquire_lock(&directory, "scope").is_err());
        symlink(directory.join("scope.lock"), directory.join("alias.lock")).unwrap();
        assert!(acquire_lock(&directory, "alias").is_err());
        assert!(LinuxSecretServiceStore::new(root.0.join("../escape")).is_err());
    }
    #[test]
    fn writable_ancestor_cannot_split_lock_namespace() {
        let root = Directory::new();
        let parent = root.0.join("ancestor");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(acquire_lock(&parent.join("private"), "scope").is_err());
        assert!(!parent.join("private").exists());
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(acquire_lock(&parent.join("private"), "scope").is_ok());
        assert!(trusted_ancestor(0, 0o1777));
        assert!(!trusted_ancestor(0, 0o0777));
        assert!(!trusted_ancestor(
            geteuid().as_raw().saturating_add(1),
            0o1777
        ));
    }
    #[tokio::test]
    async fn uncertain_commit_marker_survives_restart_without_secret() {
        let root = Directory::new();
        let directory = root.0.join("locks");
        let lock = acquire_lock(&directory, "scope").unwrap();
        journal(&lock, true).await.unwrap();
        drop(lock);
        assert!(acquire_lock(&directory, "scope").is_err());
        assert_eq!(std::fs::read(directory.join("scope.lock")).unwrap(), b"1");
    }
    #[tokio::test]
    async fn acknowledged_marker_reopens_and_lock_contention_is_bounded() {
        let root = Directory::new();
        let directory = root.0.join("locks");
        let lock = acquire_lock(&directory, "scope").unwrap();
        journal(&lock, true).await.unwrap();
        journal(&lock, false).await.unwrap();
        let start = Instant::now();
        assert!(acquire_lock(&directory, "scope").is_err());
        assert!(start.elapsed() < Duration::from_secs(4));
        drop(lock);
        assert!(acquire_lock(&directory, "scope").is_ok());
    }
}
