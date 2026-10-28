//! 身份存储接口；显式内存、Linux Secret Service 及 Windows DPAPI 适配器。
//! 系统服务不可用时不回退明文文件或内存；平台运行验证见对应必需 CI。
//! 自定义适配器应使用系统安全设施，并保证 CAS 更新、取消期间的原子性和不记录秘密。
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxSecretServiceStore;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsDpapiStore;

use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

/// 隐藏 Debug 的敏感字符串。只清理此包装器持有的内存，不保证 HTTP 库副本也被清理。
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    /// 仅在必要的认证或安全存储边界暴露；不得写入日志。
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}
impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityScope {
    pub server_origin: String,
    pub application_id: String,
}

#[derive(Debug, Clone)]
pub struct StoredIdentity {
    pub device_id: String,
    pub device_credential: SecretString,
    pub expires_at: String,
}

#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    /// 删除仍递增 revision，避免 ABA；0 表示从未写入。
    pub revision: u64,
    pub identity: Option<StoredIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    Conflict,
    Unavailable,
    RevisionOverflow,
}
impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for StorageError {}

/// 接口只定义契约，不证明实现使用了加密或系统安全存储。
/// 不得同步阻塞网络执行器。save/delete 必须原子比较 revision 后更新。
/// Future 被取消时，状态只能是完整旧值或完整新值，不得部分写入。
// async-trait 0.1.89 generates redundant must_use on Rust 1.99 futures.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn load(&self, scope: &IdentityScope) -> Result<Snapshot, StorageError>;
    async fn save(
        &self,
        scope: &IdentityScope,
        expected_revision: u64,
        identity: StoredIdentity,
    ) -> Result<u64, StorageError>;
    async fn delete(
        &self,
        scope: &IdentityScope,
        expected_revision: u64,
    ) -> Result<u64, StorageError>;
}

/// 进程退出后身份丢失；调用者显式选择，不能用于声称重启身份已持久化。
#[derive(Default)]
pub struct MemoryIdentityStore {
    values: Mutex<HashMap<IdentityScope, Snapshot>>,
}

#[async_trait]
impl IdentityStore for MemoryIdentityStore {
    async fn load(&self, scope: &IdentityScope) -> Result<Snapshot, StorageError> {
        Ok(self
            .values
            .lock()
            .await
            .get(scope)
            .cloned()
            .unwrap_or_default())
    }
    async fn save(
        &self,
        scope: &IdentityScope,
        expected_revision: u64,
        identity: StoredIdentity,
    ) -> Result<u64, StorageError> {
        self.update(scope, expected_revision, Some(identity)).await
    }
    async fn delete(
        &self,
        scope: &IdentityScope,
        expected_revision: u64,
    ) -> Result<u64, StorageError> {
        self.update(scope, expected_revision, None).await
    }
}
impl MemoryIdentityStore {
    async fn update(
        &self,
        scope: &IdentityScope,
        expected_revision: u64,
        identity: Option<StoredIdentity>,
    ) -> Result<u64, StorageError> {
        let mut values = self.values.lock().await;
        let entry = values.entry(scope.clone()).or_default();
        if entry.revision != expected_revision {
            return Err(StorageError::Conflict);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow)?;
        *entry = Snapshot { revision, identity };
        Ok(revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> StoredIdentity {
        StoredIdentity {
            device_id: "id".into(),
            device_credential: SecretString::new("secret".into()),
            expires_at: "later".into(),
        }
    }
    fn scope() -> IdentityScope {
        IdentityScope {
            server_origin: "https://example.invalid".into(),
            application_id: "app".into(),
        }
    }
    #[tokio::test]
    async fn atomic_update_rejects_stale_writer_and_delete_avoids_aba() {
        let store = MemoryIdentityStore::default();
        assert_eq!(store.save(&scope(), 0, identity()).await, Ok(1));
        assert_eq!(
            store.save(&scope(), 0, identity()).await,
            Err(StorageError::Conflict)
        );
        assert_eq!(store.delete(&scope(), 1).await, Ok(2));
        assert!(store.load(&scope()).await.unwrap().identity.is_none());
        assert_eq!(
            store.save(&scope(), 0, identity()).await,
            Err(StorageError::Conflict)
        );
    }
    #[tokio::test]
    async fn scopes_isolate_origins_and_applications() {
        let store = MemoryIdentityStore::default();
        store.save(&scope(), 0, identity()).await.unwrap();
        let mut other = scope();
        other.server_origin = "https://elsewhere.invalid".into();
        assert!(store.load(&other).await.unwrap().identity.is_none());
        other = scope();
        other.application_id = "different".into();
        assert!(store.load(&other).await.unwrap().identity.is_none());
    }
    #[test]
    fn debug_redacts_credential() {
        assert!(!format!("{:?}", identity()).contains("secret"));
    }
}
