//! Explicit installation reset. This deletes only the local identity, not server-side devices.
use super::{IdentityError, IdentitySession};
use device_storage::StorageError;

#[derive(Clone)]
pub(super) struct ResetPending {
    device_id: String,
    revision: u64,
}

impl IdentitySession {
    /// Call only after stopping every local connection and credential mutation owner.
    /// The exact current device ID is an explicit destructive-action confirmation.
    /// Success leaves a CAS tombstone and no identity; registration is a separate,
    /// explicit operation with a fresh key/grant. This does not revoke other instances.
    ///
    /// Cancellation or an error retains reset state in this object. Retry with
    /// `retry_reset`; never silently register while the deletion outcome is unknown.
    /// Dropping this object loses the in-memory operation journal; durable crash
    /// recovery of mutations remains a separate host responsibility.
    pub async fn reset(&mut self, expected_device_id: &str) -> Result<(), IdentityError> {
        if self.reset_pending.is_some() || self.pending.is_some() || self.dirty {
            return Err(IdentityError::PendingMutation);
        }
        let expected = uuid::Uuid::parse_str(expected_device_id)
            .map_err(|_| IdentityError::InvalidRequest)?
            .to_string();
        let current = self.identity.as_ref().ok_or(IdentityError::NoIdentity)?;
        if current.device_id != expected {
            return Err(IdentityError::InvalidRequest);
        }
        self.revision
            .checked_add(1)
            .ok_or(IdentityError::Storage(StorageError::RevisionOverflow))?;
        self.reset_pending = Some(ResetPending {
            device_id: expected,
            revision: self.revision,
        });
        // Stop exposing the old credential even if delete subsequently fails.
        self.identity = None;
        self.retry_reset().await
    }

    pub fn has_pending_reset(&self) -> bool {
        self.reset_pending.is_some()
    }

    /// Recognize only our exact next tombstone, or retry against the unchanged
    /// original snapshot. Never delete an identity installed by another CAS owner.
    pub async fn retry_reset(&mut self) -> Result<(), IdentityError> {
        let pending = self
            .reset_pending
            .clone()
            .ok_or(IdentityError::NoIdentity)?;
        let next = pending
            .revision
            .checked_add(1)
            .ok_or(IdentityError::Storage(StorageError::RevisionOverflow))?;
        let snapshot = self
            .store
            .load(&self.scope)
            .await
            .map_err(IdentityError::Storage)?;
        if snapshot.revision == next && snapshot.identity.is_none() {
            self.revision = next;
            self.reset_pending = None;
            return Ok(());
        }
        if snapshot.revision != pending.revision
            || snapshot
                .identity
                .as_ref()
                .is_none_or(|identity| identity.device_id != pending.device_id)
        {
            return Err(IdentityError::Storage(StorageError::Conflict));
        }
        let revision = self
            .store
            .delete(&self.scope, pending.revision)
            .await
            .map_err(IdentityError::Storage)?;
        if revision != next {
            return Err(IdentityError::InvalidResponse);
        }
        self.revision = next;
        self.reset_pending = None;
        Ok(())
    }
}
