//! Stopped SDK retains its identity journal until an explicit reset is resolved.
use super::*;

impl DeviceSdk {
    /// Explicitly resets this installation after fencing all its old connections.
    /// No registration, server-side revocation, or automatic new identity is implied.
    /// The object remains owned by the caller after errors/cancellation so its
    /// in-memory recovery journal is not silently discarded. Ordinary operations
    /// stay closed once reset starts, even if storage subsequently fails.
    pub async fn reset(&mut self, expected_device_id: &str) -> Result<(), SdkError> {
        self.reset_inner(expected_device_id, false).await
    }

    /// Explicit recovery of a previously initiated reset. A pending credential
    /// mutation is retried with its original key/body first; no new mutation key
    /// or registration is invented. Storage deletion uses exact CAS/read-back.
    pub async fn retry_reset(&mut self, expected_device_id: &str) -> Result<(), SdkError> {
        if !self.reset_started {
            return Err(SdkError::InvalidConfiguration);
        }
        self.reset_inner(expected_device_id, true).await
    }

    pub fn is_resetting(&self) -> bool {
        self.reset_started
    }

    async fn reset_inner(&mut self, expected: &str, recover: bool) -> Result<(), SdkError> {
        let expected = uuid::Uuid::parse_str(expected)
            .map_err(|_| SdkError::InvalidConfiguration)?
            .to_string();
        if expected != self.device_id {
            return Err(SdkError::InvalidConfiguration);
        }
        if self.reset_complete {
            return Ok(());
        }
        self.reset_started = true;
        // Shared by every connection gate: takes effect before any await.
        self.installation_closed.store(true, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if self.reset_shutdown_unknown {
            return Err(SdkError::RequestOutcomeUnknown);
        }
        if let Some(task) = self.task.as_mut() {
            match tokio::time::timeout(Duration::from_secs(35), &mut *task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    self.reset_shutdown_unknown = true;
                    self.task.take();
                    return Err(SdkError::RequestOutcomeUnknown);
                }
                Err(_) => {
                    self.reset_shutdown_unknown = true;
                    task.abort();
                    let _ = task.await;
                    self.task.take();
                    return Err(SdkError::RequestOutcomeUnknown);
                }
            }
            self.task.take();
        }
        let mut identity = self.identity_state.lock().await;
        if identity.has_pending_mutation() || identity.needs_persistence() {
            if !recover {
                return Err(SdkError::Identity(IdentityError::PendingMutation));
            }
            if identity.has_pending_mutation() {
                identity.retry_pending().await.map_err(SdkError::Identity)?;
            }
            if identity.needs_persistence() {
                identity.retry_persist().await.map_err(SdkError::Identity)?;
            }
        }
        if identity.has_pending_reset() {
            if !recover {
                return Err(SdkError::Identity(IdentityError::PendingMutation));
            }
            identity.retry_reset().await.map_err(SdkError::Identity)?;
        } else {
            identity
                .reset(&expected)
                .await
                .map_err(SdkError::Identity)?;
        }
        self.reset_complete = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installation_fence_invalidates_existing_connection_observers() {
        let installation = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(Gate {
            installation_closed: installation.clone(),
            ..Gate::default()
        });
        gate.update(Some(Instant::now() + Duration::from_secs(60)));
        let observer = ConnectionValidity(gate.clone());
        assert!(observer.is_valid());
        installation.store(true, Ordering::Release);
        assert!(!observer.is_valid());
        assert!(matches!(gate.check(), Err(SdkError::Closed)));
    }
    #[tokio::test]
    async fn reset_fence_is_shared_by_recovery_and_replacement_gates() {
        use device_storage::{IdentityScope, MemoryIdentityStore, SecretString};
        let app = uuid::Uuid::new_v4().to_string();
        let source = uuid::Uuid::new_v4().to_string();
        let target = uuid::Uuid::new_v4().to_string();
        let session_id = uuid::Uuid::new_v4().to_string();
        let config = SdkConfig::new("https://reset.example".into(), app.clone());
        let store = Arc::new(MemoryIdentityStore::default());
        let stored = StoredIdentity {
            device_id: source.clone(),
            device_credential: SecretString::new(format!("dev_{}", "a".repeat(43))),
            expires_at: "2099-01-01T00:00:00Z".into(),
        };
        store
            .save(
                &IdentityScope {
                    server_origin: "https://reset.example/".into(),
                    application_id: app,
                },
                0,
                stored.clone(),
            )
            .await
            .unwrap();
        let identity = DeviceSdk::identity(&config, store).await.unwrap();
        let (commands, _command_rx) = mpsc::channel(32);
        let (events, _event_rx) = mpsc::channel(32);
        let mut actor = Actor::new(config, identity, stored, commands, events);
        let installation = actor.installation_closed.clone();
        let initial = Arc::new(Gate {
            installation_closed: installation.clone(),
            ..Gate::default()
        });
        actor
            .sessions
            .insert_incoming(
                session_id.clone(),
                Session {
                    id: session_id.clone(),
                    initial_request_id: None,
                    source: source.clone(),
                    target: target.clone(),
                    guard: LeaseGuard::new(session_id.clone(), source, target).unwrap(),
                    gate: initial.clone(),
                    worker: None,
                    renew_at: Instant::now(),
                    ready: true,
                    generation: 1,
                    recovery_at: None,
                    recovery_attempt: 0,
                    sync_pending: false,
                    requests: std::collections::VecDeque::new(),
                },
            )
            .unwrap();
        actor
            .prepare_recovery(&session_id, SdkError::Transport(TransportError::Ice))
            .await
            .unwrap();
        let retry = actor.sessions.get(&session_id).unwrap().gate.clone();
        assert!(Arc::ptr_eq(&retry.installation_closed, &installation));
        assert!(initial.closed.load(Ordering::Acquire));
        actor.replace_generation(&session_id, 2).await.unwrap();
        let replacement = actor.sessions.get(&session_id).unwrap().gate.clone();
        assert!(Arc::ptr_eq(&replacement.installation_closed, &installation));
        assert!(retry.closed.load(Ordering::Acquire));
        replacement.update(Some(Instant::now() + Duration::from_secs(60)));
        assert!(replacement.check().is_ok());
        // Same immediate fence used by reset before its first await.
        installation.store(true, Ordering::Release);
        assert_eq!(replacement.check(), Err(SdkError::Closed));
        actor.replace_generation(&session_id, 3).await.unwrap();
        let late = actor.sessions.get(&session_id).unwrap().gate.clone();
        late.update(Some(Instant::now() + Duration::from_secs(60)));
        assert!(Arc::ptr_eq(&late.installation_closed, &installation));
        assert_eq!(late.check(), Err(SdkError::Closed));
    }
}
