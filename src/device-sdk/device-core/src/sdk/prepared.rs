//! 准备接入只通过correlated只读快照验证，再提交带epoch的原会话接入。
use super::session_map::Reservation;
use super::*;
use crate::exclusive::ExclusiveSnapshot;

pub(super) struct PendingPrepared {
    pub request: String,
    reservation: Reservation,
    deadline: Instant,
    result: oneshot::Sender<Result<String, SdkError>>,
}
impl Actor {
    pub(super) async fn begin_prepared(
        &mut self,
        id: String,
        result: oneshot::Sender<Result<String, SdkError>>,
    ) {
        if let Some(session) = self.sessions.get(&id) {
            let outcome = if !session.closing
                && !session.guard.expired(Instant::now())
                && session.source == self.stored.device_id
                && session.guard.target_epoch().is_some()
            {
                session.initial_request_id.clone().ok_or(SdkError::Busy)
            } else {
                Err(SdkError::Closed)
            };
            let _ = result.send(outcome);
            return;
        }
        if self.prepared.contains_key(&id) {
            let _ = result.send(Err(SdkError::Busy));
            return;
        }
        if self.signal.is_none() {
            let _ = result.send(Err(SdkError::Offline));
            return;
        }
        if self.prepared.try_reserve(1).is_err() {
            let _ = result.send(Err(SdkError::QueueFull));
            return;
        }
        let reservation = match self.sessions.reserve_outgoing(id.clone()) {
            Ok(value) => value,
            Err(_) => {
                let _ = result.send(Err(SdkError::Busy));
                return;
            }
        };
        match self.send("sync.request", Some(&id), json!({})).await {
            Ok(request) => {
                self.prepared.insert(
                    id,
                    PendingPrepared {
                        request,
                        reservation,
                        deadline: Instant::now() + self.config.transport.operation_timeout,
                        result,
                    },
                );
            }
            Err(error) => {
                self.sessions.release_reservation(reservation);
                let _ = result.send(Err(error));
            }
        }
    }
    pub(super) fn expire_prepared(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .prepared
            .iter()
            .filter(|(_, p)| now >= p.deadline)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(value) = self.prepared.remove(&id) {
                self.sessions.release_reservation(value.reservation);
                let _ = value
                    .result
                    .send(Err(SdkError::Transport(TransportError::Timeout)));
            }
        }
    }
    pub(super) fn clear_prepared(&mut self) {
        for (_, value) in self.prepared.drain() {
            self.sessions.release_reservation(value.reservation);
            let _ = value.result.send(Err(SdkError::Closed));
        }
    }
    pub(super) async fn prepared_message(&mut self, message: &Envelope) -> bool {
        let id = if message.kind == "error" {
            self.prepared
                .iter()
                .find(|(_, p)| Some(&p.request) == message.request_id.as_ref())
                .map(|(id, _)| id.clone())
        } else if message.kind == "sync.snapshot" {
            message
                .session_id
                .as_ref()
                .filter(|id| {
                    self.prepared
                        .get(*id)
                        .is_some_and(|p| Some(&p.request) == message.request_id.as_ref())
                })
                .cloned()
        } else {
            None
        };
        let Some(id) = id else {
            return false;
        };
        let value = self
            .prepared
            .remove(&id)
            .expect("correlated prepared request");
        let result = self.finish_prepared(&id, &value, message).await;
        if result.is_err() {
            self.sessions.release_reservation(value.reservation);
        }
        let _ = value.result.send(result);
        true
    }
    async fn finish_prepared(
        &mut self,
        id: &str,
        pending: &PendingPrepared,
        message: &Envelope,
    ) -> Result<String, SdkError> {
        let invalid = || SdkError::Signal(SignalError::InvalidMessage);
        diagnostic("snapshot_received");
        if Instant::now() >= pending.deadline {
            return Err(SdkError::Transport(TransportError::Timeout));
        }
        if message.kind == "error" {
            return Err(SdkError::Rejected(
                message.payload["code"]
                    .as_str()
                    .unwrap_or("REQUEST_DENIED")
                    .to_owned(),
            ));
        }
        let exclusive = ExclusiveSnapshot::parse(message)
            .map_err(|_| {
                diagnostic("snapshot_invalid");
                invalid()
            })?
            .ok_or_else(invalid)?;
        diagnostic("snapshot_valid");
        let source = message.payload["source_device_id"]
            .as_str()
            .ok_or_else(invalid)?
            .to_owned();
        let target = message.payload["target_device_id"]
            .as_str()
            .ok_or_else(invalid)?
            .to_owned();
        if source != self.stored.device_id
            || message.payload["session_id"].as_str() != Some(id)
            || message.payload["state"] == "closed"
        {
            return Err(invalid());
        }
        let generation = message.payload["negotiation_generation"]
            .as_u64()
            .filter(|v| (1..=MAX_NEGOTIATION_GENERATION).contains(v))
            .ok_or_else(invalid)?;
        let clock = self
            .signal
            .as_ref()
            .ok_or(SdkError::Offline)?
            .server_clock();
        if exclusive.prepared {
            clock
                .continuous_deadline(exclusive.connect_deadline)
                .map_err(|_| SdkError::AuthorizationExpired)?;
        }
        let mut guard = LeaseGuard::new(id.to_owned(), source.clone(), target.clone())
            .map_err(|_| invalid())?;
        guard
            .apply(message, &clock, Instant::now())
            .map_err(|_| SdkError::AuthorizationExpired)?;
        diagnostic("lease_valid");
        let request = self
            .signal
            .as_ref()
            .ok_or(SdkError::Offline)?
            .send_generation_epoch(
                "session.connect_prepared",
                Some(id),
                json!({}),
                generation,
                Some(exclusive.epoch),
            )
            .await
            .map_err(SdkError::Signal)?;
        diagnostic("connect_sent");
        self.sessions
            .retarget(pending.reservation, target.clone())
            .map_err(|_| invalid())?;
        self.sessions
            .bind_request(pending.reservation, request.clone())
            .map_err(|_| invalid())?;
        let gate = Arc::new(Gate {
            installation_closed: self.installation_closed.clone(),
            ..Gate::default()
        });
        gate.update_guard(&guard);
        let session = Session {
            fence_safe: true,
            id: id.to_owned(),
            initial_request_id: Some(request.clone()),
            source,
            target: target.clone(),
            guard,
            gate,
            worker: None,
            authority: None,
            closing: false,
            renew_at: Instant::now() + Duration::from_secs(10),
            ready: false,
            generation,
            recovery_at: None,
            recovery_attempt: 0,
            sync_pending: false,
            sync_requested: false,
            requests: std::collections::VecDeque::from([(request.clone(), generation)]),
        };
        self.sessions
            .promote(&request, &target, id.to_owned(), session)
            .map_err(|_| invalid())?;
        diagnostic("promoted");
        Ok(request)
    }
}

fn diagnostic(stage: &str) {
    #[cfg(feature = "test-diagnostics")]
    eprintln!("exclusive_prepared stage={stage}");
    #[cfg(not(feature = "test-diagnostics"))]
    let _ = stage;
}

#[cfg(test)]
mod tests {
    use super::super::multiconnection_tests::capacity_actor;
    use super::*;
    fn snapshot(actor: &Actor, id: &str) -> Envelope {
        let mut message = crate::exclusive::tests::message();
        message.session_id = Some(id.into());
        message.payload["session_id"] = json!(id);
        message.payload["source_device_id"] = json!(actor.stored.device_id);
        message.payload["target_device_id"] = json!(uuid::Uuid::new_v4().to_string());
        let now = time::OffsetDateTime::now_utc();
        message.sent_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        for field in [
            "lease_expires_at",
            "source_lease_expires_at",
            "target_lease_expires_at",
            "connect_deadline",
            "release_not_before",
        ] {
            message.payload[field] = json!(
                (now + time::Duration::seconds(30))
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap()
            );
        }
        message
    }
    #[tokio::test]
    async fn prepared_connect_requires_exact_fresh_correlation_and_is_single_session() {
        let (mut actor, _events, server, authority) = capacity_actor(1).await;
        let id = uuid::Uuid::new_v4().to_string();
        authority
            .lock()
            .unwrap()
            .insert(id.clone(), snapshot(&actor, &id));
        let (done, reply) = oneshot::channel();
        actor.begin_prepared(id.clone(), done).await;
        assert_eq!(actor.sessions.admission_len(), 1);
        let message = actor.signal.as_mut().unwrap().receive().await.unwrap();
        let mut wrong = message.clone();
        wrong.request_id = Some(uuid::Uuid::new_v4().to_string());
        assert!(!actor.prepared_message(&wrong).await);
        assert_eq!(actor.prepared.len(), 1);
        assert!(actor.prepared_message(&message).await);
        let request = reply.await.unwrap().unwrap();
        assert!(actor.prepared.is_empty());
        assert_eq!(actor.sessions.admission_len(), 1);
        let session = actor.sessions.get(&id).unwrap();
        assert_eq!(session.guard.target_epoch(), Some(i64::MAX as u64));
        assert!(session.worker.is_none());
        let (done, reply) = oneshot::channel();
        actor.begin_prepared(id, done).await;
        assert_eq!(reply.await.unwrap().unwrap(), request);
        assert_eq!(actor.sessions.admission_len(), 1);
        actor.signal.take().unwrap().close().await;
        server.await.unwrap();
    }
    #[tokio::test]
    async fn prepared_wrong_source_and_expired_lookup_release_only_pending_reservation() {
        for expired in [false, true] {
            let (mut actor, _events, server, authority) = capacity_actor(1).await;
            let id = uuid::Uuid::new_v4().to_string();
            let mut message = snapshot(&actor, &id);
            if !expired {
                message.payload["source_device_id"] = json!(uuid::Uuid::new_v4().to_string());
            }
            authority.lock().unwrap().insert(id.clone(), message);
            let (done, reply) = oneshot::channel();
            actor.begin_prepared(id.clone(), done).await;
            if expired {
                actor.prepared.get_mut(&id).unwrap().deadline = Instant::now();
            }
            let message = actor.signal.as_mut().unwrap().receive().await.unwrap();
            assert!(actor.prepared_message(&message).await);
            assert!(reply.await.unwrap().is_err());
            assert!(actor.prepared.is_empty());
            assert_eq!(actor.sessions.admission_len(), 0);
            assert!(actor.sessions.get(&id).is_none());
            actor.signal.take().unwrap().close().await;
            server.await.unwrap();
        }
    }
    #[tokio::test]
    async fn target_fence_ack_requires_tracked_epoch_and_successful_worker_join() {
        for mode in [0, 1, 2] {
            // normal join, aborted worker, unknown session
            let (mut actor, _events, server, authority) = capacity_actor(0).await;
            let id = uuid::Uuid::new_v4().to_string();
            let mut initial = snapshot(&actor, &id);
            initial.kind = "session.pending".into();
            initial.payload["source_device_id"] = json!(uuid::Uuid::new_v4().to_string());
            initial.payload["target_device_id"] = json!(actor.stored.device_id);
            initial.payload["prepared"] = json!(false);
            authority
                .lock()
                .unwrap()
                .insert(id.clone(), initial.clone());
            let joined = Arc::new(std::sync::atomic::AtomicBool::new(false));
            if mode != 2 {
                actor.message(initial.clone()).await.unwrap();
                let reply = actor.signal.as_mut().unwrap().receive().await.unwrap();
                actor.message(reply).await.unwrap();
                let (stop, stopped) = oneshot::channel();
                let (control, _) = mpsc::channel(1);
                let done = joined.clone();
                let task = tokio::spawn(async move {
                    let _ = stopped.await;
                    done.store(true, Ordering::Release);
                });
                if mode == 1 {
                    task.abort();
                }
                actor.sessions.get_mut(&id).unwrap().worker = Some(Worker {
                    control,
                    stop: Some(stop),
                    task,
                });
            }
            let mut terminal = initial;
            terminal.kind = "session.terminated".into();
            terminal.payload["state"] = json!("closed");
            terminal.payload["exclusive_release_state"] = json!("closing");
            terminal.payload["fence_required"] = json!(true);
            authority
                .lock()
                .unwrap()
                .insert(id.clone(), terminal.clone());
            actor.message(terminal).await.unwrap();
            assert!(actor.sessions.get(&id).is_none());
            if mode == 0 {
                assert!(joined.load(Ordering::Acquire));
                // The mock replies only to a real outgoing session command.
                let ack = tokio::time::timeout(
                    Duration::from_secs(1),
                    actor.signal.as_mut().unwrap().receive(),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(ack.request_id.is_some());
                assert_eq!(ack.target_epoch.as_deref(), Some("9223372036854775807"));
            } else {
                assert!(!joined.load(Ordering::Acquire));
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(50),
                        actor.signal.as_mut().unwrap().receive()
                    )
                    .await
                    .is_err()
                );
            }
            actor.signal.take().unwrap().close().await;
            server.await.unwrap();
        }
    }
    #[tokio::test]
    async fn recovery_invalidation_precedes_authoritative_terminal_without_new_ready() {
        let (mut actor, mut events, server, authority) = capacity_actor(1).await;
        let id = uuid::Uuid::new_v4().to_string();
        authority
            .lock()
            .unwrap()
            .insert(id.clone(), snapshot(&actor, &id));
        let (done, reply) = oneshot::channel();
        actor.begin_prepared(id.clone(), done).await;
        let response = actor.signal.as_mut().unwrap().receive().await.unwrap();
        actor.prepared_message(&response).await;
        reply.await.unwrap().unwrap();
        actor.sessions.get_mut(&id).unwrap().ready = true;
        actor
            .prepare_recovery(&id, SdkError::Transport(TransportError::Closed))
            .await
            .unwrap();
        actor
            .close_session(&id, SdkError::Rejected("CLIENT_CLOSED".into()), false)
            .await;
        assert!(matches!(
            events.try_recv().unwrap(),
            SdkEvent::ConnectionClosed {
                reason: SdkError::Transport(TransportError::Closed),
                ..
            }
        ));
        assert!(
            matches!(events.try_recv().unwrap(), SdkEvent::ConnectionClosed { reason: SdkError::Rejected(ref code), .. } if code == "CLIENT_CLOSED")
        );
        assert!(events.try_recv().is_err());
        actor.signal.take().unwrap().close().await;
        server.await.unwrap();
    }
}
