use crate::{state::*, storage::ExternalStore};
use device_core::{
    identity::{IdempotencyKey, IdentityError, Platform, RegistrationRequest},
    sdk::{Connection, DeviceSdk, SdkConfig, SdkError, SdkEvent},
};
use device_storage::{IdentityStore, MemoryIdentityStore, SecretString};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::mpsc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub abi_version: u32,
    pub origin: String,
    pub application_id: String,
    pub storage: String,
    #[serde(default)]
    pub development_loopback: bool,
    #[serde(default = "yes")]
    pub auto_reconnect: bool,
}
fn yes() -> bool {
    true
}
impl Config {
    pub fn validate(&self) -> bool {
        self.abi_version == 1
            && matches!(self.storage.as_str(), "memory" | "external")
            && self.origin.len() <= 2048
            && self.application_id.len() <= 36
    }
    fn sdk(&self) -> SdkConfig {
        let mut c = SdkConfig::new(self.origin.clone(), self.application_id.clone());
        c.development_loopback = self.development_loopback;
        c.auto_reconnect = self.auto_reconnect;
        c.transport.include_loopback = self.development_loopback;
        c
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    #[serde(default)]
    registration: Option<Registration>,
    #[serde(default)]
    idempotency_key: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    platform: Platform,
    installation_public_key: String,
    registration_grant: String,
    sdk_version: String,
    #[serde(default)]
    metadata: serde_json::Map<String, serde_json::Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    target_device_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Respond {
    session_id: String,
    accept: bool,
}
fn error(error: SdkError) -> u32 {
    match error {
        SdkError::InvalidConfiguration => INVALID,
        SdkError::Busy => BUSY,
        SdkError::QueueFull => FULL,
        SdkError::Closed => CLOSED,
        SdkError::RequestOutcomeUnknown => UNKNOWN,
        SdkError::AuthorizationExpired => 3,
        SdkError::Identity(IdentityError::NoIdentity) => NOT_READY,
        SdkError::Identity(IdentityError::Transport | IdentityError::PendingMutation) => UNKNOWN,
        SdkError::Identity(IdentityError::Server {
            status: 401 | 403, ..
        }) => 3,
        SdkError::Signal(
            device_core::signaling::SignalError::AuthorizationRejected
            | device_core::signaling::SignalError::PolicyRejected,
        ) => 3,
        SdkError::Signal(device_core::signaling::SignalError::Timeout) => 4,
        SdkError::Transport(device_transport_webrtc::TransportError::Timeout) => 4,
        SdkError::Transport(device_transport_webrtc::TransportError::BufferFull) => FULL,
        SdkError::Transport(device_transport_webrtc::TransportError::Closed) => CLOSED,
        SdkError::Offline => NOT_READY,
        SdkError::MessageTooLarge => INVALID,
        _ => INTERNAL,
    }
}
async fn connection_receive(
    connection: &mut Option<(u64, Connection)>,
) -> Result<Vec<u8>, SdkError> {
    match connection {
        Some((_, c)) => c.receive().await,
        None => std::future::pending().await,
    }
}
async fn sdk_event(sdk: &mut Option<DeviceSdk>) -> Option<SdkEvent> {
    match sdk {
        Some(s) => s.next_event().await,
        None => std::future::pending().await,
    }
}

pub async fn run(instance: Arc<Instance>, config: Config, mut commands: mpsc::Receiver<Operation>) {
    let store: Arc<dyn IdentityStore> = if config.storage == "external" {
        Arc::new(ExternalStore(Arc::downgrade(&instance)))
    } else {
        Arc::new(MemoryIdentityStore::default())
    };
    let mut sdk: Option<DeviceSdk> = None;
    let mut connection: Option<(u64, Connection)> = None;
    loop {
        if connection.is_none() {
            if let Ok(mut validity) = instance.connection_validity.lock() {
                *validity = None;
            }
            instance.connection_id.store(0, Ordering::Release);
        }
        if instance.shutting.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            _ = instance.stop.notified() => break,
            command = commands.recv() => {
                let Some(op) = command else { break };
                let queued_phase = if op.kind == 6 { 4 } else { 0 };
                if op.phase.compare_exchange(
                    queued_phase, 1, Ordering::AcqRel, Ordering::Acquire,
                ).is_err() {
                    instance.finish(op, CANCELLED, Vec::new());
                    continue;
                }
                let result = execute(&config, store.clone(), &mut sdk, &mut connection, &op).await;
                let (status, payload) = match result {
                    Ok(payload) => (OK, payload),
                    Err(status) => (status, Vec::new()),
                };
                instance.finish(op, status, payload);
            },
            event = sdk_event(&mut sdk) => {
                match event {
                    Some(SdkEvent::Online) => {
                        instance.emit(Event::new(2, 0, 0, OK, Vec::new()));
                    },
                    Some(SdkEvent::Offline) => {
                        instance.emit(Event::new(3, 0, 0, OK, Vec::new()));
                    },
                    Some(SdkEvent::IncomingConnection { session_id, source_device_id }) => {
                        let payload = json!({
                            "session_id": session_id,
                            "source_device_id": source_device_id,
                        }).to_string().into_bytes();
                        instance.emit(Event::new(4, 0, 0, OK, payload));
                    },
                    Some(SdkEvent::ConnectionReady(c)) => {
                        if connection.is_some() {
                            drop(c);
                            instance.stop();
                            continue;
                        }
                        let Ok(id) = next_id() else {
                            instance.stop();
                            continue;
                        };
                        let payload = json!({"session_id": c.session_id()}).to_string().into_bytes();
                        if let Ok(mut validity) = instance.connection_validity.lock() {
                            *validity = Some((id, c.validity()));
                        } else { drop(c); instance.stop(); continue; }
                        instance.connection_id.store(id, Ordering::Release);
                        instance.closing_connection.store(0, Ordering::Release);
                        let mut event = Event::new(5, 0, id, OK, payload);
                        event.validity = Some(c.validity());
                        connection = Some((id, c));
                        instance.emit(event);
                    },
                    Some(SdkEvent::ConnectionClosed { session_id, reason }) => {
                        let id = connection.as_ref()
                            .filter(|(_, c)| c.session_id() == session_id)
                            .map(|(id, _)| *id)
                            .unwrap_or(0);
                        if id != 0 {
                            connection.take();
                        }
                        let payload = json!({"session_id": session_id}).to_string().into_bytes();
                        instance.emit(Event::new(7, 0, id, error(reason), payload));
                    },
                    Some(SdkEvent::IdentityPersistencePending) => {
                        instance.emit(Event::new(8, 0, 0, NOT_READY, Vec::new()));
                    },
                    Some(SdkEvent::Stopped(reason)) => {
                        instance.emit(Event::new(11, 0, 0, error(reason), Vec::new()));
                        instance.stop();
                    },
                    None => instance.stop(),
                }
            },
            received = connection_receive(&mut connection) => {
                if let Some((id, c)) = &connection {
                    match received {
                        Ok(payload) => {
                            let mut event = Event::new(6, 0, *id, OK, payload);
                            event.validity = Some(c.validity());
                            instance.emit(event);
                        },
                        Err(reason) => {
                            instance.emit(Event::new(7, 0, *id, error(reason), Vec::new()));
                            connection.take();
                        },
                    }
                }
            }
        }
    }
    commands.close();
    let mut close_requests = Vec::new();
    while let Some(op) = commands.recv().await {
        if op.kind == 6 {
            close_requests.push(op);
        } else {
            instance.finish(op, CANCELLED, Vec::new());
        }
    }
    let close_status = if let Some((_, connection)) = connection.take() {
        connection.close().await.err().map(error).unwrap_or(OK)
    } else {
        OK
    };
    // Close admission already stopped local delivery and cannot be rolled back. During
    // shutdown it completes only after the same resource cleanup, never falsely Cancelled.
    for op in close_requests {
        instance.finish(op, close_status, Vec::new());
    }
    if let Some(sdk) = sdk.take() {
        sdk.close().await;
    }
    if let Ok(mut validity) = instance.connection_validity.lock() {
        *validity = None;
    }
    instance.connection_id.store(0, Ordering::Release);
    if let Ok(mut pending) = instance.storage.lock() {
        pending.clear();
    }
}
async fn execute(
    config: &Config,
    store: Arc<dyn IdentityStore>,
    sdk: &mut Option<DeviceSdk>,
    connection: &mut Option<(u64, Connection)>,
    op: &Operation,
) -> Result<Vec<u8>, u32> {
    if op.kind == 1 {
        if sdk.is_some() || op.connection != 0 {
            return Err(BUSY);
        }
        let start: Start = serde_json::from_slice(&op.input).map_err(|_| INVALID)?;
        let created = if let Some(registration) = start.registration {
            let key =
                IdempotencyKey::new(start.idempotency_key.ok_or(INVALID)?).map_err(|_| INVALID)?;
            DeviceSdk::register(
                config.sdk(),
                store,
                RegistrationRequest {
                    application_id: config.application_id.clone(),
                    platform: registration.platform,
                    installation_public_key: registration.installation_public_key,
                    registration_grant: SecretString::new(registration.registration_grant),
                    sdk_version: registration.sdk_version,
                    metadata: registration.metadata,
                },
                key,
            )
            .await
        } else {
            if start.idempotency_key.is_some() {
                return Err(INVALID);
            }
            DeviceSdk::load(config.sdk(), store).await
        }
        .map_err(error)?;
        let payload = json!({"device_id":created.device_id()})
            .to_string()
            .into_bytes();
        *sdk = Some(created);
        return Ok(payload);
    }
    let sdk = sdk.as_ref().ok_or(NOT_READY)?;
    match op.kind {
        2 => {
            if op.connection != 0 {
                return Err(HANDLE);
            }
            let t: Target = serde_json::from_slice(&op.input).map_err(|_| INVALID)?;
            sdk.connect(&t.target_device_id).await.map_err(error)?;
        }
        3 => {
            if op.connection != 0 {
                return Err(HANDLE);
            }
            let r: Respond = serde_json::from_slice(&op.input).map_err(|_| INVALID)?;
            if r.accept {
                sdk.accept(&r.session_id).await
            } else {
                sdk.reject(&r.session_id).await
            }
            .map_err(error)?;
        }
        4 => {
            let (_, c) = connection
                .as_ref()
                .filter(|(id, _)| *id == op.connection)
                .ok_or(HANDLE)?;
            c.send(&op.input).await.map_err(error)?;
        }
        5 => {
            if op.connection != 0 || !op.input.is_empty() {
                return Err(INVALID);
            }
            sdk.refresh_credentials().await.map_err(error)?;
        }
        6 => {
            if !op.input.is_empty() {
                return Err(INVALID);
            }
            if connection
                .as_ref()
                .is_none_or(|(id, _)| *id != op.connection)
            {
                return Err(HANDLE);
            }
            let (_, c) = connection.take().ok_or(HANDLE)?;
            c.close().await.map_err(error)?;
        }
        _ => return Err(UNSUPPORTED),
    }
    Ok(Vec::new())
}

pub fn runtime(instance: Arc<Instance>, config: Config, commands: mpsc::Receiver<Operation>) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build();
        let runtime = runtime.map_err(|_| ())?;
        runtime.block_on(run(instance.clone(), config, commands));
        drop(runtime);
        Ok::<(), ()>(())
    }));
    instance.stop();
    // Any worker panic becomes an explicit internal completion, never an unwind across C.
    let pending: Vec<_> = instance
        .operations
        .lock()
        .map(|ops| {
            ops.iter()
                .filter(|(_, p)| p.load(Ordering::Acquire) != 3)
                .map(|(id, p)| (*id, p.clone()))
                .collect()
        })
        .unwrap_or_default();
    for (id, phase) in pending {
        phase.store(3, Ordering::Release);
        instance.emit(Event::new(COMPLETE, id, 0, INTERNAL, Vec::new()));
    }
    instance.runtime_done.store(true, Ordering::Release);
    instance.emit(Event::new(
        SHUTDOWN,
        {
            let id = instance.shutdown_id.load(Ordering::Acquire);
            if id == u64::MAX { 0 } else { id }
        },
        0,
        if matches!(result, Ok(Ok(()))) {
            OK
        } else {
            INTERNAL
        },
        Vec::new(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use device_core::{identity::IdentityError, signaling::SignalError};
    use device_transport_webrtc::TransportError;
    #[test]
    fn typed_errors_do_not_collapse_auth_and_timeout_or_expose_details() {
        let cases = [
            (SdkError::AuthorizationExpired, 3),
            (
                SdkError::Identity(IdentityError::Server {
                    status: 401,
                    code: "untrusted-secret-text".into(),
                }),
                3,
            ),
            (SdkError::Signal(SignalError::PolicyRejected), 3),
            (SdkError::Transport(TransportError::Timeout), 4),
            (SdkError::Signal(SignalError::Timeout), 4),
            (SdkError::Identity(IdentityError::Transport), UNKNOWN),
            (SdkError::Identity(IdentityError::NoIdentity), NOT_READY),
            (SdkError::QueueFull, FULL),
            (SdkError::Closed, CLOSED),
        ];
        for (input, expected) in cases {
            assert_eq!(error(input), expected);
        }
    }
}
