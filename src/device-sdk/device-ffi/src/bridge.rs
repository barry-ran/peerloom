use crate::{state::*, storage::ExternalStore};
use device_core::{
    identity::{IdempotencyKey, IdentityError, Platform, RegistrationRequest},
    sdk::{DeviceSdk, SdkConfig, SdkError, SdkEvent},
};
use device_storage::{IdentityStore, MemoryIdentityStore, SecretString};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};
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
    #[serde(default = "one")]
    pub max_connections: usize,
    #[serde(default = "one")]
    pub max_channels_per_connection: usize,
    #[serde(default = "eight")]
    pub max_channel_creations_per_connection: usize,
}
fn eight() -> usize {
    8
}
fn one() -> usize {
    1
}
fn yes() -> bool {
    true
}
impl Config {
    pub fn validate(&self) -> bool {
        self.abi_version == 1
            && matches!(self.storage.as_str(), "memory" | "external")
            && (1..=32).contains(&self.max_connections)
            && (1..=32).contains(&self.max_channels_per_connection)
            && (self.max_channels_per_connection..=128)
                .contains(&self.max_channel_creations_per_connection)
            && self.origin.len() <= 2048
            && self.application_id.len() <= 36
    }
    fn sdk(&self) -> SdkConfig {
        let mut c = SdkConfig::new(self.origin.clone(), self.application_id.clone());
        c.max_connections = self.max_connections;
        c.max_channels_per_connection = self.max_channels_per_connection;
        c.transport.max_channels = self.max_channel_creations_per_connection;
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
    #[serde(default)]
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
pub(crate) fn error(error: SdkError) -> u32 {
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
async fn sdk_event(sdk: &mut Option<DeviceSdk>) -> Option<SdkEvent> {
    match sdk {
        Some(s) if !s.is_resetting() => s.next_event().await,
        Some(_) => std::future::pending().await,
        None => std::future::pending().await,
    }
}

async fn close_connections(connections: &mut HashMap<u64, (String, crate::channels::Task)>) {
    let mut closes = tokio::task::JoinSet::new();
    for (_, (_, task)) in connections.drain() {
        closes.spawn(task.close());
    }
    while closes.join_next().await.is_some() {}
}

pub async fn run(instance: Arc<Instance>, config: Config, mut commands: mpsc::Receiver<Operation>) {
    #[cfg(feature = "test-diagnostics")]
    let _diagnostic = (std::env::var("TEST_C_SCHEDULER_PROBE").as_deref() == Ok("1"))
        .then(SchedulerDiagnostic::start);
    let store: Arc<dyn IdentityStore> = if config.storage == "external" {
        Arc::new(ExternalStore(Arc::downgrade(&instance)))
    } else {
        Arc::new(MemoryIdentityStore::default())
    };
    let mut sdk: Option<DeviceSdk> = None;
    let mut connections: HashMap<u64, (String, crate::channels::Task)> = HashMap::new();
    loop {
        if instance.shutting.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            _ = instance.stop.notified() => break,
            command = commands.recv() => {
                let Some(operation) = command else { break };
                if matches!(operation.kind, 4 | 6 | 8 | 64..=68) {
                    if let Some((_, task)) = connections.get(&operation.connection) { task.route(&instance, operation); }
                    else { instance.finish(operation, CLOSED, Vec::new()); }
                    continue;
                }
                let Some(guard) = CompletionGuard::start(instance.clone(), operation) else { continue };
                if guard.operation().kind == 7 { close_connections(&mut connections).await; }
                let result = execute(&config, store.clone(), &mut sdk, guard.operation()).await;
                if result.is_ok() && guard.operation().kind == 1
                    && let Ok(mut current) = instance.device_id.lock() {
                    *current = sdk.as_ref().map(|sdk| sdk.device_id().to_owned());
                }
                if guard.operation().kind == 7 {
                    instance.reset_active.store(false, Ordering::Release);
                    if result.is_ok() {
                        if let Ok(mut current) = instance.device_id.lock() { *current = None; }
                        instance.resetting.store(false, Ordering::Release);
                    }
                }
                match result { Ok(payload) => guard.finish(OK, payload, None), Err(status) => guard.finish(status, Vec::new(), None) }
            },
            event = sdk_event(&mut sdk) => {
                match event {
                    Some(SdkEvent::Online) => { instance.emit(Event::new(2, 0, 0, OK, Vec::new())); },
                    Some(SdkEvent::Offline) => { instance.emit(Event::new(3, 0, 0, OK, Vec::new())); },
                    Some(SdkEvent::IncomingConnection { session_id, source_device_id }) => {
                        let payload = json!({"session_id":session_id,"source_device_id":source_device_id}).to_string().into_bytes();
                        instance.emit(Event::new(4, 0, 0, OK, payload));
                    },
                    Some(SdkEvent::ConnectionReady(connection)) => {
                        let session = connection.session_id().to_owned();
                        let generation = connection.negotiation_generation();
                        let peer_device_id = connection.peer_device_id().to_owned();
                        let request_id = connection.request_id().map(str::to_owned);
                        let old = connections.iter().find(|(_, (value, _))| value == &session).map(|(id, _)| *id);
                        if let Some(old) = old
                            && let Some((_, task)) = connections.remove(&old) {
                            task.close().await;
                        }
                        let admitted = (|| {
                            let mut handles = instance.handles.lock().map_err(|_| INTERNAL)?;
                            let id = handles.add_connection(Authority::Connection(connection.validity()), || next_id().map_err(|_| crate::handles::HandleError::Allocator)).map_err(handle_error)?;
                            Ok::<_,u32>((id, handles.connection(id).map_err(handle_error)?))
                        })();
                        let Ok((id, validity)) = admitted else { drop(connection); instance.stop(); continue; };
                        match crate::channels::spawn_connection(instance.clone(), id, validity.clone(), connection) {
                            Ok(task) => {
                                let payload = json!({"session_id":session,"generation":generation,"peer_device_id":peer_device_id,"request_id":request_id}).to_string().into_bytes();
                                connections.insert(id, (session, task));
                                let mut event = Event::new(5, 0, id, OK, payload);
                                event.validity = Some(validity);
                                instance.emit(event);
                            }
                            Err(_) => { if let Ok(mut handles) = instance.handles.lock() { let _ = handles.remove_connection(id); } instance.stop(); }
                        }
                    },
                    Some(SdkEvent::ConnectionRequestFailed { target_device_id, request_id, reason }) => {
                        let payload = json!({"session_id":"","target_device_id":target_device_id,"request_id":request_id}).to_string().into_bytes();
                        instance.emit(Event::new(7, 0, 0, error(reason), payload));
                    },
                    Some(SdkEvent::ConnectionClosed { session_id, reason }) => {
                        let id = connections.iter().find(|(_, (value, _))| value == &session_id).map(|(id, _)| *id).unwrap_or(0);
                        if let Some((_, task)) = connections.remove(&id) { task.close().await; }
                        instance.emit(Event::new(7, 0, id, error(reason), json!({"session_id":session_id}).to_string().into_bytes()));
                    },
                    Some(SdkEvent::IdentityPersistencePending) => { instance.emit(Event::new(8, 0, 0, NOT_READY, Vec::new())); },
                    Some(SdkEvent::Stopped(reason)) => { instance.emit(Event::new(11, 0, 0, error(reason), Vec::new())); instance.stop(); },
                    None => instance.stop(),
                }
            }
        }
    }
    commands.close();
    while let Some(operation) = commands.recv().await {
        if operation.kind == 7 {
            close_connections(&mut connections).await;
            let result = execute(&config, store.clone(), &mut sdk, &operation).await;
            let (status, payload) = match result {
                Ok(payload) => (OK, payload),
                Err(status) => (status, Vec::new()),
            };
            instance.finish(operation, status, payload);
        } else if matches!(operation.kind, 6 | 68) {
            if let Some((_, task)) = connections.get(&operation.connection) {
                task.route(&instance, operation);
            } else {
                instance.finish(operation, CLOSED, Vec::new());
            }
        } else {
            let status = if operation.kind == 67 {
                CLOSED
            } else {
                CANCELLED
            };
            instance.finish(operation, status, Vec::new());
        }
    }
    close_connections(&mut connections).await;
    if let Some(sdk) = sdk.take() {
        sdk.close().await;
    }
    if let Ok(mut handles) = instance.handles.lock() {
        handles.clear();
    }
    if let Ok(mut pending) = instance.storage.lock() {
        pending.clear();
    }
}
fn reset_error(reason: SdkError) -> u32 {
    match reason {
        SdkError::Identity(IdentityError::Storage(device_storage::StorageError::Conflict)) => BUSY,
        SdkError::Identity(IdentityError::Storage(_) | IdentityError::PendingMutation) => UNKNOWN,
        other => error(other),
    }
}
async fn execute(
    config: &Config,
    store: Arc<dyn IdentityStore>,
    sdk: &mut Option<DeviceSdk>,
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
    if op.kind == 7 {
        let request: ResetRequest = serde_json::from_slice(&op.input).map_err(|_| INVALID)?;
        let active = sdk.as_mut().ok_or(NOT_READY)?;
        if request.retry {
            active
                .retry_reset(&request.expected_device_id)
                .await
                .map_err(reset_error)?;
        } else {
            active
                .reset(&request.expected_device_id)
                .await
                .map_err(reset_error)?;
        }
        sdk.take();
        return Ok(json!({"identity_reset":true,"registration_required":true})
            .to_string()
            .into_bytes());
    }
    let sdk = sdk.as_ref().ok_or(NOT_READY)?;
    match op.kind {
        2 => {
            if op.connection != 0 {
                return Err(HANDLE);
            }
            let t: Target = serde_json::from_slice(&op.input).map_err(|_| INVALID)?;
            let request_id = sdk
                .connect_with_request(&t.target_device_id)
                .await
                .map_err(error)?;
            return Ok(
                json!({"request_id":request_id,"target_device_id":t.target_device_id})
                    .to_string()
                    .into_bytes(),
            );
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
        5 => {
            if op.connection != 0 || !op.input.is_empty() {
                return Err(INVALID);
            }
            sdk.refresh_credentials().await.map_err(error)?;
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
        if matches!(result, Ok(Ok(()))) && !instance.failed.load(Ordering::Acquire) {
            OK
        } else {
            INTERNAL
        },
        Vec::new(),
    ));
}

/// Test-only scheduling witness: no application identifiers or payloads.
#[cfg(feature = "test-diagnostics")]
struct SchedulerDiagnostic(tokio::task::JoinHandle<()>);
#[cfg(feature = "test-diagnostics")]
impl SchedulerDiagnostic {
    fn start() -> Self {
        Self(tokio::spawn(async {
            let period = std::time::Duration::from_millis(20);
            let mut expected = tokio::time::Instant::now() + period;
            let mut report = std::time::Instant::now();
            let mut maximum = 0;
            let mut samples = 0;
            loop {
                tokio::time::sleep_until(expected).await;
                let now = tokio::time::Instant::now();
                maximum = maximum.max(now.saturating_duration_since(expected).as_millis());
                samples += 1;
                expected = now + period;
                if report.elapsed() >= std::time::Duration::from_secs(5) {
                    eprintln!(
                        "PeerloomTestDiag scheduler samples={} maximum_lag_ms={}",
                        samples, maximum
                    );
                    report = std::time::Instant::now();
                    maximum = 0;
                    samples = 0;
                }
            }
        }))
    }
}
#[cfg(feature = "test-diagnostics")]
impl Drop for SchedulerDiagnostic {
    fn drop(&mut self) {
        self.0.abort();
    }
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
    #[test]
    fn ffi_creation_budget_matches_core_limit() {
        let mut config: Config = serde_json::from_str(r#"{"abi_version":1,"origin":"https://localhost","application_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","storage":"memory","max_channels_per_connection":32,"max_channel_creations_per_connection":128}"#).unwrap();
        assert!(config.validate());
        assert_eq!(config.sdk().transport.max_channels, 128);
        config.max_channel_creations_per_connection = 129;
        assert!(!config.validate());
        config.max_channel_creations_per_connection = 31;
        assert!(!config.validate());
        config.max_channel_creations_per_connection = 32;
        assert!(config.validate());
    }
}
