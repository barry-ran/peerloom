//! Native HTTP identity client. No disk persistence or platform keystore is implied.
//! Mutations are never retried automatically: retain the same key after uncertain outcomes.
mod reset;
use device_storage::{IdentityScope, IdentityStore, SecretString, StorageError, StoredIdentity};
use reqwest::{Client, Method, Url, header};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

const MAX_BODY: usize = 65536;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    InvalidConfiguration,
    InvalidRequest,
    Transport,
    InvalidResponse,
    ResponseTooLarge,
    Server { status: u16, code: String },
    Storage(StorageError),
    PendingMutation,
    NoIdentity,
}
impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for IdentityError {}
#[derive(Clone, PartialEq, Eq)]
pub struct IdempotencyKey(Zeroizing<String>);
impl std::fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdempotencyKey([REDACTED])")
    }
}
impl IdempotencyKey {
    pub fn new(value: String) -> Result<Self, IdentityError> {
        if !(8..=128).contains(&value.len()) || !value.bytes().all(|b| (33..=126).contains(&b)) {
            return Err(IdentityError::InvalidRequest);
        }
        Ok(Self(Zeroizing::new(value)))
    }
    pub fn random() -> Self {
        Self(Zeroizing::new(uuid::Uuid::new_v4().to_string()))
    }
    /// Direct enrollment recovery secret: 32 CSPRNG bytes, canonical base64url.
    /// Persist this exact key securely with the request until the replay outcome is known.
    pub fn recovery() -> Result<Self, IdentityError> {
        use base64::Engine;
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| IdentityError::InvalidConfiguration)?;
        Ok(Self(Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_ref()),
        )))
    }
    /// Explicit exposure only for encrypted request journaling or authenticated HTTP headers.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
    fn validate_direct(&self) -> Result<(), IdentityError> {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.expose())
            .map_err(|_| IdentityError::InvalidRequest)?;
        let decoded = Zeroizing::new(decoded);
        if self.0.len() != 43 || decoded.len() != 32 {
            return Err(IdentityError::InvalidRequest);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
    Android,
    Ios,
    Web,
}
#[derive(Debug, Clone)]
pub struct RegistrationRequest {
    pub application_id: String,
    pub platform: Platform,
    pub installation_public_key: String,
    /// Empty only for explicitly requested direct enrollment; server policy still controls access.
    pub registration_grant: SecretString,
    pub sdk_version: String,
    pub metadata: serde_json::Map<String, serde_json::Value>,
}
impl RegistrationRequest {
    fn body(&self) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        if uuid::Uuid::parse_str(&self.application_id).is_err()
            || !(1..=4096).contains(&self.installation_public_key.chars().count())
            || (!self.registration_grant.expose().is_empty()
                && !self.registration_grant.expose().starts_with("reg_"))
            || self.registration_grant.expose().len() > 512
            || self.sdk_version.chars().count() > 64
            || self.sdk_version.contains('\0')
            || self.metadata.len() > 32
            || self.metadata.iter().any(|(k, v)| {
                k.is_empty()
                    || k.chars().count() > 64
                    || k.contains('\0')
                    || match v {
                        serde_json::Value::Null
                        | serde_json::Value::Bool(_)
                        | serde_json::Value::Number(_) => false,
                        serde_json::Value::String(s) => {
                            s.chars().count() > 1024 || s.contains('\0')
                        }
                        _ => true,
                    }
            })
        {
            return Err(IdentityError::InvalidRequest);
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            application_id: &'a str,
            platform: Platform,
            installation_public_key: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            registration_grant: Option<&'a str>,
            sdk_version: &'a str,
            metadata: &'a serde_json::Map<String, serde_json::Value>,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&Wire {
                application_id: &self.application_id,
                platform: self.platform,
                installation_public_key: &self.installation_public_key,
                registration_grant: (!self.registration_grant.expose().is_empty())
                    .then(|| self.registration_grant.expose()),
                sdk_version: &self.sdk_version,
                metadata: &self.metadata,
            })
            .map_err(|_| IdentityError::InvalidRequest)?,
        );
        if body.len() > 16384 {
            return Err(IdentityError::InvalidRequest);
        }
        Ok(body)
    }
}
#[derive(Debug, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub tenant_id: String,
    pub application_id: String,
    pub platform: Platform,
    pub metadata: serde_json::Map<String, serde_json::Value>,
}
#[derive(Clone)]
pub struct IdentityClient {
    client: Client,
    pub(crate) tls_config: std::sync::Arc<rustls::ClientConfig>,
    pub(crate) origin: Url,
}
impl IdentityClient {
    /// HTTP is allowed only for an explicit development IP-literal loopback origin.
    pub fn new(
        origin: &str,
        development_loopback: bool,
        timeout: Duration,
    ) -> Result<Self, IdentityError> {
        let origin = Url::parse(origin).map_err(|_| IdentityError::InvalidConfiguration)?;
        let loopback = origin
            .host_str()
            .and_then(|host| {
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        if (origin.scheme() != "https"
            && !(origin.scheme() == "http" && development_loopback && loopback))
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || timeout.is_zero()
            || timeout > Duration::from_secs(60)
        {
            return Err(IdentityError::InvalidConfiguration);
        }
        let tls_config =
            crate::tls::client_config().map_err(|_| IdentityError::InvalidConfiguration)?;
        let client = Client::builder()
            .tls_backend_preconfigured((*tls_config).clone())
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(timeout)
            .build()
            .map_err(|_| IdentityError::InvalidConfiguration)?;
        Ok(Self {
            client,
            origin,
            tls_config,
        })
    }
    pub(crate) async fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&SecretString>,
        key: Option<&IdempotencyKey>,
        body: Option<&[u8]>,
        expected: u16,
    ) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        self.request_epoch(method, path, token, key, body, expected, None)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn request_epoch(
        &self,
        method: Method,
        path: &str,
        token: Option<&SecretString>,
        key: Option<&IdempotencyKey>,
        body: Option<&[u8]>,
        expected: u16,
        epoch: Option<u64>,
    ) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        let mut request = self.client.request(
            method,
            self.origin
                .join(path)
                .map_err(|_| IdentityError::InvalidConfiguration)?,
        );
        if let Some(epoch) = epoch {
            if epoch == 0 || epoch > i64::MAX as u64 {
                return Err(IdentityError::InvalidRequest);
            }
            request = request.header("X-Peerloom-Target-Epoch", epoch.to_string());
        }
        if let Some(token) = token {
            let mut value = header::HeaderValue::from_str(&format!("Bearer {}", token.expose()))
                .map_err(|_| IdentityError::InvalidRequest)?;
            value.set_sensitive(true);
            request = request.header(header::AUTHORIZATION, value);
        }
        if let Some(key) = key {
            let mut value = header::HeaderValue::from_str(key.expose())
                .map_err(|_| IdentityError::InvalidRequest)?;
            value.set_sensitive(true);
            request = request.header("Idempotency-Key", value);
        }
        if let Some(body) = body {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let mut response = request.send().await.map_err(|_| IdentityError::Transport)?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("");
        if content_type != "application/json" && content_type != "application/problem+json" {
            return Err(IdentityError::InvalidResponse);
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_BODY as u64)
        {
            return Err(IdentityError::ResponseTooLarge);
        }
        let mut data = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| IdentityError::Transport)?
        {
            if chunk.len() > MAX_BODY - data.len() {
                return Err(IdentityError::ResponseTooLarge);
            }
            data.extend_from_slice(&chunk);
        }
        if status != expected {
            #[derive(Deserialize)]
            struct Problem {
                code: String,
            }
            let code = serde_json::from_slice::<Problem>(&data)
                .ok()
                .map(|p| p.code)
                .filter(|c| {
                    !c.is_empty()
                        && c.len() <= 64
                        && c.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
                })
                .unwrap_or_else(|| "UNKNOWN_SERVER_ERROR".into());
            return Err(IdentityError::Server { status, code });
        }
        Ok(data)
    }
    pub async fn register(
        &self,
        request: &RegistrationRequest,
        key: &IdempotencyKey,
    ) -> Result<StoredIdentity, IdentityError> {
        if request.registration_grant.expose().is_empty() {
            key.validate_direct()?;
        }
        let body = request.body()?;
        credential(
            &self
                .request(
                    Method::POST,
                    "/v1/device-registrations",
                    None,
                    Some(key),
                    Some(&body),
                    201,
                )
                .await?,
        )
    }
    pub async fn refresh(
        &self,
        identity: &StoredIdentity,
        key: &IdempotencyKey,
    ) -> Result<StoredIdentity, IdentityError> {
        validate_identity(identity)?;
        let next = credential(
            &self
                .request(
                    Method::POST,
                    "/v1/device-credentials/refresh",
                    Some(&identity.device_credential),
                    Some(key),
                    Some(b"{}"),
                    200,
                )
                .await?,
        )?;
        if next.device_id != identity.device_id {
            return Err(IdentityError::InvalidResponse);
        }
        Ok(next)
    }
    pub async fn device_self(
        &self,
        identity: &StoredIdentity,
    ) -> Result<DeviceInfo, IdentityError> {
        validate_identity(identity)?;
        let data = self
            .request(
                Method::GET,
                "/v1/device-self",
                Some(&identity.device_credential),
                None,
                None,
                200,
            )
            .await?;
        let info: DeviceInfo =
            serde_json::from_slice(&data).map_err(|_| IdentityError::InvalidResponse)?;
        if info.device_id != identity.device_id
            || uuid::Uuid::parse_str(&info.tenant_id).is_err()
            || uuid::Uuid::parse_str(&info.application_id).is_err()
        {
            return Err(IdentityError::InvalidResponse);
        }
        Ok(info)
    }
}
fn validate_identity(identity: &StoredIdentity) -> Result<(), IdentityError> {
    let token = identity.device_credential.expose();
    if uuid::Uuid::parse_str(&identity.device_id).is_err()
        || token.len() != 47
        || !token.starts_with("dev_")
        || !token[4..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || time::OffsetDateTime::parse(
            &identity.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(IdentityError::InvalidResponse);
    }
    Ok(())
}
fn credential(data: &[u8]) -> Result<StoredIdentity, IdentityError> {
    #[derive(Deserialize)]
    struct Wire {
        device_id: String,
        device_credential: String,
        expires_at: String,
    }
    let wire: Wire = serde_json::from_slice(data).map_err(|_| IdentityError::InvalidResponse)?;
    let identity = StoredIdentity {
        device_id: wire.device_id,
        device_credential: SecretString::new(wire.device_credential),
        expires_at: wire.expires_at,
    };
    validate_identity(&identity)?;
    Ok(identity)
}
#[derive(Clone)]
enum Pending {
    Register(RegistrationRequest, IdempotencyKey),
    Refresh(StoredIdentity, IdempotencyKey),
}
/// Single mutable owner serializes rotations. Separate owners are fenced by store CAS.
/// Dropping an in-flight future preserves pending retry data; dropping this entire object
/// loses that in-memory recovery data. Durable crash recovery is not implemented.
pub struct IdentitySession {
    pub(crate) client: IdentityClient,
    store: Arc<dyn IdentityStore>,
    scope: IdentityScope,
    revision: u64,
    identity: Option<StoredIdentity>,
    pending: Option<Pending>,
    dirty: bool,
    reset_pending: Option<reset::ResetPending>,
}
impl IdentitySession {
    pub async fn load(
        client: IdentityClient,
        application_id: String,
        store: Arc<dyn IdentityStore>,
    ) -> Result<Self, IdentityError> {
        if uuid::Uuid::parse_str(&application_id).is_err() {
            return Err(IdentityError::InvalidRequest);
        }
        let application_id = uuid::Uuid::parse_str(&application_id)
            .map_err(|_| IdentityError::InvalidRequest)?
            .to_string();
        let scope = IdentityScope {
            server_origin: client.origin.to_string(),
            application_id,
        };
        let snapshot = store.load(&scope).await.map_err(IdentityError::Storage)?;
        if let Some(identity) = &snapshot.identity {
            validate_identity(identity)?;
        }
        Ok(Self {
            client,
            store,
            scope,
            revision: snapshot.revision,
            identity: snapshot.identity,
            pending: None,
            dirty: false,
            reset_pending: None,
        })
    }
    pub fn identity(&self) -> Option<&StoredIdentity> {
        self.identity.as_ref()
    }
    /// 校验服务端返回的 application 与当前存储作用域一致。
    pub async fn device_self(&self) -> Result<DeviceInfo, IdentityError> {
        let identity = self.identity.as_ref().ok_or(IdentityError::NoIdentity)?;
        let info = self.client.device_self(identity).await?;
        if info.application_id != self.scope.application_id {
            return Err(IdentityError::InvalidResponse);
        }
        Ok(info)
    }
    pub fn has_pending_mutation(&self) -> bool {
        self.pending.is_some()
    }
    pub fn needs_persistence(&self) -> bool {
        self.dirty
    }
    pub async fn register(
        &mut self,
        mut request: RegistrationRequest,
        key: IdempotencyKey,
    ) -> Result<(), IdentityError> {
        if self.reset_pending.is_some()
            || self.pending.is_some()
            || self.dirty
            || self.identity.is_some()
        {
            return Err(IdentityError::PendingMutation);
        }
        request.application_id = uuid::Uuid::parse_str(&request.application_id)
            .map_err(|_| IdentityError::InvalidRequest)?
            .to_string();
        if request.application_id != self.scope.application_id {
            return Err(IdentityError::InvalidRequest);
        }
        request.body()?;
        if request.registration_grant.expose().is_empty() {
            key.validate_direct()?;
        }
        self.pending = Some(Pending::Register(request, key));
        self.retry_pending().await
    }
    pub async fn refresh(&mut self, key: IdempotencyKey) -> Result<(), IdentityError> {
        if self.reset_pending.is_some() || self.pending.is_some() || self.dirty {
            return Err(IdentityError::PendingMutation);
        }
        let identity = self.identity.clone().ok_or(IdentityError::NoIdentity)?;
        self.pending = Some(Pending::Refresh(identity, key));
        self.retry_pending().await
    }
    /// Retries exactly the original key/body/token. Server replay windows remain finite.
    pub async fn retry_pending(&mut self) -> Result<(), IdentityError> {
        let next = match self.pending.clone().ok_or(IdentityError::NoIdentity)? {
            Pending::Register(request, key) => self.client.register(&request, &key).await?,
            Pending::Refresh(identity, key) => self.client.refresh(&identity, &key).await?,
        };
        self.identity = Some(next);
        self.pending = None;
        self.dirty = true;
        self.retry_persist().await
    }
    /// A failed or cancelled save never rolls back the newly issued credential.
    pub async fn retry_persist(&mut self) -> Result<(), IdentityError> {
        if !self.dirty {
            return Ok(());
        }
        let identity = self.identity.clone().ok_or(IdentityError::NoIdentity)?;
        self.revision = match self
            .store
            .save(&self.scope, self.revision, identity.clone())
            .await
        {
            Ok(revision) => revision,
            Err(error) => {
                // A cancelled adapter may already have atomically committed this exact value.
                // Read back only to recognize our own result, never overwrite another writer.
                let snapshot = self
                    .store
                    .load(&self.scope)
                    .await
                    .map_err(IdentityError::Storage)?;
                if snapshot.revision > self.revision
                    && snapshot.identity.as_ref().is_some_and(|stored| {
                        stored.device_id == identity.device_id
                            && stored.expires_at == identity.expires_at
                            && stored.device_credential.expose()
                                == identity.device_credential.expose()
                    })
                {
                    snapshot.revision
                } else {
                    return Err(IdentityError::Storage(error));
                }
            }
        };
        self.dirty = false;
        Ok(())
    }
}
