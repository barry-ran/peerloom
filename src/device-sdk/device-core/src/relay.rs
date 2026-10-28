//! 已授权会话的托管 TURN 配置。只获取 gen1 初始配置，不承诺 ICE restart。
use crate::identity::{IdentityClient, IdentityError};
use device_storage::SecretString;
use device_transport_webrtc::RTCIceServer;
use reqwest::Method;
use serde::{Deserialize, Deserializer};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SecretString, D::Error> {
    String::deserialize(deserializer).map(SecretString::new)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireServer {
    urls: Vec<String>,
    #[serde(deserialize_with = "secret")]
    username: SecretString,
    #[serde(deserialize_with = "secret")]
    credential: SecretString,
    expires_at: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    session_id: String,
    negotiation_generation: u32,
    ice_servers: Vec<WireServer>,
}

/// No Debug implementation: even authenticated ICE configuration is secret.
/// The backend RTCIceServer owns ordinary string copies; this does not claim
/// that every third-party WebRTC allocation is zeroized on drop.
pub struct ManagedIceServers {
    servers: Vec<RTCIceServer>,
    earliest_expiry: Option<OffsetDateTime>,
}
impl ManagedIceServers {
    /// Credentials need to be live when beginning a new allocation. Their REST
    /// expiry is not an authorization lease or a timer to kill existing data.
    pub fn into_live_servers(self) -> Result<Vec<RTCIceServer>, IdentityError> {
        if self
            .earliest_expiry
            .is_some_and(|expiry| expiry <= OffsetDateTime::now_utc())
        {
            return Err(IdentityError::InvalidResponse);
        }
        Ok(self.servers)
    }
}

fn parse(
    data: &[u8],
    session_id: &str,
    now: OffsetDateTime,
) -> Result<ManagedIceServers, IdentityError> {
    let wire: WireResponse =
        serde_json::from_slice(data).map_err(|_| IdentityError::InvalidResponse)?;
    if wire.session_id != session_id
        || wire.negotiation_generation != 1
        || wire.ice_servers.len() > 4
    {
        return Err(IdentityError::InvalidResponse);
    }
    let mut servers = Vec::with_capacity(wire.ice_servers.len());
    let mut earliest_expiry: Option<OffsetDateTime> = None;
    for server in wire.ice_servers {
        let expiry = OffsetDateTime::parse(&server.expires_at, &Rfc3339)
            .map_err(|_| IdentityError::InvalidResponse)?;
        if expiry.nanosecond() != 0 || expiry <= now || expiry > now + time::Duration::minutes(11) {
            return Err(IdentityError::InvalidResponse);
        }
        if server.urls.len() != 1 || !valid_turn_url(&server.urls[0]) {
            return Err(IdentityError::InvalidResponse);
        }
        let username = server.username.expose();
        let Some((timestamp, nonce)) = username.split_once(':') else {
            return Err(IdentityError::InvalidResponse);
        };
        if timestamp != expiry.unix_timestamp().to_string()
            || nonce.len() != 22
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(IdentityError::InvalidResponse);
        }
        let password = server.credential.expose();
        if password.len() != 28
            || !password.ends_with('=')
            || !password[..27]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        {
            return Err(IdentityError::InvalidResponse);
        }
        earliest_expiry = Some(earliest_expiry.map_or(expiry, |old| old.min(expiry)));
        servers.push(RTCIceServer {
            urls: server.urls,
            username: username.to_owned(),
            credential: password.to_owned(),
        });
    }
    Ok(ManagedIceServers {
        servers,
        earliest_expiry,
    })
}

fn valid_turn_url(value: &str) -> bool {
    if !value.is_ascii()
        || value.len() > 2048
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || value.contains(['#', '@', '/', '\\'])
    {
        return false;
    }
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    if scheme != "turn" && scheme != "turns" {
        return false;
    }
    let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
    if !matches!(query, "" | "transport=udp" | "transport=tcp")
        || (scheme == "turns" && query == "transport=udp")
    {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(&format!("https://{authority}")) else {
        return false;
    };
    // A managed node has an explicit port and no extra URL components. Its
    // hostname/address network policy was approved by the operator, not the SDK.
    authority
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok_and(|port| port != 0))
        && url.host_str().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}

impl IdentityClient {
    pub async fn session_ice_servers(
        &self,
        session_id: &str,
        credential: &SecretString,
    ) -> Result<ManagedIceServers, IdentityError> {
        let token = credential.expose();
        if token.len() != 47
            || !token.starts_with("dev_")
            || !token[4..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(IdentityError::InvalidRequest);
        }
        let id = uuid::Uuid::parse_str(session_id).map_err(|_| IdentityError::InvalidRequest)?;
        let session_id = id.to_string();
        let bytes = self
            .request(
                Method::GET,
                &format!("/v1/device-sessions/{session_id}/ice-servers"),
                Some(credential),
                None,
                None,
                200,
            )
            .await?;
        parse(&bytes, &session_id, OffsetDateTime::now_utc())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const ID: &str = "00000000-0000-0000-0000-000000000001";

    fn response(now: OffsetDateTime) -> serde_json::Value {
        let expiry = now + time::Duration::minutes(5);
        json!({"session_id":ID,"negotiation_generation":1,"ice_servers":[{
            "urls":["turn:relay.example.com:3478?transport=udp"],
            "username":format!("{}:abcdefghijklmnopqrstuv",expiry.unix_timestamp()),
            "credential":"abcdefghijklmnopqrstuvwxyza=",
            "expires_at":expiry.format(&Rfc3339).unwrap()
        }]})
    }
    #[test]
    fn managed_configuration_is_bounded_and_session_scoped() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let value = response(now);
        assert!(parse(&serde_json::to_vec(&value).unwrap(), ID, now).is_ok());
        let mut cases = Vec::new();
        let mut wrong = value.clone();
        wrong["session_id"] = json!("00000000-0000-0000-0000-000000000002");
        cases.push(wrong);
        let mut wrong = value.clone();
        wrong["negotiation_generation"] = json!(2);
        cases.push(wrong);
        let mut wrong = value.clone();
        wrong["ice_servers"] = json!(vec![value["ice_servers"][0].clone(); 5]);
        cases.push(wrong);
        for url in [
            "stun:host:3478",
            "turn:secret@host:3478",
            "turn:host:3478/path",
            "turns:host:3478?transport=udp",
        ] {
            let mut wrong = value.clone();
            wrong["ice_servers"][0]["urls"] = json!([url]);
            cases.push(wrong);
        }
        for wrong in cases {
            assert!(parse(&serde_json::to_vec(&wrong).unwrap(), ID, now).is_err());
        }
        assert!(
            parse(
                &serde_json::to_vec(&value).unwrap(),
                ID,
                now + time::Duration::minutes(6)
            )
            .is_err()
        );
        let empty = json!({"session_id":ID,"negotiation_generation":1,"ice_servers":[]});
        assert!(
            parse(&serde_json::to_vec(&empty).unwrap(), ID, now)
                .unwrap()
                .servers
                .is_empty()
        );
    }
}
