//! 独占快照的严格版本边界；不推断业务角色，不把epoch当Bearer。
use crate::{lease::LeaseError, signaling::Envelope};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
#[derive(Clone, Debug)]
pub(crate) struct ExclusiveSnapshot {
    pub epoch: u64,
    pub prepared: bool,
    pub connect_deadline: OffsetDateTime,
    pub fence_required: bool,
}
impl ExclusiveSnapshot {
    pub fn parse(message: &Envelope) -> Result<Option<Self>, LeaseError> {
        let p = &message.payload;
        #[cfg(feature = "test-diagnostics")]
        if p["exclusive_target"] == true {
            eprintln!(
                "exclusive_shape version_ok={} epoch_string={} epoch_valid={} epoch_echo={} prepared_bool={} fence_bool={} fenced_bool={} connect_z={} release_z={} held={} closing={} released={} authorizing={} closed={}",
                p["exclusive_protocol_version"].as_u64() == Some(1),
                p["target_epoch"].is_string(),
                p["target_epoch"]
                    .as_str()
                    .and_then(device_protocol::parse_target_epoch)
                    .is_some(),
                message.target_epoch.as_deref() == p["target_epoch"].as_str(),
                p["prepared"].is_boolean(),
                p["fence_required"].is_boolean(),
                p["target_fenced"].is_boolean(),
                p["connect_deadline"]
                    .as_str()
                    .is_some_and(|v| v.ends_with('Z')),
                p["release_not_before"]
                    .as_str()
                    .is_some_and(|v| v.ends_with('Z')),
                p["exclusive_release_state"] == "held",
                p["exclusive_release_state"] == "closing",
                p["exclusive_release_state"] == "released",
                p["state"] == "authorizing",
                p["state"] == "closed"
            );
        }

        match p.get("exclusive_target") {
            None | Some(serde_json::Value::Bool(false)) => {
                if message.target_epoch.is_some()
                    || p.get("target_epoch").is_some()
                    || p.get("exclusive_protocol_version").is_some()
                {
                    return Err(LeaseError::InvalidUpdate);
                }
                return Ok(None);
            }
            Some(serde_json::Value::Bool(true)) => {}
            _ => return Err(LeaseError::InvalidUpdate),
        }
        if p["exclusive_protocol_version"].as_u64() != Some(1) {
            return Err(LeaseError::InvalidUpdate);
        }
        let text = p["target_epoch"]
            .as_str()
            .ok_or(LeaseError::InvalidUpdate)?;
        let epoch = device_protocol::parse_target_epoch(text).ok_or(LeaseError::InvalidUpdate)?;
        if message.target_epoch.as_deref() != Some(text) {
            return Err(LeaseError::InvalidUpdate);
        }
        let boolean = |key: &str| p[key].as_bool().ok_or(LeaseError::InvalidUpdate);
        let timestamp = |key: &str| {
            let value = p[key].as_str().ok_or(LeaseError::InvalidUpdate)?;
            if !value.ends_with('Z') {
                return Err(LeaseError::InvalidUpdate);
            }
            OffsetDateTime::parse(value, &Rfc3339).map_err(|_| LeaseError::InvalidUpdate)
        };
        let prepared = boolean("prepared")?;
        let fence_required = boolean("fence_required")?;
        let fenced = boolean("target_fenced")?;
        let connect_deadline = timestamp("connect_deadline")?;
        let _release_not_before = timestamp("release_not_before")?;
        let release = p["exclusive_release_state"]
            .as_str()
            .ok_or(LeaseError::InvalidUpdate)?;
        if !matches!(release, "held" | "closing" | "released")
            || (fenced && release != "released")
            || (fence_required && p["state"] != "closed")
            || (prepared && p["state"] != "authorizing" && p["state"] != "closed")
            || ((release == "held") == (p["state"] == "closed"))
        {
            return Err(LeaseError::InvalidUpdate);
        }
        Ok(Some(Self {
            epoch,
            prepared,
            connect_deadline,
            fence_required,
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    pub(crate) fn message() -> Envelope {
        serde_json::from_value(json!({"v":1,"type":"sync.snapshot","id":"00000000-0000-4000-8000-000000000001","session_id":"00000000-0000-4000-8000-000000000002","seq":1,"sent_at":"2026-10-29T12:00:00Z","target_epoch":"9223372036854775807","payload":{
            "session_id":"00000000-0000-4000-8000-000000000002","source_device_id":"00000000-0000-4000-8000-000000000003","target_device_id":"00000000-0000-4000-8000-000000000004","state":"authorizing","lease_generation":1,"negotiation_generation":1,
            "lease_expires_at":"2026-10-29T12:00:30Z","source_lease_expires_at":"2026-10-29T12:00:30Z","target_lease_expires_at":"2026-10-29T12:00:30Z",
            "exclusive_target":true,"exclusive_protocol_version":1,"target_epoch":"9223372036854775807","prepared":true,"connect_deadline":"2026-10-29T12:00:30Z","exclusive_release_state":"held","release_not_before":"2026-10-29T12:00:32Z","fence_required":false,"target_fenced":false
        }})).unwrap()
    }
    #[test]
    fn strict_version_epoch_and_fields_do_not_silently_downgrade() {
        let base = message();
        assert_eq!(
            ExclusiveSnapshot::parse(&base).unwrap().unwrap().epoch,
            i64::MAX as u64
        );
        for epoch in ["0", "01", "+1", "-1", "9223372036854775808", " 1"] {
            let mut value = base.clone();
            value.target_epoch = Some(epoch.into());
            value.payload["target_epoch"] = json!(epoch);
            assert!(ExclusiveSnapshot::parse(&value).is_err());
        }
        for (key, value) in [
            ("exclusive_protocol_version", json!(2)),
            ("prepared", json!(null)),
            ("target_epoch", json!(1)),
            ("fence_required", json!(true)),
            ("exclusive_release_state", json!("unknown")),
            ("release_not_before", json!(null)),
        ] {
            let mut message = base.clone();
            message.payload[key] = value;
            assert!(ExclusiveSnapshot::parse(&message).is_err());
        }
        let mut missing = base.clone();
        missing.target_epoch = None;
        assert!(ExclusiveSnapshot::parse(&missing).is_err());
        let mut downgraded = base;
        downgraded.payload["exclusive_target"] = json!(false);
        assert!(ExclusiveSnapshot::parse(&downgraded).is_err());
    }
}
