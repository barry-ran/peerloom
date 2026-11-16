use super::SignalError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IceCandidate {
    pub candidate: String,
    pub sdp_mid: String,
    pub sdp_mline_index: u16,
    pub username_fragment: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IceBatch {
    pub candidates: Vec<IceCandidate>,
    pub complete: bool,
}
impl IceBatch {
    pub fn parse(value: &Value) -> Result<Self, SignalError> {
        if serde_json::to_vec(value)
            .map_err(|_| SignalError::InvalidMessage)?
            .len()
            > device_protocol::ICE_MAX_PAYLOAD_BYTES
        {
            return Err(SignalError::InvalidMessage);
        }
        let batch: Self =
            serde_json::from_value(value.clone()).map_err(|_| SignalError::InvalidMessage)?;
        let protocol = device_protocol::IceBatch {
            candidates: batch
                .candidates
                .iter()
                .map(|c| device_protocol::IceCandidate {
                    candidate: c.candidate.clone(),
                    sdp_mid: c.sdp_mid.clone(),
                    sdp_mline_index: c.sdp_mline_index,
                    username_fragment: c.username_fragment.clone(),
                })
                .collect(),
            complete: batch.complete,
        };
        if !protocol.validate() {
            return Err(SignalError::InvalidMessage);
        }
        Ok(batch)
    }
    pub fn bytes(&self) -> usize {
        self.candidates
            .iter()
            .map(|c| c.candidate.len() + c.sdp_mid.len() + c.username_fragment.len())
            .sum()
    }
    pub fn dedup_pending(&mut self, pending: &[Self]) -> bool {
        let mut unique = Vec::new();
        for candidate in std::mem::take(&mut self.candidates) {
            if !unique.contains(&candidate)
                && !pending
                    .iter()
                    .any(|batch| batch.candidates.contains(&candidate))
            {
                unique.push(candidate);
            }
        }
        self.candidates = unique;
        !self.candidates.is_empty() || self.complete
    }
    pub fn transport_candidates(&self) -> Vec<device_transport_webrtc::IceCandidate> {
        self.candidates
            .iter()
            .map(|c| device_transport_webrtc::IceCandidate {
                candidate: c.candidate.clone(),
                sdp_mid: c.sdp_mid.clone(),
                sdp_mline_index: c.sdp_mline_index,
                username_fragment: c.username_fragment.clone(),
            })
            .collect()
    }
    pub fn local(candidate: Option<device_transport_webrtc::IceCandidate>) -> Self {
        let complete = candidate.is_none();
        Self {
            candidates: candidate
                .into_iter()
                .map(|c| IceCandidate {
                    candidate: c.candidate,
                    sdp_mid: c.sdp_mid,
                    sdp_mline_index: c.sdp_mline_index,
                    username_fragment: c.username_fragment,
                })
                .collect(),
            complete,
        }
    }
}
#[derive(Default)]
pub(crate) struct IceBudget {
    count: usize,
    bytes: usize,
    complete: bool,
}
impl IceBudget {
    // Count duplicates before transport deduplication; empty completion is idempotent.
    pub fn admit(&mut self, batch: &IceBatch) -> Result<bool, SignalError> {
        let count = self.count + batch.candidates.len();
        let bytes = self.bytes + batch.bytes();
        if count > device_protocol::ICE_MAX_CANDIDATES
            || bytes > device_protocol::ICE_MAX_TOTAL_BYTES
        {
            return Err(SignalError::QueueFull);
        }
        self.count = count;
        self.bytes = bytes;
        let deliver = !self.complete;
        self.complete |= batch.complete;
        Ok(deliver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn candidate() -> Value {
        json!({"candidate":"candidate:1 1 UDP 1 192.0.2.1 1234 typ host",
            "sdp_mid":"0","sdp_mline_index":0,"username_fragment":"test"})
    }
    #[test]
    fn strict_wire_requires_fields_and_bounds_without_coercion() {
        let good = json!({"candidates":[candidate()],"complete":false});
        assert!(IceBatch::parse(&good).is_ok());
        for bad in [
            json!({"candidates":[],"complete":false}),
            json!({"candidates":[],"complete":null}),
            json!({"candidates":[],"complete":true,"extra":1}),
            json!({"candidates":[candidate()]}),
        ] {
            assert!(IceBatch::parse(&bad).is_err());
        }
        for (key, value) in [
            ("sdp_mid", json!("")),
            ("username_fragment", json!(null)),
            ("sdp_mline_index", json!(65536)),
            ("candidate", json!("x".repeat(4097))),
        ] {
            let mut bad = good.clone();
            bad["candidates"][0][key] = value;
            assert!(IceBatch::parse(&bad).is_err());
        }
        assert!(
            IceBatch::parse(&json!({"candidates":vec![candidate();17],"complete":false})).is_err()
        );
    }
    #[test]
    fn duplicates_consume_budget_end_is_idempotent_and_late_candidates_are_budgeted() {
        let batch = IceBatch::parse(&json!({"candidates":[candidate()],"complete":false})).unwrap();
        let mut budget = IceBudget::default();
        for _ in 0..256 {
            assert_eq!(budget.admit(&batch), Ok(true));
        }
        assert_eq!(budget.admit(&batch), Err(SignalError::QueueFull));
        let end = IceBatch::parse(&json!({"candidates":[],"complete":true})).unwrap();
        assert_eq!(budget.admit(&end), Ok(true));
        for _ in 0..1000 {
            assert_eq!(budget.admit(&end), Ok(false));
        }
        assert_eq!(budget.admit(&batch), Err(SignalError::QueueFull));
        let mut fresh = IceBudget::default();
        assert_eq!(fresh.admit(&end), Ok(true));
        assert_eq!(fresh.admit(&batch), Ok(false));
        assert_eq!(fresh.count, 1);
        assert_eq!(fresh.admit(&end), Ok(false));
    }
    #[test]
    fn byte_limit_counts_utf8_and_rejection_is_atomic() {
        let mut value = candidate();
        value["candidate"] = json!("x".repeat(4096));
        let batch = IceBatch::parse(&json!({"candidates":[value],"complete":false})).unwrap();
        let mut budget = IceBudget::default();
        while budget.bytes + batch.bytes() <= device_protocol::ICE_MAX_TOTAL_BYTES {
            budget.admit(&batch).unwrap();
        }
        let before = (budget.count, budget.bytes);
        assert_eq!(budget.admit(&batch), Err(SignalError::QueueFull));
        assert_eq!((budget.count, budget.bytes), before);
        let mut value = candidate();
        value["candidate"] = json!("\"".repeat(4096));
        assert!(
            IceBatch::parse(
                &json!({"candidates":[value.clone(),value.clone(),value],"complete":false})
            )
            .is_err()
        );
    }
}
