use super::*;

/// Whether the exchanged local SDP represents completed gathering or a bounded
/// Auto fallback. Late candidates are not implicitly signaled to the remote peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatheringOutcome {
    Pending,
    Complete,
    PartialAtDeadline,
}

impl PeerTransport {
    pub fn gathering_outcome(&self) -> GatheringOutcome {
        match self.gathering_outcome.load(Ordering::Acquire) {
            1 => GatheringOutcome::Complete,
            2 => GatheringOutcome::PartialAtDeadline,
            _ => GatheringOutcome::Pending,
        }
    }

    pub(super) async fn gathered_description(&self) -> Result<SessionDescription, TransportError> {
        let deadline = tokio::time::Instant::now() + self.config.operation_timeout;
        let mut closed = self.close_signal.subscribe();
        let mut candidates = self.candidates.clone();
        // At most one already-validated, size-bounded snapshot from this peer's
        // one-shot negotiation. No work/lock acquisition is started after deadline.
        let mut fallback = None;
        #[cfg(feature = "test-diagnostics")]
        let mut diagnostic = Trace::new(Phase::GatherLock);
        let collect = async {
            let mut gathered = self.gathered.lock().await;
            let mut refresh = true;
            loop {
                self.ensure_open()?;
                let complete = *gathered.borrow_and_update();
                if complete || (refresh && self.config.policy == ConnectionPolicy::Auto) {
                    refresh = false;
                    #[cfg(feature = "test-diagnostics")]
                    diagnostic.enter(Phase::GatherReadLocal);
                    let description = self
                        .peer
                        .local_description()
                        .await
                        .ok_or(TransportError::WebRtc)?;
                    #[cfg(feature = "test-diagnostics")]
                    diagnostic.enter(Phase::GatherValidate);
                    validate_remote_sdp(&self.config, &description)?;
                    self.ensure_open()?;
                    if complete {
                        #[cfg(feature = "test-diagnostics")]
                        diagnostic.enter(Phase::GatherDone);
                        self.gathering_outcome.store(1, Ordering::Release);
                        return Ok(description);
                    }
                    if has_nonrelay_candidate(&description)? {
                        fallback = Some(description);
                    }
                }
                #[cfg(feature = "test-diagnostics")]
                diagnostic.enter(Phase::GatherWait);
                tokio::select! {
                    changed = gathered.changed() => { changed.map_err(|_| TransportError::Closed)?; },
                    changed = candidates.changed(), if self.config.policy == ConnectionPolicy::Auto => {
                        changed.map_err(|_| TransportError::Closed)?;
                        refresh = true;
                    }
                }
            }
        };
        let result = tokio::select! {
            biased;
            _ = closed.changed() => return Err(TransportError::Closed),
            result = tokio::time::timeout_at(deadline, collect) => result,
        };
        self.ensure_open()?;
        match result {
            Ok(result) => result,
            Err(_) if self.config.policy == ConnectionPolicy::Auto => {
                let description = fallback.ok_or(TransportError::Timeout)?;
                self.gathering_outcome.store(2, Ordering::Release);
                Ok(description)
            }
            Err(_) => Err(TransportError::Timeout),
        }
    }
}

fn has_nonrelay_candidate(description: &SessionDescription) -> Result<bool, TransportError> {
    for line in description.sdp.lines() {
        if let Some(raw) = line.trim().strip_prefix("a=candidate:") {
            let candidate = rtc::ice::candidate::unmarshal_candidate(raw)
                .map_err(|_| TransportError::InvalidCandidate)?;
            if matches!(
                candidate.candidate_type(),
                rtc::ice::candidate::CandidateType::Host
                    | rtc::ice::candidate::CandidateType::ServerReflexive
                    | rtc::ice::candidate::CandidateType::PeerReflexive
            ) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_relay_only_snapshots_are_not_direct_fallbacks() {
        let mut description = SessionDescription::default();
        assert!(!has_nonrelay_candidate(&description).unwrap());
        description.sdp = "a=candidate:1 1 udp 1 192.0.2.1 3478 typ relay\r\n".into();
        assert!(!has_nonrelay_candidate(&description).unwrap());
        description.sdp = "a=candidate:1 1 udp 1 192.0.2.1 3478 typ host\r\n".into();
        assert!(has_nonrelay_candidate(&description).unwrap());
        description.sdp = "a=candidate:malformed\r\n".into();
        assert!(matches!(
            has_nonrelay_candidate(&description),
            Err(TransportError::InvalidCandidate)
        ));
    }
}
