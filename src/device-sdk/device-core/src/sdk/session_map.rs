//! Actor-owned connection admission. Pending requests consume the same finite
//! budget as authorizing/connecting/ready/recovering sessions. No WSS or task is
//! created here; one identity actor owns this map and all transport generations.
use std::collections::{BTreeMap, BTreeSet};
const LIFETIME_SESSIONS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Reservation(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MapError {
    InvalidCapacity,
    InvalidIdentifier,
    Full,
    UnknownReservation,
    DuplicateRequest,
    DuplicateSession,
    RequestMismatch,
    TargetMismatch,
    Closed,
}

struct Pending {
    target: String,
    request: Option<String>,
}

pub(super) struct SessionMap<T> {
    capacity: usize,
    next_reservation: u64,
    pending: BTreeMap<Reservation, Pending>,
    sessions: BTreeMap<String, T>,
    seen: BTreeSet<String>,
    closed: bool,
}

impl<T> SessionMap<T> {
    pub(super) fn new(capacity: usize) -> Result<Self, MapError> {
        if !(1..=1024).contains(&capacity) {
            return Err(MapError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            next_reservation: 0,
            pending: BTreeMap::new(),
            sessions: BTreeMap::new(),
            seen: BTreeSet::new(),
            closed: false,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.pending.len() + self.sessions.len()
    }

    fn identifier(value: &str) -> Result<(), MapError> {
        // Actor additionally validates UUID syntax and authenticated peers. Bound
        // memory here too, so the admission container cannot accept huge keys.
        if value.is_empty() || value.len() > 128 || !value.is_ascii() {
            Err(MapError::InvalidIdentifier)
        } else {
            Ok(())
        }
    }

    fn admission(&self) -> Result<(), MapError> {
        if self.closed {
            Err(MapError::Closed)
        } else if self.len() >= self.capacity
            || self.seen.len() + self.pending.len() >= LIFETIME_SESSIONS
        {
            Err(MapError::Full)
        } else {
            Ok(())
        }
    }

    /// Reserve BEFORE awaiting WSS send; bind its returned request id afterward.
    /// Reservation ids never repeat, including after failures and bulk shutdown.
    pub(super) fn reserve_outgoing(&mut self, target: String) -> Result<Reservation, MapError> {
        self.admission()?;
        Self::identifier(&target)?;
        let next = self.next_reservation.checked_add(1).ok_or(MapError::Full)?;
        self.next_reservation = next;
        let id = Reservation(next);
        self.pending.insert(
            id,
            Pending {
                target,
                request: None,
            },
        );
        Ok(id)
    }

    pub(super) fn bind_request(
        &mut self,
        reservation: Reservation,
        request: String,
    ) -> Result<(), MapError> {
        Self::identifier(&request)?;
        if self.closed {
            return Err(MapError::Closed);
        }
        if self
            .pending
            .values()
            .any(|value| value.request.as_ref() == Some(&request))
        {
            return Err(MapError::DuplicateRequest);
        }
        let pending = self
            .pending
            .get_mut(&reservation)
            .ok_or(MapError::UnknownReservation)?;
        if pending.request.is_some() {
            return Err(MapError::RequestMismatch);
        }
        pending.request = Some(request);
        Ok(())
    }

    /// Validate request correlation and peer identity before transferring a slot.
    /// Failed promotion is atomic: the old reservation remains charged.
    pub(super) fn promote(
        &mut self,
        request: &str,
        target: &str,
        session_id: String,
        value: T,
    ) -> Result<(), MapError> {
        Self::identifier(&session_id)?;
        if self.closed {
            return Err(MapError::Closed);
        }
        if self.seen.contains(&session_id) {
            return Err(MapError::DuplicateSession);
        }
        let (reservation, pending) = self
            .pending
            .iter()
            .find(|(_, value)| value.request.as_deref() == Some(request))
            .ok_or(MapError::RequestMismatch)?;
        if pending.target != target {
            return Err(MapError::TargetMismatch);
        }
        let reservation = *reservation;
        self.pending.remove(&reservation);
        self.seen.insert(session_id.clone());
        self.sessions.insert(session_id, value);
        Ok(())
    }

    pub(super) fn insert_incoming(&mut self, session_id: String, value: T) -> Result<(), MapError> {
        Self::identifier(&session_id)?;
        if self.closed {
            return Err(MapError::Closed);
        }
        if self.seen.contains(&session_id) {
            return Err(MapError::DuplicateSession);
        }
        self.admission()?;
        self.seen.insert(session_id.clone());
        self.sessions.insert(session_id, value);
        Ok(())
    }

    pub(super) fn release_reservation(&mut self, reservation: Reservation) -> bool {
        self.pending.remove(&reservation).is_some()
    }

    pub(super) fn pending_target(&self, request: &str) -> Option<&str> {
        self.pending
            .values()
            .find(|pending| pending.request.as_deref() == Some(request))
            .map(|pending| pending.target.as_str())
    }

    pub(super) fn reject_request(&mut self, request: &str) -> bool {
        let reservation = self
            .pending
            .iter()
            .find_map(|(id, value)| (value.request.as_deref() == Some(request)).then_some(*id));
        reservation.is_some_and(|id| self.release_reservation(id))
    }

    /// WSS loss makes unsynchronized request outcomes unknown. Never replay them.
    pub(super) fn drain_pending(&mut self) -> Vec<(String, Option<String>)> {
        std::mem::take(&mut self.pending)
            .into_values()
            .map(|pending| (pending.target, pending.request))
            .collect()
    }

    pub(super) fn has_seen(&self, id: &str) -> bool {
        self.seen.contains(id)
    }

    pub(super) fn get(&self, id: &str) -> Option<&T> {
        self.sessions.get(id)
    }
    pub(super) fn get_mut(&mut self, id: &str) -> Option<&mut T> {
        self.sessions.get_mut(id)
    }
    pub(super) fn remove(&mut self, id: &str) -> Option<T> {
        self.sessions.remove(id)
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&str, &T)> {
        self.sessions.iter().map(|(id, value)| (id.as_str(), value))
    }
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (&str, &mut T)> {
        self.sessions
            .iter_mut()
            .map(|(id, value)| (id.as_str(), value))
    }

    /// Admission closes synchronously; caller first fences EVERY value's gate,
    /// then drains and joins all workers under ONE overall shutdown deadline.
    pub(super) fn close_admission(&mut self) {
        self.closed = true;
    }
    pub(super) fn drain_sessions(&mut self) -> impl Iterator<Item = T> {
        std::mem::take(&mut self.sessions).into_values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_session_never_readmitted_and_lifetime_budget_is_bounded() {
        let mut map = SessionMap::new(2).unwrap();
        map.insert_incoming("first".into(), 1).unwrap();
        map.remove("first");
        assert!(map.has_seen("first"));
        assert_eq!(
            map.insert_incoming("first".into(), 2),
            Err(MapError::DuplicateSession)
        );
        for n in 1..LIFETIME_SESSIONS {
            let id = format!("session-{n}");
            map.insert_incoming(id.clone(), n).unwrap();
            if n != LIFETIME_SESSIONS - 1 {
                map.remove(&id);
            }
        }
        assert_eq!(map.reserve_outgoing("new".into()), Err(MapError::Full));
        assert_eq!(map.get("session-1023"), Some(&1023));
        assert_eq!(map.insert_incoming("new".into(), 0), Err(MapError::Full));
        assert!(map.has_seen("first"));
    }

    #[test]
    fn pending_authorizing_and_connecting_share_capacity() {
        let mut map = SessionMap::new(3).unwrap();
        let first = map.reserve_outgoing("peer-a".into()).unwrap();
        map.bind_request(first, "request-a".into()).unwrap();
        map.insert_incoming("authorizing".into(), "waiting consent")
            .unwrap();
        map.insert_incoming("connecting".into(), "waiting transport")
            .unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.reserve_outgoing("peer-b".into()), Err(MapError::Full));
        map.promote("request-a", "peer-a", "ready".into(), "connected")
            .unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.insert_incoming("overflow".into(), "denied"),
            Err(MapError::Full)
        );
    }

    #[test]
    fn failed_correlation_does_not_release_or_overwrite() {
        let mut map = SessionMap::new(2).unwrap();
        let reservation = map.reserve_outgoing("peer-a".into()).unwrap();
        map.bind_request(reservation, "request-a".into()).unwrap();
        map.insert_incoming("existing".into(), 1).unwrap();
        assert_eq!(
            map.promote("request-a", "peer-b", "new".into(), 2),
            Err(MapError::TargetMismatch)
        );
        assert_eq!(
            map.promote("wrong", "peer-a", "new".into(), 2),
            Err(MapError::RequestMismatch)
        );
        assert_eq!(
            map.promote("request-a", "peer-a", "existing".into(), 2),
            Err(MapError::DuplicateSession)
        );
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("existing"), Some(&1));
        map.promote("request-a", "peer-a", "new".into(), 2).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("new"), Some(&2));
    }

    #[test]
    fn duplicate_request_binding_preserves_each_reservation() {
        let mut map: SessionMap<()> = SessionMap::new(2).unwrap();
        let first = map.reserve_outgoing("a".into()).unwrap();
        let second = map.reserve_outgoing("b".into()).unwrap();
        map.bind_request(first, "same".into()).unwrap();
        assert_eq!(
            map.bind_request(second, "same".into()),
            Err(MapError::DuplicateRequest)
        );
        assert_eq!(map.len(), 2);
        map.bind_request(second, "different".into()).unwrap();
        assert!(map.reject_request("same"));
        assert!(!map.reject_request("same"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn generation_replacement_and_single_failure_leave_siblings() {
        let mut map = SessionMap::new(2).unwrap();
        map.insert_incoming("a".into(), 1).unwrap();
        map.insert_incoming("b".into(), 7).unwrap();
        *map.get_mut("a").unwrap() = 2;
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("b"), Some(&7));
        assert_eq!(map.remove("a"), Some(2));
        assert_eq!(map.get("b"), Some(&7));
        map.reserve_outgoing("c".into()).unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn disconnect_releases_only_unknown_pending_not_live_sessions() {
        let mut map = SessionMap::new(3).unwrap();
        map.insert_incoming("live".into(), 1).unwrap();
        map.reserve_outgoing("a".into()).unwrap();
        map.reserve_outgoing("b".into()).unwrap();
        assert_eq!(map.drain_pending().len(), 2);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("live"), Some(&1));
    }

    #[test]
    fn shutdown_fences_all_before_drain_and_never_reopens() {
        let mut map = SessionMap::new(3).unwrap();
        map.insert_incoming("a".into(), false).unwrap();
        map.insert_incoming("b".into(), false).unwrap();
        map.reserve_outgoing("c".into()).unwrap();
        map.close_admission();
        for (_, closed) in map.iter_mut() {
            *closed = true;
        }
        assert!(map.iter().all(|(_, closed)| *closed));
        assert_eq!(map.drain_pending().len(), 1);
        assert!(map.drain_sessions().all(|closed| closed));
        assert_eq!(map.len(), 0);
        assert_eq!(map.reserve_outgoing("d".into()), Err(MapError::Closed));
        assert_eq!(
            map.insert_incoming("late".into(), false),
            Err(MapError::Closed)
        );
    }

    #[test]
    fn stale_reservation_and_counter_wrap_do_not_alias() {
        let mut map: SessionMap<()> = SessionMap::new(1).unwrap();
        let old = map.reserve_outgoing("a".into()).unwrap();
        assert!(map.release_reservation(old));
        let new = map.reserve_outgoing("a".into()).unwrap();
        assert_ne!(old, new);
        assert!(!map.release_reservation(old));
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.bind_request(old, "stale".into()),
            Err(MapError::UnknownReservation)
        );
        map.release_reservation(new);
        map.next_reservation = u64::MAX;
        assert_eq!(map.reserve_outgoing("a".into()), Err(MapError::Full));
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn identifier_storage_is_bounded_without_mutating_admission() {
        let mut map: SessionMap<()> = SessionMap::new(1).unwrap();
        assert_eq!(
            map.reserve_outgoing("x".repeat(129)),
            Err(MapError::InvalidIdentifier)
        );
        assert_eq!(
            map.insert_incoming(String::new(), ()),
            Err(MapError::InvalidIdentifier)
        );
        assert_eq!(map.len(), 0);
        let id = map.reserve_outgoing("valid".into()).unwrap();
        assert_eq!(
            map.bind_request(id, "x".repeat(129)),
            Err(MapError::InvalidIdentifier)
        );
        assert_eq!(map.len(), 1);
        map.bind_request(id, "request".into()).unwrap();
    }

    #[test]
    fn capacity_is_always_finite_nonzero() {
        assert!(matches!(
            SessionMap::<()>::new(0),
            Err(MapError::InvalidCapacity)
        ));
        assert!(matches!(
            SessionMap::<()>::new(1025),
            Err(MapError::InvalidCapacity)
        ));
        assert!(SessionMap::<()>::new(1024).is_ok());
    }
}
