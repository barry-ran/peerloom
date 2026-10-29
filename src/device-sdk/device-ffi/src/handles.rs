//! Bounded current-handle ownership, without a historical handle tombstone set.
//! The boundary supplies its process-global, checked, never-reused ID allocator.
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

pub trait Validity: Clone {
    fn is_valid(&self) -> bool;
}

#[derive(Clone)]
pub struct ScopedValidity<V: Validity> {
    authorization: V,
    parent_authorization: Option<V>,
    parent_closed: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
}
impl<V: Validity> ScopedValidity<V> {
    pub fn is_valid(&self) -> bool {
        !self.parent_closed.load(Ordering::Acquire)
            && !self.closed.load(Ordering::Acquire)
            && self.authorization.is_valid()
            && self
                .parent_authorization
                .as_ref()
                .is_none_or(Validity::is_valid)
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleError {
    InvalidConfiguration,
    InvalidHandle,
    Closed,
    Full,
    Allocator,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    ReliableMessage,
    LowLatencyMessage,
    ReliableStream,
}
struct Channel<V: Validity> {
    gate: ScopedValidity<V>,
    kind: ChannelKind,
    write_closed: bool,
    message_ttl: Duration,
}
struct Connection<V: Validity> {
    gate: ScopedValidity<V>,
    channels: HashMap<u64, Channel<V>>,
}
impl<V: Validity> Drop for Connection<V> {
    fn drop(&mut self) {
        // Queued callbacks can retain gate clones after registry removal.
        self.gate.close();
    }
}

pub struct HandleRegistry<V: Validity> {
    connections: HashMap<u64, Connection<V>>,
    max_connections: usize,
    max_channels: usize,
}
impl<V: Validity> HandleRegistry<V> {
    pub fn new(max_connections: usize, max_channels: usize) -> Result<Self, HandleError> {
        Ok(Self {
            connections: HashMap::new(),
            max_connections,
            max_channels,
        })
    }
    pub fn add_connection(
        &mut self,
        authorization: V,
        allocate: impl FnOnce() -> Result<u64, HandleError>,
    ) -> Result<u64, HandleError> {
        if !authorization.is_valid() {
            return Err(HandleError::Closed);
        }
        if self.max_connections != 0 && self.connections.len() >= self.max_connections {
            return Err(HandleError::Full);
        }
        self.connections
            .try_reserve(1)
            .map_err(|_| HandleError::Full)?;
        let id = allocate()?;
        if id == 0 || self.connections.contains_key(&id) {
            return Err(HandleError::Allocator);
        }
        self.connections.insert(
            id,
            Connection {
                gate: ScopedValidity {
                    authorization,
                    parent_authorization: None,
                    parent_closed: Arc::new(AtomicBool::new(false)),
                    closed: Arc::new(AtomicBool::new(false)),
                },
                channels: HashMap::new(),
            },
        );
        Ok(id)
    }
    pub fn connection(&self, id: u64) -> Result<ScopedValidity<V>, HandleError> {
        let entry = self
            .connections
            .get(&id)
            .ok_or(HandleError::InvalidHandle)?;
        if !entry.gate.is_valid() {
            return Err(HandleError::Closed);
        }
        Ok(entry.gate.clone())
    }
    pub fn add_channel(
        &mut self,
        parent: u64,
        kind: ChannelKind,
        authorization: V,
        allocate: impl FnOnce() -> Result<u64, HandleError>,
    ) -> Result<u64, HandleError> {
        let entry = self
            .connections
            .get_mut(&parent)
            .ok_or(HandleError::InvalidHandle)?;
        if !entry.gate.is_valid() || !authorization.is_valid() {
            return Err(HandleError::Closed);
        }
        if self.max_channels != 0 && entry.channels.len() >= self.max_channels {
            return Err(HandleError::Full);
        }
        entry
            .channels
            .try_reserve(1)
            .map_err(|_| HandleError::Full)?;
        let id = allocate()?;
        if id == 0 || id == parent || entry.channels.contains_key(&id) {
            return Err(HandleError::Allocator);
        }
        entry.channels.insert(
            id,
            Channel {
                gate: ScopedValidity {
                    authorization,
                    parent_authorization: Some(entry.gate.authorization.clone()),
                    parent_closed: entry.gate.closed.clone(),
                    closed: Arc::new(AtomicBool::new(false)),
                },
                kind,
                write_closed: false,
                message_ttl: Duration::from_secs(30),
            },
        );
        Ok(id)
    }
    pub fn channel(&self, parent: u64, id: u64) -> Result<ScopedValidity<V>, HandleError> {
        let entry = self
            .connections
            .get(&parent)
            .ok_or(HandleError::InvalidHandle)?;
        let child = entry.channels.get(&id).ok_or(HandleError::InvalidHandle)?;
        if !entry.gate.is_valid() || !child.gate.is_valid() {
            return Err(HandleError::Closed);
        }
        Ok(child.gate.clone())
    }
    pub fn close_connection(&self, parent: u64) -> Result<(), HandleError> {
        self.connections
            .get(&parent)
            .ok_or(HandleError::InvalidHandle)?
            .gate
            .close();
        Ok(())
    }
    pub fn close_channel(&self, parent: u64, id: u64) -> Result<(), HandleError> {
        self.connections
            .get(&parent)
            .ok_or(HandleError::InvalidHandle)?
            .channels
            .get(&id)
            .ok_or(HandleError::InvalidHandle)?
            .gate
            .close();
        Ok(())
    }
    pub fn channel_kind(&self, parent: u64, id: u64) -> Result<ChannelKind, HandleError> {
        self.channel(parent, id)?;
        Ok(self.connections[&parent].channels[&id].kind)
    }
    pub fn set_message_ttl(
        &mut self,
        parent: u64,
        id: u64,
        ttl: Duration,
    ) -> Result<(), HandleError> {
        if ttl.is_zero() {
            return Err(HandleError::InvalidConfiguration);
        }
        self.channel(parent, id)?;
        self.connections
            .get_mut(&parent)
            .unwrap()
            .channels
            .get_mut(&id)
            .unwrap()
            .message_ttl = ttl;
        Ok(())
    }
    pub fn message_deadline(
        &self,
        parent: u64,
        id: u64,
        now: Instant,
    ) -> Result<Instant, HandleError> {
        self.channel(parent, id)?;
        now.checked_add(self.connections[&parent].channels[&id].message_ttl)
            .ok_or(HandleError::InvalidConfiguration)
    }
    pub fn check_writable(&self, parent: u64, id: u64) -> Result<(), HandleError> {
        self.channel(parent, id)?;
        if self.connections[&parent].channels[&id].write_closed {
            return Err(HandleError::Closed);
        }
        Ok(())
    }
    pub fn finish_write(&mut self, parent: u64, id: u64) -> Result<(), HandleError> {
        self.check_writable(parent, id)?;
        let child = self
            .connections
            .get_mut(&parent)
            .unwrap()
            .channels
            .get_mut(&id)
            .unwrap();
        if child.kind != ChannelKind::ReliableStream {
            return Err(HandleError::InvalidHandle);
        }
        child.write_closed = true;
        Ok(())
    }
    pub fn remove_channel(&mut self, parent: u64, id: u64) -> Result<(), HandleError> {
        let entry = self
            .connections
            .get_mut(&parent)
            .ok_or(HandleError::InvalidHandle)?;
        let child = entry
            .channels
            .remove(&id)
            .ok_or(HandleError::InvalidHandle)?;
        child.gate.close();
        Ok(())
    }
    pub fn remove_connection(&mut self, parent: u64) -> Result<(), HandleError> {
        self.connections
            .remove(&parent)
            .ok_or(HandleError::InvalidHandle)?;
        Ok(())
    }
    pub fn clear(&mut self) {
        self.connections.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone)]
    struct Gate(Arc<AtomicBool>);
    impl Gate {
        fn new() -> Self {
            Self(Arc::new(AtomicBool::new(true)))
        }
    }
    impl Validity for Gate {
        fn is_valid(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }
    #[test]
    fn unlimited_and_explicit_large_limits_grow_on_demand_and_fence_on_clear() {
        for limit in [0, 500] {
            let mut registry = HandleRegistry::new(limit, limit).unwrap();
            assert_eq!(registry.connections.capacity(), 0);
            let mut retained = Vec::new();
            for id in 1..=500 {
                registry.add_connection(Gate::new(), || Ok(id)).unwrap();
                retained.push(registry.connection(id).unwrap());
            }
            for id in 501..=1000 {
                registry
                    .add_channel(1, ChannelKind::ReliableMessage, Gate::new(), || Ok(id))
                    .unwrap();
                retained.push(registry.channel(1, id).unwrap());
            }
            if limit != 0 {
                assert_eq!(
                    registry.add_connection(Gate::new(), || Ok(1001)),
                    Err(HandleError::Full)
                );
                assert_eq!(
                    registry.add_channel(1, ChannelKind::ReliableMessage, Gate::new(), || Ok(1002)),
                    Err(HandleError::Full)
                );
            }
            registry.clear();
            assert!(retained.iter().all(|gate| !gate.is_valid()));
            assert!(registry.connections.is_empty());
        }
    }
    #[test]
    fn ownership_and_parent_close_fence_queued_child_clones() {
        let mut registry = HandleRegistry::new(2, 2).unwrap();
        let a = registry.add_connection(Gate::new(), || Ok(1)).unwrap();
        let b = registry.add_connection(Gate::new(), || Ok(2)).unwrap();
        let channel = registry
            .add_channel(a, ChannelKind::ReliableMessage, Gate::new(), || Ok(3))
            .unwrap();
        assert_eq!(
            registry.channel(b, channel).err(),
            Some(HandleError::InvalidHandle)
        );
        let queued = registry.channel(a, channel).unwrap();
        registry.close_connection(a).unwrap();
        assert!(!queued.is_valid());
        assert!(registry.connection(b).is_ok());
        registry.remove_connection(a).unwrap();
        assert_eq!(
            registry.channel(a, channel).err(),
            Some(HandleError::InvalidHandle)
        );
        assert!(!queued.is_valid());
    }
    #[test]
    fn child_close_does_not_close_sibling_and_removal_releases_slot() {
        let mut registry = HandleRegistry::new(1, 2).unwrap();
        let parent = registry.add_connection(Gate::new(), || Ok(1)).unwrap();
        let a = registry
            .add_channel(parent, ChannelKind::ReliableMessage, Gate::new(), || Ok(2))
            .unwrap();
        let b = registry
            .add_channel(parent, ChannelKind::ReliableMessage, Gate::new(), || Ok(3))
            .unwrap();
        let queued = registry.channel(parent, a).unwrap();
        assert_eq!(
            registry.add_channel(
                parent,
                ChannelKind::ReliableMessage,
                Gate::new(),
                || panic!("must not allocate")
            ),
            Err(HandleError::Full)
        );
        registry.close_channel(parent, a).unwrap();
        assert!(!queued.is_valid());
        assert!(registry.channel(parent, b).is_ok());
        registry.remove_channel(parent, a).unwrap();
        registry
            .add_channel(parent, ChannelKind::ReliableMessage, Gate::new(), || Ok(4))
            .unwrap();
        assert!(!queued.is_valid());
    }
    #[test]
    fn generation_and_reset_authority_remain_fail_closed() {
        let mut registry = HandleRegistry::new(1, 1).unwrap();
        let authority = Gate::new();
        let parent = registry
            .add_connection(authority.clone(), || Ok(1))
            .unwrap();
        let channel = registry
            .add_channel(parent, ChannelKind::ReliableMessage, Gate::new(), || Ok(2))
            .unwrap();
        let queued = registry.channel(parent, channel).unwrap();
        authority.0.store(false, Ordering::Release);
        assert!(!queued.is_valid());
        assert_eq!(registry.connection(parent).err(), Some(HandleError::Closed));
        assert_eq!(
            registry.channel(parent, channel).err(),
            Some(HandleError::Closed)
        );
    }
    #[test]
    fn clearing_or_dropping_registry_invalidates_retained_events() {
        let mut registry = HandleRegistry::new(1, 1).unwrap();
        let parent = registry.add_connection(Gate::new(), || Ok(1)).unwrap();
        let channel = registry
            .add_channel(parent, ChannelKind::ReliableMessage, Gate::new(), || Ok(2))
            .unwrap();
        let queued = registry.channel(parent, channel).unwrap();
        registry.clear();
        assert!(!queued.is_valid());
        let parent = registry.add_connection(Gate::new(), || Ok(3)).unwrap();
        let connection_event = registry.connection(parent).unwrap();
        drop(registry);
        assert!(!connection_event.is_valid());
    }
    #[test]
    fn no_historical_registry_growth_and_limits_are_checked() {
        assert!(HandleRegistry::<Gate>::new(0, 1).is_ok());
        assert!(HandleRegistry::<Gate>::new(usize::MAX, 2).is_ok());
        let mut registry = HandleRegistry::new(1, 1).unwrap();
        for id in 1..1000 {
            let parent = registry.add_connection(Gate::new(), || Ok(id)).unwrap();
            assert_eq!(
                registry.add_connection(Gate::new(), || panic!("full")),
                Err(HandleError::Full)
            );
            registry.remove_connection(parent).unwrap();
            assert!(registry.connections.is_empty());
        }
    }
    #[test]
    fn fin_only_fences_writes_and_message_deadline_is_absolute() {
        let mut registry = HandleRegistry::new(1, 2).unwrap();
        let parent = registry.add_connection(Gate::new(), || Ok(1)).unwrap();
        let stream = registry
            .add_channel(parent, ChannelKind::ReliableStream, Gate::new(), || Ok(2))
            .unwrap();
        registry.finish_write(parent, stream).unwrap();
        assert_eq!(
            registry.check_writable(parent, stream),
            Err(HandleError::Closed)
        );
        assert!(registry.channel(parent, stream).unwrap().is_valid());
        let message = registry
            .add_channel(parent, ChannelKind::ReliableMessage, Gate::new(), || Ok(3))
            .unwrap();
        let now = std::time::Instant::now();
        registry
            .set_message_ttl(parent, message, std::time::Duration::from_millis(7))
            .unwrap();
        assert_eq!(
            registry.message_deadline(parent, message, now).unwrap(),
            now + std::time::Duration::from_millis(7)
        );
    }
}
