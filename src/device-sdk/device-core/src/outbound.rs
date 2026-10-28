//! Message-only admission with shared SDK payload accounting. Bytes remain charged
//! while queued AND while a transport future owns its send ticket. This is not a
//! WebRTC/SCTP memory cap, delivery acknowledgment, or a byte-stream drop policy.
use crate::{EnqueueOutcome, QueueConfig, QueueError, QueueWrite};
use device_protocol::{ChannelMode, OverflowPolicy};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Default)]
struct Usage {
    bytes: usize,
    messages: usize,
}
struct Shared {
    used: Usage,
    max_bytes: usize,
    max_messages: usize,
    closed: bool,
}

/// Clone once per message channel. Closing admission never fabricates released
/// capacity: live tickets retain their charges until transport cancellation joins.
#[derive(Clone)]
pub struct OutboundBudget(Arc<Mutex<Shared>>);
impl OutboundBudget {
    pub fn new(max_bytes: usize, max_messages: usize) -> Result<Self, QueueError> {
        if max_bytes == 0 || max_messages == 0 {
            return Err(QueueError::InvalidConfiguration);
        }
        Ok(Self(Arc::new(Mutex::new(Shared {
            used: Usage::default(),
            max_bytes,
            max_messages,
            closed: false,
        }))))
    }
    /// Byte-stream chunks/FIN use strict fail-only global admission, never message
    /// eviction. The stream owner separately enforces its per-channel chunk bound.
    pub fn reserve(&self, bytes: usize) -> Result<GlobalPermit, QueueError> {
        let mut shared = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if shared.closed {
            return Err(QueueError::Closed);
        }
        if bytes > shared.max_bytes - shared.used.bytes
            || shared.used.messages >= shared.max_messages
        {
            return Err(QueueError::Full);
        }
        shared.used.bytes += bytes;
        shared.used.messages += 1;
        Ok(GlobalPermit {
            budget: self.clone(),
            bytes,
        })
    }
    pub fn usage(&self) -> (usize, usize) {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        (state.used.bytes, state.used.messages)
    }
    pub fn close(&self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
    }
}

/// Non-cloneable ownership for one stream write or FIN. Keep this in the actual
/// worker command until completion/cancellation; partial writes do not release it.
/// No payload is copied or returned, and no stream data can be evicted by messages.
#[must_use]
pub struct GlobalPermit {
    budget: OutboundBudget,
    bytes: usize,
}
impl GlobalPermit {
    pub fn check_open(&self) -> Result<(), QueueError> {
        let shared = self.budget.0.lock().unwrap_or_else(|e| e.into_inner());
        if shared.closed {
            Err(QueueError::Closed)
        } else {
            Ok(())
        }
    }
}
impl Drop for GlobalPermit {
    fn drop(&mut self) {
        let mut shared = self.budget.0.lock().unwrap_or_else(|e| e.into_inner());
        shared.used.bytes -= self.bytes;
        shared.used.messages -= 1;
    }
}

struct Channel {
    used: Usage,
    closed: bool,
}
struct Permit {
    global: OutboundBudget,
    channel: Arc<Mutex<Channel>>,
    bytes: usize,
    active: bool,
}
impl Drop for Permit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // Every path uses global -> channel order; never holds either across I/O.
        let mut global = self.global.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut channel = self.channel.lock().unwrap_or_else(|e| e.into_inner());
        global.used.bytes -= self.bytes;
        global.used.messages -= 1;
        channel.used.bytes -= self.bytes;
        channel.used.messages -= 1;
    }
}
struct Entry {
    id: u64,
    bytes: Box<[u8]>,
    expires: Instant,
    permit: Permit,
}

/// Metadata never owns payload bytes. IDs are scoped to this channel queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementReason {
    Expired,
    DroppedOldest,
    Cancelled,
    Closed,
    Sent,
    SendFailed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    pub id: u64,
    pub reason: SettlementReason,
}
/// Always process settlements, including when result is Full/Closed. There is no
/// hidden callback queue and each admitted queued ID is removed at most once.
#[must_use]
pub struct QueueMutation<T> {
    pub result: Result<T, QueueError>,
    pub settled: Vec<Settlement>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketRejection {
    pub id: u64,
    pub reason: TicketError,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Sent,
    Failed,
    Cancelled,
}

/// Owned, non-cloneable dequeue ticket. Dropping it is cancellation, not success.
/// Call begin immediately before starting transport I/O, after authorization gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    Expired,
    Closed,
    ClockMovedBackwards,
}
pub struct MessageTicket {
    entry: Entry,
    dequeued_at: Instant,
}
impl MessageTicket {
    pub fn id(&self) -> u64 {
        self.entry.id
    }
    pub fn cancel(self) -> Settlement {
        Settlement {
            id: self.entry.id,
            reason: SettlementReason::Cancelled,
        }
    }
    pub fn begin(self, now: Instant) -> Result<SendingMessage, TicketRejection> {
        {
            let global = self
                .entry
                .permit
                .global
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let channel = self
                .entry
                .permit
                .channel
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if global.closed || channel.closed {
                return Err(TicketRejection {
                    id: self.entry.id,
                    reason: TicketError::Closed,
                });
            }
            if now < self.dequeued_at {
                return Err(TicketRejection {
                    id: self.entry.id,
                    reason: TicketError::ClockMovedBackwards,
                });
            }
            if now >= self.entry.expires {
                return Err(TicketRejection {
                    id: self.entry.id,
                    reason: TicketError::Expired,
                });
            }
        }
        Ok(SendingMessage(self.entry))
    }
}

/// Keep this owner in the actual send future until it settles or is cancelled.
/// TTL is a queue/start deadline; already handed-off bytes cannot be retracted.
pub struct SendingMessage(Entry);
impl SendingMessage {
    pub fn finish(self, outcome: SendOutcome) -> Settlement {
        Settlement {
            id: self.0.id,
            reason: match outcome {
                SendOutcome::Sent => SettlementReason::Sent,
                SendOutcome::Failed => SettlementReason::SendFailed,
                SendOutcome::Cancelled => SettlementReason::Cancelled,
            },
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0.bytes
    }
    pub fn id(&self) -> u64 {
        self.0.id
    }
}

pub struct MessageQueue {
    config: QueueConfig,
    global: OutboundBudget,
    channel: Arc<Mutex<Channel>>,
    entries: VecDeque<Entry>,
    next_id: u64,
    last_now: Option<Instant>,
}
impl MessageQueue {
    pub fn new(
        mode: ChannelMode,
        config: QueueConfig,
        global: OutboundBudget,
    ) -> Result<Self, QueueError> {
        if mode == ChannelMode::ReliableStream
            || config.max_messages == 0
            || config.max_bytes == 0
            || config.max_message_bytes == 0
            || config.max_message_bytes > config.max_bytes
            || config.ttl.is_zero()
        {
            return Err(QueueError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            global,
            channel: Arc::new(Mutex::new(Channel {
                used: Usage::default(),
                closed: false,
            })),
            entries: VecDeque::new(),
            next_id: 0,
            last_now: None,
        })
    }
    fn clock(&mut self, now: Instant) -> Result<(), QueueError> {
        if self.last_now.is_some_and(|previous| now < previous) {
            return Err(QueueError::ClockMovedBackwards);
        }
        self.last_now = Some(now);
        Ok(())
    }
    pub fn expire(&mut self, now: Instant) -> QueueMutation<usize> {
        let mut settled = Vec::new();
        let result = self.expire_inner(now, &mut settled);
        QueueMutation { result, settled }
    }
    fn expire_inner(
        &mut self,
        now: Instant,
        settled: &mut Vec<Settlement>,
    ) -> Result<usize, QueueError> {
        self.clock(now)?;
        let mut expired = 0;
        // Caller deadlines may be shorter than earlier entries. Scan the bounded
        // FIFO without reordering survivors; expiry must not hide behind its head.
        self.entries.retain(|entry| {
            if now >= entry.expires {
                settled.push(Settlement {
                    id: entry.id,
                    reason: SettlementReason::Expired,
                });
                expired += 1;
                false
            } else {
                true
            }
        });
        Ok(expired)
    }
    pub fn enqueue(
        &mut self,
        bytes: Vec<u8>,
        now: Instant,
    ) -> QueueMutation<(Option<u64>, QueueWrite)> {
        let mut settled = Vec::new();
        let result = self.enqueue_inner(bytes, now, None, &mut settled);
        QueueMutation { result, settled }
    }
    /// Never extends a deadline captured by an upper-layer admission queue.
    pub fn enqueue_before(
        &mut self,
        bytes: Vec<u8>,
        now: Instant,
        deadline: Instant,
    ) -> QueueMutation<(Option<u64>, QueueWrite)> {
        let mut settled = Vec::new();
        let result = self.enqueue_inner(bytes, now, Some(deadline), &mut settled);
        QueueMutation { result, settled }
    }
    fn enqueue_inner(
        &mut self,
        bytes: Vec<u8>,
        now: Instant,
        caller_deadline: Option<Instant>,
        settled: &mut Vec<Settlement>,
    ) -> Result<(Option<u64>, QueueWrite), QueueError> {
        self.clock(now)?;
        if bytes.len() > self.config.max_message_bytes {
            return Err(QueueError::MessageTooLarge);
        }
        let expires = now
            .checked_add(self.config.ttl)
            .ok_or(QueueError::DeadlineOverflow)?;
        let expires = caller_deadline.map_or(expires, |deadline| deadline.min(expires));
        let id = self.next_id.checked_add(1).ok_or(QueueError::Full)?;
        let expired_messages = self.expire_inner(now, settled)?;
        if expires <= now {
            return Err(QueueError::Expired);
        }
        let mut global = self.global.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut channel = self.channel.lock().unwrap_or_else(|e| e.into_inner());
        if global.closed || channel.closed {
            return Err(QueueError::Closed);
        }
        let fits = |freed_bytes: usize, freed_count: usize| {
            bytes.len()
                <= global
                    .max_bytes
                    .saturating_sub(global.used.bytes - freed_bytes)
                && bytes.len()
                    <= self
                        .config
                        .max_bytes
                        .saturating_sub(channel.used.bytes - freed_bytes)
                && global.used.messages - freed_count < global.max_messages
                && channel.used.messages - freed_count < self.config.max_messages
        };
        let mut freed_bytes = 0;
        let mut dropped = 0;
        if !fits(0, 0) {
            match self.config.overflow {
                OverflowPolicy::Fail => return Err(QueueError::Full),
                OverflowPolicy::DropNewest => {
                    return Ok((
                        None,
                        QueueWrite {
                            outcome: EnqueueOutcome::DroppedNewest,
                            expired_messages,
                        },
                    ));
                }
                OverflowPolicy::DropOldest => {
                    // Preflight before eviction: an in-flight/other-channel charge
                    // cannot be stolen. If our entire FIFO is insufficient, fail unchanged.
                    for entry in &self.entries {
                        freed_bytes += entry.bytes.len();
                        dropped += 1;
                        if fits(freed_bytes, dropped) {
                            break;
                        }
                    }
                    if !fits(freed_bytes, dropped) {
                        return Err(QueueError::Full);
                    }
                }
            }
        }
        // Replace charges atomically while holding the shared lock. Evicted owners
        // are disarmed below so their Drop cannot release this replacement twice.
        global.used.bytes = global.used.bytes - freed_bytes + bytes.len();
        global.used.messages = global.used.messages - dropped + 1;
        channel.used.bytes = channel.used.bytes - freed_bytes + bytes.len();
        channel.used.messages = channel.used.messages - dropped + 1;
        drop(channel);
        drop(global);
        for _ in 0..dropped {
            let mut entry = self
                .entries
                .pop_front()
                .expect("preflight counted queued entry");
            entry.permit.active = false;
            settled.push(Settlement {
                id: entry.id,
                reason: SettlementReason::DroppedOldest,
            });
        }
        self.next_id = id;
        self.entries.push_back(Entry {
            id,
            permit: Permit {
                global: self.global.clone(),
                channel: self.channel.clone(),
                bytes: bytes.len(),
                active: true,
            },
            bytes: bytes.into_boxed_slice(),
            expires,
        });
        Ok((
            Some(id),
            QueueWrite {
                outcome: if dropped == 0 {
                    EnqueueOutcome::Accepted
                } else {
                    EnqueueOutcome::AcceptedAfterDropping { messages: dropped }
                },
                expired_messages,
            },
        ))
    }
    pub fn pop(&mut self, now: Instant) -> QueueMutation<Option<MessageTicket>> {
        let mut settled = Vec::new();
        let result = self.pop_inner(now, &mut settled);
        QueueMutation { result, settled }
    }
    fn pop_inner(
        &mut self,
        now: Instant,
        settled: &mut Vec<Settlement>,
    ) -> Result<Option<MessageTicket>, QueueError> {
        self.expire_inner(now, settled)?;
        let global = self.global.0.lock().unwrap_or_else(|e| e.into_inner());
        let channel = self.channel.lock().unwrap_or_else(|e| e.into_inner());
        if global.closed || channel.closed {
            return Err(QueueError::Closed);
        }
        Ok(self.entries.pop_front().map(|entry| MessageTicket {
            entry,
            dequeued_at: now,
        }))
    }
    pub fn cancel(&mut self, id: u64) -> Option<Settlement> {
        let index = self.entries.iter().position(|entry| entry.id == id)?;
        self.entries.remove(index);
        Some(Settlement {
            id,
            reason: SettlementReason::Cancelled,
        })
    }
    pub fn close(&mut self) -> Vec<Settlement> {
        self.channel
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closed = true;
        self.entries
            .drain(..)
            .map(|entry| Settlement {
                id: entry.id,
                reason: SettlementReason::Closed,
            })
            .collect()
    }
}
impl Drop for MessageQueue {
    fn drop(&mut self) {
        self.close();
    }
}
