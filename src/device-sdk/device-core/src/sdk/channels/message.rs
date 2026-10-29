use super::*;
use crate::outbound::{MessageQueue, OutboundBudget, Settlement, SettlementReason, TicketError};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendDisposition {
    Sent,
    Dropped,
}
type Completion = oneshot::Sender<Result<SendDisposition, SdkError>>;
struct SendState {
    queue: MessageQueue,
    completions: BTreeMap<u64, Completion>,
}
impl SendState {
    fn settle(&mut self, values: Vec<Settlement>) {
        for value in values {
            let result = match value.reason {
                SettlementReason::Sent => Ok(SendDisposition::Sent),
                SettlementReason::DroppedOldest => Ok(SendDisposition::Dropped),
                SettlementReason::Expired => Err(SdkError::Transport(TransportError::Timeout)),
                _ => Err(SdkError::Closed),
            };
            self.finish(value.id, result);
        }
    }
    fn finish(&mut self, id: u64, result: Result<SendDisposition, SdkError>) {
        if let Some(completion) = self.completions.remove(&id) {
            let _ = completion.send(result);
        }
    }
}
struct CancelSend {
    state: Arc<Mutex<SendState>>,
    id: u64,
}
impl Drop for CancelSend {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.queue.cancel(self.id);
            // If already in flight its ticket remains charged until I/O settles.
            state.completions.remove(&self.id);
        }
    }
}

pub struct SdkMessageChannel {
    #[cfg(test)]
    test_worker: Option<Box<MessageWorker>>,
    scope: Scope,
    state: Arc<Mutex<SendState>>,
    notify: Arc<Notify>,
    messages: mpsc::Receiver<Vec<u8>>,
    max_message_bytes: usize,
}
impl SdkMessageChannel {
    #[cfg(test)]
    pub(super) fn retain_test_worker(&mut self, worker: MessageWorker) {
        self.test_worker = Some(Box::new(worker));
    }

    pub fn label(&self) -> &str {
        &self.scope.label
    }
    pub fn mode(&self) -> ChannelMode {
        self.scope.mode
    }
    pub fn session_id(&self) -> &str {
        &self.scope.session_id
    }
    pub fn negotiation_generation(&self) -> u64 {
        self.scope.generation
    }
    pub fn validity(&self) -> ChannelValidity {
        self.scope.validity()
    }
    pub fn sender(&self) -> SdkMessageSender {
        SdkMessageSender {
            scope: self.scope.clone(),
            state: self.state.clone(),
            notify: self.notify.clone(),
            max_message_bytes: self.max_message_bytes,
        }
    }
    pub async fn send(&self, bytes: &[u8]) -> Result<SendDisposition, SdkError> {
        self.sender().send(bytes).await
    }
    pub async fn receive(&mut self) -> Result<Vec<u8>, SdkError> {
        self.scope.gate.check()?;
        tokio::select! {
            biased;
            _ = self.scope.gate.invalidated() => Err(self.scope.gate.check().err().unwrap_or(SdkError::Closed)),
            data = self.messages.recv() => { self.scope.gate.check()?; data.ok_or(SdkError::Closed) },
        }
    }
    pub async fn close(self) -> Result<(), SdkError> {
        self.scope.gate.close_and_wait().await
    }
}
impl Drop for SdkMessageChannel {
    fn drop(&mut self) {
        self.scope.gate.close();
    }
}

pub(super) fn wrap(
    scope: Scope,
    config: QueueConfig,
    global: OutboundBudget,
) -> Result<(SdkMessageChannel, MessageWorker), SdkError> {
    let queue = MessageQueue::new(scope.mode, config, global).map_err(queue_error)?;
    let state = Arc::new(Mutex::new(SendState {
        queue,
        completions: BTreeMap::new(),
    }));
    let notify = Arc::new(Notify::new());
    let (receive, messages) = mpsc::channel(32);
    Ok((
        SdkMessageChannel {
            #[cfg(test)]
            test_worker: None,
            scope: scope.clone(),
            state: state.clone(),
            notify: notify.clone(),
            messages,
            max_message_bytes: config.max_message_bytes,
        },
        MessageWorker {
            scope,
            state,
            notify,
            receive,
        },
    ))
}
pub(super) struct MessageWorker {
    scope: Scope,
    state: Arc<Mutex<SendState>>,
    notify: Arc<Notify>,
    receive: mpsc::Sender<Vec<u8>>,
}
impl MessageWorker {
    #[cfg(test)]
    pub(super) fn test_sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.receive.clone()
    }
    pub(super) async fn run(
        self,
        mut raw: MessageChannel,
        _permit: ActivePermit,
    ) -> Result<(), SdkError> {
        let operation = async {
            loop {
                self.scope.gate.check()?;
                let notified = self.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let ticket = {
                    let mut state = self.state.lock().map_err(|_| SdkError::Closed)?;
                    let mutation = state.queue.pop(Instant::now());
                    state.settle(mutation.settled);
                    mutation.result.map_err(queue_error)?
                };
                if let Some(ticket) = ticket {
                    let id = ticket.id();
                    let sending = match ticket.begin(Instant::now()) {
                        Ok(sending) => sending,
                        Err(error) => {
                            let error = match error.reason {
                                TicketError::Expired => {
                                    SdkError::Transport(TransportError::Timeout)
                                }
                                _ => SdkError::Closed,
                            };
                            self.state
                                .lock()
                                .map_err(|_| SdkError::Closed)?
                                .finish(id, Err(error));
                            continue;
                        }
                    };
                    // Charge remains owned across actual network I/O and cancellation.
                    let result = tokio::select! {
                        biased;
                        _ = self.scope.gate.invalidated() => Err(SdkError::Closed),
                        result = raw.send(sending.bytes()) => result.map(|_| SendDisposition::Sent).map_err(SdkError::Transport),
                    };
                    let fatal = result
                        .as_ref()
                        .err()
                        .filter(|error| {
                            !matches!(
                                error,
                                SdkError::Transport(
                                    TransportError::BufferFull | TransportError::MessageTooLarge
                                )
                            )
                        })
                        .cloned();
                    drop(sending);
                    self.state
                        .lock()
                        .map_err(|_| SdkError::Closed)?
                        .finish(id, result);
                    if let Some(error) = fatal {
                        return Err(error);
                    }
                    tokio::task::yield_now().await;
                }
                tokio::select! {
                    biased;
                    _ = self.scope.gate.invalidated() => return Err(SdkError::Closed),
                    data = raw.receive() => match data {
                        Ok(data) => { self.scope.gate.check()?; self.receive.try_send(data).map_err(|_| SdkError::QueueFull)?; },
                        Err(TransportError::Timeout) => {},
                        Err(error) => return Err(SdkError::Transport(error)),
                    },
                    _ = &mut notified => {},
                    // Yield to ready inbound data before handling another queued write.
                    _ = tokio::task::yield_now(), if ticket_was_present(&self.state) => {},
                }
            }
        };
        let result = operation.await;
        self.scope.gate.close();
        if let Ok(mut state) = self.state.lock() {
            let settled = state.queue.close();
            state.settle(settled);
            for (_, completion) in std::mem::take(&mut state.completions) {
                let _ = completion.send(Err(SdkError::Closed));
            }
        }
        let _ = raw.close().await;
        drop(_permit);
        self.scope.gate.finished();
        result
    }
}
impl Drop for MessageWorker {
    fn drop(&mut self) {
        // JoinSet cancellation bypasses async cleanup. Settle all queued requests
        // synchronously even if senders keep SendState alive across a generation.
        self.scope.gate.close();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let settled = state.queue.close();
        state.settle(settled);
        for (_, completion) in std::mem::take(&mut state.completions) {
            let _ = completion.send(Err(SdkError::Closed));
        }
        self.scope.gate.finished();
    }
}

fn ticket_was_present(state: &Mutex<SendState>) -> bool {
    // At most one in-flight completion; after its finish remaining IDs are queued.
    state
        .lock()
        .is_ok_and(|state| !state.completions.is_empty())
}

/// Cloneable sending capability. Dropping it never closes the owning channel.
#[derive(Clone)]
pub struct SdkMessageSender {
    scope: Scope,
    state: Arc<Mutex<SendState>>,
    notify: Arc<Notify>,
    max_message_bytes: usize,
}
impl SdkMessageSender {
    pub fn validity(&self) -> ChannelValidity {
        self.scope.validity()
    }
    /// Resolves to local transport acceptance or explicit queue drop, never peer business delivery.
    pub async fn send(&self, bytes: &[u8]) -> Result<SendDisposition, SdkError> {
        self.send_with_deadline(bytes, None).await
    }
    pub async fn send_before(
        &self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<SendDisposition, SdkError> {
        self.send_with_deadline(bytes, Some(deadline)).await
    }
    async fn send_with_deadline(
        &self,
        bytes: &[u8],
        deadline: Option<Instant>,
    ) -> Result<SendDisposition, SdkError> {
        self.scope.gate.check()?;
        if bytes.len() > self.max_message_bytes {
            return Err(SdkError::MessageTooLarge);
        }
        let (completion, result) = oneshot::channel();
        let id = {
            let mut state = self.state.lock().map_err(|_| SdkError::Closed)?;
            self.scope.gate.check()?;
            let now = Instant::now();
            let mutation = if let Some(deadline) = deadline {
                state.queue.enqueue_before(bytes.to_vec(), now, deadline)
            } else {
                state.queue.enqueue(bytes.to_vec(), now)
            };
            state.settle(mutation.settled);
            let (id, _) = mutation.result.map_err(queue_error)?;
            let Some(id) = id else {
                return Ok(SendDisposition::Dropped);
            };
            state.completions.insert(id, completion);
            id
        };
        let _cancel = CancelSend {
            state: self.state.clone(),
            id,
        };
        self.notify.notify_one();
        tokio::select! {
            biased;
            _ = self.scope.gate.invalidated() => Err(self.scope.gate.check().err().unwrap_or(SdkError::Closed)),
            result = result => result.map_err(|_| SdkError::Closed)?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use device_protocol::OverflowPolicy;
    use futures_util::{pin_mut, poll};
    use std::task::Poll;

    fn fixture(
        policy: OverflowPolicy,
        budget: OutboundBudget,
    ) -> (SdkMessageChannel, MessageWorker, Arc<Gate>) {
        let parent = Arc::new(Gate::default());
        parent.update(Some(Instant::now() + Duration::from_secs(60)));
        let scope = Scope {
            session_id: "session".into(),
            generation: 2,
            label: "test".into(),
            mode: ChannelMode::ReliableMessage,
            gate: ChannelGate::new(parent.clone()),
        };
        let config = QueueConfig {
            max_messages: 1,
            max_bytes: 8,
            max_message_bytes: 8,
            ttl: Duration::from_secs(1),
            overflow: policy,
        };
        let (channel, worker) = wrap(scope, config, budget).unwrap();
        (channel, worker, parent)
    }
    #[tokio::test]
    async fn upper_admission_deadline_cannot_be_restarted_after_ffi_queue_delay() {
        let budget = OutboundBudget::new(8, 1).unwrap();
        let (channel, worker, _) = fixture(OverflowPolicy::Fail, budget.clone());
        let sender = channel.sender();
        assert_eq!(
            sender.send_before(b"late", Instant::now()).await,
            Err(SdkError::Transport(TransportError::Timeout))
        );
        assert_eq!(budget.usage(), (0, 0));
        let deadline = Instant::now() + Duration::from_millis(10);
        let future = sender.send_before(b"short", deadline);
        pin_mut!(future);
        assert!(poll!(&mut future).is_pending());
        {
            let mut state = worker.state.lock().unwrap();
            let mutation = state.queue.expire(deadline);
            state.settle(mutation.settled);
        }
        assert_eq!(
            future.await,
            Err(SdkError::Transport(TransportError::Timeout))
        );
        assert_eq!(budget.usage(), (0, 0));
    }
    #[tokio::test]
    async fn worker_drop_settles_queued_sends_and_releases_budget_with_sender_retained() {
        let budget = OutboundBudget::new(8, 1).unwrap();
        let (channel, worker, _) = fixture(OverflowPolicy::Fail, budget.clone());
        let sender = channel.sender();
        let future = sender.send(b"queued");
        pin_mut!(future);
        assert!(poll!(&mut future).is_pending());
        assert_eq!(budget.usage(), (6, 1));
        drop(worker);
        assert_eq!(budget.usage(), (0, 0));
        assert!(!sender.validity().is_valid());
        assert_eq!(future.await, Err(SdkError::Closed));
        assert_eq!(sender.send(b"late").await, Err(SdkError::Closed));
    }
    #[tokio::test]
    async fn dropped_oldest_completes_exact_sender_and_cancellation_releases_new() {
        let budget = OutboundBudget::new(8, 1).unwrap();
        let (channel, _worker, _) = fixture(OverflowPolicy::DropOldest, budget.clone());
        let first = channel.sender();
        let second = channel.sender();
        let a = first.send(b"old");
        pin_mut!(a);
        assert!(poll!(&mut a).is_pending());
        {
            let b = second.send(b"new");
            pin_mut!(b);
            assert!(poll!(&mut b).is_pending());
            assert_eq!(poll!(&mut a), Poll::Ready(Ok(SendDisposition::Dropped)));
            assert_eq!(budget.usage(), (3, 1));
        }
        assert_eq!(budget.usage(), (0, 0));
    }
    #[tokio::test]
    async fn newest_drop_does_not_cancel_existing_sender_or_consume_extra_budget() {
        let budget = OutboundBudget::new(8, 1).unwrap();
        let (channel, _worker, _) = fixture(OverflowPolicy::DropNewest, budget.clone());
        let sender = channel.sender();
        let first = sender.send(b"old");
        pin_mut!(first);
        assert!(poll!(&mut first).is_pending());
        assert_eq!(channel.send(b"new").await, Ok(SendDisposition::Dropped));
        assert_eq!(budget.usage(), (3, 1));
        assert!(poll!(&mut first).is_pending());
    }
    #[tokio::test]
    async fn expiration_settles_waiter_and_inflight_cancel_retains_charge_until_drop() {
        let budget = OutboundBudget::new(8, 1).unwrap();
        let (channel, worker, _) = fixture(OverflowPolicy::Fail, budget.clone());
        let sender = channel.sender();
        let first = sender.send(b"ttl");
        pin_mut!(first);
        assert!(poll!(&mut first).is_pending());
        {
            let mut state = worker.state.lock().unwrap();
            let expired = state.queue.expire(Instant::now() + Duration::from_secs(2));
            state.settle(expired.settled);
        }
        assert_eq!(
            first.await,
            Err(SdkError::Transport(TransportError::Timeout))
        );
        assert_eq!(budget.usage(), (0, 0));
        // Fresh queue keeps the injected monotonic clock from moving backwards.
        let (channel, worker, _) = fixture(OverflowPolicy::Fail, budget.clone());
        let sending;
        {
            let future = channel.send(b"flight");
            pin_mut!(future);
            assert!(poll!(&mut future).is_pending());
            let ticket = worker
                .state
                .lock()
                .unwrap()
                .queue
                .pop(Instant::now())
                .result
                .unwrap()
                .unwrap();
            sending = ticket.begin(Instant::now()).unwrap();
        }
        assert_eq!(budget.usage(), (6, 1));
        drop(sending);
        assert_eq!(budget.usage(), (0, 0));
    }
    #[tokio::test]
    async fn global_budget_and_parent_expiry_cover_sibling_channels_and_cloned_senders() {
        let budget = OutboundBudget::new(8, 1).unwrap();
        let (a, _wa, parent) = fixture(OverflowPolicy::Fail, budget.clone());
        let (b, _wb, _) = fixture(OverflowPolicy::Fail, budget.clone());
        let sender = a.sender();
        let future = sender.send(b"held");
        pin_mut!(future);
        assert!(poll!(&mut future).is_pending());
        assert_eq!(b.send(b"sibling").await, Err(SdkError::QueueFull));
        parent.update(Some(Instant::now()));
        assert_eq!(future.await, Err(SdkError::AuthorizationExpired));
        assert_eq!(budget.usage(), (0, 0));
        assert!(!sender.validity().is_valid());
    }
    #[tokio::test]
    async fn continuous_suspend_blocks_queued_messages_senders_and_validity() {
        let budget = OutboundBudget::new(8, 1).unwrap();
        let (mut channel, worker, parent) = fixture(OverflowPolicy::Fail, budget.clone());
        let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reading = ticks.clone();
        test_continuous_grant(&parent, move || {
            Ok(Duration::from_secs(reading.load(Ordering::SeqCst)))
        });
        let sender = channel.sender();
        let sending = sender.send(b"queued");
        pin_mut!(sending);
        assert!(poll!(&mut sending).is_pending());
        worker.receive.try_send(b"old".to_vec()).unwrap();
        assert!(sender.validity().is_valid());
        // Instant's scheduling deadline stays in the future, while sleep advances
        // the independently injected authorization clock by two minutes.
        ticks.store(120, Ordering::SeqCst);
        assert!(Instant::now() < parent.deadline.lock().unwrap().unwrap());
        assert!(!sender.validity().is_valid());
        assert_eq!(channel.receive().await, Err(SdkError::AuthorizationExpired));
        assert_eq!(
            sender.send(b"new").await,
            Err(SdkError::AuthorizationExpired)
        );
        assert_eq!(sending.await, Err(SdkError::AuthorizationExpired));
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn continuous_expiry_is_rechecked_after_select_dequeues_message() {
        let budget = OutboundBudget::new(8, 1).unwrap();
        let (mut channel, worker, parent) = fixture(OverflowPolicy::Fail, budget);
        worker.receive.try_send(b"old".to_vec()).unwrap();
        let reads = std::sync::atomic::AtomicUsize::new(0);
        test_continuous_grant(&parent, move || {
            // Entry and the invalidation select branch pass. Expire exactly on
            // the final check after the ready message has been dequeued.
            let read = reads.fetch_add(1, Ordering::SeqCst);
            Ok(Duration::from_secs(if read < 2 { 0 } else { 120 }))
        });
        assert_eq!(channel.receive().await, Err(SdkError::AuthorizationExpired));
        assert!(channel.messages.is_empty());
        assert!(Instant::now() < parent.deadline.lock().unwrap().unwrap());
    }
}
