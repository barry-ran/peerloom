//! Lazy three-lane queues: every allocation is budget charged and a terminal can
//! reserve its slot before the corresponding operation is admitted.
use crate::{
    budget::{Budget, Permit as Bytes},
    state::FULL,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;
pub trait Item {
    fn key(&self) -> u64 {
        0
    }
    fn critical(&self) -> bool;
    fn lane(&self) -> usize {
        usize::from(self.critical())
    }
    fn barrier(&self) -> bool {
        false
    }
}
struct Lane<T> {
    values: VecDeque<T>,
    reserved: usize,
    capacity_bytes: Option<Bytes>,
    last_key: u64,
}
impl<T> Default for Lane<T> {
    fn default() -> Self {
        Self {
            values: VecDeque::new(),
            reserved: 0,
            capacity_bytes: None,
            last_key: 0,
        }
    }
}
struct State<T> {
    lanes: [Lane<T>; 3],
    closed: bool,
    critical_burst: usize,
    secondary: usize,
}
struct Shared<T> {
    state: Mutex<State<T>>,
    budget: Arc<Budget>,
    notify: Notify,
    cond: Condvar,
    senders: AtomicUsize,
}
pub struct Sender<T>(Arc<Shared<T>>);
pub struct Receiver<T>(Arc<Shared<T>>);
pub struct Reservation<T> {
    sender: Sender<T>,
    lane: usize,
    live: bool,
}
pub struct SendError<T>(pub T);
impl<T> SendError<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}
pub fn channel<T>(budget: Arc<Budget>) -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(Shared {
        state: Mutex::new(State {
            lanes: [Lane::default(), Lane::default(), Lane::default()],
            closed: false,
            critical_burst: 0,
            secondary: 0,
        }),
        budget,
        notify: Notify::new(),
        cond: Condvar::new(),
        senders: AtomicUsize::new(1),
    });
    (Sender(inner.clone()), Receiver(inner))
}
impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.0.senders.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}
impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        if self.0.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Synchronize the terminal predicate with Condvar::wait: notifying
            // without this mutex can lose the last-sender wakeup.
            let lock = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
            drop(lock);
            self.0.notify.notify_one();
            self.0.cond.notify_all();
        }
    }
}
impl<T> Sender<T> {
    pub fn try_reserve(&self, critical: bool) -> Result<Reservation<T>, u32> {
        self.try_reserve_lane(usize::from(critical))
    }
    pub fn try_reserve_lane(&self, lane: usize) -> Result<Reservation<T>, u32> {
        if lane > 2 {
            return Err(FULL);
        }
        let mut state = self.0.state.lock().map_err(|_| FULL)?;
        if state.closed {
            return Err(FULL);
        }
        let q = &mut state.lanes[lane];
        let required = q
            .values
            .len()
            .checked_add(q.reserved)
            .and_then(|n| n.checked_add(1))
            .ok_or(FULL)?;
        if required > q.values.capacity() {
            let capacity = required.checked_next_power_of_two().ok_or(FULL)?;
            let bytes = capacity
                .checked_mul(std::mem::size_of::<T>().max(1))
                .ok_or(FULL)?;
            // Charge the entire replacement before allocation: old/new buffers
            // can coexist briefly while moving, never refund the old one early.
            let mut charge = self.0.budget.reserve_lane(bytes, lane)?;
            let mut replacement = VecDeque::new();
            replacement.try_reserve_exact(capacity).map_err(|_| FULL)?;
            charge.grow_to(
                replacement
                    .capacity()
                    .checked_mul(std::mem::size_of::<T>().max(1))
                    .ok_or(FULL)?,
            )?;
            replacement.append(&mut q.values);
            let old = std::mem::replace(&mut q.values, replacement);
            drop(old);
            q.capacity_bytes = Some(charge);
        }
        q.reserved += 1;
        Ok(Reservation {
            sender: self.clone(),
            lane,
            live: true,
        })
    }
}
impl<T: Item> Sender<T> {
    pub fn try_send(&self, item: T) -> Result<(), SendError<T>> {
        match self.try_reserve_lane(item.lane()) {
            Ok(permit) => permit.send(item),
            Err(_) => Err(SendError(item)),
        }
    }
}
impl<T> Reservation<T> {
    pub fn send(mut self, item: T) -> Result<(), SendError<T>> {
        let mut state = self
            .sender
            .0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let q = &mut state.lanes[self.lane];
        q.reserved -= 1;
        self.live = false;
        if state.closed {
            return Err(SendError(item));
        }
        state.lanes[self.lane].values.push_back(item);
        drop(state);
        self.sender.0.notify.notify_one();
        self.sender.0.cond.notify_one();
        Ok(())
    }
}
impl<T> Drop for Reservation<T> {
    fn drop(&mut self) {
        if self.live {
            self.sender
                .0
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .lanes[self.lane]
                .reserved -= 1;
        }
    }
}
impl<T: Item> Lane<T> {
    fn pop(&mut self, allow_barrier: bool) -> Option<T> {
        let eligible = |item: &&T| !item.barrier() || allow_barrier;
        let key = self
            .values
            .iter()
            .filter(eligible)
            .map(Item::key)
            .filter(|key| *key > self.last_key)
            .min()
            .or_else(|| self.values.iter().filter(eligible).map(Item::key).min())?;
        let index = self
            .values
            .iter()
            .position(|item| item.key() == key && (!item.barrier() || allow_barrier))?;
        self.last_key = key;
        self.values.remove(index)
    }
}
impl<T: Item> State<T> {
    fn pop(&mut self) -> Option<T> {
        let allow_barrier = self
            .lanes
            .iter()
            .map(|lane| lane.values.len())
            .sum::<usize>()
            == 1;
        let ready = |lane: &Lane<T>| {
            lane.values
                .iter()
                .any(|item| !item.barrier() || allow_barrier)
        };
        let management = ready(&self.lanes[1]);
        let secondary = [self.secondary, 2 - self.secondary]
            .into_iter()
            .find(|lane| ready(&self.lanes[*lane]));
        let lane = if management && (self.critical_burst < 8 || secondary.is_none()) {
            self.critical_burst = self.critical_burst.saturating_add(1).min(8);
            1
        } else {
            let lane = secondary?;
            self.critical_burst = 0;
            self.secondary = 2 - lane;
            lane
        };
        self.lanes[lane].pop(allow_barrier)
    }
}
impl<T: Item> Receiver<T> {
    pub fn try_recv(&self) -> Result<T, ()> {
        self.0.state.lock().map_err(|_| ())?.pop().ok_or(())
    }
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(item) = state.pop() {
                    return Some(item);
                }
                if state.closed || self.0.senders.load(Ordering::Acquire) == 0 {
                    return None;
                }
            }
            notified.await;
        }
    }
    pub fn blocking_recv(&self) -> Option<T> {
        self.blocking_recv_before_wait(|| {})
    }
    fn blocking_recv_before_wait(&self, mut before_wait: impl FnMut()) -> Option<T> {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(item) = state.pop() {
                return Some(item);
            }
            if state.closed || self.0.senders.load(Ordering::Acquire) == 0 {
                return None;
            }
            before_wait();
            state = self.0.cond.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }
    pub fn close(&mut self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closed = true;
        self.0.notify.notify_one();
        self.0.cond.notify_all();
    }
}
impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let drained = {
            let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
            state.closed = true;
            [
                std::mem::take(&mut state.lanes[0].values),
                std::mem::take(&mut state.lanes[1].values),
                std::mem::take(&mut state.lanes[2].values),
            ]
        };
        drop(drained);
        self.0.notify.notify_one();
        self.0.cond.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    struct Value {
        key: u64,
        critical: bool,
        barrier: bool,
        id: usize,
    }
    impl Item for Value {
        fn key(&self) -> u64 {
            self.key
        }
        fn critical(&self) -> bool {
            self.critical
        }
        fn barrier(&self) -> bool {
            self.barrier
        }
    }
    fn value(key: u64, critical: bool, id: usize) -> Value {
        Value {
            key,
            critical,
            id,
            barrier: false,
        }
    }
    #[test]
    fn round_robin_management_and_terminal_barrier() {
        let b = Budget::new(crate::budget::MIN_BYTES).unwrap();
        let (sender, receiver) = channel(b.clone());
        for id in 0..20 {
            sender.try_send(value(1, false, id)).ok().unwrap();
        }
        sender.try_send(value(2, false, 100)).ok().unwrap();
        sender.try_send(value(3, false, 101)).ok().unwrap();
        for id in 200..220 {
            sender.try_send(value(0, true, id)).ok().unwrap();
        }
        sender
            .try_send(Value {
                key: 0,
                critical: true,
                barrier: true,
                id: 999,
            })
            .ok()
            .unwrap();
        let mut ids = Vec::new();
        while let Ok(item) = receiver.try_recv() {
            ids.push(item.id);
        }
        assert_eq!(&ids[..8], &[200, 201, 202, 203, 204, 205, 206, 207]);
        assert_eq!(ids[8], 0);
        let data: Vec<_> = ids.iter().copied().filter(|id| *id < 200).collect();
        assert_eq!(&data[..3], &[0, 100, 101]);
        assert_eq!(ids.last(), Some(&999));
        drop(sender);
        drop(receiver);
        assert_eq!(b.snapshot().1, 0);
        assert_eq!(b.snapshot().2, 0);
    }
    #[test]
    fn reserved_terminal_needs_no_new_allocation_and_receiver_close_refunds_once() {
        let b = Budget::new(crate::budget::MIN_BYTES).unwrap();
        let (sender, mut receiver) = channel(b.clone());
        let permit = sender.try_reserve(false).unwrap();
        let second = sender.try_reserve(false).unwrap();
        let (total, used, _) = b.snapshot();
        let fill = b.reserve(total - 256 * 1024 - used, false).unwrap();
        assert!(permit.send(value(1, false, 0)).is_ok());
        receiver.close();
        assert!(second.send(value(1, false, 1)).is_err());
        assert_eq!(receiver.try_recv().unwrap().id, 0);
        drop(fill);
        drop(sender);
        drop(receiver);
        assert_eq!(b.snapshot(), (total, 0, 0));
    }
    #[test]
    fn final_sender_cannot_notify_between_predicate_and_condvar_wait() {
        let b = Budget::new(crate::budget::MIN_BYTES).unwrap();
        let (sender, receiver) = channel::<Value>(b);
        let shared = sender.0.clone();
        let checked = Arc::new(std::sync::Barrier::new(2));
        let proceed = Arc::new(std::sync::Barrier::new(2));
        let (tx, rx) = std::sync::mpsc::channel();
        let a = checked.clone();
        let z = proceed.clone();
        let receiver_thread = std::thread::spawn(move || {
            let mut once = true;
            let result = receiver.blocking_recv_before_wait(|| {
                if once {
                    once = false;
                    a.wait();
                    z.wait();
                }
            });
            tx.send(result.is_none()).unwrap();
        });
        checked.wait();
        let dropper = std::thread::spawn(move || drop(sender));
        while shared.senders.load(Ordering::Acquire) != 0 {
            std::thread::yield_now();
        }
        proceed.wait();
        let result = rx.recv_timeout(Duration::from_secs(1));
        // Ensure a broken implementation cannot leave a hanging test process.
        if result.is_err() {
            let lock = shared.state.lock().unwrap();
            drop(lock);
            shared.cond.notify_all();
        }
        receiver_thread.join().unwrap();
        dropper.join().unwrap();
        assert_eq!(result, Ok(true));
    }
}
