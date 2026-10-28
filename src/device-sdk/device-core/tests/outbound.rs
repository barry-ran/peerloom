use device_core::outbound::{
    MessageQueue, OutboundBudget, SendOutcome, SettlementReason, TicketError, TicketRejection,
};
use device_core::{EnqueueOutcome, QueueConfig, QueueError};
use device_protocol::{ChannelMode, OverflowPolicy};
use std::time::{Duration, Instant};

fn queue(global: OutboundBudget, overflow: OverflowPolicy) -> MessageQueue {
    MessageQueue::new(
        ChannelMode::ReliableMessage,
        QueueConfig {
            max_messages: 2,
            max_bytes: 6,
            max_message_bytes: 6,
            ttl: Duration::from_secs(10),
            overflow,
        },
        global,
    )
    .unwrap()
}
#[test]
fn dequeue_keeps_both_budgets_until_send_or_cancel_settles() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let mut a = queue(budget.clone(), OverflowPolicy::Fail);
    let mut b = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    a.enqueue(vec![1; 6], now).result.unwrap();
    let ticket = a.pop(now).result.unwrap().unwrap();
    assert_eq!(budget.usage(), (6, 1));
    assert_eq!(a.enqueue(vec![2], now).result, Err(QueueError::Full));
    assert_eq!(b.enqueue(vec![2], now).result, Err(QueueError::Full));
    let sending = ticket.begin(now).unwrap();
    assert_eq!(sending.bytes(), &[1; 6]);
    assert_eq!(budget.usage(), (6, 1));
    drop(sending);
    assert_eq!(budget.usage(), (0, 0));
    b.enqueue(vec![2; 6], now).result.unwrap();
    drop(b.pop(now).result.unwrap());
    assert_eq!(budget.usage(), (0, 0));
}
#[test]
fn drop_oldest_only_evicts_own_queued_whole_messages() {
    let budget = OutboundBudget::new(9, 4).unwrap();
    let mut a = queue(budget.clone(), OverflowPolicy::DropOldest);
    let mut b = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    b.enqueue(vec![9; 3], now).result.unwrap();
    let in_flight = b.pop(now).result.unwrap().unwrap();
    a.enqueue(vec![1; 3], now).result.unwrap();
    a.enqueue(vec![2; 3], now).result.unwrap();
    let (_, write) = a.enqueue(vec![3; 6], now).result.unwrap();
    assert_eq!(
        write.outcome,
        EnqueueOutcome::AcceptedAfterDropping { messages: 2 }
    );
    assert_eq!(budget.usage(), (9, 2));
    assert_eq!(
        a.pop(now)
            .result
            .unwrap()
            .unwrap()
            .begin(now)
            .unwrap()
            .bytes(),
        &[3; 6]
    );
    assert_eq!(budget.usage(), (3, 1));
    drop(in_flight);
    assert_eq!(budget.usage(), (0, 0));
}
#[test]
fn impossible_drop_oldest_is_atomic_and_does_not_steal_siblings() {
    let budget = OutboundBudget::new(6, 4).unwrap();
    let mut a = queue(budget.clone(), OverflowPolicy::DropOldest);
    let mut b = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    a.enqueue(vec![1], now).result.unwrap();
    b.enqueue(vec![2; 5], now).result.unwrap();
    assert_eq!(a.enqueue(vec![3; 2], now).result, Err(QueueError::Full));
    assert_eq!(
        a.pop(now)
            .result
            .unwrap()
            .unwrap()
            .begin(now)
            .unwrap()
            .bytes(),
        &[1]
    );
    assert_eq!(budget.usage(), (5, 1));
}
#[test]
fn newest_rejection_and_oversize_never_claim_admission() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::DropNewest);
    let now = Instant::now();
    q.enqueue(vec![1; 6], now).result.unwrap();
    let (id, write) = q.enqueue(vec![2], now).result.unwrap();
    assert_eq!(id, None);
    assert_eq!(write.outcome, EnqueueOutcome::DroppedNewest);
    assert_eq!(
        q.enqueue(vec![3; 7], now).result,
        Err(QueueError::MessageTooLarge)
    );
    assert_eq!(budget.usage(), (6, 1));
}
#[test]
fn ttl_boundary_and_dequeued_deadline_release_once() {
    let budget = OutboundBudget::new(12, 4).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    q.enqueue(vec![1; 3], now).result.unwrap();
    q.enqueue(vec![2; 3], now + Duration::from_secs(1))
        .result
        .unwrap();
    assert_eq!(q.expire(now + Duration::from_secs(10)).result.unwrap(), 1);
    let ticket = q
        .pop(now + Duration::from_secs(10))
        .result
        .unwrap()
        .unwrap();
    assert!(matches!(
        ticket.begin(now + Duration::from_secs(11)),
        Err(TicketRejection {
            reason: TicketError::Expired,
            ..
        })
    ));
    assert_eq!(budget.usage(), (0, 0));
}
#[test]
fn cancel_close_reset_and_inflight_ownership_are_exact() {
    let budget = OutboundBudget::new(12, 4).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    let (id, _) = q.enqueue(vec![1; 3], now).result.unwrap();
    assert!(q.cancel(id.unwrap()).is_some());
    assert!(q.cancel(id.unwrap()).is_none());
    q.enqueue(vec![2; 3], now).result.unwrap();
    let ticket = q.pop(now).result.unwrap().unwrap();
    q.enqueue(vec![3; 3], now).result.unwrap();
    q.close();
    q.close();
    assert_eq!(budget.usage(), (3, 1));
    assert!(matches!(
        ticket.begin(now),
        Err(TicketRejection {
            reason: TicketError::Closed,
            ..
        })
    ));
    assert_eq!(budget.usage(), (0, 0));
    let mut sibling = queue(budget.clone(), OverflowPolicy::Fail);
    sibling.enqueue(vec![4], now).result.unwrap();
    let ticket = sibling.pop(now).result.unwrap().unwrap();
    budget.close();
    assert!(matches!(
        ticket.begin(now),
        Err(TicketRejection {
            reason: TicketError::Closed,
            ..
        })
    ));
    assert_eq!(budget.usage(), (0, 0));
    assert_eq!(
        sibling.enqueue(vec![5], now).result,
        Err(QueueError::Closed)
    );
}
#[test]
fn zero_length_messages_consume_global_count_budget() {
    let budget = OutboundBudget::new(6, 1).unwrap();
    let mut a = queue(budget.clone(), OverflowPolicy::Fail);
    let mut b = queue(budget.clone(), OverflowPolicy::DropNewest);
    let now = Instant::now();
    a.enqueue(vec![], now).result.unwrap();
    assert_eq!(
        b.enqueue(vec![], now).result.unwrap().1.outcome,
        EnqueueOutcome::DroppedNewest
    );
    assert_eq!(budget.usage(), (0, 1));
    drop(a);
    assert_eq!(budget.usage(), (0, 0));
}
#[test]
fn backwards_clock_cannot_extend_or_start_ticket() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    q.enqueue(vec![1], now + Duration::from_secs(1))
        .result
        .unwrap();
    assert_eq!(q.expire(now).result, Err(QueueError::ClockMovedBackwards));
    let ticket = q.pop(now + Duration::from_secs(2)).result.unwrap().unwrap();
    assert!(matches!(
        ticket.begin(now),
        Err(TicketRejection {
            reason: TicketError::ClockMovedBackwards,
            ..
        })
    ));
    assert_eq!(budget.usage(), (0, 0));
}
#[test]
fn streams_never_use_message_drop_or_ttl_policy() {
    for policy in [
        OverflowPolicy::Fail,
        OverflowPolicy::DropOldest,
        OverflowPolicy::DropNewest,
    ] {
        assert!(matches!(
            MessageQueue::new(
                ChannelMode::ReliableStream,
                QueueConfig {
                    overflow: policy,
                    ..QueueConfig::default()
                },
                OutboundBudget::new(1024, 4).unwrap()
            ),
            Err(QueueError::InvalidConfiguration)
        ));
    }
}
#[test]
fn concurrent_channels_never_exceed_global_budget() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let budget = budget.clone();
            scope.spawn(move || {
                let mut q = queue(budget.clone(), OverflowPolicy::DropOldest);
                for _ in 0..500 {
                    let now = Instant::now();
                    let _ = q.enqueue(vec![1; 3], now).result;
                    let (bytes, count) = budget.usage();
                    assert!(bytes <= 6 && count <= 2);
                    drop(q.pop(now).result.unwrap());
                }
            });
        }
    });
    assert_eq!(budget.usage(), (0, 0));
}

#[test]
fn overflow_deadline_rejects_without_eviction() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let mut q = MessageQueue::new(
        ChannelMode::ReliableMessage,
        QueueConfig {
            ttl: Duration::MAX,
            ..QueueConfig::default()
        },
        budget.clone(),
    )
    .unwrap();
    assert_eq!(
        q.enqueue(vec![1], Instant::now()).result,
        Err(QueueError::DeadlineOverflow)
    );
    assert_eq!(budget.usage(), (0, 0));
}

#[test]
fn drop_and_expiry_return_each_original_id_once_without_payload() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::DropOldest);
    let now = Instant::now();
    let a = q.enqueue(vec![1; 3], now).result.unwrap().0.unwrap();
    let b = q.enqueue(vec![2; 3], now).result.unwrap().0.unwrap();
    let changed = q.enqueue(vec![3; 6], now);
    let c = changed.result.unwrap().0.unwrap();
    assert_eq!(
        changed
            .settled
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        vec![a, b]
    );
    assert!(
        changed
            .settled
            .iter()
            .all(|item| item.reason == SettlementReason::DroppedOldest)
    );
    assert!(q.cancel(a).is_none());
    let changed = q.pop(now + Duration::from_secs(10));
    assert!(changed.result.unwrap().is_none());
    assert_eq!(changed.settled.len(), 1);
    assert_eq!(changed.settled[0].id, c);
    assert_eq!(changed.settled[0].reason, SettlementReason::Expired);
    assert!(q.expire(now + Duration::from_secs(11)).settled.is_empty());
    assert!(q.close().is_empty());
    assert_eq!(budget.usage(), (0, 0));
}

#[test]
fn full_after_expiry_still_returns_settlement_metadata() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    let expired = q.enqueue(vec![1], now).result.unwrap().0.unwrap();
    let remaining = q
        .enqueue(vec![2; 5], now + Duration::from_secs(1))
        .result
        .unwrap()
        .0
        .unwrap();
    let changed = q.enqueue(vec![3; 2], now + Duration::from_secs(10));
    assert_eq!(changed.result, Err(QueueError::Full));
    assert_eq!(changed.settled.len(), 1);
    assert_eq!(changed.settled[0].id, expired);
    assert_eq!(changed.settled[0].reason, SettlementReason::Expired);
    let closed = q.close();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].id, remaining);
    assert_eq!(closed[0].reason, SettlementReason::Closed);
    assert!(q.close().is_empty());
    assert_eq!(budget.usage(), (0, 0));
}

#[test]
fn cancellation_start_rejection_and_send_finish_preserve_identity() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    let a = q.enqueue(vec![1], now).result.unwrap().0.unwrap();
    let cancelled = q.pop(now).result.unwrap().unwrap().cancel();
    assert_eq!(cancelled.id, a);
    assert_eq!(cancelled.reason, SettlementReason::Cancelled);
    let b = q.enqueue(vec![2], now).result.unwrap().0.unwrap();
    let ticket = q.pop(now).result.unwrap().unwrap();
    let error = match ticket.begin(now + Duration::from_secs(10)) {
        Err(error) => error,
        Ok(_) => panic!("expired ticket began sending"),
    };
    assert_eq!(error.id, b);
    assert_eq!(error.reason, TicketError::Expired);
    assert_eq!(budget.usage(), (0, 0));
    for outcome in [
        SendOutcome::Sent,
        SendOutcome::Failed,
        SendOutcome::Cancelled,
    ] {
        let id = q.enqueue(vec![3], now).result.unwrap().0.unwrap();
        let sent = q
            .pop(now)
            .result
            .unwrap()
            .unwrap()
            .begin(now)
            .unwrap()
            .finish(outcome);
        assert_eq!(sent.id, id);
        assert_eq!(
            sent.reason,
            match outcome {
                SendOutcome::Sent => SettlementReason::Sent,
                SendOutcome::Failed => SettlementReason::SendFailed,
                SendOutcome::Cancelled => SettlementReason::Cancelled,
            }
        );
        assert_eq!(budget.usage(), (0, 0));
    }
}

#[test]
fn batch_expiry_is_fifo_and_drain_has_no_duplicate_completions() {
    let budget = OutboundBudget::new(1024, 128).unwrap();
    let mut q = MessageQueue::new(
        ChannelMode::LowLatencyMessage,
        QueueConfig {
            max_messages: 128,
            max_bytes: 1024,
            max_message_bytes: 64,
            ttl: Duration::from_secs(10),
            overflow: OverflowPolicy::Fail,
        },
        budget.clone(),
    )
    .unwrap();
    let now = Instant::now();
    let mut ids = Vec::new();
    for index in 0..100 {
        ids.push(q.enqueue(vec![index; 8], now).result.unwrap().0.unwrap());
    }
    let expired = q.expire(now + Duration::from_secs(10));
    assert_eq!(expired.result.unwrap(), 100);
    assert_eq!(
        expired
            .settled
            .into_iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        ids
    );
    assert!(q.close().is_empty());
    assert_eq!(budget.usage(), (0, 0));
}

#[test]
fn stream_reservations_share_global_limits_without_message_eviction() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let stream = budget.reserve(5).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::DropOldest);
    let now = Instant::now();
    q.enqueue(vec![1], now).result.unwrap();
    assert_eq!(q.enqueue(vec![2; 2], now).result, Err(QueueError::Full));
    assert_eq!(budget.usage(), (6, 2));
    drop(stream);
    assert_eq!(budget.usage(), (1, 1));
    let next = budget.reserve(5).unwrap();
    q.close();
    assert_eq!(budget.usage(), (5, 1));
    drop(next);
    assert_eq!(budget.usage(), (0, 0));
}

#[test]
fn stream_fin_consumes_count_and_reset_does_not_fake_inflight_release() {
    let budget = OutboundBudget::new(16_384, 1).unwrap();
    let fin = budget.reserve(0).unwrap();
    assert_eq!(budget.usage(), (0, 1));
    assert!(matches!(budget.reserve(1), Err(QueueError::Full)));
    drop(fin);
    let write = budget.reserve(16_384).unwrap();
    assert!(write.check_open().is_ok());
    budget.close();
    assert_eq!(write.check_open(), Err(QueueError::Closed));
    assert!(matches!(budget.reserve(0), Err(QueueError::Closed)));
    assert_eq!(budget.usage(), (16_384, 1));
    drop(write);
    assert_eq!(budget.usage(), (0, 0));
}

#[test]
fn stream_reservation_cancellation_and_oversize_do_not_leak() {
    let budget = OutboundBudget::new(4, 2).unwrap();
    assert!(matches!(budget.reserve(usize::MAX), Err(QueueError::Full)));
    assert_eq!(budget.usage(), (0, 0));
    {
        let _cancelled_command = budget.reserve(4).unwrap();
        assert_eq!(budget.usage(), (4, 1));
    }
    assert_eq!(budget.usage(), (0, 0));
}

#[test]
fn caller_deadline_never_extends_default_and_expired_tail_is_not_hidden_by_head() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    let first = q
        .enqueue_before(vec![1], now, now + Duration::from_secs(100))
        .result
        .unwrap()
        .0
        .unwrap();
    let second = q
        .enqueue_before(vec![2], now, now + Duration::from_secs(1))
        .result
        .unwrap()
        .0
        .unwrap();
    let expired = q.expire(now + Duration::from_secs(2));
    assert_eq!(expired.result, Ok(1));
    assert_eq!(expired.settled.len(), 1);
    assert_eq!(expired.settled[0].id, second);
    assert_eq!(expired.settled[0].reason, SettlementReason::Expired);
    assert_eq!(budget.usage(), (1, 1));
    let later = q.expire(now + Duration::from_secs(10));
    assert_eq!(later.settled.len(), 1);
    assert_eq!(later.settled[0].id, first);
    assert_eq!(budget.usage(), (0, 0));
}
#[test]
fn already_expired_admission_settles_older_expiry_without_charging_or_id_reuse() {
    let budget = OutboundBudget::new(6, 2).unwrap();
    let mut q = queue(budget.clone(), OverflowPolicy::Fail);
    let now = Instant::now();
    let first = q.enqueue(vec![1], now).result.unwrap().0.unwrap();
    let late = q.enqueue_before(
        vec![2],
        now + Duration::from_secs(10),
        now + Duration::from_secs(9),
    );
    assert_eq!(late.result, Err(QueueError::Expired));
    assert_eq!(late.settled.len(), 1);
    assert_eq!(late.settled[0].id, first);
    assert_eq!(budget.usage(), (0, 0));
    let next = q
        .enqueue(vec![3], now + Duration::from_secs(10))
        .result
        .unwrap()
        .0
        .unwrap();
    assert!(next > first);
}
