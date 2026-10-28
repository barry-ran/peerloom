use device_core::{EnqueueOutcome, QueueConfig, QueueError, SendQueue};
use device_protocol::{ChannelMode, OverflowPolicy};
use std::time::{Duration, Instant};

fn config(overflow: OverflowPolicy) -> QueueConfig {
    QueueConfig {
        max_messages: 2,
        max_bytes: 6,
        max_message_bytes: 6,
        ttl: Duration::from_secs(10),
        overflow,
    }
}

fn queue(overflow: OverflowPolicy) -> SendQueue {
    SendQueue::new(ChannelMode::ReliableMessage, config(overflow)).unwrap()
}

#[test]
fn fifo_preserves_message_boundaries_and_releases_capacity() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::Fail);
    assert_eq!(
        queue.enqueue(vec![1, 2], now).unwrap().outcome,
        EnqueueOutcome::Accepted
    );
    queue.enqueue(vec![3], now).unwrap();
    assert_eq!(queue.payload_bytes(), 3);
    assert_eq!(queue.pop(now).unwrap().message.unwrap().as_ref(), &[1, 2]);
    assert_eq!(queue.payload_bytes(), 1);
    assert_eq!(queue.pop(now).unwrap().message.unwrap().as_ref(), &[3]);
    assert!(queue.pop(now).unwrap().message.is_none());
    assert!(queue.is_empty());
    assert_eq!(queue.payload_bytes(), 0);
}

#[test]
fn independent_message_and_byte_caps() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::Fail);
    queue.enqueue(vec![1; 6], now).unwrap();
    assert_eq!(queue.enqueue(vec![2], now), Err(QueueError::Full));
    assert_eq!(queue.payload_bytes(), 6);
    queue.pop(now).unwrap();
    queue.enqueue(vec![], now).unwrap();
    queue.enqueue(vec![], now).unwrap();
    assert_eq!(queue.enqueue(vec![], now), Err(QueueError::Full));
    assert_eq!(queue.len(), 2);
}

#[test]
fn drop_newest_never_claims_accepted() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::DropNewest);
    queue.enqueue(vec![1; 6], now).unwrap();
    assert_eq!(
        queue.enqueue(vec![2], now).unwrap().outcome,
        EnqueueOutcome::DroppedNewest
    );
    assert_eq!(queue.pop(now).unwrap().message.unwrap().as_ref(), &[1; 6]);
}

#[test]
fn drop_oldest_can_evict_multiple_but_keeps_new_message_whole() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::DropOldest);
    queue.enqueue(vec![1; 3], now).unwrap();
    queue.enqueue(vec![2; 3], now).unwrap();
    assert_eq!(
        queue.enqueue(vec![3; 6], now).unwrap().outcome,
        EnqueueOutcome::AcceptedAfterDropping { messages: 2 }
    );
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.payload_bytes(), 6);
    assert_eq!(queue.pop(now).unwrap().message.unwrap().as_ref(), &[3; 6]);
}

#[test]
fn oversized_message_never_evicts_existing_message() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::DropOldest);
    queue.enqueue(vec![1; 6], now).unwrap();
    assert_eq!(
        queue.enqueue(vec![2; 7], now),
        Err(QueueError::MessageTooLarge)
    );
    assert_eq!(queue.pop(now).unwrap().message.unwrap().as_ref(), &[1; 6]);
}

#[test]
fn expiry_boundary_does_not_expire_younger_message() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::Fail);
    queue.enqueue(vec![1; 3], now).unwrap();
    queue
        .enqueue(vec![2; 3], now + Duration::from_secs(1))
        .unwrap();
    let read = queue.pop(now + Duration::from_secs(10)).unwrap();
    assert_eq!(read.expired_messages, 1);
    assert_eq!(read.message.unwrap().as_ref(), &[2; 3]);
    assert_eq!(queue.payload_bytes(), 0);
}

#[test]
fn enqueue_reclaims_expired_capacity() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::Fail);
    queue.enqueue(vec![1; 6], now).unwrap();
    let write = queue
        .enqueue(vec![2; 6], now + Duration::from_secs(10))
        .unwrap();
    assert_eq!(write.expired_messages, 1);
    assert_eq!(write.outcome, EnqueueOutcome::Accepted);
}

#[test]
fn invalid_limits_and_zero_ttl_rejected() {
    let baseline = config(OverflowPolicy::Fail);
    for bad in [
        QueueConfig {
            max_messages: 0,
            ..baseline
        },
        QueueConfig {
            max_bytes: 0,
            ..baseline
        },
        QueueConfig {
            max_message_bytes: 0,
            ..baseline
        },
        QueueConfig {
            max_message_bytes: 7,
            ..baseline
        },
        QueueConfig {
            ttl: Duration::ZERO,
            ..baseline
        },
    ] {
        assert_eq!(
            SendQueue::new(ChannelMode::ReliableMessage, bad)
                .unwrap_err()
                .to_string(),
            "INVALID_QUEUE_CONFIGURATION"
        );
    }
}

#[test]
fn streams_reject_drop_policies() {
    for policy in [OverflowPolicy::DropOldest, OverflowPolicy::DropNewest] {
        assert!(SendQueue::new(ChannelMode::ReliableStream, config(policy)).is_err());
    }
}

#[test]
fn expired_stream_fails_closed_instead_of_skipping_bytes() {
    let now = Instant::now();
    let mut queue =
        SendQueue::new(ChannelMode::ReliableStream, config(OverflowPolicy::Fail)).unwrap();
    queue.enqueue(vec![1], now).unwrap();
    queue
        .enqueue(vec![2], now + Duration::from_secs(1))
        .unwrap();
    let later = now + Duration::from_secs(10);
    assert_eq!(queue.pop(later), Err(QueueError::StreamExpired));
    assert_eq!(
        queue.enqueue(vec![3], later),
        Err(QueueError::StreamExpired)
    );
    assert_eq!(queue.payload_bytes(), 0);
    assert!(queue.is_empty());
}

#[test]
fn close_is_idempotent_and_terminal() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::Fail);
    queue.enqueue(vec![1], now).unwrap();
    queue.close();
    queue.close();
    assert_eq!(queue.pop(now), Err(QueueError::Closed));
    assert_eq!(queue.enqueue(vec![1], now), Err(QueueError::Closed));
    assert_eq!(queue.payload_bytes(), 0);
}

#[test]
fn clock_regression_rejected_without_dequeue() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::Fail);
    queue
        .enqueue(vec![1], now + Duration::from_secs(1))
        .unwrap();
    assert_eq!(queue.pop(now), Err(QueueError::ClockMovedBackwards));
    assert_eq!(queue.len(), 1);
}

#[test]
fn unrepresentable_deadline_rejected_without_eviction() {
    let now = Instant::now();
    let mut queue = SendQueue::new(
        ChannelMode::ReliableMessage,
        QueueConfig {
            ttl: Duration::MAX,
            ..config(OverflowPolicy::DropOldest)
        },
    )
    .unwrap();
    assert_eq!(
        queue.enqueue(vec![1], now),
        Err(QueueError::DeadlineOverflow)
    );
    assert!(queue.is_empty());
}

#[test]
fn very_large_config_does_not_preallocate_or_overflow() {
    let now = Instant::now();
    let mut queue = SendQueue::new(
        ChannelMode::LowLatencyMessage,
        QueueConfig {
            max_messages: usize::MAX,
            max_bytes: usize::MAX,
            max_message_bytes: usize::MAX,
            ..QueueConfig::default()
        },
    )
    .unwrap();
    queue.enqueue(vec![1], now).unwrap();
    assert_eq!(queue.payload_bytes(), 1);
}

#[test]
fn repeated_bounded_operations_preserve_accounting() {
    let now = Instant::now();
    for policy in [
        OverflowPolicy::Fail,
        OverflowPolicy::DropNewest,
        OverflowPolicy::DropOldest,
    ] {
        let mut queue = queue(policy);
        for step in 0..10_000 {
            let time = now + Duration::from_millis(step);
            let _ = queue.enqueue(vec![7; (step % 8) as usize], time);
            if step % 3 == 0 {
                queue.pop(time).unwrap();
            }
            assert!(queue.payload_bytes() <= 6);
            assert!(queue.len() <= 2);
        }
        let read = queue.pop(now + Duration::from_secs(30)).unwrap();
        assert!(read.message.is_none());
        assert_eq!(queue.payload_bytes(), 0);
    }
}

#[test]
fn expiry_remains_observable_when_following_enqueue_is_full() {
    let now = Instant::now();
    let mut queue = queue(OverflowPolicy::Fail);
    queue.enqueue(vec![1], now).unwrap();
    queue
        .enqueue(vec![2; 5], now + Duration::from_secs(1))
        .unwrap();
    let later = now + Duration::from_secs(10);
    assert_eq!(queue.enqueue(vec![3; 2], later), Err(QueueError::Full));
    assert_eq!(queue.expired_messages_total(), 1);
    assert_eq!(queue.pop(later).unwrap().expired_messages, 0);
    assert_eq!(queue.expired_messages_total(), 1);
}
