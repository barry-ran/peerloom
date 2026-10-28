//! SDK 的可独立测试基础规则；尚不提供注册、网络连接或可靠字节流协议。
//! 队列容量限制的是排队消息数量和有效载荷字节，不代表整个进程内存上限。

pub mod identity;
pub mod lease;
pub mod sdk;
pub mod signaling;

use device_protocol::{ChannelMode, OverflowPolicy};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// 可配置工程初值，不是性能 SLA。创建队列时验证一次，此后不可更改。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueConfig {
    pub max_messages: usize,
    pub max_bytes: usize,
    pub max_message_bytes: usize,
    pub ttl: Duration,
    pub overflow: OverflowPolicy,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_messages: 256,
            max_bytes: 1024 * 1024,
            max_message_bytes: 64 * 1024,
            ttl: Duration::from_secs(30),
            overflow: OverflowPolicy::Fail,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    InvalidConfiguration,
    MessageTooLarge,
    Full,
    DeadlineOverflow,
    ClockMovedBackwards,
    /// 字节流缺少一段便不能继续传输；丢弃整个队列，终止该流。
    StreamExpired,
    Closed,
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "INVALID_QUEUE_CONFIGURATION",
            Self::MessageTooLarge => "MESSAGE_TOO_LARGE",
            Self::Full => "BUFFER_FULL",
            Self::DeadlineOverflow => "DEADLINE_OVERFLOW",
            Self::ClockMovedBackwards => "CLOCK_MOVED_BACKWARDS",
            Self::StreamExpired => "STREAM_EXPIRED",
            Self::Closed => "QUEUE_CLOSED",
        })
    }
}

impl std::error::Error for QueueError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Accepted,
    AcceptedAfterDropping { messages: usize },
    DroppedNewest,
}

/// 仅计本次操作清理的过期消息，避免无界累计计数溢出。
#[derive(Debug, PartialEq, Eq)]
pub struct QueueRead {
    pub message: Option<Box<[u8]>>,
    pub expired_messages: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueWrite {
    pub outcome: EnqueueOutcome,
    pub expired_messages: usize,
}

#[derive(Debug)]
struct PendingMessage {
    bytes: Box<[u8]>,
    expires_at: Instant,
}

/// 单一拥有者队列。并发调用需要由上层 actor 或锁串行化，不在这里持锁调用客户回调。
/// `enqueue` 获得输入所有权；成功仅表示排队，不表示网络写入或业务消费。
#[derive(Debug)]
pub struct SendQueue {
    config: QueueConfig,
    mode: ChannelMode,
    messages: VecDeque<PendingMessage>,
    payload_bytes: usize,
    expired_messages_total: u64,
    terminal_error: Option<QueueError>,
    last_now: Option<Instant>,
}

impl SendQueue {
    pub fn new(mode: ChannelMode, config: QueueConfig) -> Result<Self, QueueError> {
        if config.max_messages == 0
            || config.max_bytes == 0
            || config.max_message_bytes == 0
            || config.max_message_bytes > config.max_bytes
            || config.ttl.is_zero()
            || (mode == ChannelMode::ReliableStream && config.overflow != OverflowPolicy::Fail)
        {
            return Err(QueueError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            mode,
            messages: VecDeque::new(),
            payload_bytes: 0,
            expired_messages_total: 0,
            terminal_error: None,
            last_now: None,
        })
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    /// 即使清理后入队失败，过期消息也仍可观测。计数达到 u64::MAX 时饱和，不回绕。
    pub fn expired_messages_total(&self) -> u64 {
        self.expired_messages_total
    }

    /// 关闭不可逆，释放排队数据；后续入队及读取都报错。
    pub fn close(&mut self) {
        self.messages.clear();
        self.payload_bytes = 0;
        self.terminal_error.get_or_insert(QueueError::Closed);
    }

    pub fn enqueue(&mut self, bytes: Vec<u8>, now: Instant) -> Result<QueueWrite, QueueError> {
        self.check_clock(now)?;
        // 先验证新消息；超大或无法表达截止时间的输入不得驱逐已有消息。
        if bytes.len() > self.config.max_message_bytes {
            return Err(QueueError::MessageTooLarge);
        }
        let expires_at = now
            .checked_add(self.config.ttl)
            .ok_or(QueueError::DeadlineOverflow)?;
        let expired_messages = self.expire(now)?;
        let mut dropped = 0;
        if !self.fits(bytes.len()) {
            match self.config.overflow {
                OverflowPolicy::Fail => return Err(QueueError::Full),
                OverflowPolicy::DropNewest => {
                    return Ok(QueueWrite {
                        outcome: EnqueueOutcome::DroppedNewest,
                        expired_messages,
                    });
                }
                OverflowPolicy::DropOldest => {
                    while !self.fits(bytes.len()) {
                        // 配置保证每条有效新消息均能单独容纳。
                        let Some(old) = self.messages.pop_front() else {
                            return Err(QueueError::InvalidConfiguration);
                        };
                        self.payload_bytes -= old.bytes.len();
                        dropped += 1;
                    }
                }
            }
        }
        // fits 使用减法验证剩余空间，避免 usize 累加溢出。
        self.payload_bytes += bytes.len();
        self.messages.push_back(PendingMessage {
            bytes: bytes.into_boxed_slice(),
            expires_at,
        });
        Ok(QueueWrite {
            outcome: if dropped == 0 {
                EnqueueOutcome::Accepted
            } else {
                EnqueueOutcome::AcceptedAfterDropping { messages: dropped }
            },
            expired_messages,
        })
    }

    pub fn pop(&mut self, now: Instant) -> Result<QueueRead, QueueError> {
        self.check_clock(now)?;
        let expired_messages = self.expire(now)?;
        let message = self.messages.pop_front().map(|entry| {
            self.payload_bytes -= entry.bytes.len();
            entry.bytes
        });
        Ok(QueueRead {
            message,
            expired_messages,
        })
    }

    fn check_clock(&mut self, now: Instant) -> Result<(), QueueError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        if self.last_now.is_some_and(|last| now < last) {
            return Err(QueueError::ClockMovedBackwards);
        }
        self.last_now = Some(now);
        Ok(())
    }

    fn fits(&self, incoming: usize) -> bool {
        self.messages.len() < self.config.max_messages
            && incoming <= self.config.max_bytes - self.payload_bytes
    }

    fn expire(&mut self, now: Instant) -> Result<usize, QueueError> {
        let mut expired = 0;
        while self
            .messages
            .front()
            .is_some_and(|entry| now >= entry.expires_at)
        {
            if self.mode == ChannelMode::ReliableStream {
                let expired_count = self
                    .messages
                    .iter()
                    .take_while(|entry| now >= entry.expires_at)
                    .count();
                self.expired_messages_total = self
                    .expired_messages_total
                    .saturating_add(u64::try_from(expired_count).unwrap_or(u64::MAX));
                self.messages.clear();
                self.payload_bytes = 0;
                self.terminal_error = Some(QueueError::StreamExpired);
                return Err(QueueError::StreamExpired);
            }
            if let Some(entry) = self.messages.pop_front() {
                self.payload_bytes -= entry.bytes.len();
                self.expired_messages_total = self.expired_messages_total.saturating_add(1);
                expired += 1;
            }
        }
        Ok(expired)
    }
}
