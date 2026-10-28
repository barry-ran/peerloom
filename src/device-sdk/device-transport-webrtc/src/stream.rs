//! 有界可靠字节流：显式帧、偏移读取与单向 FIN；不保留消息边界。
//! `write` 返回已接纳字节数，BufferFull 表示未接纳，调用者不得丢旧/丢新。
//! 取消正在发送的 future 后该流失败关闭，不能猜测或重放不确定字节。

use crate::{IncomingChannel, MessageChannel, PeerTransport, TransportError, reserve_channel};
use std::sync::atomic::Ordering;
use webrtc::data_channel::RTCDataChannelInit;

pub(crate) const PROTOCOL: &str = "peerloom.stream.v1";
const HEADER: usize = 17;
pub(crate) const MIN_MESSAGE_BYTES: usize = HEADER + 4;
const MAX_CHUNK: usize = 16 << 10;
const MAGIC: &[u8; 4] = b"PLS1";
const DATA: u8 = 1;
const FIN: u8 = 2;
const SETTINGS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    Transport(TransportError),
    Protocol,
    Closed,
    WriteClosed,
    CancelledWrite,
}
impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for StreamError {}
impl From<TransportError> for StreamError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

pub struct ByteStream {
    channel: MessageChannel,
    receive_limit: usize,
    send_limit: usize,
    settings_sent: bool,
    initialized: bool,
    tx_seq: u64,
    rx_seq: u64,
    tx_pending: bool,
    write_closed: bool,
    read_closed: bool,
    failed: bool,
    pending: Vec<u8>,
    offset: usize,
}

impl PeerTransport {
    /// 创建独立的可靠字节流通道；需要先完成协商再 wait_open。
    pub async fn create_stream(&self, label: &str) -> Result<ByteStream, StreamError> {
        self.ensure_open()?;
        if label.len() > 128 || self.config.max_message_bytes < HEADER + 4 {
            return Err(TransportError::InvalidConfiguration.into());
        }
        reserve_channel(&self.channel_count, self.config.max_channels)?;
        let options = RTCDataChannelInit {
            protocol: PROTOCOL.into(),
            ..Default::default()
        };
        match self
            .bounded(self.peer.create_data_channel(label, Some(options)))
            .await
        {
            Ok(channel) => Ok(ByteStream::new(self.wrap_channel(channel))),
            Err(error) => {
                if error != TransportError::Timeout {
                    self.channel_count.fetch_sub(1, Ordering::AcqRel);
                }
                Err(error.into())
            }
        }
    }

    /// 接收专用 stream 协议；错误类型通道被关闭，不把不可靠通道当字节流。
    pub async fn accept_stream(&self) -> Result<ByteStream, StreamError> {
        match self.accept_incoming().await {
            Ok(IncomingChannel::ReliableStream(stream)) => Ok(stream),
            Ok(
                IncomingChannel::ReliableMessage(channel)
                | IncomingChannel::LowLatencyMessage(channel),
            ) => {
                let _ = channel.close().await;
                Err(StreamError::Protocol)
            }
            Err(TransportError::UnsupportedChannel) => Err(StreamError::Protocol),
            Err(error) => Err(error.into()),
        }
    }
}

impl ByteStream {
    pub async fn metadata(&self) -> Result<crate::ChannelMetadata, StreamError> {
        self.channel.metadata().await.map_err(StreamError::from)
    }

    pub(crate) fn new(channel: MessageChannel) -> Self {
        let max_chunk = MAX_CHUNK.min(channel.max_message_bytes - HEADER);
        Self {
            channel,
            receive_limit: max_chunk,
            send_limit: max_chunk,
            settings_sent: false,
            initialized: false,
            tx_seq: 0,
            rx_seq: 0,
            tx_pending: false,
            write_closed: false,
            read_closed: false,
            failed: false,
            pending: Vec::new(),
            offset: 0,
        }
    }

    pub async fn wait_open(&mut self) -> Result<(), StreamError> {
        self.ensure_valid()?;
        if self.initialized {
            return Ok(());
        }
        self.channel.wait_open().await?;
        if !self.settings_sent {
            self.send_frame(SETTINGS, &(self.receive_limit as u32).to_be_bytes())
                .await?;
            self.settings_sent = true;
        }
        let frame = match self.channel.receive().await {
            Ok(frame) => frame,
            Err(error) => {
                self.failed = true;
                return Err(error.into());
            }
        };
        let result = decode_frame(&frame, 0, self.receive_limit);
        let remote_limit = match result {
            Ok((SETTINGS, payload)) => {
                u32::from_be_bytes(payload.try_into().map_err(|_| StreamError::Protocol)?) as usize
            }
            _ => {
                self.failed = true;
                return Err(StreamError::Protocol);
            }
        };
        if !(4..=MAX_CHUNK).contains(&remote_limit) {
            self.failed = true;
            return Err(StreamError::Protocol);
        }
        self.send_limit = self.receive_limit.min(remote_limit);
        self.rx_seq = 1;
        self.initialized = true;
        Ok(())
    }

    fn ensure_valid(&mut self) -> Result<(), StreamError> {
        if self.tx_pending {
            self.failed = true;
            return Err(StreamError::CancelledWrite);
        }
        if self.failed {
            return Err(StreamError::Closed);
        }
        Ok(())
    }

    /// 最多接纳一个有限分片；返回 n 后调用者继续发送剩余字节。
    pub async fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        self.ensure_valid()?;
        if !self.initialized {
            return Err(TransportError::NotReady.into());
        }
        if self.write_closed {
            return Err(StreamError::WriteClosed);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let n = bytes.len().min(self.send_limit);
        self.send_frame(DATA, &bytes[..n]).await?;
        Ok(n)
    }

    async fn send_frame(&mut self, kind: u8, payload: &[u8]) -> Result<(), StreamError> {
        let next = self.tx_seq.checked_add(1).ok_or(StreamError::Protocol)?;
        let frame = encode_frame(kind, self.tx_seq, payload);
        self.tx_pending = true;
        let outcome = self.channel.send(&frame).await;
        self.tx_pending = false;
        match outcome {
            Ok(()) => {
                self.tx_seq = next;
                Ok(())
            }
            Err(TransportError::BufferFull) => Err(TransportError::BufferFull.into()),
            Err(error) => {
                self.failed = true;
                Err(error.into())
            }
        }
    }

    /// 单向 EOF；对端仍可向此端发送。FIN 未成功入队时不能宣称 EOF 已发送。
    pub async fn shutdown_write(&mut self) -> Result<(), StreamError> {
        self.ensure_valid()?;
        if !self.initialized {
            return Err(TransportError::NotReady.into());
        }
        if self.write_closed {
            return Ok(());
        }
        self.send_frame(FIN, &[]).await?;
        self.write_closed = true;
        Ok(())
    }

    /// 消费字节而非消息；只有显式 FIN（或空输出缓冲）返回 0。
    pub async fn read(&mut self, output: &mut [u8]) -> Result<usize, StreamError> {
        self.ensure_valid()?;
        if !self.initialized {
            return Err(TransportError::NotReady.into());
        }
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset < self.pending.len() {
            return Ok(self.copy_pending(output));
        }
        if self.read_closed {
            return Ok(0);
        }
        let frame = match self.channel.receive().await {
            Ok(frame) => frame,
            // receive returns complete SCTP messages atomically. A timeout while
            // awaiting the next event consumed no frame and advances no sequence.
            Err(TransportError::Timeout) => return Err(TransportError::Timeout.into()),
            Err(error) => {
                self.failed = true;
                return Err(error.into());
            }
        };
        let parsed = decode_frame(&frame, self.rx_seq, self.receive_limit);
        let (kind, payload) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        if kind == SETTINGS {
            self.failed = true;
            return Err(StreamError::Protocol);
        }
        self.rx_seq = self.rx_seq.checked_add(1).ok_or(StreamError::Protocol)?;
        if kind == FIN {
            self.read_closed = true;
            return Ok(0);
        }
        self.pending.clear();
        self.pending.extend_from_slice(payload);
        self.offset = 0;
        Ok(self.copy_pending(output))
    }

    fn copy_pending(&mut self, output: &mut [u8]) -> usize {
        let n = output.len().min(self.pending.len() - self.offset);
        output[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
        self.offset += n;
        if self.offset == self.pending.len() {
            self.pending.clear();
            self.offset = 0;
        }
        n
    }

    /// 双向中止，不承诺尚未消费的数据送达；无 Drop 后台任务。
    pub async fn close(&mut self) -> Result<(), StreamError> {
        self.failed = true;
        self.pending.clear();
        self.channel.close().await.map_err(Into::into)
    }
}

fn encode_frame(kind: u8, sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.push(kind);
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
fn decode_frame(frame: &[u8], sequence: u64, max_chunk: usize) -> Result<(u8, &[u8]), StreamError> {
    if frame.len() < HEADER || &frame[..4] != MAGIC {
        return Err(StreamError::Protocol);
    }
    let kind = frame[4];
    let actual_seq =
        u64::from_be_bytes(frame[5..13].try_into().map_err(|_| StreamError::Protocol)?);
    let length = u32::from_be_bytes(
        frame[13..17]
            .try_into()
            .map_err(|_| StreamError::Protocol)?,
    ) as usize;
    if actual_seq != sequence
        || length > max_chunk
        || frame.len() - HEADER != length
        || !matches!(kind, DATA | FIN | SETTINGS)
        || (kind == SETTINGS && length != 4)
        || (kind == FIN && length != 0)
        || (kind == DATA && length == 0)
    {
        return Err(StreamError::Protocol);
    }
    Ok((kind, &frame[HEADER..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_validate_sequence_size_type_and_fin() {
        let frame = encode_frame(DATA, 3, b"abc");
        assert_eq!(decode_frame(&frame, 3, 3), Ok((DATA, b"abc".as_slice())));
        assert_eq!(decode_frame(&frame, 4, 3), Err(StreamError::Protocol));
        assert_eq!(decode_frame(&frame, 3, 2), Err(StreamError::Protocol));
        for bad in [
            encode_frame(9, 0, b"x"),
            encode_frame(DATA, 0, b""),
            encode_frame(FIN, 0, b"x"),
            vec![0; 8],
        ] {
            assert_eq!(decode_frame(&bad, 0, MAX_CHUNK), Err(StreamError::Protocol));
        }
        assert_eq!(
            decode_frame(&encode_frame(FIN, 0, &[]), 0, MAX_CHUNK),
            Ok((FIN, b"".as_slice()))
        );
    }
}
