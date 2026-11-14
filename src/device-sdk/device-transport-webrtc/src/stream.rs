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

/// Immutable owned receive bytes. Slices retain the original allocation charge.
#[derive(Clone, Debug, Default)]
pub struct OwnedChunk {
    bytes: bytes::Bytes,
    capacity: usize,
}
impl OwnedChunk {
    pub fn from_buffer(mut buffer: bytes::BytesMut) -> Self {
        // Bound retained backing storage, not just the visible payload.
        if buffer.capacity() > 65536 {
            buffer = bytes::BytesMut::from(buffer.as_ref());
        }
        let capacity = buffer.capacity();
        Self {
            bytes: buffer.freeze(),
            capacity,
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub fn allocation_capacity(&self) -> usize {
        self.capacity
    }
    pub fn split_to(&mut self, count: usize) -> Self {
        let bytes = self.bytes.split_to(count);
        let capacity = self.capacity;
        if self.bytes.is_empty() {
            *self = Self::default();
        }
        Self { bytes, capacity }
    }
    fn advance(&mut self, count: usize) {
        self.bytes = self.bytes.slice(count..);
    }
}
impl From<Vec<u8>> for OwnedChunk {
    fn from(value: Vec<u8>) -> Self {
        let capacity = value.capacity();
        Self {
            bytes: value.into(),
            capacity,
        }
    }
}

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
    pending: OwnedChunk,
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
            pending: OwnedChunk::default(),
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
        let chunk = self.read_owned(output.len()).await?;
        output[..chunk.len()].copy_from_slice(chunk.as_slice());
        Ok(chunk.len())
    }

    /// Transfers a bounded immutable slice without copying its payload.
    pub async fn read_owned(&mut self, maximum: usize) -> Result<OwnedChunk, StreamError> {
        self.ensure_valid()?;
        if !self.initialized {
            return Err(TransportError::NotReady.into());
        }
        if maximum == 0 || self.read_closed {
            return Ok(OwnedChunk::default());
        }
        if !self.pending.is_empty() {
            return Ok(self.pending.split_to(maximum.min(self.pending.len())));
        }
        let frame = match self.channel.receive_owned().await {
            Ok(frame) => frame,
            Err(TransportError::Timeout) => return Err(TransportError::Timeout.into()),
            Err(error) => {
                self.failed = true;
                return Err(error.into());
            }
        };
        let kind = match decode_frame(&frame, self.rx_seq, self.receive_limit) {
            Ok((kind, _)) if kind != SETTINGS => kind,
            _ => {
                self.failed = true;
                return Err(StreamError::Protocol);
            }
        };
        self.rx_seq = self.rx_seq.checked_add(1).ok_or(StreamError::Protocol)?;
        if kind == FIN {
            self.read_closed = true;
            return Ok(OwnedChunk::default());
        }
        self.pending = OwnedChunk::from_buffer(frame);
        self.pending.advance(HEADER);
        Ok(self.pending.split_to(maximum.min(self.pending.len())))
    }

    /// 已收到 FIN 后继续等待底层完全关闭；FIN 本身不关闭反向写入。
    /// 只能在读到 EOF 后调用，避免消费尚未交付的正常字节。
    /// 可取消；接收超时不改变状态，调用方可继续等待。
    pub async fn wait_closed_after_fin(&mut self) -> Result<(), StreamError> {
        self.ensure_valid()?;
        if !self.read_closed {
            return Err(TransportError::NotReady.into());
        }
        match self.channel.receive().await {
            Err(TransportError::Timeout) => Err(TransportError::Timeout.into()),
            Err(TransportError::Closed) => {
                self.failed = true;
                Ok(())
            }
            Err(error) => {
                self.failed = true;
                Err(error.into())
            }
            Ok(_) => {
                // FIN 已终止对方发送方向，后续任何帧都是协议错误。
                self.failed = true;
                Err(StreamError::Protocol)
            }
        }
    }

    /// 双向中止，不承诺尚未消费的数据送达；无 Drop 后台任务。
    pub async fn close(&mut self) -> Result<(), StreamError> {
        self.failed = true;
        self.pending = OwnedChunk::default();
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
    fn owned_slices_keep_storage_alive_and_charge_full_capacity() {
        let mut buffer = bytes::BytesMut::with_capacity(4096);
        buffer.extend_from_slice(b"abcdef");
        let original = buffer.as_ptr();
        let mut chunk = OwnedChunk::from_buffer(buffer);
        let first = chunk.split_to(2);
        let rest = chunk.split_to(4);
        assert_eq!(first.as_slice().as_ptr(), original);
        assert_eq!(first.as_slice(), b"ab");
        assert_eq!(rest.as_slice(), b"cdef");
        assert_eq!(first.allocation_capacity(), 4096);
        assert_eq!(rest.allocation_capacity(), 4096);
        assert_eq!(chunk.allocation_capacity(), 0);
        drop(chunk);
        drop(first);
        assert_eq!(rest.as_slice(), b"cdef");
    }

    #[test]
    fn oversized_backing_allocation_is_compacted() {
        let mut buffer = bytes::BytesMut::with_capacity(131072);
        buffer.extend_from_slice(b"small");
        let chunk = OwnedChunk::from_buffer(buffer);
        assert_eq!(chunk.as_slice(), b"small");
        assert!(chunk.allocation_capacity() <= 65536);
    }

    // Reproducible in-process copy microbenchmark, not network throughput.
    #[test]
    #[ignore = "manual release-mode copy baseline"]
    fn receive_copy_microbenchmark() {
        use std::hint::black_box;
        use std::time::Instant;
        let frame = encode_frame(DATA, 0, &vec![0x5a; MAX_CHUNK]);
        let start = Instant::now();
        let mut checksum = 0u64;
        for _ in 0..100_000 {
            let (_, payload) = decode_frame(black_box(&frame), 0, MAX_CHUNK).unwrap();
            let pending = payload.to_vec();
            let mut scratch = vec![0u8; MAX_CHUNK];
            scratch.copy_from_slice(&pending);
            let queued = scratch.to_vec();
            let mut ffi = vec![0u8; MAX_CHUNK];
            ffi.copy_from_slice(&queued);
            checksum += black_box(ffi)[0] as u64;
        }
        eprintln!(
            "baseline_receive_copy bytes={} elapsed_us={} checksum={}",
            100_000 * MAX_CHUNK,
            start.elapsed().as_micros(),
            checksum
        );
        assert_eq!(checksum, 9_000_000);
        let owned_frame = OwnedChunk::from_buffer(bytes::BytesMut::from(frame.as_slice()));
        let start = Instant::now();
        let mut checksum = 0u64;
        for _ in 0..100_000 {
            let mut pending = black_box(owned_frame.clone());
            decode_frame(pending.as_slice(), 0, MAX_CHUNK).unwrap();
            pending.advance(HEADER);
            let queued = pending.split_to(MAX_CHUNK);
            let ffi = black_box(queued);
            checksum += ffi.as_slice()[0] as u64;
        }
        eprintln!(
            "owned_receive_slices bytes={} elapsed_us={} checksum={}",
            100_000 * MAX_CHUNK,
            start.elapsed().as_micros(),
            checksum
        );
        assert_eq!(checksum, 9_000_000);
    }

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
