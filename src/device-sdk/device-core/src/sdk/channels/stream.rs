use super::*;
use crate::outbound::{GlobalPermit, OutboundBudget};
use device_transport_webrtc::stream::{ByteStream, StreamError};

const CHUNK: usize = 16 * 1024;
struct WriteRequest {
    bytes: Vec<u8>,
    fin: bool,
    expires: Instant,
    charge: GlobalPermit,
    result: oneshot::Sender<Result<usize, SdkError>>,
}
pub struct SdkStreamReader {
    scope: Scope,
    received: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    offset: usize,
    eof: bool,
}
pub struct SdkStreamWriter {
    scope: Scope,
    commands: mpsc::Sender<WriteRequest>,
    budget: OutboundBudget,
}
pub struct SdkByteStream {
    reader: SdkStreamReader,
    writer: SdkStreamWriter,
}
macro_rules! scope_methods {
    () => {
        pub fn label(&self) -> &str {
            &self.scope.label
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
    };
}
impl SdkByteStream {
    pub fn label(&self) -> &str {
        self.reader.label()
    }
    pub fn session_id(&self) -> &str {
        self.reader.session_id()
    }
    pub fn negotiation_generation(&self) -> u64 {
        self.reader.negotiation_generation()
    }
    pub fn validity(&self) -> ChannelValidity {
        self.reader.validity()
    }
    pub fn split(self) -> (SdkStreamReader, SdkStreamWriter) {
        (self.reader, self.writer)
    }
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize, SdkError> {
        self.reader.read(bytes).await
    }
    pub async fn write(&self, bytes: &[u8]) -> Result<usize, SdkError> {
        self.writer.write(bytes).await
    }
    pub async fn shutdown_write(&self) -> Result<(), SdkError> {
        self.writer.shutdown_write().await
    }
    pub async fn close(self) -> Result<(), SdkError> {
        self.reader.scope.gate.close_and_wait().await
    }
}
impl SdkStreamReader {
    scope_methods!();
    pub async fn read(&mut self, output: &mut [u8]) -> Result<usize, SdkError> {
        self.scope.gate.check()?;
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset == self.pending.len() && !self.eof {
            let chunk = tokio::select! {
                biased;
                _ = self.scope.gate.invalidated() => return Err(SdkError::Closed),
                chunk = self.received.recv() => chunk.ok_or(SdkError::Closed)?,
            };
            self.scope.gate.check()?;
            self.eof = chunk.is_empty();
            self.pending = chunk;
            self.offset = 0;
        }
        if self.eof {
            return Ok(0);
        }
        let n = output.len().min(self.pending.len() - self.offset);
        output[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
    pub async fn close(self) -> Result<(), SdkError> {
        self.scope.gate.close_and_wait().await
    }
}
// Cancelled/expired write has an uncertain transport result. Close this whole
// stream rather than silently dropping/retrying a middle byte range.
struct WriteCancellation {
    gate: Arc<ChannelGate>,
    completed: bool,
}
impl Drop for WriteCancellation {
    fn drop(&mut self) {
        if !self.completed {
            self.gate.close();
        }
    }
}
impl SdkStreamWriter {
    scope_methods!();
    async fn submit(
        &self,
        bytes: &[u8],
        fin: bool,
        caller_deadline: Option<Instant>,
    ) -> Result<usize, SdkError> {
        self.scope.gate.check()?;
        let now = Instant::now();
        let default_deadline = now + Duration::from_secs(30);
        let expires =
            caller_deadline.map_or(default_deadline, |deadline| deadline.min(default_deadline));
        if expires <= now {
            self.scope.gate.close();
            return Err(SdkError::Transport(TransportError::Timeout));
        }
        let permit = self.commands.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => SdkError::QueueFull,
            _ => SdkError::Closed,
        })?;
        let n = bytes.len().min(CHUNK);
        let charge = self.budget.reserve(n).map_err(queue_error)?;
        let (result, completion) = oneshot::channel();
        permit.send(WriteRequest {
            bytes: bytes[..n].to_vec(),
            fin,
            expires,
            charge,
            result,
        });
        let mut cancellation = WriteCancellation {
            gate: self.scope.gate.clone(),
            completed: false,
        };
        let result = tokio::select! {
            biased;
            _ = self.scope.gate.invalidated() => Err(SdkError::Closed),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(expires)) => {
                self.scope.gate.close(); Err(SdkError::Transport(TransportError::Timeout))
            },
            result = completion => result.map_err(|_| SdkError::Closed)?,
        };
        cancellation.completed = true;
        result
    }
    pub async fn write(&self, bytes: &[u8]) -> Result<usize, SdkError> {
        if bytes.is_empty() {
            self.scope.gate.check()?;
            return Ok(0);
        }
        self.submit(bytes, false, None).await
    }
    pub async fn shutdown_write(&self) -> Result<(), SdkError> {
        self.submit(&[], true, None).await.map(|_| ())
    }
    pub async fn write_before(&self, bytes: &[u8], deadline: Instant) -> Result<usize, SdkError> {
        self.submit(bytes, false, Some(deadline)).await
    }
    pub async fn shutdown_write_before(&self, deadline: Instant) -> Result<(), SdkError> {
        self.submit(&[], true, Some(deadline)).await.map(|_| ())
    }

    pub async fn close(self) -> Result<(), SdkError> {
        self.scope.gate.close_and_wait().await
    }
}
impl Drop for SdkStreamReader {
    fn drop(&mut self) {
        self.scope.gate.close();
    }
}
impl Drop for SdkStreamWriter {
    fn drop(&mut self) {
        self.scope.gate.close();
    }
}

pub(super) fn wrap(scope: Scope, budget: OutboundBudget) -> (SdkByteStream, StreamWorker) {
    let (commands, writes) = mpsc::channel(1);
    let (received, reads) = mpsc::channel(4);
    let stream = SdkByteStream {
        reader: SdkStreamReader {
            scope: scope.clone(),
            received: reads,
            pending: Vec::new(),
            offset: 0,
            eof: false,
        },
        writer: SdkStreamWriter {
            scope: scope.clone(),
            commands,
            budget,
        },
    };
    (
        stream,
        StreamWorker {
            scope,
            writes,
            received,
        },
    )
}
pub(super) struct StreamWorker {
    scope: Scope,
    writes: mpsc::Receiver<WriteRequest>,
    received: mpsc::Sender<Vec<u8>>,
}
fn error(error: StreamError) -> SdkError {
    match error {
        StreamError::Transport(error) => SdkError::Transport(error),
        StreamError::Protocol => SdkError::Transport(TransportError::UnsupportedChannel),
        _ => SdkError::Closed,
    }
}
impl StreamWorker {
    pub(super) async fn run(
        mut self,
        mut raw: ByteStream,
        _permit: ActivePermit,
    ) -> Result<(), SdkError> {
        let operation = async {
            let mut eof = false;
            let mut buffer = vec![0; CHUNK];
            loop {
                self.scope.gate.check()?;
                // Reserve delivery capacity BEFORE reading. No consumed stream bytes
                // are discarded on backpressure; writes remain selectable while full.
                let read_permit = if eof {
                    None
                } else {
                    self.received.clone().try_reserve_owned().ok()
                };
                // Fair duplex arbitration: an always-ready write queue must not
                // starve incoming bytes/FIN. Each selected branch rechecks the gate.
                tokio::select! {
                    _ = self.scope.gate.invalidated() => return Err(SdkError::Closed),
                    request = self.writes.recv() => {
                        let Some(request) = request else { return Ok(()); };
                        if Instant::now() >= request.expires {
                            let _ = request.result.send(Err(SdkError::Transport(TransportError::Timeout)));
                            return Err(SdkError::Transport(TransportError::Timeout));
                        }
                        request.charge.check_open().map_err(queue_error)?;
                        let write = async {
                            if request.fin { raw.shutdown_write().await.map(|_| 0) }
                            else { raw.write(&request.bytes).await }
                        };
                        let result = tokio::select! {
                            biased;
                            _ = self.scope.gate.invalidated() => Err(StreamError::Closed),
                            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(request.expires)) => Err(StreamError::Transport(TransportError::Timeout)),
                            result = write => result,
                        };
                        // FIN closes only our writing half. A rejected write-after-FIN
                        // must not tear down the still-readable reverse direction.
                        let fatal = result.as_ref().err().filter(|value| !matches!(value,
                            StreamError::WriteClosed | StreamError::Transport(TransportError::BufferFull)))
                            .copied().map(error);
                        let _ = request.result.send(result.map_err(error));
                        drop(request.charge);
                        if let Some(error) = fatal { return Err(error); }
                    },
                    result = raw.read(&mut buffer), if read_permit.is_some() => {
                        let n = match result {
                            Ok(n) => n,
                            Err(StreamError::Transport(TransportError::Timeout)) => continue,
                            Err(value) => return Err(error(value)),
                        };
                        self.scope.gate.check()?;
                        read_permit.expect("reserved stream capacity").send(buffer[..n].to_vec());
                        eof = n == 0;
                    },
                    // Bounded backpressure retry, never busy-spin on a full receiver.
                    _ = tokio::time::sleep(Duration::from_millis(5)), if !eof && read_permit.is_none() => {},
                }
            }
        };
        let result = operation.await;
        self.scope.gate.close();
        self.writes.close();
        while let Some(request) = self.writes.recv().await {
            let _ = request.result.send(Err(SdkError::Closed));
        }
        let _ = raw.close().await;
        drop(_permit);
        self.scope.gate.finished();
        result
    }
}

impl Drop for StreamWorker {
    fn drop(&mut self) {
        self.scope.gate.close();
        self.writes.close();
        while let Ok(request) = self.writes.try_recv() {
            let _ = request.result.send(Err(SdkError::Closed));
        }
        self.scope.gate.finished();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{pin_mut, poll};
    fn fixture() -> (SdkByteStream, StreamWorker, OutboundBudget, Arc<Gate>) {
        let parent = Arc::new(Gate::default());
        parent.update(Some(Instant::now() + Duration::from_secs(60)));
        let scope = Scope {
            session_id: "session".into(),
            generation: 3,
            label: "stream".into(),
            mode: ChannelMode::ReliableStream,
            gate: ChannelGate::new(parent.clone()),
        };
        let budget = OutboundBudget::new(16384, 2).unwrap();
        let (stream, worker) = wrap(scope, budget.clone());
        (stream, worker, budget, parent)
    }
    #[tokio::test]
    async fn earlier_ffi_deadline_expires_queued_stream_without_resuming_middle_bytes() {
        let (stream, worker, budget, _) = fixture();
        let (_reader, writer) = stream.split();
        let deadline = Instant::now() + Duration::from_millis(10);
        assert_eq!(
            writer.write_before(b"queued", deadline).await,
            Err(SdkError::Transport(TransportError::Timeout))
        );
        assert!(!writer.validity().is_valid());
        assert_eq!(budget.usage(), (6, 1));
        assert_eq!(writer.write(b"no resume").await, Err(SdkError::Closed));
        drop(worker);
        assert_eq!(budget.usage(), (0, 0));
    }
    #[tokio::test]
    async fn already_expired_fin_is_fail_closed_without_consuming_budget() {
        let (stream, worker, budget, _) = fixture();
        let (_reader, writer) = stream.split();
        assert_eq!(
            writer.shutdown_write_before(Instant::now()).await,
            Err(SdkError::Transport(TransportError::Timeout))
        );
        assert_eq!(budget.usage(), (0, 0));
        assert!(!writer.validity().is_valid());
        drop(worker);
    }
    #[tokio::test]
    async fn worker_abort_drop_settles_queued_stream_write_and_releases_charge() {
        let (stream, worker, budget, _) = fixture();
        let (mut reader, writer) = stream.split();
        let future = writer.write(b"queued");
        pin_mut!(future);
        assert!(poll!(&mut future).is_pending());
        assert_eq!(budget.usage(), (6, 1));
        drop(worker);
        assert_eq!(budget.usage(), (0, 0));
        assert!(!writer.validity().is_valid());
        assert_eq!(future.await, Err(SdkError::Closed));
        assert_eq!(reader.read(&mut [0; 1]).await, Err(SdkError::Closed));
    }
    #[tokio::test]
    async fn cancel_uncertain_stream_write_closes_stream_but_keeps_charge_until_worker_drop() {
        let (stream, worker, budget, _) = fixture();
        let validity = stream.validity();
        {
            let future = stream.write(b"in queue");
            pin_mut!(future);
            assert!(poll!(&mut future).is_pending());
        }
        assert!(!validity.is_valid());
        assert_eq!(budget.usage(), (8, 1));
        assert_eq!(stream.write(b"never replay").await, Err(SdkError::Closed));
        drop(worker);
        assert_eq!(budget.usage(), (0, 0));
    }
    #[tokio::test]
    async fn queuefull_is_non_admission_not_stream_failure_and_parent_expiry_blocks_data() {
        let (stream, worker, budget, parent) = fixture();
        let first = stream.write(b"queued");
        pin_mut!(first);
        assert!(poll!(&mut first).is_pending());
        assert_eq!(stream.write(b"next").await, Err(SdkError::QueueFull));
        assert!(stream.validity().is_valid());
        parent.update(Some(Instant::now()));
        assert_eq!(
            stream.write(b"expired").await,
            Err(SdkError::AuthorizationExpired)
        );
        drop(worker);
        assert_eq!(budget.usage(), (0, 0));
        assert!(first.await.is_err());
    }
}
