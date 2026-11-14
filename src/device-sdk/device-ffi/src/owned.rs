//! Independently owned read allocations; no SDK pointer survives in a lease.
use crate::{
    budget,
    state::{HANDLE, INTERNAL, INVALID, next_id},
};
use device_transport_webrtc::stream::OwnedChunk;
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

pub struct Payload {
    pub chunk: OwnedChunk,
    pub _charge: budget::Permit,
}
static BUFFERS: OnceLock<Mutex<BTreeMap<u64, Payload>>> = OnceLock::new();
fn buffers() -> &'static Mutex<BTreeMap<u64, Payload>> {
    BUFFERS.get_or_init(Default::default)
}
pub fn transfer(payload: Payload) -> Result<(u64, *const u8, usize, usize), u32> {
    if payload.chunk.is_empty() || payload.chunk.allocation_capacity() > 65536 {
        return Err(INVALID);
    }
    let id = next_id()?;
    let pointer = payload.chunk.as_slice().as_ptr();
    let length = payload.chunk.len();
    let capacity = payload.chunk.allocation_capacity();
    buffers().lock().map_err(|_| INTERNAL)?.insert(id, payload);
    Ok((id, pointer, length, capacity))
}
pub fn release(handle: u64) -> Result<(), u32> {
    let payload = buffers()
        .lock()
        .map_err(|_| INTERNAL)?
        .remove(&handle)
        .ok_or(HANDLE)?;
    drop(payload);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lease_outlives_owner_and_double_release_is_rejected() {
        let budget = budget::Budget::new(budget::DEFAULT_BYTES).unwrap();
        let payload = Payload {
            chunk: vec![1, 2, 3].into(),
            _charge: budget.reserve(65536, false).unwrap(),
        };
        let (handle, _, length, _) = transfer(payload).unwrap();
        assert_eq!(length, 3);
        assert_eq!(budget.snapshot().1, 65536);
        std::thread::spawn(move || release(handle).unwrap())
            .join()
            .unwrap();
        assert_eq!(budget.snapshot().1, 0);
        assert_eq!(release(handle), Err(HANDLE));
    }
}
