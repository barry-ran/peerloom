//! Charged FFI buffers/queue capacity, not an allocator/RSS accounting API.
use crate::state::{FULL, INVALID};
use std::sync::{Arc, Mutex};
pub const DEFAULT_BYTES: usize = 128 * 1024 * 1024;
pub const MIN_BYTES: usize = 2 * 1024 * 1024;
pub const OP_METADATA: usize = 1024;
pub const EVENT_METADATA: usize = 256;
#[derive(Default)]
struct Used {
    data: usize,
    critical: usize,
    lifecycle: usize,
}
pub struct Budget {
    data_limit: usize,
    critical_limit: usize,
    used: Mutex<Used>,
}
pub struct Permit {
    budget: Arc<Budget>,
    bytes: usize,
    lane: usize,
}
impl Budget {
    pub fn new(bytes: usize) -> Result<Arc<Self>, u32> {
        if bytes < MIN_BYTES || bytes > isize::MAX as usize {
            return Err(INVALID);
        }
        let critical_limit = (256 * 1024).max(bytes / 8);
        Ok(Arc::new(Self {
            data_limit: bytes.checked_sub(critical_limit).ok_or(INVALID)?,
            critical_limit,
            used: Mutex::new(Used::default()),
        }))
    }
    #[cfg(any(test, feature = "test-diagnostics"))]
    pub fn snapshot(&self) -> (usize, usize, usize) {
        let used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        (
            self.data_limit + self.critical_limit,
            used.data,
            used.critical + used.lifecycle,
        )
    }
    #[cfg(test)]
    pub fn remaining_lane(&self, lane: usize) -> usize {
        let used = self.used.lock().unwrap();
        match lane {
            0 => self.data_limit - used.data,
            1 => self.critical_limit / 2 - used.critical,
            _ => self.critical_limit - self.critical_limit / 2 - used.lifecycle,
        }
    }
    pub fn reserve(self: &Arc<Self>, bytes: usize, critical: bool) -> Result<Permit, u32> {
        self.reserve_lane(bytes, usize::from(critical))
    }
    pub fn reserve_lane(self: &Arc<Self>, bytes: usize, lane: usize) -> Result<Permit, u32> {
        let mut used = self.used.lock().map_err(|_| FULL)?;
        let (count, limit) = match lane {
            0 => (&mut used.data, self.data_limit),
            1 => (&mut used.critical, self.critical_limit / 2),
            2 => (
                &mut used.lifecycle,
                self.critical_limit - self.critical_limit / 2,
            ),
            _ => return Err(FULL),
        };
        *count = count
            .checked_add(bytes)
            .filter(|n| *n <= limit)
            .ok_or(FULL)?;
        Ok(Permit {
            budget: self.clone(),
            bytes,
            lane,
        })
    }
}
impl Permit {
    pub fn grow_to(&mut self, bytes: usize) -> Result<(), u32> {
        if bytes <= self.bytes {
            return Ok(());
        }
        let extra = bytes.checked_sub(self.bytes).ok_or(FULL)?;
        let mut used = self.budget.used.lock().map_err(|_| FULL)?;
        let (count, limit) = match self.lane {
            0 => (&mut used.data, self.budget.data_limit),
            1 => (&mut used.critical, self.budget.critical_limit / 2),
            _ => (
                &mut used.lifecycle,
                self.budget.critical_limit - self.budget.critical_limit / 2,
            ),
        };
        *count = count
            .checked_add(extra)
            .filter(|n| *n <= limit)
            .ok_or(FULL)?;
        self.bytes = bytes;
        Ok(())
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut used = self.budget.used.lock().unwrap_or_else(|e| e.into_inner());
        let count = match self.lane {
            0 => &mut used.data,
            1 => &mut used.critical,
            _ => &mut used.lifecycle,
        };
        *count = count
            .checked_sub(self.bytes)
            .expect("owned byte permit returned once");
    }
}
pub fn limits(connections: usize, streams: usize) -> Result<(usize, usize), u32> {
    let data = connections
        .checked_mul(8)
        .and_then(|n| streams.checked_mul(2).and_then(|s| n.checked_add(s)))
        .and_then(|n| n.checked_add(64))
        .ok_or(FULL)?;
    let critical = connections
        .checked_add(streams)
        .and_then(|n| n.checked_add(64))
        .ok_or(FULL)?;
    Ok((data, critical))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partitions_and_checked_growth() {
        assert!(Budget::new(1).is_err());
        assert_eq!(limits(500, 500).unwrap(), (5064, 1064));
        assert!(limits(usize::MAX, 1).is_err());
        let b = Budget::new(MIN_BYTES).unwrap();
        let data = b.reserve(MIN_BYTES - 256 * 1024, false).unwrap();
        assert!(b.reserve(1, false).is_err());
        let management = b.reserve(128 * 1024, true).unwrap();
        let lifecycle = b.reserve_lane(128 * 1024, 2).unwrap();
        assert!(b.reserve_lane(1, 2).is_err());
        drop(lifecycle);
        assert!(b.reserve(1, true).is_err());
        drop(data);
        drop(management);
        assert!(b.reserve(1024, false).is_ok());
    }
}
