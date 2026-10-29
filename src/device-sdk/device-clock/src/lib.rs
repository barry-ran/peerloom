//! 包含系统休眠的单调时钟。仅 OS 边界允许审核的 unsafe；不回退至墙钟。
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
#[allow(unsafe_code)]
mod platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    Unavailable,
    Regressed,
    Overflow,
}
#[derive(Default)]
struct State {
    last: Option<Duration>,
    failed: Option<ClockError>,
}
/// 所有副本共享高水位与错误锁存；一次读失败/倒退后不会重新授予权限。
#[derive(Clone, Default)]
pub struct ContinuousClock(Arc<Mutex<State>>);
impl ContinuousClock {
    pub fn system() -> Self {
        static CLOCK: std::sync::OnceLock<ContinuousClock> = std::sync::OnceLock::new();
        CLOCK.get_or_init(Self::default).clone()
    }
    pub fn now(&self) -> Result<Duration, ClockError> {
        self.sample(platform::read)
    }
    fn sample(
        &self,
        read: impl FnOnce() -> Result<Duration, ClockError>,
    ) -> Result<Duration, ClockError> {
        // Read under the same lock: out-of-order concurrent completion cannot
        // manufacture a clock regression from two valid platform readings.
        let mut state = self.0.lock().map_err(|_| ClockError::Unavailable)?;
        if let Some(error) = state.failed {
            return Err(error);
        }
        let value = match read() {
            Ok(value) if state.last.is_none_or(|old| value >= old) => value,
            Ok(_) => {
                state.failed = Some(ClockError::Regressed);
                return Err(ClockError::Regressed);
            }
            Err(error) => {
                state.failed = Some(error);
                return Err(error);
            }
        };
        state.last = Some(value);
        Ok(value)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sleep_advances_and_wall_clock_is_not_an_input() {
        let clock = ContinuousClock::default();
        let before = clock.sample(|| Ok(Duration::from_secs(10))).unwrap();
        let deadline = before + Duration::from_secs(60);
        let resumed = clock.sample(|| Ok(Duration::from_secs(310))).unwrap();
        assert!(resumed >= deadline);
    }
    #[test]
    fn failure_and_regression_are_latched_across_clones() {
        let clock = ContinuousClock::default();
        clock.sample(|| Ok(Duration::from_secs(10))).unwrap();
        assert_eq!(
            clock.sample(|| Ok(Duration::from_secs(9))),
            Err(ClockError::Regressed)
        );
        assert_eq!(
            clock.clone().sample(|| Ok(Duration::from_secs(20))),
            Err(ClockError::Regressed)
        );
        let clock = ContinuousClock::default();
        assert_eq!(
            clock.sample(|| Err(ClockError::Unavailable)),
            Err(ClockError::Unavailable)
        );
        assert_eq!(
            clock.sample(|| Ok(Duration::from_secs(20))),
            Err(ClockError::Unavailable)
        );
    }
    #[test]
    fn native_read_is_monotonic() {
        let clock = ContinuousClock::default();
        assert!(clock.now().unwrap() <= clock.now().unwrap());
    }
}
