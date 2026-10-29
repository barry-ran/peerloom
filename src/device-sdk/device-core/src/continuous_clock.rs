//! 授权使用的连续时钟。克隆共享故障状态；任何读数故障或倒退永久失败关闭。
use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClockError;

type Reader = dyn Fn() -> Result<Duration, ClockError> + Send + Sync;
struct State {
    reader: Box<Reader>,
    last: Option<Duration>,
    failed: bool,
}

#[derive(Clone)]
pub(crate) struct ContinuousClock(Arc<Mutex<State>>);

impl ContinuousClock {
    pub(crate) fn new() -> Self {
        // 所有生产连接共享故障锁存；重连不能绕过已观察到的时钟故障。
        static CLOCK: OnceLock<ContinuousClock> = OnceLock::new();
        CLOCK
            .get_or_init(|| {
                Self::from_reader(|| device_continuous_clock::now().map_err(|_| ClockError))
            })
            .clone()
    }

    fn from_reader(
        reader: impl Fn() -> Result<Duration, ClockError> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(Mutex::new(State {
            reader: Box::new(reader),
            last: None,
            failed: false,
        })))
    }

    pub(crate) fn now(&self) -> Result<Duration, ClockError> {
        let mut state = self.0.lock().map_err(|_| ClockError)?;
        if state.failed {
            return Err(ClockError);
        }
        // Read while holding the lock so two threads cannot publish reads in reverse order.
        match (state.reader)() {
            Ok(value) if state.last.is_none_or(|last| value >= last) => {
                state.last = Some(value);
                Ok(value)
            }
            _ => {
                state.failed = true;
                Err(ClockError)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn with_reader(
        reader: impl Fn() -> Result<Duration, ClockError> + Send + Sync + 'static,
    ) -> Self {
        Self::from_reader(reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn sequence(values: impl IntoIterator<Item = Result<Duration, ClockError>>) -> ContinuousClock {
        let values = Mutex::new(values.into_iter().collect::<VecDeque<_>>());
        ContinuousClock::with_reader(move || values.lock().unwrap().pop_front().unwrap())
    }

    #[test]
    fn backward_clock_is_sticky_across_clones() {
        let clock = sequence([Ok(Duration::from_secs(10)), Ok(Duration::from_secs(9))]);
        let clone = clock.clone();
        assert_eq!(clock.now(), Ok(Duration::from_secs(10)));
        assert_eq!(clone.now(), Err(ClockError));
        // There is no third read: failure never recovers, even if the source would.
        assert_eq!(clock.now(), Err(ClockError));
    }

    #[test]
    fn unavailable_clock_is_sticky() {
        let clock = sequence([Err(ClockError)]);
        assert_eq!(clock.now(), Err(ClockError));
        assert_eq!(clock.now(), Err(ClockError));
    }

    #[test]
    fn equal_ticks_and_suspend_jump_are_allowed() {
        let clock = sequence([
            Ok(Duration::ZERO),
            Ok(Duration::ZERO),
            Ok(Duration::from_secs(120)),
        ]);
        assert_eq!(clock.now(), Ok(Duration::ZERO));
        assert_eq!(clock.now(), Ok(Duration::ZERO));
        assert_eq!(clock.now(), Ok(Duration::from_secs(120)));
    }
}
