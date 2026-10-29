//! 内部授权时钟的系统边界：读数包含系统休眠，不使用可调墙钟。
//! 这里只返回本次系统读数；跨调用倒退和故障锁存由调用方负责。
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockError;

#[allow(unsafe_code)]
mod platform;

/// 从固定系统时钟原点计算的连续时间。不能跨系统启动保存或比较。
pub fn now() -> Result<Duration, ClockError> {
    platform::now()
}

#[cfg(any(target_vendor = "apple", target_os = "windows", test))]
fn from_nanos(value: u128) -> Result<Duration, ClockError> {
    let seconds = u64::try_from(value / 1_000_000_000).map_err(|_| ClockError)?;
    let nanos = (value % 1_000_000_000) as u32;
    Ok(Duration::new(seconds, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_rejects_overflow_instead_of_wrapping() {
        assert_eq!(from_nanos(1_500_000_001), Ok(Duration::new(1, 500_000_001)));
        let limit = u128::from(u64::MAX) * 1_000_000_000 + 999_999_999;
        assert_eq!(from_nanos(limit), Ok(Duration::MAX));
        assert_eq!(from_nanos(limit + 1), Err(ClockError));
    }

    #[test]
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "windows"
    ))]
    fn supported_platform_can_read_nondecreasing_clock() {
        let first = now().expect("continuous clock must be available");
        assert!(now().expect("continuous clock must remain available") >= first);
    }
}
