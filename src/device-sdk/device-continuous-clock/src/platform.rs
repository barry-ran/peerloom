use super::ClockError;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn now() -> Result<Duration, ClockError> {
    // CLOCK_BOOTTIME includes suspend; CLOCK_MONOTONIC does not.
    // https://docs.kernel.org/core-api/timekeeping.html
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is an initialized, writable timespec for this call. No pointer escapes.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(ClockError);
    }
    let seconds = u64::try_from(value.tv_sec).map_err(|_| ClockError)?;
    let nanos = u32::try_from(value.tv_nsec).map_err(|_| ClockError)?;
    if nanos >= 1_000_000_000 {
        return Err(ClockError);
    }
    Ok(Duration::new(seconds, nanos))
}

#[cfg(target_vendor = "apple")]
pub(super) fn now() -> Result<Duration, ClockError> {
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    #[link(name = "System")]
    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut Timebase) -> i32;
    }
    let mut timebase = Timebase { numer: 0, denom: 0 };
    // SAFETY: the ABI matches mach_timebase_info_data_t; the writable pointer is valid
    // for the call. Both APIs are provided on supported macOS/iOS deployment targets.
    if unsafe { mach_timebase_info(&mut timebase) } != 0
        || timebase.numer == 0
        || timebase.denom == 0
    {
        return Err(ClockError);
    }
    // SAFETY: this parameterless system read has no memory preconditions. Unlike
    // mach_absolute_time, it includes sleep. No wall-clock fallback is permitted.
    // https://developer.apple.com/documentation/kernel/1646199-mach_continuous_time
    let ticks = unsafe { mach_continuous_time() };
    let nanos = u128::from(ticks)
        .checked_mul(u128::from(timebase.numer))
        .ok_or(ClockError)?
        / u128::from(timebase.denom);
    super::from_nanos(nanos)
}

#[cfg(target_os = "windows")]
pub(super) fn now() -> Result<Duration, ClockError> {
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };
    let mut ticks = 0_i64;
    let mut frequency = 0_i64;
    // SAFETY: both pointers address initialized writable i64 values for these synchronous
    // system calls. QPC includes standby/hibernate; do not use unbiased interrupt time.
    // https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps
    if unsafe { QueryPerformanceCounter(&mut ticks) } == 0
        || unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
        || ticks < 0
        || frequency <= 0
    {
        return Err(ClockError);
    }
    let nanos = (ticks as u128)
        .checked_mul(1_000_000_000)
        .ok_or(ClockError)?
        / frequency as u128;
    super::from_nanos(nanos)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "windows"
)))]
pub(super) fn now() -> Result<Duration, ClockError> {
    // An unsupported clock cannot establish an authorization bound.
    Err(ClockError)
}
