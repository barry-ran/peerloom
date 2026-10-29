use crate::ClockError;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn read() -> Result<Duration, ClockError> {
    // CLOCK_BOOTTIME includes suspend; libc supplies the ABI-correct timespec
    // on 32-bit Android as well. No wall clock or CLOCK_MONOTONIC fallback.
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: writable correctly aligned timespec; only read after success.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, value.as_mut_ptr()) } != 0 {
        return Err(ClockError::Unavailable);
    }
    // SAFETY: successful clock_gettime initialized both fields.
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec).map_err(|_| ClockError::Unavailable)?;
    let nanos = u32::try_from(value.tv_nsec).map_err(|_| ClockError::Unavailable)?;
    if nanos >= 1_000_000_000 {
        return Err(ClockError::Unavailable);
    }
    Ok(Duration::new(seconds, nanos))
}
#[cfg(target_vendor = "apple")]
pub fn read() -> Result<Duration, ClockError> {
    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
    }
    let mut scale = libc::mach_timebase_info { numer: 0, denom: 0 };
    // SAFETY: writable ABI structure; function is available on supported OS baselines.
    if unsafe { libc::mach_timebase_info(&mut scale) } != 0 || scale.numer == 0 || scale.denom == 0
    {
        return Err(ClockError::Unavailable);
    }
    // SAFETY: no-argument OS clock, available since macOS 10.12 / iOS 10.
    let ticks = unsafe { mach_continuous_time() };
    let nanos = u128::from(ticks)
        .checked_mul(u128::from(scale.numer))
        .ok_or(ClockError::Overflow)?
        / u128::from(scale.denom);
    let seconds = u64::try_from(nanos / 1_000_000_000).map_err(|_| ClockError::Overflow)?;
    Ok(Duration::new(seconds, (nanos % 1_000_000_000) as u32))
}
#[cfg(target_os = "windows")]
pub fn read() -> Result<Duration, ClockError> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn QueryInterruptTime(value: *mut u64);
    }
    let mut ticks = u64::MAX;
    // SAFETY: valid writable ULONGLONG. Biased interrupt time includes sleep;
    // do not substitute QueryUnbiasedInterruptTime or QueryPerformanceCounter.
    unsafe { QueryInterruptTime(&mut ticks) };
    if ticks == u64::MAX {
        return Err(ClockError::Unavailable);
    }
    Ok(Duration::new(
        ticks / 10_000_000,
        ((ticks % 10_000_000) * 100) as u32,
    ))
}
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "windows"
)))]
pub fn read() -> Result<Duration, ClockError> {
    Err(ClockError::Unavailable)
}
