//! 原生 C ABI：有界异步操作、不可复用整数句柄与独立回调线程。
//! 只有 boundary 模块允许审核过的 unsafe；不接管外部缓冲区所有权。
#[allow(unsafe_code)]
mod boundary;
mod bridge;
mod state;
mod storage;
pub use boundary::*;

#[cfg(target_os = "android")]
#[allow(unsafe_code)]
mod android;
