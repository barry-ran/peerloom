//! Windows 原生安全边界。仅 boundary 模块允许逐处审核的 Win32 unsafe。
//! Linux cargo check 不构成 Windows 链接/DPAPI/ACL 运行验证。
#![cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod boundary;
pub use boundary::{NativeError, ProtectedDirectory, protect, unprotect};
