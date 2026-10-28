//! Must execute on actual Windows/MSVC. Linux compilation is not a test pass.
#![cfg(target_os = "windows")]
use device_storage_windows::{ProtectedDirectory, protect, unprotect};
use std::{path::PathBuf, process::Command};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("peerloom-win32-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn dpapi_round_trip_scope_binding_and_tamper_rejection() {
    let bytes = b"synthetic-secret-not-a-real-credential";
    let encrypted = protect(bytes, b"scope-a").unwrap();
    assert_ne!(&*encrypted, bytes);
    assert!(!encrypted.windows(bytes.len()).any(|w| w == bytes));
    assert_eq!(&*unprotect(&encrypted, b"scope-a").unwrap(), bytes);
    assert!(unprotect(&encrypted, b"scope-b").is_err());
    let mut corrupt = encrypted.to_vec();
    let end = corrupt.len() - 1;
    corrupt[end] ^= 1;
    assert!(unprotect(&corrupt, b"scope-a").is_err());
}
#[test]
fn private_dacl_atomic_replacement_and_ancestor_handle_lifetime() {
    let fixture = Fixture::new();
    let root = fixture.0.join("private");
    let directory = ProtectedDirectory::open(&root).unwrap();
    for name in [
        "CON.bin",
        "prn.bin",
        "COM1.bin",
        "LPT0.bin",
        "scope.bin.",
        "scope.bin ",
        "scope:stream.bin",
        "../scope.bin",
    ] {
        assert!(directory.read(name).is_err());
        assert!(directory.replace(name, b"ciphertext").is_err());
    }
    assert!(directory.open_lock("scope.bin").is_err());
    assert!(directory.replace("scope.lock", b"ciphertext").is_err());
    let lock = directory.open_lock("scope.lock").unwrap();
    lock.lock().unwrap();
    let other = directory.open_lock("scope.lock").unwrap();
    assert!(matches!(
        other.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    directory.replace("scope.bin", b"ciphertext-one").unwrap();
    assert_eq!(
        directory.read("scope.bin").unwrap().unwrap(),
        b"ciphertext-one"
    );
    directory.replace("scope.bin", b"ciphertext-two").unwrap();
    assert_eq!(
        directory.read("scope.bin").unwrap().unwrap(),
        b"ciphertext-two"
    );
    assert!(
        std::fs::rename(&root, fixture.0.join("renamed")).is_err(),
        "held non-share-delete directory must reject rename"
    );
    drop(other);
    drop(lock);
    drop(directory);
    std::fs::rename(&root, fixture.0.join("renamed")).unwrap();
}
#[test]
fn rejects_weakened_dacl_reparse_ancestor_and_hardlinks() {
    let fixture = Fixture::new();
    let root = fixture.0.join("private");
    let directory = ProtectedDirectory::open(&root).unwrap();
    directory.replace("scope.bin", b"ciphertext").unwrap();
    std::fs::hard_link(root.join("scope.bin"), root.join("alias.bin")).unwrap();
    assert!(directory.read("scope.bin").is_err());
    let junction = fixture.0.join("junction");
    let status = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&root)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "native junction fixture must actually be created"
    );
    assert!(ProtectedDirectory::open(&junction).is_err());
    assert!(ProtectedDirectory::open(&junction.join("child")).is_err());
    drop(directory);
    // Only an isolated synthetic test directory is made less restrictive. Never
    // grants access to real user files or changes an account/security policy.
    let status = Command::new("icacls.exe")
        .arg(&root)
        .args(["/grant", "*S-1-1-0:(F)"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(ProtectedDirectory::open(&root).is_err());
}
#[test]
fn rejects_relative_parent_unc_and_alternate_stream_paths() {
    for path in [
        r"relative",
        r"C:\example\..\escape",
        r"\\server\share\peerloom",
        r"C:\example\stream:name",
    ] {
        assert!(ProtectedDirectory::open(std::path::Path::new(path)).is_err());
    }
}
