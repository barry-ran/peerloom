use std::{
    ffi::{OsStr, c_void},
    fs::File,
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Cryptography::*, *},
    Storage::FileSystem::*,
    System::{
        SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
        WindowsProgramming::{DRIVE_FIXED, FS_PERSISTENT_ACLS},
    },
};
use zeroize::{Zeroize, Zeroizing};
const MAX_BLOB: usize = 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeError {
    InvalidPath,
    Security,
    Limit,
    Os(u32),
}
impl std::fmt::Display for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath => f.write_str("WINDOWS_INVALID_PATH"),
            Self::Security => f.write_str("WINDOWS_SECURITY_REJECTED"),
            Self::Limit => f.write_str("WINDOWS_BUFFER_LIMIT"),
            Self::Os(code) => write!(f, "WINDOWS_OS_{code}"),
        }
    }
}
impl std::error::Error for NativeError {}
type Result<T> = std::result::Result<T, NativeError>;
fn last_error() -> NativeError {
    // SAFETY: GetLastError has no arguments or pointer preconditions.
    NativeError::Os(unsafe { GetLastError() })
}
fn io_error(error: std::io::Error) -> NativeError {
    NativeError::Os(error.raw_os_error().unwrap_or(1) as u32)
}
fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut result: Vec<_> = value.encode_wide().collect();
    if result.contains(&0) || result.len() >= 32760 {
        return Err(NativeError::InvalidPath);
    }
    result.push(0);
    Ok(result)
}
fn api_path(path: &Path) -> Result<Vec<u16>> {
    let mut value = std::ffi::OsString::from(r"\\?\");
    value.push(path.as_os_str());
    wide(&value)
}
struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this RAII owner is created only for Win32 LocalAlloc-family outputs;
            // no other owner frees the pointer, and LocalFree is called exactly once.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
fn reject_impersonation() -> Result<()> {
    let mut token = null_mut();
    // SAFETY: GetCurrentThread returns a valid pseudo-handle; token is writable.
    // We never revert or change the caller's security context.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        // SAFETY: successful OpenThreadToken transferred a single owned HANDLE.
        let _token = unsafe { OwnedHandle::from_raw_handle(token) };
        return Err(NativeError::Security);
    }
    if last_error() != NativeError::Os(ERROR_NO_TOKEN) {
        return Err(NativeError::Security);
    }
    Ok(())
}
fn crypt(bytes: &[u8], scope: &[u8], decrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    reject_impersonation()?;
    if bytes.is_empty() || bytes.len() > MAX_BLOB || scope.is_empty() || scope.len() > 256 {
        return Err(NativeError::Limit);
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: scope.len() as u32,
        pbData: scope.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input/entropy refer to valid slices for the entire call; DPAPI treats
    // them as inputs. Output is initialized. No prompt structure, UI is forbidden,
    // and LOCAL_MACHINE is deliberately not set: protection is CurrentUser.
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                null_mut(),
                &entropy,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                null(),
                &entropy,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(last_error());
    }
    let allocation = LocalAllocation(output.pbData.cast());
    if output.pbData.is_null() || output.cbData as usize > MAX_BLOB {
        return Err(NativeError::Limit);
    }
    // SAFETY: successful DPAPI returns cbData accessible bytes allocated by LocalAlloc;
    // allocation remains alive through copying and wiping. Pointer is non-null above.
    let output_bytes =
        unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let owned = Zeroizing::new(output_bytes.to_vec());
    output_bytes.zeroize();
    drop(allocation);
    Ok(owned)
}
pub fn protect(plaintext: &[u8], scope: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    crypt(plaintext, scope, false)
}
pub fn unprotect(ciphertext: &[u8], scope: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    crypt(ciphertext, scope, true)
}

struct SecurityContext {
    token_user: Vec<usize>,
    descriptor: LocalAllocation,
}
impl SecurityContext {
    fn new() -> Result<Self> {
        reject_impersonation()?;
        let mut token = null_mut();
        // SAFETY: process pseudo-handle is valid; token points to writable HANDLE.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_error());
        }
        // SAFETY: successful OpenProcessToken transfers one owned HANDLE to caller.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut needed = 0;
        // SAFETY: size query has no output buffer and valid required-length pointer.
        unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut needed);
        }
        if needed < std::mem::size_of::<TOKEN_USER>() as u32 || needed > 65536 {
            return Err(NativeError::Security);
        }
        // usize storage guarantees TOKEN_USER alignment, unlike Vec<u8>.
        let mut token_user = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: allocation is aligned and at least needed bytes; token stays alive.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                token_user.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(last_error());
        }
        // SAFETY: successful TOKEN_USER query initialized an aligned TOKEN_USER whose
        // SID points into the same live allocation; no buffer mutation follows.
        let sid = unsafe { (*token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut sid_text = null_mut();
        // SAFETY: sid was returned by the OS, output pointer is initialized and writable.
        if unsafe { ConvertSidToStringSidW(sid, &mut sid_text) } == 0 {
            return Err(last_error());
        }
        let sid_allocation = LocalAllocation(sid_text.cast());
        if sid_text.is_null() {
            return Err(NativeError::Security);
        }
        let mut length = 0;
        // SAFETY: ConvertSidToStringSidW guarantees a terminated UTF-16 SID string.
        // Windows SID textual representation is bounded; this scan never outlives it.
        while unsafe { *sid_text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: the preceding scan established exactly length initialized units.
        let sid_string =
            String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, length) })
                .map_err(|_| NativeError::Security)?;
        drop(sid_allocation);
        let sddl = wide(OsStr::new(&format!(
            "O:{sid_string}D:P(A;;FA;;;{sid_string})"
        )))?;
        let mut descriptor = null_mut();
        // SAFETY: SDDL buffer is NUL-terminated; output is valid for one owned allocation.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(last_error());
        }
        Ok(Self {
            token_user,
            descriptor: LocalAllocation(descriptor),
        })
    }
    fn sid(&self) -> PSID {
        // SAFETY: token_user owns the aligned successful TOKEN_USER query buffer.
        unsafe { (*self.token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: 0,
        }
    }
    fn verify(&self, file: &File) -> Result<()> {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: file owns a live handle opened with READ_CONTROL; all output pointers
        // are writable. Returned owner/ACL pointers borrow the returned descriptor.
        let code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(NativeError::Os(code));
        }
        let _descriptor = LocalAllocation(descriptor);
        if owner.is_null() || dacl.is_null() || descriptor.is_null() {
            return Err(NativeError::Security);
        }
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: OS-produced security descriptor/SIDs/ACL are live and validated before
        // dereferencing ACE memory; all output scalar pointers are writable.
        unsafe {
            if IsValidSecurityDescriptor(descriptor) == 0
                || IsValidAcl(dacl) == 0
                || EqualSid(owner, self.sid()) == 0
                || GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
                || control & SE_DACL_PROTECTED == 0
                || (*dacl).AceCount != 1
            {
                return Err(NativeError::Security);
            }
            let mut ace = null_mut();
            if GetAce(dacl, 0, &mut ace) == 0 || ace.is_null() {
                return Err(NativeError::Security);
            }
            let header = &*ace.cast::<ACE_HEADER>();
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || header.AceFlags != 0
                || usize::from(header.AceSize)
                    < std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
            {
                return Err(NativeError::Security);
            }
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid_bytes = std::ptr::addr_of!(allowed.SidStart).cast::<u8>();
            let sid_size = 8 + usize::from(*sid_bytes.add(1)) * 4;
            if std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart) + sid_size
                > usize::from(header.AceSize)
            {
                return Err(NativeError::Security);
            }
            let sid = sid_bytes.cast_mut().cast();
            if allowed.Mask != FILE_ALL_ACCESS
                || IsValidSid(sid) == 0
                || EqualSid(sid, self.sid()) == 0
            {
                return Err(NativeError::Security);
            }
        }
        Ok(())
    }
}
fn open_file(
    path: &Path,
    access: u32,
    share: u32,
    disposition: u32,
    flags: u32,
    attributes: Option<&SECURITY_ATTRIBUTES>,
) -> Result<File> {
    let path = api_path(path)?;
    // SAFETY: path is NUL-terminated; optional attributes borrow a live descriptor;
    // returned handle is checked before transfer to File, which closes it exactly once.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            attributes.map_or(null(), |a| a),
            disposition,
            flags | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: successful CreateFileW returns one owned file/directory handle.
    let file = unsafe { File::from_raw_handle(handle) };
    let metadata = information(&file)?;
    if metadata.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(NativeError::Security);
    }
    Ok(file)
}
fn information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut result = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live file handle and writable structure of the exact Win32 ABI layout.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut result) } == 0 {
        return Err(last_error());
    }
    Ok(result)
}
/// Holds every ancestor without FILE_SHARE_DELETE, preventing a rename-based lock
/// namespace split while a transaction is active. Each File handle is RAII-owned.
pub struct ProtectedDirectory {
    path: PathBuf,
    _ancestors: Vec<File>,
    security: SecurityContext,
}
impl ProtectedDirectory {
    pub fn open(path: &Path) -> Result<Self> {
        let components: Vec<_> = path.components().collect();
        if components.len() < 3 || !matches!(components[0], Component::Prefix(p) if matches!(p.kind(), Prefix::Disk(_))) || components[1] != Component::RootDir || !components[2..].iter().all(|c| matches!(c, Component::Normal(n) if n.to_str().is_some_and(|s| !s.contains(':') && !s.ends_with(['.', ' '])))) { return Err(NativeError::InvalidPath); }
        let mut current = PathBuf::from(components[0].as_os_str());
        current.push(r"\");
        verify_ntfs(&current)?;
        let security = SecurityContext::new()?;
        let attributes = security.attributes();
        let mut ancestors = vec![open_file(
            &current,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?];
        for (index, component) in components[2..].iter().enumerate() {
            current.push(component.as_os_str());
            let final_directory = index + 3 == components.len();
            if final_directory {
                let name = api_path(&current)?;
                // SAFETY: path/attributes remain valid during call. Existing directories
                // are not chmod'ed or silently adopted: strict ACL verification follows.
                if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
                    let error = last_error();
                    if error != NativeError::Os(ERROR_ALREADY_EXISTS) {
                        return Err(error);
                    }
                }
            }
            let directory = open_file(
                &current,
                FILE_READ_ATTRIBUTES | if final_directory { READ_CONTROL } else { 0 },
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )?;
            if information(&directory)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(NativeError::Security);
            }
            if final_directory {
                security.verify(&directory)?;
            }
            ancestors.push(directory);
        }
        Ok(Self {
            path: current,
            _ancestors: ancestors,
            security,
        })
    }
    fn child(&self, name: &str) -> Result<PathBuf> {
        let (base, extension) = name.rsplit_once('.').ok_or(NativeError::InvalidPath)?;
        let reserved = base.to_ascii_uppercase();
        if base.is_empty()
            || base.len() > 128
            || !matches!(extension, "lock" | "bin")
            || !base.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || matches!(reserved.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ((reserved.starts_with("COM") || reserved.starts_with("LPT"))
                && reserved.len() == 4
                && reserved.as_bytes()[3].is_ascii_digit())
        {
            return Err(NativeError::InvalidPath);
        }
        Ok(self.path.join(name))
    }
    pub fn open_lock(&self, name: &str) -> Result<File> {
        if !name.ends_with(".lock") {
            return Err(NativeError::InvalidPath);
        }
        let file = open_file(
            &self.child(name)?,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            Some(&self.security.attributes()),
        )?;
        self.verify_regular(&file)?;
        Ok(file)
    }
    fn verify_regular(&self, file: &File) -> Result<()> {
        let metadata = information(file)?;
        if metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 || metadata.nNumberOfLinks != 1
        {
            return Err(NativeError::Security);
        }
        self.security.verify(file)
    }
    pub fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        if !name.ends_with(".bin") {
            return Err(NativeError::InvalidPath);
        }
        let file = match open_file(
            &self.child(name)?,
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            Ok(file) => file,
            Err(NativeError::Os(ERROR_FILE_NOT_FOUND)) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.verify_regular(&file)?;
        let mut bytes = Vec::new();
        file.take(MAX_BLOB as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() > MAX_BLOB {
            return Err(NativeError::Limit);
        }
        Ok(Some(bytes))
    }
    /// Atomic same-directory replacement of ciphertext. Caller holds its scope lock
    /// and has persisted an uncertainty marker before calling this function.
    pub fn replace(&self, name: &str, ciphertext: &[u8]) -> Result<()> {
        if !name.ends_with(".bin") {
            return Err(NativeError::InvalidPath);
        }
        if ciphertext.is_empty() || ciphertext.len() > MAX_BLOB {
            return Err(NativeError::Limit);
        }
        let target = self.child(name)?;
        let exists = self.read(name)?.is_some();
        let temporary = self.child(&format!("tmp-{}.bin", uuid::Uuid::new_v4()))?;
        let mut file = open_file(
            &temporary,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            0,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            Some(&self.security.attributes()),
        )?;
        self.verify_regular(&file)?;
        let written = file
            .write_all(ciphertext)
            .and_then(|()| file.sync_all())
            .map_err(io_error);
        drop(file);
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        let source = api_path(&temporary)?;
        let destination = api_path(&target)?;
        // SAFETY: both paths are NUL-terminated within the held private directory;
        // flags preserve ACL checking, no backup/prompt/reserved pointers are supplied.
        let ok = unsafe {
            if exists {
                ReplaceFileW(
                    destination.as_ptr(),
                    source.as_ptr(),
                    null(),
                    0,
                    null(),
                    null(),
                )
            } else {
                MoveFileExW(
                    source.as_ptr(),
                    destination.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            }
        };
        if ok == 0 {
            let error = last_error();
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        let file = open_file(
            &target,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?;
        self.verify_regular(&file)?;
        file.sync_all().map_err(io_error)
    }
}
fn verify_ntfs(root: &Path) -> Result<()> {
    let root = wide(root.as_os_str())?;
    let mut flags = 0;
    let mut filesystem = [0u16; 32];
    // SAFETY: root is NUL-terminated; output arrays/scalars have the lengths passed.
    unsafe {
        if GetDriveTypeW(root.as_ptr()) != DRIVE_FIXED
            || GetVolumeInformationW(
                root.as_ptr(),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut flags,
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            ) == 0
        {
            return Err(NativeError::InvalidPath);
        }
    }
    let end = filesystem
        .iter()
        .position(|u| *u == 0)
        .unwrap_or(filesystem.len());
    if String::from_utf16_lossy(&filesystem[..end]) != "NTFS" || flags & FS_PERSISTENT_ACLS == 0 {
        return Err(NativeError::InvalidPath);
    }
    Ok(())
}
