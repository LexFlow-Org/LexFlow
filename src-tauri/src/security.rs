// ═══════════════════════════════════════════════════════════
//  SECURITY — Leak prevention, core dump disable, mlock
// ═══════════════════════════════════════════════════════════

/// Wrapper that prevents accidental logging of sensitive data.
/// Debug/Display always prints "[REDACTED]". Access value via .0
///
/// LOW SEC-SE-7 (audit): Rust's `Drop` impls cannot carry stricter trait bounds
/// than the struct itself, so we cannot conditionally `Zeroize` on drop here
/// without locking the wrapper to `T: Zeroize` (which would bar
/// `Sensitive<&str>` / `Sensitive<i32>`). Callers that need real wipe-on-drop
/// must use `zeroize::Zeroizing<T>` directly. See `state::SecureKey` for the
/// canonical secret-bearing wrapper.
#[allow(dead_code)]
pub(crate) struct Sensitive<T>(pub T);

impl<T> std::fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T> std::fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Disable core dumps at process level.
/// Prevents DEK/plaintext from being written to disk on crash.
///
/// MEDIUM SEC-SE-4 (audit): now returns `Result<(), String>` so the setup path
/// can log/refuse on failure instead of silently continuing with core dumps
/// possibly enabled.
pub(crate) fn disable_core_dumps() -> Result<(), String> {
    #[cfg(unix)]
    {
        use libc::{rlimit, setrlimit, RLIMIT_CORE};
        let rl = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let result = unsafe { setrlimit(RLIMIT_CORE, &rl) };
        if result == 0 {
            eprintln!("[LexFlow] SECURITY: Core dumps disabled ✓");
            Ok(())
        } else {
            let msg = format!(
                "Failed to disable core dumps: setrlimit returned {} (errno={})",
                result,
                std::io::Error::last_os_error()
            );
            eprintln!("[LexFlow] WARNING: {}", msg);
            Err(msg)
        }
    }
    #[cfg(windows)]
    {
        // Windows: SetErrorMode suppresses crash dialogs but does NOT disable
        // Windows Error Reporting (WER) — full memory dumps may still land in
        // %LOCALAPPDATA%\CrashDumps\.
        // TODO(audit:SEC-SE-2): disable WER via registry write to
        //   HKCU\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\<exe>
        //   with DumpType = 0, OR call WerAddExcludedApplication via FFI from
        //   wer.dll. Either approach prevents heap dumps from being written.
        unsafe {
            winapi_stub_set_error_mode();
        }
        return Ok(());
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(())
    }
}

/// Stub for Windows SetErrorMode (avoid heavy winapi dependency)
#[cfg(windows)]
unsafe fn winapi_stub_set_error_mode() {
    // Using raw FFI to avoid adding windows-sys dependency
    #[link(name = "kernel32")]
    extern "system" {
        fn SetErrorMode(mode: u32) -> u32;
    }
    // SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
    SetErrorMode(0x0001 | 0x0002);
}

// ─── Memory locking (mlock / VirtualLock) ─────────────────────
//
// HIGH SEC-SE-3 (audit): Windows now has a real implementation via VirtualLock
// instead of always returning `false`.  Note that `VirtualLock` requires the
// process to have the SE_LOCK_MEMORY_NAME privilege OR for the page count to
// stay below the working-set minimum — for the small DEK/KEK buffers (32-64
// bytes) we lock here, the second condition holds on default Windows installs.
//
// MEDIUM SEC-SE-5 (audit): the buffer-based variants take `&[u8]` so the
// caller cannot pass a wrong (ptr, len) pair.  The legacy `*const u8` versions
// remain for state.rs callers that operate on raw pointers (e.g. when the
// buffer lives inside a struct that does not lend itself to a slice borrow).

#[cfg(target_os = "windows")]
extern "system" {
    fn VirtualLock(addr: *const std::ffi::c_void, size: usize) -> i32;
    fn VirtualUnlock(addr: *const std::ffi::c_void, size: usize) -> i32;
}

/// Lock memory pages containing sensitive data (prevents swap to disk).
/// Only for small buffers like DEK/KEK (32-64 bytes). NOT for large plaintext.
///
/// LOW SEC-SE-6 (audit): `#[must_use]` so callers cannot silently ignore a
/// failed lock attempt.
#[must_use]
#[allow(dead_code)]
pub(crate) fn mlock_buffer_slice(buf: &[u8]) -> bool {
    #[cfg(unix)]
    unsafe {
        libc::mlock(buf.as_ptr().cast(), buf.len()) == 0
    }
    #[cfg(target_os = "windows")]
    unsafe {
        VirtualLock(buf.as_ptr().cast(), buf.len()) != 0
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = buf;
        false
    }
}

#[allow(dead_code)]
pub(crate) fn munlock_buffer_slice(buf: &[u8]) {
    #[cfg(unix)]
    unsafe {
        libc::munlock(buf.as_ptr().cast(), buf.len());
    }
    #[cfg(target_os = "windows")]
    unsafe {
        VirtualUnlock(buf.as_ptr().cast(), buf.len());
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = buf;
    }
}

/// Legacy raw-pointer mlock wrapper, kept for state.rs callers that hand us
/// `(ptr, len)` from a `Zeroizing<Vec<u8>>`. The signature is intentionally
/// `safe fn` even though the body performs unsafe FFI, because (a) state.rs
/// already owns the buffer for the entire call duration and (b) flipping
/// this to `unsafe fn` would be a cross-file refactor outside this audit's
/// blast radius.
///
/// TODO(audit:SEC-SE-5): migrate state.rs callers to `mlock_buffer_slice(&[u8])`
/// (which is safe because the slice borrow proves liveness) and then convert
/// this wrapper to `unsafe fn` or delete it.
///
/// LOW SEC-SE-6 (audit): `#[must_use]` to surface unchecked mlock failures.
#[must_use]
#[allow(dead_code)]
pub(crate) fn mlock_buffer(ptr: *const u8, len: usize) -> bool {
    #[cfg(unix)]
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len) == 0
    }
    #[cfg(target_os = "windows")]
    unsafe {
        VirtualLock(ptr as *const std::ffi::c_void, len) != 0
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (ptr, len);
        false
    }
}

#[allow(dead_code)]
pub(crate) fn munlock_buffer(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
    #[cfg(target_os = "windows")]
    unsafe {
        VirtualUnlock(ptr as *const std::ffi::c_void, len);
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (ptr, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_debug_redacted() {
        let s = Sensitive("my_secret_key_12345");
        let debug = format!("{:?}", s);
        assert_eq!(debug, "[REDACTED]");
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn test_sensitive_display_redacted() {
        let s = Sensitive(vec![0xDE_u8, 0xAD, 0xBE, 0xEF]);
        let display = format!("{}", s);
        assert_eq!(display, "[REDACTED]");
    }

    #[test]
    fn test_sensitive_inner_accessible() {
        let s = Sensitive(42_i32);
        assert_eq!(s.0, 42);
    }

    #[test]
    fn test_secure_delete_nonexistent() {
        let path = std::path::Path::new("/tmp/lexflow_test_nonexistent_file_xyz");
        assert!(secure_delete_file(path).is_ok());
    }

    #[test]
    fn test_secure_delete_existing_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("lexflow_sec_del_test_{}", rand::random::<u64>()));
        std::fs::write(&path, b"sensitive data that must be wiped").unwrap();
        assert!(path.exists());
        secure_delete_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_secure_delete_empty_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("lexflow_sec_del_empty_{}", rand::random::<u64>()));
        std::fs::write(&path, b"").unwrap();
        secure_delete_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_mlock_munlock_slice() {
        let data = vec![0xAA_u8; 64];
        let locked = mlock_buffer_slice(&data);
        // mlock may fail if RLIMIT_MEMLOCK is too low — both outcomes are valid
        if locked {
            munlock_buffer_slice(&data);
        }
    }
}

/// Secure overwrite + delete for temporary unencrypted files (PDF exports, etc.)
///
/// HIGH SEC-SE-1 (audit):
/// - Open with `O_NOFOLLOW` on Unix so a symlink swap between caller's intent
///   and our open() can't redirect the overwrite to a victim file.
/// - Seek back to 0 before overwriting (BUG-SE-1) — without it, on a freshly
///   `OpenOptions::new().write(true).open(...)` handle the cursor can land at
///   a non-zero offset on some platforms once we re-call `metadata()`.
///
/// CAVEATS (BUG-SE-2 + flash storage limitations):
///   - On SSDs, NVMe, and copy-on-write filesystems (APFS, Btrfs, ZFS) a
///     single-pass overwrite cannot guarantee the original blocks are
///     erased: the FTL may have remapped the LBA, and the COW layer keeps
///     prior versions until garbage collection.
///   - Sparse files: the "size" we obtain from `metadata()` reflects the
///     logical extent. A sparse hole in the middle is still readable as
///     zeros; overwriting it pads the file to its full size on disk. That
///     is intentional — we want every byte clobbered before unlink.
///   - For genuine sanitisation of secrets on flash, callers must layer
///     this with full-disk encryption (FileVault/BitLocker/LUKS) so that
///     "deletion" comes down to discarding the FDE key.
///
/// On Linux a future enhancement could call `fallocate(FALLOC_FL_PUNCH_HOLE)`
/// to release the underlying blocks back to the FS after the overwrite.
pub(crate) fn secure_delete_file(path: &std::path::Path) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};

    // Open first — if it fails, file doesn't exist or no permission.
    // Unix: O_NOFOLLOW to refuse symlinks (TOCTOU defence).
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // libc::O_NOFOLLOW is the canonical flag; expose it via custom_flags.
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Secure delete open failed: {}", e)),
    };

    // Get size from the OPEN fd (not from path — no TOCTOU)
    let len = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    if len > 0 {
        // BUG-SE-1: seek to start before the overwrite loop.
        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Secure delete seek failed: {}", e))?;
        const CHUNK: usize = 65536;
        let mut remaining = len;
        let mut buf = vec![0u8; CHUNK.min(len)];
        while remaining > 0 {
            let n = remaining.min(CHUNK);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf[..n]);
            f.write_all(&buf[..n])
                .map_err(|e| format!("Secure delete write failed: {}", e))?;
            remaining -= n;
        }
        f.sync_all()
            .map_err(|e| format!("Secure delete sync failed: {}", e))?;
    }
    drop(f); // close fd before unlink
    std::fs::remove_file(path).map_err(|e| format!("Secure delete failed: {}", e))
}
