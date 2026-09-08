// ═══════════════════════════════════════════════════════════
//  SECURITY — Leak prevention, core dump disable, mlock
// ═══════════════════════════════════════════════════════════

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
// Slice borrows ensure pointer/length pairs refer to live allocations.

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

#[cfg(test)]
mod tests {
    use super::*;

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
