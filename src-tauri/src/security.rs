// ═══════════════════════════════════════════════════════════
//  SECURITY — Leak prevention, core dump disable, mlock
// ═══════════════════════════════════════════════════════════

/// Wrapper that prevents accidental logging of sensitive data.
/// Debug/Display always prints "[REDACTED]". Access value via .0
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
pub(crate) fn disable_core_dumps() {
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
        } else {
            eprintln!("[LexFlow] WARNING: Failed to disable core dumps");
        }
    }
    #[cfg(windows)]
    {
        // Windows: disable WER heap dumps via SetErrorMode
        // This prevents full memory dumps on crash
        unsafe {
            // SEM_NOGPFAULTERRORBOX = 0x0002 — no crash dialog
            // SEM_FAILCRITICALERRORS = 0x0001 — no system error dialog
            winapi_stub_set_error_mode();
        }
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

/// Lock memory pages containing sensitive data (prevents swap to disk).
/// Only for small buffers like DEK/KEK (32-64 bytes). NOT for large plaintext.
#[cfg(unix)]
pub(crate) fn mlock_buffer(ptr: *const u8, len: usize) -> bool {
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

#[cfg(unix)]
pub(crate) fn munlock_buffer(ptr: *const u8, len: usize) {
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(not(unix))]
pub(crate) fn mlock_buffer(_ptr: *const u8, _len: usize) -> bool {
    // Windows VirtualLock could be used here but requires unsafe winapi
    // For now, rely on Zeroizing for cleanup
    false
}

#[cfg(not(unix))]
pub(crate) fn munlock_buffer(_ptr: *const u8, _len: usize) {}

/// Secure overwrite + delete for temporary unencrypted files (PDF exports, etc.)
/// SECURITY FIX: open file FIRST (via fd), then fstat the fd, then overwrite.
/// This prevents TOCTOU symlink swap between exists()/metadata() and open().
pub(crate) fn secure_delete_file(path: &std::path::Path) -> Result<(), String> {
    use std::io::Write;
    // Open first — if it fails, file doesn't exist or no permission
    let mut f = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Secure delete open failed: {}", e)),
    };
    // Get size from the OPEN fd (not from path — no TOCTOU)
    let len = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    if len > 0 {
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
