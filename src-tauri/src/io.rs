// ═══════════════════════════════════════════════════════════
//  FILE I/O — Atomic writes, secure permissions, bounded reads
// ═══════════════════════════════════════════════════════════

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Centralized atomic write with fsync — replaces 5+ duplicated patterns.
/// Uses u64 random for tmp name (larger namespace) + cleanup on rename failure.
pub(crate) fn atomic_write_with_sync(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    // FIX: u64 for larger collision-resistant namespace (was u32)
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        rand::random::<u64>()
    );
    let tmp = path.with_file_name(&tmp_name);
    secure_write(&tmp, data).map_err(|e| e.to_string())?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        // FIX: cleanup orphan tmp on rename failure
        let _ = std::fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    // fsync directory to persist rename across crashes (ext4/f2fs)
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(target_os = "windows")]
    set_hidden_on_windows(path);
    Ok(())
}

/// Mark dot-prefixed files as Hidden on Windows.
/// Uses absolute path to attrib.exe to prevent PATH manipulation.
#[cfg(target_os = "windows")]
pub(crate) fn set_hidden_on_windows(path: &std::path::Path) {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.starts_with('.') {
            // FIX: absolute path prevents PATH manipulation attack
            let _ = std::process::Command::new(r"C:\Windows\System32\attrib.exe")
                .arg("+H")
                .arg(path)
                .output();
        }
    }
}

pub(crate) fn secure_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    #[cfg(target_os = "windows")]
    set_hidden_on_windows(path);
    Ok(())
}

/// Safe bounded read — anti-TOCTOU + anti-OOM. Single metadata call.
pub(crate) fn safe_bounded_read(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    // FIX: single metadata call, reuse result
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len > max_bytes {
        return Err(format!(
            "File troppo grande ({} bytes) — OOM limit superato",
            file_len
        ));
    }
    let mut buffer = Vec::with_capacity(file_len.min(max_bytes) as usize);
    file.take(max_bytes)
        .read_to_end(&mut buffer)
        .map_err(|e| e.to_string())?;
    Ok(buffer)
}

/// Safe timestamp — prevents panic on pre-1970 clocks.
pub(crate) fn safe_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}
