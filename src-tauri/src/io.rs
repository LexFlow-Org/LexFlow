// ═══════════════════════════════════════════════════════════
//  FILE I/O — Atomic writes, secure permissions, bounded reads
// ═══════════════════════════════════════════════════════════

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Centralized atomic write with fsync — replaces 5+ duplicated patterns.
/// SECURITY FIX (Gemini Audit Chunk 05): random tmp name to prevent TOCTOU symlink attacks.
/// Also performs directory fsync after rename for crash-safe persistence.
pub(crate) fn atomic_write_with_sync(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        rand::random::<u32>()
    );
    let tmp = path.with_file_name(tmp_name);
    secure_write(&tmp, data).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    // SECURITY FIX (Gemini Audit Chunk 05): fsync directory to persist rename across crashes
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    // SECURITY FIX (Gemini Audit Chunk 01): mark dot-files as Hidden on Windows after rename
    #[cfg(target_os = "windows")]
    set_hidden_on_windows(path);
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn set_hidden_on_windows(path: &std::path::Path) {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.starts_with('.') {
            let _ = std::process::Command::new("attrib")
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

/// SECURITY FIX (Gemini Audit Chunk 10): safe bounded read — anti-TOCTOU + anti-OOM.
pub(crate) fn safe_bounded_read(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if let Ok(meta) = file.metadata() {
        if meta.len() > max_bytes {
            return Err(format!(
                "File troppo grande ({} bytes) — OOM limit superato",
                meta.len()
            ));
        }
    }
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut buffer = Vec::with_capacity(file_len.min(max_bytes) as usize);
    file.take(max_bytes)
        .read_to_end(&mut buffer)
        .map_err(|e| e.to_string())?;
    Ok(buffer)
}

/// SECURITY FIX (Audit Chunk 12): safe timestamp — prevents panic on pre-1970 clocks.
pub(crate) fn safe_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}
