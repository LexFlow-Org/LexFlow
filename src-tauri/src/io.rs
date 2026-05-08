// ═══════════════════════════════════════════════════════════
//  FILE I/O — Atomic writes, secure permissions, bounded reads
// ═══════════════════════════════════════════════════════════

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Centralized atomic write with fsync — replaces 5+ duplicated patterns.
/// Uses u64 random for tmp name (larger namespace) + cleanup on rename failure.
pub(crate) fn atomic_write_with_sync(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    // FIX: u64 for larger collision-resistant namespace (was u32)
    let file_name = path.file_name().ok_or_else(|| {
        "Path has no filename component — cannot create temp file".to_string()
    })?;
    let tmp_name = format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        rand::random::<u64>()
    );
    let tmp = path.with_file_name(&tmp_name);
    // FIX-S17: tmp file must use create_new(true) to refuse to clobber any
    // existing file (e.g. an attacker-planted one). secure_write currently
    // uses create+truncate; we open the tmp here with O_CREAT|O_EXCL and then
    // delegate the rest of the write to a small inline helper.
    secure_write_create_new(&tmp, data).map_err(|e| e.to_string())?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        // FIX: cleanup orphan tmp on rename failure
        let _ = std::fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    // fsync directory to persist rename across crashes (ext4/f2fs)
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            // FIX-B9: surface parent fsync errors to logs instead of silently
            // dropping them — they indicate a non-durable rename.
            if let Err(e) = dir.sync_all() {
                eprintln!("[io] WARN: parent fsync failed: {}", e);
            }
        }
    }
    #[cfg(target_os = "windows")]
    set_hidden_on_windows(path);
    Ok(())
}

/// FIX-S17: variant of `secure_write` that opens with `create_new(true)` so a
/// pre-existing tmp file (race) causes an explicit error rather than a silent
/// truncate. Used by `atomic_write_with_sync` for the .tmp staging file.
fn secure_write_create_new(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    #[cfg(target_os = "windows")]
    {
        set_hidden_on_windows(path);
        // ACL restriction is best-effort here; the rename-target will inherit
        // the same restriction once moved into place.
        apply_user_only_acl_windows(path);
    }
    Ok(())
}

/// Mark dot-prefixed files as Hidden on Windows.
/// Uses absolute path to attrib.exe to prevent PATH manipulation.
#[cfg(target_os = "windows")]
pub(crate) fn set_hidden_on_windows(path: &std::path::Path) {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.starts_with('.') {
            // FIX: absolute path prevents PATH manipulation attack
            if let Err(e) = std::process::Command::new(r"C:\Windows\System32\attrib.exe")
                .arg("+H")
                .arg(path)
                .output()
            {
                eprintln!(
                    "[LexFlow] WARNING: set_hidden_on_windows failed for {:?}: {}",
                    path, e
                );
            }
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
    {
        set_hidden_on_windows(path);
        apply_user_only_acl_windows(path);
    }
    Ok(())
}

/// FIX-S15: apply Windows ACL restriction (current user only) using a sanitized
/// username and an explicit exit-status check. The current user is always
/// looked up via `whoami::username()`, then validated to a safe charset before
/// being passed into icacls so it can never inject command flags.
#[cfg(target_os = "windows")]
fn apply_user_only_acl_windows(path: &std::path::Path) {
    let username = whoami::username();
    // Strict allowlist: ASCII alnum, dot, underscore, hyphen, at-sign, dollar,
    // backslash (DOMAIN\user), and space. Reject anything else outright.
    let safe = !username.is_empty()
        && username.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '-' | '@' | '$' | '\\' | ' ')
        });
    if !safe {
        eprintln!(
            "[LexFlow] WARNING: icacls skipped — username failed safe-charset validation"
        );
        return;
    }
    let grant = format!("{}:F", username);
    match std::process::Command::new(r"C:\Windows\System32\icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                eprintln!(
                    "[LexFlow] WARNING: icacls ACL restriction non-zero exit for {:?}: status={:?} stderr={}",
                    path,
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Err(e) => {
            eprintln!(
                "[LexFlow] WARNING: icacls ACL restriction failed for {:?}: {}",
                path, e
            );
        }
    }
}

/// Safe bounded read — anti-TOCTOU + anti-OOM. Single metadata call.
pub(crate) fn safe_bounded_read(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    // FIX: single metadata call, reuse result
    let meta = file.metadata().map_err(|e| e.to_string())?;
    // FIX-V9: refuse anything that's not a regular file (no /dev/zero,
    // FIFOs, sockets, …).
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    let file_len = meta.len();
    if file_len > max_bytes {
        return Err(format!(
            "File troppo grande ({} bytes) — OOM limit superato",
            file_len
        ));
    }
    // FIX-S16: cap initial allocation at 64 KiB so a maliciously declared
    // max_bytes (e.g. 500 MiB) cannot pre-allocate 500 MiB on every call.
    const INITIAL_CAP: u64 = 64 * 1024;
    let initial = file_len.min(max_bytes).min(INITIAL_CAP) as usize;
    let mut buffer = Vec::with_capacity(initial);
    file.take(max_bytes)
        .read_to_end(&mut buffer)
        .map_err(|e| e.to_string())?;
    Ok(buffer)
}

/// Safe timestamp — prevents panic on pre-1970 clocks.
/// Uses a sanity floor of ~Nov 2023 to catch broken/pre-1970 system clocks.
pub(crate) fn safe_now_ms() -> u64 {
    const MIN_TIMESTAMP_MS: u64 = 1_700_000_000_000; // ~Nov 2023 sanity floor
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64;
    if ts < MIN_TIMESTAMP_MS {
        eprintln!(
            "[SECURITY] System clock returned suspiciously low timestamp ({} ms). Using sanity floor.",
            ts
        );
        MIN_TIMESTAMP_MS
    } else {
        ts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lexflow_io_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_atomic_write_read_roundtrip() {
        let dir = test_dir();
        let path = dir.join("test.dat");
        let data = b"Hello LexFlow atomic write";
        atomic_write_with_sync(&path, data).unwrap();
        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, data);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_atomic_write_overwrites() {
        let dir = test_dir();
        let path = dir.join("overwrite.dat");
        atomic_write_with_sync(&path, b"first").unwrap();
        atomic_write_with_sync(&path, b"second").unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data, b"second");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_atomic_write_no_orphan_tmp() {
        let dir = test_dir();
        let path = dir.join("clean.dat");
        atomic_write_with_sync(&path, b"data").unwrap();
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            entries.is_empty(),
            "No .tmp files should remain after successful write"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_secure_write_creates_file() {
        let dir = test_dir();
        let path = dir.join("secure.dat");
        secure_write(&path, b"secure data").unwrap();
        assert!(path.exists());
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data, b"secure data");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_write_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir();
        let path = dir.join("perms.dat");
        secure_write(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "File must have 0o600 permissions");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_safe_bounded_read_within_limit() {
        let dir = test_dir();
        let path = dir.join("small.dat");
        std::fs::write(&path, b"small file").unwrap();
        let data = safe_bounded_read(&path, 1024).unwrap();
        assert_eq!(data, b"small file");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_safe_bounded_read_exceeds_limit() {
        let dir = test_dir();
        let path = dir.join("big.dat");
        std::fs::write(&path, vec![0u8; 1000]).unwrap();
        let result = safe_bounded_read(&path, 500);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("OOM"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_safe_bounded_read_exact_limit() {
        let dir = test_dir();
        let path = dir.join("exact.dat");
        let data = vec![0xABu8; 100];
        std::fs::write(&path, &data).unwrap();
        let result = safe_bounded_read(&path, 100).unwrap();
        assert_eq!(result, data);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_safe_bounded_read_nonexistent() {
        let result = safe_bounded_read(std::path::Path::new("/nonexistent/path.dat"), 1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_bounded_read_empty_file() {
        let dir = test_dir();
        let path = dir.join("empty.dat");
        std::fs::write(&path, b"").unwrap();
        let data = safe_bounded_read(&path, 1024).unwrap();
        assert!(data.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_safe_now_ms_reasonable() {
        let now = safe_now_ms();
        // Must be after 2024-01-01 (1704067200000 ms)
        assert!(now > 1_704_067_200_000, "Timestamp must be after 2024");
        // Must be before 2100-01-01
        assert!(now < 4_102_444_800_000, "Timestamp must be before 2100");
    }

    #[test]
    fn test_safe_now_ms_monotonic() {
        let t1 = safe_now_ms();
        let t2 = safe_now_ms();
        assert!(t2 >= t1, "Timestamps must be monotonically non-decreasing");
    }
}
