// ═══════════════════════════════════════════════════════════
//  AUTO-BACKUP — encrypted vault snapshots with rotation
// ═══════════════════════════════════════════════════════════

use crate::constants::VAULT_FILE;
use crate::io::{atomic_write_with_sync, secure_write};
use crate::platform::get_local_encryption_key;
use crate::state::AppState;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::State;

const MAX_BACKUPS: usize = 3;
const BACKUP_DIR: &str = ".auto-backups";

/// Monotonic per-process counter to disambiguate same-second backups.
/// LOW (audit): without this, two backups taken in the same second collide on filename.
static BACKUP_SEQ: AtomicU64 = AtomicU64::new(0);

fn backup_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join(BACKUP_DIR)
}

/// HMAC-SHA256(local_key, vault_bytes || machine_id) — written next to each backup
/// as a `.hmac` sidecar so a tampered/swapped backup file can be detected on restore.
fn compute_backup_hmac(vault_bytes: &[u8]) -> String {
    let key = get_local_encryption_key();
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(b"LEXFLOW-BACKUP-V1:");
    mac.update(vault_bytes);
    // Machine binding — `get_or_create_machine_id` always returns a value (cached
    // hex of the persisted 32-byte machine id, or an ephemeral fallback in release
    // builds). On Android the helper is not available; we omit the binding.
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let mid = crate::platform::get_or_create_machine_id();
        mac.update(b"|machine:");
        mac.update(mid.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

/// Apply 0700 permissions on Unix (best-effort).
#[cfg(unix)]
fn harden_dir_0700(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(p) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = fs::set_permissions(p, perms);
    }
}
#[cfg(not(unix))]
fn harden_dir_0700(_p: &std::path::Path) {}

/// Create an encrypted snapshot of the vault.
/// The backup is a direct copy of vault.lex — already encrypted.
pub(crate) fn create_backup(data_dir: &std::path::Path) -> Result<String, String> {
    if crate::vault_engine::is_split_vault(data_dir) {
        return Err("Sbloccare il database per completare la migrazione prima del backup.".into());
    }
    let vault_path = data_dir.join(VAULT_FILE);
    if !vault_path.exists() {
        return Err("Nessun vault da backuppare".into());
    }

    let bak_dir = backup_dir(data_dir);
    fs::create_dir_all(&bak_dir)
        .map_err(|e| format!("Impossibile creare la cartella di backup: {}", e))?;
    // HIGH (audit BE-8): ensure the backup directory is owner-only on Unix so other
    // local users cannot copy or replace snapshots.
    harden_dir_0700(&bak_dir);

    // LOW (audit): use UTC + monotonic per-process counter so two backups taken in the
    // same second don't collide on filename. The display timestamp is still readable.
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let seq = BACKUP_SEQ.fetch_add(1, Ordering::Relaxed);
    let bak_name = if seq == 0 {
        format!("vault_{}.lex.bak", timestamp)
    } else {
        format!("vault_{}_{:03}.lex.bak", timestamp, seq % 1000)
    };
    let bak_path = bak_dir.join(&bak_name);

    // LOW (audit): include the underlying error and retry once on transient
    // file-not-found (atomic-rename race window with concurrent vault writes).
    let vault_data = match crate::io::safe_bounded_read(&vault_path, 500 * 1024 * 1024) {
        Ok(d) => d,
        Err(e1) => {
            // brief retry — atomic_write_with_sync briefly unlinks the destination
            std::thread::sleep(std::time::Duration::from_millis(50));
            crate::io::safe_bounded_read(&vault_path, 500 * 1024 * 1024).map_err(|e2| {
                format!(
                    "Impossibile leggere il database per il backup ({}; retry: {})",
                    e1, e2
                )
            })?
        }
    };

    // HIGH (audit BE-8): write the backup with secure_write (0600) instead of plain copy
    // so it lands with owner-only permissions from the start. atomic_write_with_sync
    // is preserved for the data plane (already does fsync), and we then chmod 0600.
    atomic_write_with_sync(&bak_path, &vault_data).map_err(|e| {
        format!(
            "Impossibile salvare il backup ({}). Verifica lo spazio su disco.",
            e
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&bak_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&bak_path, perms);
        }
    }

    // HIGH (audit BE-8): write per-backup HMAC sidecar.
    let hmac_hex = compute_backup_hmac(&vault_data);
    // Append .hmac as a literal suffix — `with_extension` would rewrite the .bak
    // and end up with a wrong filename like vault_*.lex.lex.bak.hmac.
    let hmac_path = {
        let mut p = bak_path.clone().into_os_string();
        p.push(".hmac");
        std::path::PathBuf::from(p)
    };
    if let Err(e) = secure_write(&hmac_path, hmac_hex.as_bytes()) {
        eprintln!("[LexFlow] backup HMAC sidecar write failed: {}", e);
        // Don't fail the backup itself — the data is already on disk. The missing
        // sidecar will be flagged on restore.
    }

    // Rotate: keep only last MAX_BACKUPS
    rotate_backups(&bak_dir)?;

    Ok(bak_name)
}

/// Remove oldest backups, keeping only the most recent MAX_BACKUPS.
///
/// HIGH (audit BE-8 BUG): the previous loop advanced `entries.remove(0)` even when
/// `fs::remove_file` failed, so a permission error masked the rotation: we'd think
/// the file was gone, leave it on disk, and silently grow the backup directory
/// past the configured cap. Now we collect the targets, remove each one, and abort
/// with an explicit error on the first failure.
fn rotate_backups(bak_dir: &std::path::Path) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(bak_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let n = name.to_string_lossy();
            n.starts_with("vault_") && n.ends_with(".lex.bak")
        })
        .collect();

    // Sort by name (UTC timestamp in name ensures chronological order)
    entries.sort_by_key(|e| e.file_name());

    if entries.len() <= MAX_BACKUPS {
        return Ok(());
    }
    let to_remove = entries.len() - MAX_BACKUPS;
    let entries_to_remove: Vec<_> = entries.into_iter().take(to_remove).collect();

    for entry in entries_to_remove {
        let path = entry.path();
        match fs::remove_file(&path) {
            Ok(_) => {
                // Also remove the HMAC sidecar if present (literal `.hmac` suffix,
                // see compute path in `create_backup`).
                let sidecar = {
                    let mut p = path.clone().into_os_string();
                    p.push(".hmac");
                    std::path::PathBuf::from(p)
                };
                let _ = fs::remove_file(&sidecar);
            }
            Err(e) => {
                eprintln!("[backup] failed to rotate {}: {}", path.display(), e);
                return Err(format!("backup rotation failed: {}", e));
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn trigger_backup(state: State<AppState>) -> Result<String, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let name = create_backup(&dir)?;
    let _ = crate::audit::append_audit_log_locked(&state, &format!("Backup automatico: {}", name));
    Ok(name)
}

/// MEDIUM (audit BE-8 SEC): regex-shaped validation for backup filenames before we
/// expose them to the FE. Without this, a stray file like `../etc/passwd.lex.bak`
/// would slip through the `.lex.bak` suffix check.
fn is_valid_backup_filename(name: &str) -> bool {
    // Accept: vault_YYYYMMDD_HHMMSS.lex.bak  OR  vault_YYYYMMDD_HHMMSS_NNN.lex.bak
    let stripped = match name
        .strip_prefix("vault_")
        .and_then(|s| s.strip_suffix(".lex.bak"))
    {
        Some(s) => s,
        None => return false,
    };
    let parts: Vec<&str> = stripped.split('_').collect();
    if parts.len() != 2 && parts.len() != 3 {
        return false;
    }
    // YYYYMMDD: 8 digits
    if parts[0].len() != 8 || !parts[0].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // HHMMSS: 6 digits
    if parts[1].len() != 6 || !parts[1].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // optional NNN: 1..=3 digits
    if parts.len() == 3
        && (parts[2].is_empty()
            || parts[2].len() > 3
            || !parts[2].chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    true
}

#[tauri::command]
pub(crate) fn get_backup_list(state: State<AppState>) -> Result<serde_json::Value, String> {
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let bak_dir = backup_dir(&dir);

    if !bak_dir.exists() {
        return Ok(serde_json::json!([]));
    }

    let mut backups: Vec<serde_json::Value> = fs::read_dir(&bak_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| {
            // MEDIUM (audit BE-8 SEC): strict validation — reject anything that doesn't
            // match the canonical vault_<utc>.lex.bak pattern.
            let n = e.file_name().to_string_lossy().to_string();
            is_valid_backup_filename(&n)
        })
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            serde_json::json!({
                "name": name,
                "size": size,
                "created": e.metadata().ok()
                    .and_then(|m| m.created().ok())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Utc> = t.into();
                        dt.to_rfc3339()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect();

    backups.sort_by(|a, b| {
        b.get("name")
            .and_then(|n| n.as_str())
            .cmp(&a.get("name").and_then(|n| n.as_str()))
    });

    Ok(serde_json::json!(backups))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_backup_filename_accepts_canonical() {
        assert!(is_valid_backup_filename("vault_20260507_120000.lex.bak"));
        assert!(is_valid_backup_filename(
            "vault_20260507_120000_001.lex.bak"
        ));
    }

    #[test]
    fn test_is_valid_backup_filename_rejects_garbage() {
        assert!(!is_valid_backup_filename("vault_abcdef_120000.lex.bak"));
        assert!(!is_valid_backup_filename("vault_20260507_xyzabc.lex.bak"));
        assert!(!is_valid_backup_filename("../etc/passwd.lex.bak"));
        assert!(!is_valid_backup_filename("vault_20260507.lex.bak"));
        assert!(!is_valid_backup_filename(
            "vault_20260507_120000_evil.lex.bak"
        ));
        assert!(!is_valid_backup_filename("vault_20260507_120000.lex"));
        assert!(!is_valid_backup_filename(""));
    }
}
