// ═══════════════════════════════════════════════════════════
//  AUTO-BACKUP — encrypted vault snapshots with rotation
// ═══════════════════════════════════════════════════════════

use crate::constants::VAULT_FILE;
use crate::io::atomic_write_with_sync;
use crate::state::AppState;
use std::fs;
use std::path::PathBuf;
use tauri::State;

const MAX_BACKUPS: usize = 3;
const BACKUP_DIR: &str = ".auto-backups";

fn backup_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join(BACKUP_DIR)
}

/// Create an encrypted snapshot of the vault.
/// The backup is a direct copy of vault.lex — already encrypted.
pub(crate) fn create_backup(data_dir: &std::path::Path) -> Result<String, String> {
    let vault_path = data_dir.join(VAULT_FILE);
    if !vault_path.exists() {
        return Err("Nessun vault da backuppare".into());
    }

    let bak_dir = backup_dir(data_dir);
    fs::create_dir_all(&bak_dir).map_err(|e| format!("Errore creazione dir backup: {}", e))?;

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let bak_name = format!("vault_{}.lex.bak", timestamp);
    let bak_path = bak_dir.join(&bak_name);

    // Copy vault file (already encrypted — no need to re-encrypt)
    let vault_data = crate::io::safe_bounded_read(&vault_path, 500 * 1024 * 1024)
        .map_err(|e| format!("Errore lettura vault: {}", e))?;
    atomic_write_with_sync(&bak_path, &vault_data)
        .map_err(|e| format!("Errore scrittura backup: {}", e))?;

    // Rotate: keep only last MAX_BACKUPS
    rotate_backups(&bak_dir)?;

    Ok(bak_name)
}

/// Remove oldest backups, keeping only the most recent MAX_BACKUPS.
fn rotate_backups(bak_dir: &std::path::Path) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(bak_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name().to_string_lossy().starts_with("vault_")
                && e.file_name().to_string_lossy().ends_with(".lex.bak")
        })
        .collect();

    // Sort by name (timestamp in name ensures chronological order)
    entries.sort_by_key(|e| e.file_name());

    // Remove oldest if over limit
    while entries.len() > MAX_BACKUPS {
        if let Some(oldest) = entries.first() {
            if let Err(e) = fs::remove_file(oldest.path()) {
                eprintln!(
                    "[LexFlow] Backup rotation: failed to remove {:?}: {}",
                    oldest.path(),
                    e
                );
            }
            entries.remove(0);
        }
    }

    Ok(())
}

#[tauri::command]
pub(crate) fn trigger_backup(state: State<AppState>) -> Result<String, String> {
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let name = create_backup(&dir)?;
    let _ = crate::audit::append_audit_log(&state, &format!("Backup automatico: {}", name));
    Ok(name)
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
        .filter(|e| e.file_name().to_string_lossy().ends_with(".lex.bak"))
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            serde_json::json!({
                "name": name,
                "size": size,
                "created": e.metadata().ok()
                    .and_then(|m| m.created().ok())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Local> = t.into();
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
