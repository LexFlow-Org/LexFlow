// ═══════════════════════════════════════════════════════════
//  SETTINGS — Encrypted settings read/write
// ═══════════════════════════════════════════════════════════

use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::{atomic_write_with_sync, safe_bounded_read};
use crate::platform::get_local_encryption_key;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, State};
use zeroize::Zeroizing;

use crate::state::AppState;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use crate::platform::decrypt_local_with_migration;

#[tauri::command]
pub(crate) fn get_settings(state: State<AppState>, app: AppHandle) -> Value {
    let path = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .join(SETTINGS_FILE);
    if !path.exists() {
        return json!({});
    }
    let file_data = match safe_bounded_read(&path, MAX_SETTINGS_FILE_SIZE) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[LexFlow] SECURITY WARNING: {}", e);
            return json!({});
        }
    };
    let key = get_local_encryption_key();
    if let Ok(dec) = decrypt_data(&key, &file_data) {
        return serde_json::from_slice(&dec).unwrap_or(json!({}));
    }
    #[cfg(not(target_os = "android"))]
    {
        // V3→V4 and V2→V4 migration handled by decrypt_local_with_migration
        if let Some(dec) = decrypt_local_with_migration(&path) {
            return serde_json::from_slice(&dec).unwrap_or(json!({}));
        }
    }
    // Migration: old plaintext format
    if let Ok(text) = std::str::from_utf8(&file_data) {
        if let Ok(val) = serde_json::from_str::<Value>(text) {
            // M5 FIX: schema check — only accept JSON objects (not arrays, strings, etc.)
            if !val.is_object() {
                eprintln!("[LexFlow] Settings migration rejected: not a JSON object");
                return json!({});
            }
            if let Ok(re_enc) = encrypt_data(&key, &serde_json::to_vec(&val).unwrap_or_default()) {
                let _ = atomic_write_with_sync(&path, &re_enc);
                eprintln!("[LexFlow] Migrazione settings plaintext -> cifrato completata.");
            }
            return val;
        }
    }
    // File corrotto
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
    let backup_path = path.with_extension(format!("json.corrupt.{}", ts));
    let _ = crate::io::secure_write(&backup_path, &file_data);
    eprintln!(
        "[LexFlow] Settings file corrotto — backup salvato in {:?}",
        backup_path
    );
    let _ = app.emit(
        "settings-corrupted",
        json!({
            "backup_path": backup_path.to_string_lossy(),
            "timestamp": ts,
        }),
    );
    json!({})
}

#[tauri::command]
pub(crate) fn save_settings(state: State<AppState>, settings: Value) -> Result<bool, String> {
    let path = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .join(SETTINGS_FILE);
    let key = get_local_encryption_key();
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&settings).map_err(|e| format!("Errore serializzazione JSON: {}", e))?,
    );
    let encrypted = encrypt_data(&key, &plaintext)?;
    atomic_write_with_sync(&path, &encrypted)
        .map(|_| true)
        .map_err(|e| format!("Impossibile salvare le impostazioni su disco: {}", e))
}
