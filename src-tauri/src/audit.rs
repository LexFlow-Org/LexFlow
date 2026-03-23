// ═══════════════════════════════════════════════════════════
//  AUDIT — Encrypted audit log
// ═══════════════════════════════════════════════════════════

use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::{atomic_write_with_sync, safe_bounded_read};
use crate::state::{get_vault_key, AppState};
use serde_json::{json, Value};
use tauri::State;
use zeroize::Zeroizing;

/// Max audit log file size: 10 MB (prevents OOM from inflated/tampered file)
const MAX_AUDIT_SIZE: u64 = 10 * 1024 * 1024;

pub(crate) fn append_audit_log(state: &State<AppState>, event_name: &str) -> Result<(), String> {
    let key = match get_vault_key(state) {
        Ok(k) => k,
        Err(_) => {
            // Vault locked — can't encrypt audit event. Log to stderr as fallback.
            eprintln!(
                "[LexFlow] Audit event dropped (vault locked): {}",
                event_name
            );
            return Ok(());
        }
    };
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let path = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .join(AUDIT_LOG_FILE);
    let mut logs: Vec<Value> = if path.exists() {
        // SECURITY FIX: bounded read prevents OOM from inflated audit file
        let enc = safe_bounded_read(&path, MAX_AUDIT_SIZE).unwrap_or_default();
        match decrypt_data(&key, &enc) {
            Ok(dec) => serde_json::from_slice(&dec).unwrap_or_default(),
            Err(_) => {
                let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
                let corrupt_backup = path.with_extension(format!("audit.corrupt.{}", ts));
                let _ = std::fs::copy(&path, &corrupt_backup);
                eprintln!(
                    "[LexFlow] SECURITY: Audit log decryption failed — tampered? Backup: {:?}",
                    corrupt_backup
                );
                vec![
                    json!({"event": "AUDIT_LOG_TAMPERING_DETECTED", "time": chrono::Local::now().to_rfc3339()}),
                ]
            }
        }
    } else {
        vec![]
    };

    logs.push(json!({"event": event_name, "time": chrono::Local::now().to_rfc3339()}));
    if logs.len() > 10000 {
        let excess = logs.len() - 10000;
        logs.drain(0..excess);
    }
    // SECURITY FIX: propagate serialization error instead of unwrap_or_default
    // (which would encrypt an empty blob, destroying the entire log)
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&logs).map_err(|e| format!("Audit serialization failed: {}", e))?,
    );
    let enc = encrypt_data(&key, &plaintext)?;
    atomic_write_with_sync(&path, &enc)?;
    Ok(())
}

#[tauri::command]
pub(crate) fn get_audit_log(state: State<AppState>) -> Result<Value, String> {
    let key = get_vault_key(&state)?;
    let path = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .join(AUDIT_LOG_FILE);
    if !path.exists() {
        return Ok(json!([]));
    }
    // SECURITY FIX: bounded read
    let enc = safe_bounded_read(&path, MAX_AUDIT_SIZE).map_err(|e| e.to_string())?;
    let dec = decrypt_data(&key, &enc)?;
    serde_json::from_slice(&dec).map_err(|e| e.to_string())
}
