// ═══════════════════════════════════════════════════════════
//  AUDIT — Encrypted audit log
// ═══════════════════════════════════════════════════════════

use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::atomic_write_with_sync;
use crate::state::{get_vault_key, AppState};
use serde_json::{json, Value};
use std::fs;
use tauri::State;
use zeroize::Zeroizing;

pub(crate) fn append_audit_log(state: &State<AppState>, event_name: &str) -> Result<(), String> {
    let key = match get_vault_key(state) {
        Ok(k) => k,
        Err(_) => return Ok(()),
    };
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let path = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .join(AUDIT_LOG_FILE);
    let mut logs: Vec<Value> = if path.exists() {
        let enc = fs::read(&path).unwrap_or_default();
        match decrypt_data(&key, &enc) {
            Ok(dec) => serde_json::from_slice(&dec).unwrap_or_default(),
            Err(_) => {
                let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
                let corrupt_backup = path.with_extension(format!("audit.corrupt.{}", ts));
                let _ = fs::copy(&path, &corrupt_backup);
                eprintln!("[LexFlow] SECURITY: Audit log decryption failed — tampered? Backup saved to {:?}", corrupt_backup);
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
    let plaintext = Zeroizing::new(serde_json::to_vec(&logs).unwrap_or_default());
    let enc = encrypt_data(&key, &plaintext)?;
    atomic_write_with_sync(&path, &enc)?;
    Ok(())
}

#[tauri::command]
pub(crate) fn get_audit_log(state: State<AppState>) -> Result<Value, String> {
    let key = get_vault_key(&state)?;
    let path = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .join(AUDIT_LOG_FILE);
    if !path.exists() {
        return Ok(json!([]));
    }
    let dec = decrypt_data(&key, &fs::read(path).map_err(|e| e.to_string())?)?;
    serde_json::from_slice(&dec).map_err(|e| e.to_string())
}
