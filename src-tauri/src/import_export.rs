// ═══════════════════════════════════════════════════════════
//  IMPORT / EXPORT — Vault backup and restore (v2 + v4)
// ═══════════════════════════════════════════════════════════

use crate::audit::append_audit_log;
use crate::constants::*;
use crate::crypto::{decrypt_data, derive_secure_key, encrypt_data, verify_hash_matches};
use crate::io::atomic_write_with_sync;
use crate::state::{zeroize_password, AppState, SecureKey};
use crate::vault_v4;
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

#[tauri::command]
pub(crate) async fn export_vault(
    state: State<'_, AppState>,
    pwd: String,
    app: AppHandle,
) -> Result<Value, String> {
    use tauri_plugin_dialog::DialogExt;

    // Verify password before creating backup
    let version = crate::state::get_vault_version(&state);
    if version == 4 {
        // v4: verify by attempting to open vault
        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let vault_path = dir.join(VAULT_FILE);
        if vault_path.exists() {
            let raw = fs::read(&vault_path).map_err(|e| e.to_string())?;
            if vault_v4::open_vault_v4(&pwd, &raw).is_err() {
                return Ok(json!({"success": false, "error": "Password errata."}));
            }
        }
    } else {
        // v2: verify against salt+verify tag
        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let salt_path = dir.join(VAULT_SALT_FILE);
        if salt_path.exists() {
            let vault_salt = fs::read(&salt_path).map_err(|e| e.to_string())?;
            let vault_key_check = derive_secure_key(&pwd, &vault_salt)?;
            let stored_verify = fs::read(dir.join(VAULT_VERIFY_FILE)).unwrap_or_default();
            if !verify_hash_matches(&vault_key_check, &stored_verify) {
                return Ok(json!({"success": false, "error": "Password errata."}));
            }
        }
    }

    // Read full vault data (v2 or v4 — read_vault_internal handles both)
    let data = crate::vault::read_vault_internal(&state)?;

    // Export format: [32-byte salt] [v2-encrypted monolithic JSON]
    // This ensures backups are portable across v2 and v4 installations.
    let mut salt = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let key = derive_secure_key(&pwd, &salt)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(&data).map_err(|e| e.to_string())?);
    let encrypted = encrypt_data(&key, &plaintext)?;
    let mut out = salt;
    out.extend(encrypted);

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name("LexFlow_Backup.lex")
        .save_file(move |file_path| {
            let _ = tx.send(file_path);
        });
    let path = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    if let Some(p) = path {
        let file_path = p
            .into_path()
            .map_err(|e| format!("Percorso non valido: {}", e))?;
        atomic_write_with_sync(&file_path, &out).map_err(|e| e.to_string())?;
        zeroize_password(pwd);
        Ok(json!({"success": true}))
    } else {
        zeroize_password(pwd);
        Ok(json!({"success": false}))
    }
}

#[tauri::command]
pub(crate) async fn import_vault(
    state: State<'_, AppState>,
    pwd: String,
    app: AppHandle,
) -> Result<Value, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("LexFlow Backup", &["lex"])
        .pick_file(move |file_path| {
            let _ = tx.send(file_path);
        });
    let path = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    if let Some(p) = path {
        let file_path = p
            .into_path()
            .map_err(|e| format!("Percorso non valido: {}", e))?;
        const MAX_IMPORT_SIZE: u64 = 500 * 1024 * 1024;
        let raw = {
            let file = fs::File::open(&file_path).map_err(|e| e.to_string())?;
            let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
            if file_len > MAX_IMPORT_SIZE {
                return Err("File troppo grande (max 500MB)".into());
            }
            let mut buf = Vec::with_capacity(file_len.min(MAX_IMPORT_SIZE) as usize);
            file.take(MAX_IMPORT_SIZE + 1)
                .read_to_end(&mut buf)
                .map_err(|e| e.to_string())?;
            if buf.len() as u64 > MAX_IMPORT_SIZE {
                return Err("File troppo grande (max 500MB)".into());
            }
            buf
        };

        // Validate backup format
        let min_len = 32 + VAULT_MAGIC.len() + NONCE_LEN + 16;
        if raw.len() < min_len {
            return Err("File non valido o corrotto (dimensione insufficiente)".into());
        }
        if !raw[32..].starts_with(VAULT_MAGIC) {
            return Err("File non è un backup LexFlow valido".into());
        }

        // Decrypt backup
        let salt = &raw[..32];
        let encrypted = &raw[32..];
        let key = derive_secure_key(&pwd, salt)?;
        let decrypted =
            decrypt_data(&key, encrypted).map_err(|_| "Password errata o file corrotto")?;
        let val: Value =
            serde_json::from_slice(&decrypted).map_err(|_| "Struttura backup non valida")?;
        if val.get("practices").is_none() && val.get("agenda").is_none() {
            return Err("Il file non contiene dati LexFlow validi".into());
        }

        let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        // Import as v4 vault
        let (vault, dek) = vault_v4::create_vault_v4(&pwd)
            .map_err(|e| format!("Errore creazione vault v4: {}", e))?;

        // Write imported data into the new v4 vault
        // First write the empty v4 vault, then set state, then write data via write_vault_internal
        let serialized = vault_v4::serialize_vault(&vault)
            .map_err(|e| format!("Errore serializzazione: {}", e))?;
        atomic_write_with_sync(&dir.join(VAULT_FILE), &serialized)?;

        *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(SecureKey::new(Zeroizing::new(dek.to_vec())));
        *state
            .vault_version
            .write()
            .unwrap_or_else(|e| e.into_inner()) = 4;

        // Now write the actual data using the v4 write path
        crate::vault::write_vault_internal(&state, &val)?;

        let _ = append_audit_log(&state, "Vault importato da backup (v4)");
        zeroize_password(pwd);
        Ok(json!({"success": true}))
    } else {
        Ok(json!({"success": false, "cancelled": true}))
    }
}
