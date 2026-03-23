// ═══════════════════════════════════════════════════════════
//  VAULT — All vault CRUD, unlock/lock, password, search
//  Supports both v2 (legacy monolithic) and v4 (per-record)
// ═══════════════════════════════════════════════════════════

use crate::audit::append_audit_log;
use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
#[allow(unused_imports)] // Used in new code paths, incremental adoption
use crate::error::LexFlowError;
use crate::io::{atomic_write_with_sync, secure_write};
use crate::lockout::{check_lockout, clear_lockout, record_failed_attempt};
use crate::state::{
    get_vault_dek, get_vault_key, get_vault_version, invalidate_vault_cache, zeroize_password,
    AppState, SecureKey,
};
use crate::vault_v4;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use std::fs;
use std::time::Instant;
use tauri::State;
use zeroize::Zeroizing;

// ─── Internal vault I/O (v2/v4 transparent) ─────────────────

/// Read full vault data as a JSON value.
/// PERF: returns cached data if available, avoiding re-decryption.
pub(crate) fn read_vault_internal(state: &State<AppState>) -> Result<Value, String> {
    // PERF: check cache first
    if let Some(cached) = state
        .vault_cache
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        return Ok(cached.clone());
    }

    let version = get_vault_version(state);
    let result = if version == 4 {
        read_vault_v4(state)?
    } else {
        // v2 legacy path
        let key = get_vault_key(state)?;
        let path = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .join(VAULT_FILE);
        if !path.exists() {
            return Ok(json!({"practices":[], "agenda":[]}));
        }
        // FIX: bounded read (500MB cap) instead of unbounded fs::read
        let raw = crate::io::safe_bounded_read(&path, 500 * 1024 * 1024)?;
        let decrypted = decrypt_data(&key, &raw)?;
        serde_json::from_slice(&decrypted).map_err(|e| e.to_string())?
    };

    // PERF: store in cache
    *state.vault_cache.write().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());

    Ok(result)
}

/// v4: read vault by decrypting index + all records, reassemble into monolithic JSON.
fn read_vault_v4(state: &State<AppState>) -> Result<Value, String> {
    let dek = get_vault_dek(state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = dir.join(VAULT_FILE);
    if !path.exists() {
        return Ok(json!({"practices":[], "agenda":[]}));
    }
    // FIX: bounded read (500MB cap)
    let raw = crate::io::safe_bounded_read(&path, 500 * 1024 * 1024)?;
    let vault = vault_v4::deserialize_vault(&raw)?;

    let index = vault_v4::decrypt_index(&dek, &vault.index)?;

    let mut result =
        json!({"practices":[], "agenda":[], "contacts":[], "timeLogs":[], "invoices":[]});
    for idx_entry in &index {
        if let Some(record_entry) = vault.records.get(&idx_entry.id) {
            match vault_v4::read_current_version(record_entry, &dek) {
                Ok(plaintext) => {
                    match serde_json::from_slice::<Value>(&plaintext) {
                        Ok(val) => {
                            if let Some(arr) = result
                                .get_mut(&idx_entry.field)
                                .and_then(|v| v.as_array_mut())
                            {
                                arr.push(val);
                            }
                        }
                        Err(e) => {
                            // FIX: log malformed JSON instead of silent skip
                            eprintln!(
                                "[LexFlow] WARNING: record {} has malformed JSON: {}. Skipping.",
                                idx_entry.id, e
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[LexFlow] WARNING: Failed to decrypt record {}: {}. Skipping (isolated corruption).",
                        idx_entry.id, e
                    );
                }
            }
        }
    }
    Ok(result)
}

/// Write full vault data.
/// In v4: diffs against existing records, encrypts only changed ones.
/// In v2: encrypts the monolithic blob as before.
/// PERF: invalidates cache after successful write.
pub(crate) fn write_vault_internal(state: &State<AppState>, data: &Value) -> Result<(), String> {
    // PERF: invalidate cache before write (so concurrent reads don't get stale data)
    invalidate_vault_cache(state);

    let version = get_vault_version(state);
    if version == 4 {
        let result = write_vault_v4(state, data);
        // PERF: update cache with new data on success
        if result.is_ok() {
            *state.vault_cache.write().unwrap_or_else(|e| e.into_inner()) = Some(data.clone());
        }
        return result;
    }
    // v2 legacy path
    let key = get_vault_key(state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let plaintext = Zeroizing::new(serde_json::to_vec(data).map_err(|e| e.to_string())?);
    let encrypted = encrypt_data(&key, &plaintext)?;
    let result = atomic_write_with_sync(&dir.join(VAULT_FILE), &encrypted);
    if result.is_ok() {
        *state.vault_cache.write().unwrap_or_else(|e| e.into_inner()) = Some(data.clone());
    }
    result
}

/// v4: write vault by encrypting individual records and updating the index.
fn write_vault_v4(state: &State<AppState>, data: &Value) -> Result<(), String> {
    let dek = get_vault_dek(state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = dir.join(VAULT_FILE);

    // Load existing vault or create fresh
    let mut vault = if path.exists() {
        let raw = fs::read(&path).map_err(|e| e.to_string())?;
        vault_v4::deserialize_vault(&raw)?
    } else {
        // Should not normally happen (vault created at unlock), but handle gracefully
        return Err("v4 vault file not found".into());
    };

    let fields = ["practices", "agenda", "contacts", "timeLogs", "invoices"];
    let mut new_index: Vec<vault_v4::IndexEntry> = Vec::new();
    let mut new_records = std::collections::BTreeMap::new();

    for field in &fields {
        let items = data.get(*field).and_then(|v| v.as_array());
        if let Some(items) = items {
            for item in items {
                let id = item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if id.is_empty() {
                    continue;
                }
                let record_key = format!("{}_{}", field, id);
                let item_bytes = serde_json::to_vec(item).map_err(|e| e.to_string())?;

                // Check if record exists and data changed
                let mut entry = if let Some(existing) = vault.records.remove(&record_key) {
                    // Check if content changed by comparing plaintext
                    if let Ok(old_plain) = vault_v4::read_current_version(&existing, &dek) {
                        if old_plain == item_bytes {
                            // Unchanged — keep existing entry
                            new_records.insert(record_key.clone(), existing);
                            let title = vault_v4::extract_record_title_pub(item, field);
                            let tags = vault_v4::extract_record_tags_pub(item, field);
                            new_index.push(vault_v4::IndexEntry {
                                id: record_key,
                                field: field.to_string(),
                                title,
                                tags,
                                updated_at: item
                                    .get("updatedAt")
                                    .or_else(|| item.get("createdAt"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            });
                            continue;
                        }
                    }
                    existing
                } else {
                    vault_v4::RecordEntry {
                        versions: vec![],
                        current: 0,
                    }
                };

                // Encrypt and append new version
                vault_v4::append_record_version(&mut entry, &dek, &item_bytes)?;
                new_records.insert(record_key.clone(), entry);

                let title = vault_v4::extract_record_title_pub(item, field);
                let tags = vault_v4::extract_record_tags_pub(item, field);
                new_index.push(vault_v4::IndexEntry {
                    id: record_key,
                    field: field.to_string(),
                    title,
                    tags,
                    updated_at: item
                        .get("updatedAt")
                        .or_else(|| item.get("createdAt"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
    }

    vault.records = new_records;
    vault.index = vault_v4::encrypt_index(&dek, &new_index)?;
    vault.rotation.writes += 1;

    let serialized = vault_v4::serialize_vault(&vault)?;
    atomic_write_with_sync(&path, &serialized)
}

// ─── Password validation ────────────────────────────────────

fn validate_password_strength(password: &str) -> Result<(), Value> {
    let pwd_strong = password.len() >= 12
        && password.chars().any(|c| c.is_uppercase())
        && password.chars().any(|c| c.is_lowercase())
        && password.chars().any(|c| c.is_ascii_digit())
        && password.chars().any(|c| !c.is_alphanumeric());
    if !pwd_strong {
        return Err(
            json!({"success": false, "error": "Password troppo debole: minimo 12 caratteri, una maiuscola, una minuscola, un numero e un simbolo."}),
        );
    }
    Ok(())
}

// ─── v4 vault creation ──────────────────────────────────────

/// Create a brand new v4 vault and store DEK in state.
fn init_new_vault_v4(
    state: &State<AppState>,
    password: &str,
    dir: &std::path::Path,
) -> Result<(), Value> {
    validate_password_strength(password)?;

    let (vault, dek) = vault_v4::create_vault_v4(password).map_err(
        |e| json!({"success": false, "error": format!("Errore creazione vault v4: {}", e)}),
    )?;

    let serialized = vault_v4::serialize_vault(&vault).map_err(
        |e| json!({"success": false, "error": format!("Errore serializzazione: {}", e)}),
    )?;

    atomic_write_with_sync(&dir.join(VAULT_FILE), &serialized).map_err(
        |e| json!({"success": false, "error": format!("Errore scrittura vault: {}", e)}),
    )?;

    // Store DEK in state
    *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(SecureKey::new(Zeroizing::new(dek.to_vec())));
    *state
        .vault_version
        .write()
        .unwrap_or_else(|e| e.into_inner()) = 4;

    Ok(())
}

// ─── Vault field helpers ────────────────────────────────────

fn validate_vault_array(data: &Value, field_name: &str) -> Result<(), String> {
    if !data.is_array() {
        return Err(format!(
            "Dati '{}' non validi: atteso un array JSON, ricevuto {}.",
            field_name,
            match data {
                Value::Object(_) => "un oggetto",
                Value::String(_) => "una stringa",
                Value::Number(_) => "un numero",
                Value::Bool(_) => "un booleano",
                Value::Null => "null",
                _ => "tipo sconosciuto",
            }
        ));
    }
    Ok(())
}

fn load_vault_field(state: &State<AppState>, field: &str) -> Result<Value, String> {
    let vault = read_vault_internal(state)?;
    Ok(vault.get(field).cloned().unwrap_or(json!([])))
}

fn save_vault_field(state: &State<AppState>, field: &str, data: Value) -> Result<bool, String> {
    validate_vault_array(&data, field)?;
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let mut vault = read_vault_internal(state)?;
    vault[field] = data;
    write_vault_internal(state, &vault)?;
    Ok(true)
}

// ─── Tauri commands: vault lifecycle ────────────────────────

#[tauri::command]
pub(crate) fn vault_exists(state: State<AppState>) -> bool {
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    // v4 vault exists if vault.lex starts with V4 magic, or v2 if salt exists
    let vault_path = dir.join(VAULT_FILE);
    if vault_path.exists() {
        if let Ok(data) = fs::read(&vault_path) {
            if data.starts_with(vault_v4::VAULT_V4_MAGIC) {
                return true;
            }
        }
    }
    dir.join(VAULT_SALT_FILE).exists()
}

/// Internal unlock used by both the Tauri command and bio_unlock_vault.
/// Takes password by value to allow zeroization.
pub(crate) fn unlock_vault_with_password(state: &State<AppState>, password: String) -> Value {
    unlock_vault_inner(state, password)
}

/// PERF: async command — Argon2 KDF runs on a blocking thread pool,
/// keeping the Tauri main thread (and UI) responsive during unlock.
#[tauri::command]
pub(crate) async fn unlock_vault(
    state: State<'_, AppState>,
    password: String,
) -> Result<Value, ()> {
    Ok(unlock_vault_inner(&state, password))
}

fn unlock_vault_inner(state: &State<AppState>, password: String) -> Value {
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    if let Err(locked_json) = check_lockout(state, &sec_dir) {
        return locked_json;
    }

    let vault_path = dir.join(VAULT_FILE);

    // v4-only: check if vault exists
    let is_new = !vault_path.exists();

    if is_new {
        // Create new vault in v4 format
        match init_new_vault_v4(state, &password, &dir) {
            Ok(()) => {}
            Err(e) => {
                zeroize_password(password);
                return e;
            }
        }
        clear_lockout(state, &sec_dir);
        *state
            .last_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Instant::now();
        zeroize_password(password);
        let _ = append_audit_log(state, "Nuovo Vault v4 creato");
        return json!({"success": true, "isNew": true});
    }

    // Existing vault — detect version
    if vault_path.exists() {
        let raw = match fs::read(&vault_path) {
            Ok(r) => r,
            Err(e) => {
                zeroize_password(password);
                return json!({"success": false, "error": format!("Errore lettura vault: {}", e)});
            }
        };

        let version = vault_v4::detect_vault_version(&raw);

        if version == 4 {
            // Open v4 vault directly
            match vault_v4::open_vault_v4(&password, &raw) {
                Ok((vault, dek)) => {
                    // SECURITY: anti-rollback check
                    let counter_path = sec_dir.join(".vault-writes-counter");
                    let stored_counter = fs::read_to_string(&counter_path)
                        .ok()
                        .and_then(|s| s.trim().parse::<u64>().ok())
                        .unwrap_or(0);
                    if vault.rotation.writes < stored_counter {
                        eprintln!(
                            "[SECURITY] ROLLBACK DETECTED: vault writes={} < stored counter={}",
                            vault.rotation.writes, stored_counter
                        );
                        zeroize_password(password);
                        return json!({"success": false, "error": "Possibile rollback del vault rilevato. Il file vault potrebbe essere stato sostituito con una versione precedente. Contattare il supporto."});
                    }
                    // Update stored counter
                    if vault.rotation.writes > stored_counter {
                        let _ = atomic_write_with_sync(
                            &counter_path,
                            vault.rotation.writes.to_string().as_bytes(),
                        );
                    }

                    *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(SecureKey::new(Zeroizing::new(dek.to_vec())));
                    *state
                        .vault_version
                        .write()
                        .unwrap_or_else(|e| e.into_inner()) = 4;

                    // Perform key rotation if needed (>90 days or >10k writes)
                    if vault_v4::needs_rotation(&vault.rotation) {
                        eprintln!(
                            "[LexFlow] Key rotation triggered — re-encrypting all records..."
                        );
                        let kek = match vault_v4::derive_kek(&password, &vault.kdf) {
                            Ok(k) => k,
                            Err(e) => {
                                eprintln!("[LexFlow] KEK re-derive for rotation failed: {}", e);
                                // Non-fatal: skip rotation, vault is still usable
                                Zeroizing::new(vec![])
                            }
                        };
                        if !kek.is_empty() {
                            let mut vault_mut = vault;
                            match vault_v4::rotate_dek(&mut vault_mut, &kek) {
                                Ok(new_dek) => {
                                    // Write rotated vault
                                    if let Ok(serialized) = vault_v4::serialize_vault(&vault_mut) {
                                        let _ = atomic_write_with_sync(&vault_path, &serialized);
                                        // Update DEK in state
                                        *state
                                            .vault_dek
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner()) =
                                            Some(SecureKey::new(new_dek));
                                        let _ = append_audit_log(
                                            state,
                                            "Rotazione DEK automatica completata",
                                        );
                                        eprintln!(
                                            "[LexFlow] ✓ Key rotation completed successfully"
                                        );
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[LexFlow] Key rotation failed (non-fatal): {}", e);
                                }
                            }
                        }
                    }

                    clear_lockout(state, &sec_dir);
                    *state
                        .last_activity
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Instant::now();
                    zeroize_password(password);
                    let _ = append_audit_log(state, "Sblocco Vault v4");
                    return json!({"success": true, "isNew": false});
                }
                Err(e) => {
                    record_failed_attempt(state, &sec_dir);
                    zeroize_password(password);
                    return json!({"success": false, "error": e});
                }
            }
        }

        // v2 and unknown formats no longer supported
        zeroize_password(password);
        return json!({"success": false, "error": "Formato vault non supportato. Aggiornare da una versione precedente dell'app."});
    }

    // No vault file found
    zeroize_password(password);
    json!({"success": false, "error": "Vault non trovato"})
}

#[tauri::command]
pub(crate) fn lock_vault(state: State<AppState>) -> bool {
    // Zero both v2 key and v4 DEK + clear cache
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *state
        .vault_version
        .write()
        .unwrap_or_else(|e| e.into_inner()) = 0;
    // SECURITY: clear plaintext cache on lock
    invalidate_vault_cache(&state);
    true
}

#[tauri::command]
pub(crate) fn reset_vault(state: State<AppState>, password: String) -> Value {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let vault_path = dir.join(VAULT_FILE);
    if vault_path.exists() {
        // Verify password before reset
        if let Ok(data) = fs::read(&vault_path) {
            if vault_v4::open_vault_v4(&password, &data).is_err() {
                zeroize_password(password);
                return json!({"success": false, "error": "Password errata"});
            }
        }
    } else if false {
        zeroize_password(password);
        return json!({"success": false, "error": "Password errata"});
    }
    {
        for sensitive_file in &[
            VAULT_FILE,
            VAULT_SALT_FILE,
            VAULT_VERIFY_FILE,
            AUDIT_LOG_FILE,
        ] {
            let p = dir.join(sensitive_file);
            if p.exists() {
                if let Ok(meta) = p.metadata() {
                    let size = meta.len() as usize;
                    if size > 0 {
                        let _ = secure_write(&p, &vec![0u8; size]);
                    }
                }
                let _ = fs::remove_file(&p);
            }
        }
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
    }
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *state
        .vault_version
        .write()
        .unwrap_or_else(|e| e.into_inner()) = 0;
    invalidate_vault_cache(&state);
    zeroize_password(password);
    json!({"success": true})
}

#[tauri::command]
pub(crate) fn change_password(
    state: State<AppState>,
    current_password: String,
    new_password: String,
) -> Result<Value, String> {
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    // SECURITY: rate limit change_password to prevent brute-force on current password
    if let Err(locked_json) = check_lockout(&state, &sec_dir) {
        zeroize_password(current_password);
        zeroize_password(new_password);
        return Ok(locked_json);
    }

    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    // v4-only: re-wrap DEK with new KEK — O(1), no re-encryption needed!
    let result = change_password_v4(&state, &dir, &current_password, &new_password);

    // Record failed attempt if password was wrong
    if let Ok(ref val) = result {
        if val
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            clear_lockout(&state, &sec_dir);
        } else {
            record_failed_attempt(&state, &sec_dir);
        }
    }

    zeroize_password(current_password);
    zeroize_password(new_password);
    result
}

/// v4 change password: only re-wrap DEK with new KEK — O(1)!
fn change_password_v4(
    state: &State<AppState>,
    dir: &std::path::Path,
    current_password: &str,
    new_password: &str,
) -> Result<Value, String> {
    let vault_path = dir.join(VAULT_FILE);
    let raw = fs::read(&vault_path).map_err(|e| e.to_string())?;

    // Verify current password by opening vault
    let (mut vault, _dek) = vault_v4::open_vault_v4(current_password, &raw)
        .map_err(|_| "Password attuale errata".to_string())?;

    // Get existing DEK from state
    let dek = get_vault_dek(state)?;

    // Generate new KDF params with benchmark
    let mut new_kdf = vault_v4::benchmark_argon2_params();
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    new_kdf.salt = B64.encode(salt);

    // Derive new KEK
    let new_kek = vault_v4::derive_kek(new_password, &new_kdf)?;

    // Re-wrap DEK with new KEK
    let (wrapped, iv) = vault_v4::wrap_dek(&new_kek, &dek)?;

    // Update vault header
    vault.kdf = new_kdf;
    vault.wrapped_dek = wrapped;
    vault.dek_iv = iv;
    vault.header_mac = vault_v4::compute_header_mac(&new_kek, &vault);

    // Write updated vault
    let serialized = vault_v4::serialize_vault(&vault)?;
    atomic_write_with_sync(&vault_path, &serialized)?;

    update_bio_password_if_needed(state, new_password);

    let _ = append_audit_log(state, "Password cambiata (v4, O(1))");
    Ok(json!({"success": true}))
}

/// Update biometric keychain entry if biometric is enabled.
#[allow(unused_variables)]
fn update_bio_password_if_needed(state: &State<AppState>, new_password: &str) {
    #[cfg(not(target_os = "android"))]
    {
        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if dir.join(BIO_MARKER_FILE).exists() {
            let user = whoami::username();
            if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
                if entry.set_password(new_password).is_err() {
                    eprintln!(
                        "[SECURITY WARNING] Failed to update biometric password in keychain. \
                         Disabling biometric login."
                    );
                    let _ = fs::remove_file(dir.join(BIO_MARKER_FILE));
                    let _ = entry.delete_credential();
                }
            }
        }
    }
}

#[tauri::command]
pub(crate) fn verify_vault_password(state: State<AppState>, pwd: String) -> Result<Value, String> {
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Err(locked_json) = check_lockout(&state, &sec_dir) {
        return Ok(locked_json);
    }

    let vault_path = dir.join(VAULT_FILE);
    let valid = if let Ok(raw) = fs::read(&vault_path) {
        vault_v4::open_vault_v4(&pwd, &raw).is_ok()
    } else {
        false
    };

    if !valid {
        record_failed_attempt(&state, &sec_dir);
    } else {
        clear_lockout(&state, &sec_dir);
    }
    zeroize_password(pwd);
    Ok(json!({"valid": valid}))
}

// ─── Tauri commands: data CRUD ──────────────────────────────

#[tauri::command]
pub(crate) fn load_practices(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "practices")
}

#[tauri::command]
pub(crate) fn save_practices(state: State<AppState>, list: Value) -> Result<bool, String> {
    crate::validation::validate_practices(&list)?;
    let count = list.as_array().map(|a| a.len()).unwrap_or(0);
    let result = save_vault_field(&state, "practices", list)?;
    let _ = append_audit_log(&state, &format!("Salvati {} fascicoli", count));
    Ok(result)
}

#[tauri::command]
pub(crate) fn load_agenda(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "agenda")
}

#[tauri::command]
pub(crate) fn save_agenda(state: State<AppState>, agenda: Value) -> Result<bool, String> {
    crate::validation::validate_agenda(&agenda)?;
    let result = save_vault_field(&state, "agenda", agenda)?;
    let _ = append_audit_log(&state, "Aggiornata agenda");
    Ok(result)
}

#[tauri::command]
pub(crate) fn load_time_logs(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "timeLogs")
}

#[tauri::command]
pub(crate) fn save_time_logs(state: State<AppState>, logs: Value) -> Result<bool, String> {
    crate::validation::validate_time_logs(&logs)?;
    let result = save_vault_field(&state, "timeLogs", logs)?;
    let _ = append_audit_log(&state, "Aggiornate ore lavorate");
    Ok(result)
}

#[tauri::command]
pub(crate) fn load_invoices(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "invoices")
}

#[tauri::command]
pub(crate) fn save_invoices(state: State<AppState>, invoices: Value) -> Result<bool, String> {
    crate::validation::validate_invoices(&invoices)?;
    let result = save_vault_field(&state, "invoices", invoices)?;
    let _ = append_audit_log(&state, "Aggiornate fatture");
    Ok(result)
}

#[tauri::command]
pub(crate) fn load_contacts(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "contacts")
}

#[tauri::command]
pub(crate) fn save_contacts(state: State<AppState>, contacts: Value) -> Result<bool, String> {
    crate::validation::validate_contacts(&contacts)?;
    let count = contacts.as_array().map(|a| a.len()).unwrap_or(0);
    let result = save_vault_field(&state, "contacts", contacts)?;
    let _ = append_audit_log(&state, &format!("Salvati {} contatti", count));
    Ok(result)
}

// ─── Summary ────────────────────────────────────────────────

fn count_urgent_deadlines(practices: &[Value]) -> usize {
    let today = chrono::Local::now().naive_local().date();
    let in_7_days = today + chrono::Duration::days(7);
    practices
        .iter()
        .filter(|p| p.get("status").and_then(|s| s.as_str()) == Some("active"))
        .flat_map(|p| {
            p.get("deadlines")
                .and_then(|d| d.as_array())
                .into_iter()
                .flatten()
        })
        .filter(|d| {
            d.get("date")
                .and_then(|ds| ds.as_str())
                .and_then(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
                .map(|d_date| d_date >= today && d_date <= in_7_days)
                .unwrap_or(false)
        })
        .count()
}

#[tauri::command]
pub(crate) fn get_summary(state: State<AppState>) -> Result<Value, String> {
    let vault = read_vault_internal(&state)?;
    let practices = vault.get("practices").and_then(|p| p.as_array());
    let practices_slice = practices.map(|a| a.as_slice()).unwrap_or(&[]);
    let active_practices = practices_slice
        .iter()
        .filter(|p| p.get("status").and_then(|s| s.as_str()) == Some("active"))
        .count();
    let urgent_deadlines = count_urgent_deadlines(practices_slice);
    Ok(json!({"activePractices": active_practices, "urgentDeadlines": urgent_deadlines}))
}

// ─── Index-only reads (v4 only — instant list rendering) ────

/// PERF: Returns only the vault index (titles, tags, timestamps) without
/// decrypting any record content. On v4 this is a single AES-GCM decrypt
/// of the index block (~5ms), vs decrypting all records (~400ms for 120 records).
/// On v2 fallback: returns full data (no index available).
#[tauri::command]
pub(crate) fn get_vault_index(state: State<AppState>) -> Result<Value, String> {
    let version = get_vault_version(&state);
    if version != 4 {
        // v2: no index — return full practices/agenda with minimal fields
        let vault = read_vault_internal(&state)?;
        return Ok(vault);
    }

    let dek = get_vault_dek(&state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = dir.join(VAULT_FILE);
    if !path.exists() {
        return Ok(json!([]));
    }
    let raw = fs::read(&path).map_err(|e| e.to_string())?;
    let vault = vault_v4::deserialize_vault(&raw)?;
    let index = vault_v4::decrypt_index(&dek, &vault.index)?;

    // Convert to JSON array
    let entries: Vec<Value> = index
        .iter()
        .map(|e| {
            json!({
                "id": e.id,
                "field": e.field,
                "title": e.title,
                "tags": e.tags,
                "updatedAt": e.updated_at,
            })
        })
        .collect();

    Ok(json!(entries))
}

/// PERF: Load a single record by ID (v4: decrypt only that record).
/// On v2 fallback: loads full vault and extracts the matching item.
#[tauri::command]
pub(crate) fn load_record_detail(
    state: State<AppState>,
    record_id: String,
) -> Result<Value, String> {
    let version = get_vault_version(&state);
    if version != 4 {
        // v2: load full vault and find by id
        let vault = read_vault_internal(&state)?;
        for field in &["practices", "agenda", "contacts", "timeLogs", "invoices"] {
            if let Some(arr) = vault.get(*field).and_then(|v| v.as_array()) {
                for item in arr {
                    let item_id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    let key = format!("{}_{}", field, item_id);
                    if key == record_id {
                        return Ok(item.clone());
                    }
                }
            }
        }
        return Err("Record non trovato".into());
    }

    // v4: decrypt single record
    let dek = get_vault_dek(&state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = dir.join(VAULT_FILE);
    let raw = fs::read(&path).map_err(|e| e.to_string())?;
    let vault = vault_v4::deserialize_vault(&raw)?;

    let entry = vault.records.get(&record_id).ok_or("Record non trovato")?;
    let plaintext = vault_v4::read_current_version(entry, &dek)?;
    serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) fn load_record_history(
    state: State<AppState>,
    record_id: String,
) -> Result<Value, String> {
    let dek = get_vault_dek(&state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let raw = fs::read(dir.join(VAULT_FILE)).map_err(|e| e.to_string())?;
    let vault = vault_v4::deserialize_vault(&raw)?;

    let entry = vault.records.get(&record_id).ok_or("Record non trovato")?;

    let mut history = Vec::new();
    for ver in &entry.versions {
        let block = vault_v4::EncryptedBlock {
            iv: ver.iv.clone(),
            tag: ver.tag.clone(),
            data: ver.data.clone(),
            compressed: ver.compressed,
        };
        if let Ok(plaintext) = vault_v4::decrypt_record(&dek, &block) {
            if let Ok(val) = serde_json::from_slice::<Value>(&plaintext) {
                history.push(json!({
                    "version": ver.v,
                    "timestamp": ver.ts,
                    "data": val,
                }));
            }
        }
    }
    Ok(json!(history))
}

// ─── Conflict Check ─────────────────────────────────────────

fn field_contains(obj: &Value, field: &str, query: &str) -> bool {
    obj.get(field)
        .and_then(|v| v.as_str())
        .map(|v| v.to_lowercase().contains(query))
        .unwrap_or(false)
}

fn match_practice_fields(p: &Value, query: &str) -> Vec<String> {
    let mut matched_fields: Vec<String> = Vec::new();
    for field in &["client", "counterparty", "description", "court", "object"] {
        if field_contains(p, field, query) {
            matched_fields.push(field.to_string());
        }
    }
    matched_fields
}

fn match_practice_roles(p: &Value, contacts: &[Value], query: &str) -> Vec<String> {
    let roles = match p.get("roles").and_then(|r| r.as_array()) {
        Some(r) => r,
        None => return Vec::new(),
    };
    let mut matched = Vec::new();
    for role in roles {
        let cid = match role.get("contactId").and_then(|c| c.as_str()) {
            Some(id) => id,
            None => continue,
        };
        let contact = contacts
            .iter()
            .find(|c| c.get("id").and_then(|i| i.as_str()) == Some(cid));
        if let Some(contact) = contact {
            if field_contains(contact, "name", query) {
                let role_label = role
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("contatto");
                matched.push(format!("ruolo:{}", role_label));
            }
        }
    }
    matched
}

fn contact_matches_query(c: &Value, query: &str) -> bool {
    ["name", "fiscalCode", "vatNumber", "email", "pec", "phone"]
        .iter()
        .any(|f| field_contains(c, f, query))
}

fn find_linked_practice_ids(practices: &[Value], cid: &str) -> Vec<String> {
    practices
        .iter()
        .filter_map(|p| {
            let client_id = p.get("clientId").and_then(|i| i.as_str()).unwrap_or("");
            let counter_id = p
                .get("counterpartyId")
                .and_then(|i| i.as_str())
                .unwrap_or("");
            let in_roles = p
                .get("roles")
                .and_then(|r| r.as_array())
                .map(|roles| {
                    roles
                        .iter()
                        .any(|r| r.get("contactId").and_then(|i| i.as_str()) == Some(cid))
                })
                .unwrap_or(false);
            if client_id == cid || counter_id == cid || in_roles {
                Some(
                    p.get("id")
                        .and_then(|i| i.as_str())
                        .unwrap_or("")
                        .to_string(),
                )
            } else {
                None
            }
        })
        .collect()
}

#[tauri::command]
pub(crate) fn check_conflict(state: State<AppState>, name: String) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Ok(json!({"practiceMatches": [], "contactMatches": []}));
    }
    let vault = read_vault_internal(&state)?;
    let practices_arr = vault.get("practices").and_then(|p| p.as_array());
    let practices = practices_arr.map(|a| a.as_slice()).unwrap_or(&[]);
    let contacts_arr = vault.get("contacts").and_then(|c| c.as_array());
    let contacts = contacts_arr.map(|a| a.as_slice()).unwrap_or(&[]);
    let query = name.trim().to_lowercase();

    let results: Vec<Value> = practices
        .iter()
        .filter_map(|p| {
            let mut matched_fields = match_practice_fields(p, &query);
            matched_fields.extend(match_practice_roles(p, contacts, &query));
            if matched_fields.is_empty() {
                None
            } else {
                Some(json!({"practice": p, "matchedFields": matched_fields}))
            }
        })
        .collect();

    let contact_matches: Vec<Value> = contacts
        .iter()
        .filter_map(|c| {
            if !contact_matches_query(c, &query) {
                return None;
            }
            let cid = c.get("id").and_then(|i| i.as_str()).unwrap_or("");
            Some(json!({"contact": c, "linkedPracticeIds": find_linked_practice_ids(practices, cid)}))
        })
        .collect();

    Ok(json!({"practiceMatches": results, "contactMatches": contact_matches}))
}

// ─── Recovery Key (v4) ──────────────────────────────────────

/// Generate a recovery key for the vault. Returns the display string to show ONCE.
#[tauri::command]
pub(crate) fn generate_recovery_key(state: State<AppState>) -> Result<Value, String> {
    let version = get_vault_version(&state);
    if version != 4 {
        return Err("Recovery key requires vault v4".into());
    }
    let dek = get_vault_dek(&state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = dir.join(VAULT_FILE);
    let raw = fs::read(&path).map_err(|e| e.to_string())?;
    let mut vault = vault_v4::deserialize_vault(&raw)?;

    let display_key = vault_v4::generate_recovery_key(&mut vault, &dek)?;

    // Recovery fields are NOT in header MAC scope — they're optional add-ons
    // protected by their own AES-GCM-SIV authentication (wrap_dek).
    let serialized = vault_v4::serialize_vault(&vault)?;
    crate::io::atomic_write_with_sync(&path, &serialized)?;
    invalidate_vault_cache(&state);

    Ok(json!({"recoveryKey": display_key}))
}

/// Unlock vault using recovery key (when password is forgotten).
#[tauri::command]
pub(crate) fn unlock_with_recovery(state: State<AppState>, recovery_key: String) -> Value {
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    // SECURITY FIX: apply rate limiting to recovery unlock too.
    // Recovery key is 128-bit random (brute-force infeasible), but defense-in-depth.
    if let Err(locked_json) = crate::lockout::check_lockout(&state, &sec_dir) {
        return locked_json;
    }

    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let vault_path = dir.join(VAULT_FILE);

    if !vault_path.exists() {
        return json!({"success": false, "error": "Nessun vault trovato"});
    }

    let raw = match crate::io::safe_bounded_read(&vault_path, 500 * 1024 * 1024) {
        Ok(r) => r,
        Err(e) => return json!({"success": false, "error": format!("Errore lettura: {}", e)}),
    };

    match vault_v4::open_vault_with_recovery(&recovery_key, &raw) {
        Ok((_vault, dek)) => {
            *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(SecureKey::new(Zeroizing::new(dek.to_vec())));
            *state
                .vault_version
                .write()
                .unwrap_or_else(|e| e.into_inner()) = 4;
            *state
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Instant::now();
            crate::lockout::clear_lockout(&state, &sec_dir);
            let _ = append_audit_log(&state, "Sblocco Vault via recovery key");
            json!({"success": true})
        }
        Err(e) => {
            crate::lockout::record_failed_attempt(&state, &sec_dir);
            json!({"success": false, "error": e})
        }
    }
}

// ─── Vault Health (v4) ──────────────────────────────────────

#[tauri::command]
pub(crate) fn get_vault_health(state: State<AppState>) -> Result<Value, String> {
    let version = get_vault_version(&state);
    if version != 4 {
        return Ok(json!({
            "version": version,
            "format": "v2-legacy",
        }));
    }
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = dir.join(VAULT_FILE);
    if !path.exists() {
        return Ok(json!({"version": 4, "error": "Vault file not found"}));
    }
    let raw = fs::read(&path).map_err(|e| e.to_string())?;
    let vault = vault_v4::deserialize_vault(&raw)?;

    let rotation_due = vault_v4::needs_rotation(&vault.rotation);

    Ok(json!({
        "version": 4,
        "format": "v4-envelope",
        "kdfAlg": vault.kdf.alg,
        "kdfMemory": vault.kdf.m,
        "kdfTime": vault.kdf.t,
        "kdfParallelism": vault.kdf.p,
        "dekCreated": vault.rotation.created,
        "dekWrites": vault.rotation.writes,
        "dekMaxWrites": vault.rotation.max_writes,
        "rotationDue": rotation_due,
        "totalRecords": vault.records.len(),
    }))
}
