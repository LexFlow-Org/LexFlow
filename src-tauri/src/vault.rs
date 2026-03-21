// ═══════════════════════════════════════════════════════════
//  VAULT — All vault CRUD, unlock/lock, password, search
//  Supports both v2 (legacy monolithic) and v4 (per-record)
// ═══════════════════════════════════════════════════════════

use crate::audit::append_audit_log;
use crate::constants::*;
use crate::crypto::{
    decrypt_data, derive_secure_key, encrypt_data, make_verify_tag, verify_hash_matches,
};
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
        .lock()
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
            .lock()
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
    *state.vault_cache.lock().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());

    Ok(result)
}

/// v4: read vault by decrypting index + all records, reassemble into monolithic JSON.
fn read_vault_v4(state: &State<AppState>) -> Result<Value, String> {
    let dek = get_vault_dek(state)?;
    let dir = state
        .data_dir
        .lock()
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
            *state.vault_cache.lock().unwrap_or_else(|e| e.into_inner()) = Some(data.clone());
        }
        return result;
    }
    // v2 legacy path
    let key = get_vault_key(state)?;
    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let plaintext = Zeroizing::new(serde_json::to_vec(data).map_err(|e| e.to_string())?);
    let encrypted = encrypt_data(&key, &plaintext)?;
    let result = atomic_write_with_sync(&dir.join(VAULT_FILE), &encrypted);
    if result.is_ok() {
        *state.vault_cache.lock().unwrap_or_else(|e| e.into_inner()) = Some(data.clone());
    }
    result
}

/// v4: write vault by encrypting individual records and updating the index.
fn write_vault_v4(state: &State<AppState>, data: &Value) -> Result<(), String> {
    let dek = get_vault_dek(state)?;
    let dir = state
        .data_dir
        .lock()
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

pub(crate) fn authenticate_vault_password(
    password: &str,
    dir: &std::path::Path,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let salt = fs::read(dir.join(VAULT_SALT_FILE)).map_err(|e| e.to_string())?;
    let key = derive_secure_key(password, &salt)?;
    let stored = fs::read(dir.join(VAULT_VERIFY_FILE)).unwrap_or_default();
    if !verify_hash_matches(&key, &stored) {
        return Err("Password errata".into());
    }
    Ok(key)
}

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

fn create_new_vault_salt(password: &str, salt_path: &std::path::Path) -> Result<Vec<u8>, Value> {
    validate_password_strength(password)?;
    let mut s = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut s);
    secure_write(salt_path, &s).map_err(
        |e| json!({"success": false, "error": format!("Errore scrittura vault: {}", e)}),
    )?;
    Ok(s)
}

fn init_new_vault(
    state: &State<AppState>,
    k: Zeroizing<Vec<u8>>,
    dir: &std::path::Path,
) -> Result<(), Value> {
    let tag = make_verify_tag(&k);
    secure_write(&dir.join(VAULT_VERIFY_FILE), &tag)
        .map_err(|e| json!({"success": false, "error": format!("Errore init vault: {}", e)}))?;
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(SecureKey::new(k));
    let _ = write_vault_internal(state, &json!({"practices":[], "agenda":[]}));
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
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = 4;

    Ok(())
}

// ─── Transactional swap (shared v2/v4) ──────────────────────

pub(crate) fn transactional_vault_swap(
    dir: &std::path::Path,
    staging_dir: &std::path::Path,
) -> Result<(), String> {
    let vault_path = dir.join(VAULT_FILE);
    let salt_path = dir.join(VAULT_SALT_FILE);
    let verify_path = dir.join(VAULT_VERIFY_FILE);

    for bak_name in &[".vault.bak", ".salt.bak", ".verify.bak"] {
        let bak_path = dir.join(bak_name);
        if bak_path.exists() {
            let _ = fs::remove_file(&bak_path);
        }
    }

    let _ = fs::rename(&vault_path, dir.join(".vault.bak"));
    let _ = fs::rename(&salt_path, dir.join(".salt.bak"));
    let _ = fs::rename(&verify_path, dir.join(".verify.bak"));

    if fs::rename(staging_dir.join(VAULT_FILE), &vault_path).is_err() {
        let _ = fs::rename(dir.join(".vault.bak"), &vault_path);
        let _ = fs::rename(dir.join(".salt.bak"), &salt_path);
        let _ = fs::rename(dir.join(".verify.bak"), &verify_path);
        return Err("Errore swap vault.lex. Rollback eseguito.".into());
    }

    if fs::rename(staging_dir.join(VAULT_SALT_FILE), &salt_path).is_err() {
        let _ = fs::rename(&vault_path, staging_dir.join(VAULT_FILE));
        let _ = fs::rename(dir.join(".vault.bak"), &vault_path);
        let _ = fs::rename(dir.join(".salt.bak"), &salt_path);
        let _ = fs::rename(dir.join(".verify.bak"), &verify_path);
        return Err("Errore swap vault.salt. Rollback eseguito.".into());
    }

    if fs::rename(staging_dir.join(VAULT_VERIFY_FILE), &verify_path).is_err() {
        let _ = fs::rename(&salt_path, staging_dir.join(VAULT_SALT_FILE));
        let _ = fs::rename(dir.join(".salt.bak"), &salt_path);
        let _ = fs::rename(&vault_path, staging_dir.join(VAULT_FILE));
        let _ = fs::rename(dir.join(".vault.bak"), &vault_path);
        let _ = fs::rename(dir.join(".verify.bak"), &verify_path);
        return Err("Errore swap vault.verify. Rollback eseguito.".into());
    }

    Ok(())
}

pub(crate) fn cleanup_vault_backups(dir: &std::path::Path) {
    for bak_name in &[".vault.bak", ".salt.bak", ".verify.bak"] {
        let bak_path = dir.join(bak_name);
        if !bak_path.exists() {
            continue;
        }
        if let Ok(meta) = bak_path.metadata() {
            let size = meta.len() as usize;
            if size > 0 {
                let _ = secure_write(&bak_path, &vec![0u8; size]);
            }
        }
        let _ = fs::remove_file(&bak_path);
    }
}

fn reencrypt_audit_log(dir: &std::path::Path, old_key: &[u8], new_key: &[u8]) {
    let audit_path = dir.join(AUDIT_LOG_FILE);
    if !audit_path.exists() {
        return;
    }
    if let Ok(enc) = fs::read(&audit_path) {
        if let Ok(dec) = decrypt_data(old_key, &enc) {
            if let Ok(re_enc) = encrypt_data(new_key, &dec) {
                let _ = atomic_write_with_sync(&audit_path, &re_enc);
            }
        }
    }
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
        .lock()
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

#[tauri::command]
pub(crate) fn unlock_vault(state: State<AppState>, password: String) -> Value {
    unlock_vault_inner(&state, password)
}

fn unlock_vault_inner(state: &State<AppState>, password: String) -> Value {
    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let sec_dir = state
        .security_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    if let Err(locked_json) = check_lockout(state, &sec_dir) {
        return locked_json;
    }

    let vault_path = dir.join(VAULT_FILE);
    let salt_path = dir.join(VAULT_SALT_FILE);

    // Detect if this is a new vault, existing v4, or existing v2
    let is_new = !vault_path.exists() && !salt_path.exists();

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
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = 4;

                    // Check if key rotation is needed
                    if vault_v4::needs_rotation(&vault.rotation) {
                        eprintln!("[LexFlow] Key rotation needed — will rotate on next save");
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

        if version == 2 {
            // v2 vault — authenticate with legacy method, then migrate to v4
            let v2_salt = match fs::read(dir.join(VAULT_SALT_FILE)) {
                Ok(s) => s,
                Err(e) => {
                    zeroize_password(password);
                    return json!({"success": false, "error": format!("Salt non trovato: {}", e)});
                }
            };

            // Verify password against v2 verify tag
            let v2_key = match derive_secure_key(&password, &v2_salt) {
                Ok(k) => k,
                Err(e) => {
                    zeroize_password(password);
                    return json!({"success": false, "error": e});
                }
            };
            let stored = fs::read(dir.join(VAULT_VERIFY_FILE)).unwrap_or_default();
            if !verify_hash_matches(&v2_key, &stored) {
                record_failed_attempt(state, &sec_dir);
                zeroize_password(password);
                return json!({"success": false, "error": "Password errata"});
            }

            // Backup v2 files before migration
            let backup_dir = dir.join(".v2_backup");
            let _ = fs::create_dir_all(&backup_dir);
            for f in &[VAULT_FILE, VAULT_SALT_FILE, VAULT_VERIFY_FILE] {
                let src = dir.join(f);
                if src.exists() {
                    let _ = fs::copy(&src, backup_dir.join(f));
                }
            }

            // Migrate v2 → v4
            eprintln!("[LexFlow] Migrating vault v2 → v4...");
            match vault_v4::migrate_v2_to_v4(&password, &raw, &v2_salt) {
                Ok((vault, dek)) => {
                    // Write v4 vault
                    match vault_v4::serialize_vault(&vault) {
                        Ok(serialized) => {
                            if let Err(e) = atomic_write_with_sync(&vault_path, &serialized) {
                                eprintln!(
                                    "[LexFlow] CRITICAL: v4 write failed: {}. V2 backup at {:?}",
                                    e, backup_dir
                                );
                                // Restore v2 backup
                                for f in &[VAULT_FILE, VAULT_SALT_FILE, VAULT_VERIFY_FILE] {
                                    let bak = backup_dir.join(f);
                                    if bak.exists() {
                                        let _ = fs::copy(&bak, dir.join(f));
                                    }
                                }
                                zeroize_password(password);
                                return json!({"success": false, "error": "Migrazione v4 fallita. Vault v2 ripristinato."});
                            }
                        }
                        Err(e) => {
                            zeroize_password(password);
                            return json!({"success": false, "error": format!("Serializzazione v4 fallita: {}", e)});
                        }
                    }

                    eprintln!(
                        "[LexFlow] ✓ Vault migrated to v4 successfully. V2 backup at {:?}",
                        backup_dir
                    );

                    *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(SecureKey::new(Zeroizing::new(dek.to_vec())));
                    *state
                        .vault_version
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = 4;

                    clear_lockout(state, &sec_dir);
                    *state
                        .last_activity
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Instant::now();
                    zeroize_password(password);
                    let _ = append_audit_log(state, "Vault migrato v2→v4");
                    return json!({"success": true, "isNew": false, "migrated": true});
                }
                Err(e) => {
                    eprintln!("[LexFlow] Migration failed: {}. Falling back to v2.", e);
                    // Restore v2 backup and unlock in v2 mode
                    for f in &[VAULT_FILE, VAULT_SALT_FILE, VAULT_VERIFY_FILE] {
                        let bak = backup_dir.join(f);
                        if bak.exists() {
                            let _ = fs::copy(&bak, dir.join(f));
                        }
                    }
                    // Fall through to v2 unlock below
                }
            }

            // v2 fallback unlock (migration failed or not attempted)
            *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(SecureKey::new(v2_key));
            *state
                .vault_version
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = 2;

            clear_lockout(state, &sec_dir);
            *state
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Instant::now();
            zeroize_password(password);
            let _ = append_audit_log(state, "Sblocco Vault v2 (migrazione v4 fallita)");
            return json!({"success": true, "isNew": false});
        }

        // Unknown format
        zeroize_password(password);
        return json!({"success": false, "error": "Formato vault non riconosciuto"});
    }

    // No vault.lex but salt exists — legacy v2 first-time init path
    let salt = match create_new_vault_salt(&password, &salt_path) {
        Ok(s) => s,
        Err(e) => {
            zeroize_password(password);
            return e;
        }
    };
    let k = match derive_secure_key(&password, &salt) {
        Ok(k) => k,
        Err(e) => {
            zeroize_password(password);
            return json!({"success": false, "error": e});
        }
    };
    if let Err(e) = init_new_vault(state, k, &dir) {
        zeroize_password(password);
        return e;
    }
    *state
        .vault_version
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = 2;

    clear_lockout(state, &sec_dir);
    *state
        .last_activity
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Instant::now();
    zeroize_password(password);
    let _ = append_audit_log(state, "Sblocco Vault");
    json!({"success": true, "isNew": true})
}

#[tauri::command]
pub(crate) fn lock_vault(state: State<AppState>) -> bool {
    // Zero both v2 key and v4 DEK + clear cache
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *state
        .vault_version
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = 0;
    // SECURITY: clear plaintext cache on lock
    *state.vault_cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
    true
}

#[tauri::command]
pub(crate) fn reset_vault(state: State<AppState>, password: String) -> Value {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let salt_path = dir.join(VAULT_SALT_FILE);
    let vault_path = dir.join(VAULT_FILE);
    if vault_path.exists() && !salt_path.exists() {
        // v4 vaults don't have a separate salt file — check v4 format
        if let Ok(data) = fs::read(&vault_path) {
            if !data.starts_with(vault_v4::VAULT_V4_MAGIC) {
                zeroize_password(password);
                return json!({"success": false, "error": "Possibile manomissione: vault.lex presente ma vault.salt mancante."});
            }
            // v4: verify password via open_vault_v4
            if vault_v4::open_vault_v4(&password, &data).is_err() {
                zeroize_password(password);
                return json!({"success": false, "error": "Password errata"});
            }
        }
    } else if salt_path.exists() && authenticate_vault_password(&password, &dir).is_err() {
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
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = 0;
    *state.vault_cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
    zeroize_password(password);
    json!({"success": true})
}

#[tauri::command]
pub(crate) fn change_password(
    state: State<AppState>,
    current_password: String,
    new_password: String,
) -> Result<Value, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let version = get_vault_version(&state);

    if version == 4 {
        // v4: re-wrap DEK with new KEK — O(1), no re-encryption needed!
        let result = change_password_v4(&state, &dir, &current_password, &new_password);
        zeroize_password(current_password);
        zeroize_password(new_password);
        return result;
    }

    // v2 legacy path: re-encrypt entire vault
    let current_key = match authenticate_vault_password(&current_password, &dir) {
        Ok(k) => k,
        Err(_) => {
            zeroize_password(current_password);
            zeroize_password(new_password);
            return Ok(json!({"success": false, "error": "Password attuale errata"}));
        }
    };

    let vault_path = dir.join(VAULT_FILE);
    let vault_data = if vault_path.exists() {
        let enc = fs::read(&vault_path).map_err(|e| e.to_string())?;
        let dec = decrypt_data(&current_key, &enc)?;
        serde_json::from_slice::<Value>(&dec).map_err(|e| e.to_string())?
    } else {
        json!({"practices":[], "agenda":[]})
    };

    let mut new_salt = vec![0u8; ARGON2_SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut new_salt);
    let new_key = derive_secure_key(&new_password, &new_salt)?;

    let vault_plaintext =
        Zeroizing::new(serde_json::to_vec(&vault_data).map_err(|e| e.to_string())?);
    let encrypted_vault = encrypt_data(&new_key, &vault_plaintext)?;
    let new_verify_tag = make_verify_tag(&new_key);

    let staging_dir = dir.join(".staging");
    let _ = fs::create_dir_all(&staging_dir);
    if atomic_write_with_sync(&staging_dir.join(VAULT_FILE), &encrypted_vault).is_err()
        || atomic_write_with_sync(&staging_dir.join(VAULT_SALT_FILE), &new_salt).is_err()
        || atomic_write_with_sync(&staging_dir.join(VAULT_VERIFY_FILE), &new_verify_tag).is_err()
    {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err("Errore critico. Cambio annullato.".into());
    }

    transactional_vault_swap(&dir, &staging_dir)?;
    cleanup_vault_backups(&dir);
    let _ = fs::remove_dir_all(&staging_dir);
    reencrypt_audit_log(&dir, &current_key, &new_key);

    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(SecureKey::new(Zeroizing::new(new_key.to_vec())));

    update_bio_password_if_needed(&state, &new_password);

    let _ = append_audit_log(&state, "Password cambiata");
    zeroize_password(current_password);
    zeroize_password(new_password);
    Ok(json!({"success": true}))
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
            .lock()
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
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let sec_dir = state
        .security_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Err(locked_json) = check_lockout(&state, &sec_dir) {
        return Ok(locked_json);
    }

    let version = get_vault_version(&state);
    let valid = if version == 4 {
        let vault_path = dir.join(VAULT_FILE);
        if let Ok(raw) = fs::read(&vault_path) {
            vault_v4::open_vault_v4(&pwd, &raw).is_ok()
        } else {
            false
        }
    } else {
        authenticate_vault_password(&pwd, &dir).is_ok()
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
    save_vault_field(&state, "practices", list)
}

#[tauri::command]
pub(crate) fn load_agenda(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "agenda")
}

#[tauri::command]
pub(crate) fn save_agenda(state: State<AppState>, agenda: Value) -> Result<bool, String> {
    save_vault_field(&state, "agenda", agenda)
}

#[tauri::command]
pub(crate) fn load_time_logs(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "timeLogs")
}

#[tauri::command]
pub(crate) fn save_time_logs(state: State<AppState>, logs: Value) -> Result<bool, String> {
    save_vault_field(&state, "timeLogs", logs)
}

#[tauri::command]
pub(crate) fn load_invoices(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "invoices")
}

#[tauri::command]
pub(crate) fn save_invoices(state: State<AppState>, invoices: Value) -> Result<bool, String> {
    save_vault_field(&state, "invoices", invoices)
}

#[tauri::command]
pub(crate) fn load_contacts(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "contacts")
}

#[tauri::command]
pub(crate) fn save_contacts(state: State<AppState>, contacts: Value) -> Result<bool, String> {
    save_vault_field(&state, "contacts", contacts)
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
        .lock()
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
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = dir.join(VAULT_FILE);
    let raw = fs::read(&path).map_err(|e| e.to_string())?;
    let vault = vault_v4::deserialize_vault(&raw)?;

    let entry = vault.records.get(&record_id).ok_or("Record non trovato")?;
    let plaintext = vault_v4::read_current_version(entry, &dek)?;
    serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
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
        .lock()
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
    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let vault_path = dir.join(VAULT_FILE);

    if !vault_path.exists() {
        return json!({"success": false, "error": "Nessun vault trovato"});
    }

    let raw = match fs::read(&vault_path) {
        Ok(r) => r,
        Err(e) => return json!({"success": false, "error": format!("Errore lettura: {}", e)}),
    };

    match vault_v4::open_vault_with_recovery(&recovery_key, &raw) {
        Ok((_vault, dek)) => {
            *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(SecureKey::new(Zeroizing::new(dek.to_vec())));
            *state
                .vault_version
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = 4;
            *state
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Instant::now();
            let _ = append_audit_log(&state, "Sblocco Vault via recovery key");
            json!({"success": true})
        }
        Err(e) => json!({"success": false, "error": e}),
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
        .lock()
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
