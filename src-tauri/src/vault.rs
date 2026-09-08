// ═══════════════════════════════════════════════════════════
//  VAULT — All vault CRUD, unlock/lock, password, search
//  Supports both v2 (legacy monolithic) and v4 (per-record)
// ═══════════════════════════════════════════════════════════

use crate::audit::{append_audit_log_locked, prepare_audit_key_rotation};
use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::atomic_write_with_sync;
use crate::lockout::{check_lockout, clear_lockout, record_failed_attempt_locked};
use crate::state::{
    get_vault_dek, get_vault_key, get_vault_version, invalidate_vault_cache, zeroize_password,
    AppState, SecureKey,
};
use crate::vault_engine;
use serde_json::{json, Value};
use std::fs;
use std::time::Instant;
use tauri::State;
use zeroize::Zeroizing;

// ─── Internal vault I/O (v2/v4 transparent) ─────────────────

/// Read full vault data as a JSON value.
/// PERF: returns cached data if available, avoiding re-decryption.
pub(crate) fn read_vault_internal(state: &AppState) -> Result<Value, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    read_vault_locked(state)
}

/// Caller must hold write_mutex for a consistent read/modify/write transaction.
pub(crate) fn read_vault_locked(state: &AppState) -> Result<Value, String> {
    // Authentication precedes cache access, including after an automatic lock.
    if get_vault_version(state) >= 4 {
        get_vault_dek(state)?;
    } else {
        get_vault_key(state)?;
    }
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
    let result = if version >= 4 {
        read_vault_engine(state)?
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
fn read_vault_engine(state: &AppState) -> Result<Value, String> {
    let dek = get_vault_dek(state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let vault = vault_engine::read_authenticated_snapshot(&dir, &dek)?;

    let index = vault_engine::decrypt_index(&dek, &vault.index)?;
    let mut result =
        json!({"practices":[], "agenda":[], "contacts":[], "timeLogs":[], "invoices":[]});
    for idx_entry in &index {
        let record_entry = vault.records.get(&idx_entry.id).ok_or_else(|| {
            format!(
                "Record mancante: {}. Salvataggio interrotto per preservare i dati.",
                idx_entry.id
            )
        })?;
        let plaintext = vault_engine::read_current_version(record_entry, &dek)?;
        let value = decode_indexed_record(&plaintext, idx_entry)?;
        let array = result
            .get_mut(&idx_entry.field)
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "Categoria del record non riconosciuta; dati conservati.".to_string())?;
        array.push(value);
    }
    Ok(result)
}

fn decode_indexed_record(
    plaintext: &[u8],
    index: &vault_engine::IndexEntry,
) -> Result<Value, String> {
    let value = vault_engine::decode_record_object(plaintext)?;
    let id = value
        .as_object()
        .and_then(|record| record.get("id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or("Struttura del record non valida; dati conservati.")?;
    if format!("{}_{}", index.field, id) != index.id {
        return Err("Identificativo del record non coerente con l'indice; dati conservati.".into());
    }
    Ok(value)
}

#[cfg(test)]
mod record_format_tests {
    use super::*;

    #[test]
    fn indexed_legacy_json_uses_fallback_and_keeps_identity_check() {
        let index = vault_engine::IndexEntry {
            id: "practices_synthetic-1".into(),
            field: "practices".into(),
            title: String::new(),
            tags: vec![],
            updated_at: String::new(),
            summary: None,
        };
        let record = json!({"id":"synthetic-1", "client":"Cliente sintetico"});
        for encoded in [
            serde_json::to_vec(&record).unwrap(),
            rmp_serde::to_vec_named(&record).unwrap(),
        ] {
            assert_eq!(decode_indexed_record(&encoded, &index).unwrap(), record);
        }
        let wrong_id = serde_json::to_vec(&json!({"id":"different"})).unwrap();
        assert!(decode_indexed_record(&wrong_id, &index).is_err());
    }
}

/// Write full vault data.
/// In v4: diffs against existing records, encrypts only changed ones.
/// In v2: encrypts the monolithic blob as before.
/// PERF: invalidates cache after successful write.
pub(crate) fn write_vault_internal(state: &AppState, data: &Value) -> Result<(), String> {
    // PERF: invalidate cache before write (so concurrent reads don't get stale data)
    invalidate_vault_cache(state);

    let version = get_vault_version(state);
    if version >= 4 {
        let result = write_vault_engine(state, data);
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
fn write_vault_engine(state: &AppState, data: &Value) -> Result<(), String> {
    let dek = get_vault_dek(state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut vault = vault_engine::read_authenticated_snapshot(&dir, &dek)?;

    update_vault_records(&mut vault, &dek, data)?;

    vault_engine::write_canonical_vault(&dir, &mut vault, &dek)
}

/// Build the complete encrypted snapshot in memory before touching disk.
/// Shared by normal saves and import so a failed import preserves the old vault.
pub(crate) fn update_vault_records(
    vault: &mut vault_engine::VaultData,
    dek: &[u8],
    data: &Value,
) -> Result<(), String> {
    let fields = ["practices", "agenda", "contacts", "timeLogs", "invoices"];
    if !data.is_object() {
        return Err("Il database deve essere un oggetto; dati conservati.".into());
    }
    let next_write_count = vault
        .rotation
        .writes
        .checked_add(1)
        .ok_or("Contatore scritture esaurito; dati conservati.")?;
    // Validate every domain before mutating the in-memory snapshot. A corrupt
    // old record in another domain must never disappear on the next save.
    let mut ids = std::collections::HashSet::new();
    for field in fields {
        if let Some(value) = data.get(field) {
            let items = value
                .as_array()
                .ok_or("Categoria del database non valida; dati conservati.")?;
            for item in items {
                let id = item
                    .as_object()
                    .and_then(|record| record.get("id"))
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .ok_or("Identificativo del record non valido; dati conservati.")?;
                if !ids.insert(format!("{}_{}", field, id)) {
                    return Err("Identificativo del record duplicato; dati conservati.".into());
                }
            }
        }
    }
    let mut new_index: Vec<vault_engine::IndexEntry> = Vec::new();
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
                let record_key = format!("{}_{}", field, id);
                // V7: serialize with MessagePack (30-40% smaller than JSON).
                // Wrap in Zeroizing so the plaintext bytes are scrubbed on drop
                // (BE-5-L-5 / audit:BE-5-L-5).
                let item_bytes =
                    Zeroizing::new(rmp_serde::to_vec(item).map_err(|e| e.to_string())?);

                // Check if record exists and data changed
                let mut entry = if let Some(existing) = vault.records.remove(&record_key) {
                    // Check if content changed by comparing plaintext.
                    // `read_current_version` now returns Zeroizing<Vec<u8>> — compare
                    // via the deref'd slice (Zeroizing has no direct PartialEq with Vec).
                    if let Ok(old_plain) = vault_engine::read_current_version(&existing, dek) {
                        if old_plain.as_slice() == item_bytes.as_slice() {
                            // Unchanged — keep existing entry
                            new_records.insert(record_key.clone(), existing);
                            let title = vault_engine::extract_record_title_pub(item, field);
                            let tags = vault_engine::extract_record_tags_pub(item, field);
                            new_index.push(vault_engine::IndexEntry {
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
                                summary: vault_engine::extract_record_summary(item, field),
                            });
                            continue;
                        }
                    }
                    existing
                } else {
                    vault_engine::RecordEntry {
                        versions: vec![],
                        current: 0,
                    }
                };

                // Encrypt and append new version
                vault_engine::append_record_version(&mut entry, dek, &item_bytes)?;
                new_records.insert(record_key.clone(), entry);

                let title = vault_engine::extract_record_title_pub(item, field);
                let tags = vault_engine::extract_record_tags_pub(item, field);
                new_index.push(vault_engine::IndexEntry {
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
                    summary: vault_engine::extract_record_summary(item, field),
                });
            }
        }
    }

    vault.records = new_records;
    vault.index = vault_engine::encrypt_index(dek, &new_index)?;
    vault.rotation.writes = next_write_count;
    if vault.version >= 8 {
        vault_engine::seal_snapshot_manifest(vault, dek)?;
    }

    Ok(())
}

// ─── Password validation ────────────────────────────────────

/// Validate password/hash strength.
/// Since v2.7.0 the frontend pre-hashes passwords with SHA-256 before sending.
/// The backend receives a 64-char hex hash, so we only validate it's a valid hash.
/// The actual password strength check (12+ chars, upper, lower, digit, symbol)
/// is done in the frontend BEFORE hashing.
fn validate_password_strength(password: &str) -> Result<(), Value> {
    // Accept SHA-256 hex hashes (64 lowercase hex chars) from frontend pre-hash
    if password.len() == 64 && password.chars().all(|c| c.is_ascii_hexdigit()) {
        // FIX-4 (audit:M-2): Defense-in-depth: blacklist obviously-weak SHA-256
        // prehashes; FE strength meter is advisory, BE enforces a minimal floor.
        // The list contains common-password SHA-256 hashes (lowercase hex of the
        // raw UTF-8 bytes of the password); reject if matches.
        let normalized = password.to_ascii_lowercase();
        // Reject all-zero hash (degenerate/test input).
        if normalized == "0".repeat(64) {
            return Err(
                json!({"success": false, "error": "Password troppo debole. Scegline una più sicura."}),
            );
        }
        const WEAK_HASHES: &[&str] = &[
            // sha256("password")
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            // sha256("123456")
            "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
            // sha256("admin")
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
            // sha256("test")
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            // sha256("12345678")
            "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f",
            // sha256("qwerty")
            "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5",
            // sha256("password123")
            "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
            // sha256("letmein")
            "1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032",
            // sha256("abc123")
            "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
            // sha256("111111")
            "bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a",
        ];
        if WEAK_HASHES.iter().any(|h| *h == normalized) {
            return Err(
                json!({"success": false, "error": "Password tra le più comuni e insicure. Scegline una diversa."}),
            );
        }
        return Ok(()); // Frontend validated strength before hashing
    }
    // Fallback: validate raw password (CLI, tests, direct calls)
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
fn init_new_vault_engine(
    state: &AppState,
    password: &str,
    dir: &std::path::Path,
) -> Result<(), Value> {
    validate_password_strength(password)?;

    let (mut vault, dek) = vault_engine::create_vault(password).map_err(
        |_e| json!({"success": false, "error": format!("Impossibile creare il database sicuro. Riprova o contatta il supporto.")}),
    )?;

    // FIX-11 (audit:L-8): store DEK in state BEFORE the disk write, so an
    // intermediate write failure doesn't leave a process holding a DEK
    // bound to no on-disk vault. If the write fails, roll back state.
    *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(SecureKey::new(Zeroizing::new(dek.to_vec())));
    *state
        .vault_version
        .write()
        .unwrap_or_else(|e| e.into_inner()) = vault_engine::CURRENT_VAULT_VERSION;

    if let Err(_e) = vault_engine::write_canonical_vault(dir, &mut vault, &dek) {
        // Roll back state to avoid a "DEK in memory, no disk vault" mismatch.
        *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *state
            .vault_version
            .write()
            .unwrap_or_else(|e| e.into_inner()) = 0;
        return Err(
            json!({"success": false, "error": format!("Impossibile salvare il database. Verifica lo spazio su disco.")}),
        );
    }

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

fn load_vault_field(state: &AppState, field: &str) -> Result<Value, String> {
    let vault = read_vault_internal(state)?;
    Ok(vault.get(field).cloned().unwrap_or(json!([])))
}

fn save_vault_field(state: &AppState, field: &str, data: Value) -> Result<bool, String> {
    validate_vault_array(&data, field)?;
    let count = data.as_array().map_or(0, Vec::len);
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let mut vault = read_vault_locked(state)?;
    vault[field] = data;
    write_vault_internal(state, &vault)?;
    let event = match field {
        "practices" => format!("Salvati {} fascicoli", count),
        "contacts" => format!("Salvati {} contatti", count),
        "agenda" => "Aggiornata agenda".into(),
        "timeLogs" => "Aggiornate ore lavorate".into(),
        "invoices" => "Aggiornate fatture".into(),
        _ => "Database aggiornato".into(),
    };
    if append_audit_log_locked(state, &event).is_err() {
        // Data is already committed. Report a diagnostic without falsely
        // presenting a failed save or attaching the event to a new session.
        eprintln!("[audit] Vault saved; audit event could not be recorded.");
    }
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
    // Existence is not a bounded full-file read: valid vaults exceed 10 bytes.
    if dir.join(VAULT_FILE).is_file() {
        return true;
    }
    // V6 split migration: vault.lex renamed to .v4-backup — check split vault
    if vault_engine::is_split_vault(&dir) {
        return true;
    }
    if dir.join("vault.lex.v4-backup").exists() {
        return true;
    }
    dir.join(VAULT_SALT_FILE).exists()
}

/// Internal unlock used by both the Tauri command and bio_unlock_vault.
/// Takes password by value to allow zeroization.
#[allow(dead_code)] // Used by bio.rs on desktop; unused on Android where bio path differs
pub(crate) fn unlock_vault_with_password(state: &AppState, password: String) -> Value {
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

fn unlock_vault_inner(state: &AppState, password: String) -> Value {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    invalidate_vault_cache(state);
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
        zeroize_password(password);
        return locked_json;
    }

    let vault_path = dir.join(VAULT_FILE);
    let backup_path = dir.join("vault.lex.v4-backup");

    // After V6 split migration vault.lex is renamed to .v4-backup.
    // Use the backup as unlock source when vault.lex is gone.
    let unlock_path = if vault_path.exists() {
        vault_path.clone()
    } else if backup_path.exists() {
        backup_path.clone()
    } else {
        vault_path.clone() // neither exists → is_new
    };

    let is_new = !unlock_path.exists() && !vault_engine::is_split_vault(&dir);

    if is_new {
        // Create new vault in v4 format
        match init_new_vault_engine(state, &password, &dir) {
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
        let _ = append_audit_log_locked(state, "Nuovo Vault v4 creato");
        return json!({"success": true, "isNew": true});
    }

    // Existing vault — detect version
    if unlock_path.exists() {
        let raw = match crate::io::safe_bounded_read(&unlock_path, 500 * 1024 * 1024) {
            Ok(r) => r,
            Err(_e) => {
                zeroize_password(password);
                return json!({"success": false, "error": format!("Impossibile leggere il database. Il file potrebbe essere danneggiato.")});
            }
        };

        let version = vault_engine::detect_vault_version(&raw);

        if version >= 4 {
            // Open v4 vault directly
            match vault_engine::open_current_vault(&dir, &password) {
                Ok((mut vault, dek)) => {
                    if let Err(error) = enforce_vault_watermark(&sec_dir, vault.rotation.writes) {
                        eprintln!("[SECURITY] Vault unlock refused: {error}");
                        let _ =
                            append_audit_log_locked(state, &format!("Sblocco rifiutato: {error}"));
                        zeroize_password(password);
                        return json!({"success": false, "error": error});
                    }

                    *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(SecureKey::new(Zeroizing::new(dek.to_vec())));
                    *state
                        .vault_version
                        .write()
                        .unwrap_or_else(|e| e.into_inner()) = vault_engine::CURRENT_VAULT_VERSION;

                    // Commit the verified latest data before switching storage layouts.
                    // Legacy split files remain untouched for explicit recovery.
                    if !vault_engine::has_canonical_vault(&dir) {
                        if let Err(e) =
                            vault_engine::upgrade_canonical_header(&mut vault, &password)
                        {
                            *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) = None;
                            *state
                                .vault_version
                                .write()
                                .unwrap_or_else(|e| e.into_inner()) = 0;
                            zeroize_password(password);
                            return json!({"success": false, "error": e});
                        }
                        if let Err(e) = vault_engine::write_canonical_vault(&dir, &mut vault, &dek)
                        {
                            *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) = None;
                            *state
                                .vault_version
                                .write()
                                .unwrap_or_else(|e| e.into_inner()) = 0;
                            zeroize_password(password);
                            return json!({"success": false, "error": e});
                        }
                    }

                    // Perform key rotation if needed (>90 days or >10k writes)
                    if vault_engine::needs_rotation(&vault.rotation) {
                        eprintln!(
                            "[LexFlow] Key rotation triggered — re-encrypting all records..."
                        );
                        let kek = match vault_engine::derive_kek(&password, &vault.kdf) {
                            Ok(k) => k,
                            Err(e) => {
                                eprintln!("[LexFlow] KEK re-derive for rotation failed: {}", e);
                                // Non-fatal: skip rotation, vault is still usable
                                Zeroizing::new(vec![])
                            }
                        };
                        if !kek.is_empty() {
                            match vault_engine::rotate_dek(&mut vault, &kek) {
                                Ok(new_dek) => {
                                    // Persist audit-key access under both DEKs before
                                    // committing the replacement vault. A crash on
                                    // either side of the commit preserves its audit.
                                    let audit_ready =
                                        prepare_audit_key_rotation(&dir, &dek, &new_dek);
                                    if let Err(error) = &audit_ready {
                                        eprintln!("[LexFlow] Key rotation deferred: audit preparation failed: {error}");
                                    }
                                    if audit_ready.is_ok()
                                        && vault_engine::write_canonical_vault(
                                            &dir, &mut vault, &new_dek,
                                        )
                                        .is_ok()
                                    {
                                        // Update DEK in state
                                        *state
                                            .vault_dek
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner()) =
                                            Some(SecureKey::new(new_dek));
                                        let _ = append_audit_log_locked(
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
                    let _ = append_audit_log_locked(state, "Sblocco Vault v4");
                    return json!({"success": true, "isNew": false});
                }
                Err(e) => {
                    record_failed_attempt_locked(state, &sec_dir);
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
    json!({"success": false, "error": "Nessun database trovato."})
}

/// Password and recovery unlock enforce the same local high-water mark.
/// This detects ordinary older snapshots; it does not provide trusted hardware
/// rollback prevention against an attacker who controls all local files.
fn enforce_vault_watermark(
    security_directory: &std::path::Path,
    writes: u64,
) -> Result<(), String> {
    let counter_path = security_directory.join(".vault-writes-counter");
    let stored = match fs::symlink_metadata(&counter_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err("Impossibile verificare il contatore locale del database.".into()),
        Ok(_) => {
            let bytes = crate::io::safe_bounded_read(&counter_path, 64)
                .map_err(|_| "Impossibile leggere il contatore locale del database.")?;
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
                .ok_or("Contatore locale del database non valido. I dati sono conservati.")?
        }
    };
    if writes < stored {
        return Err("Possibile rollback del database rilevato (contatore scritture regredito). Per sicurezza lo sblocco è stato rifiutato. Contatta il supporto.".into());
    }
    if writes > stored {
        atomic_write_with_sync(&counter_path, writes.to_string().as_bytes()).map_err(|_| {
            "Impossibile aggiornare il contatore locale. Controlla i permessi e riprova lo sblocco."
        })?;
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn lock_vault(state: State<AppState>) -> bool {
    state.lock_vault();
    true
}

#[tauri::command]
pub(crate) fn reset_vault(state: State<AppState>, password: String) -> Value {
    reset_vault_inner(&state, password)
}

fn reset_vault_inner(state: &AppState, password: String) -> Value {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Err(locked_json) = check_lockout(state, &sec_dir) {
        zeroize_password(password);
        return locked_json;
    }
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let vault_path = dir.join(VAULT_FILE);
    let has_vault = vault_path.exists()
        || dir.join("vault.lex.v4-backup").exists()
        || vault_engine::is_split_vault(&dir);
    if has_vault && vault_engine::open_current_vault(&dir, &password).is_err() {
        record_failed_attempt_locked(state, &sec_dir);
        zeroize_password(password);
        return json!({"success": false, "error": "Password non corretta o database non verificabile. I dati sono conservati."});
    }
    // else: no recognizable vault on disk → empty state, allow reset without auth.
    zeroize_password(password);
    // Even a partial filesystem failure must not leave a session caching data
    // whose on-disk archive may have already been removed.
    state.lock_vault_locked();
    match remove_vault_storage_for_reset(&dir, &sec_dir) {
        Ok(()) => {
            clear_lockout(state, &sec_dir);
            json!({"success": true})
        }
        Err(error) => json!({"success": false, "error": error}),
    }
}

/// Called only after authorizing reset. The security directory is retained:
/// licenses and unrelated security state are never part of the deletion.
fn remove_vault_storage_for_reset(
    directory: &std::path::Path,
    security_directory: &std::path::Path,
) -> Result<(), String> {
    if security_directory.starts_with(directory) {
        return Err("Percorsi del database non validi. Ripristino annullato.".into());
    }
    match fs::symlink_metadata(directory) {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err("La cartella del database non è valida. I dati sono conservati.".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(
                "Impossibile verificare la cartella del database. Ripristino annullato.".into(),
            )
        }
    }

    // Reset this archive's watermark BEFORE deletion. A failed metadata write
    // leaves the archive intact; an interruption after deletion cannot cause
    // the newly created archive (writes = 0) to be mistaken for a rollback.
    let counter_path = security_directory.join(".vault-writes-counter");
    let previous_counter = match fs::symlink_metadata(&counter_path) {
        Ok(_) => Some(
            crate::io::safe_bounded_read(&counter_path, 64).map_err(|_| {
                "Impossibile leggere il contatore del database. I dati sono conservati.".to_string()
            })?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => {
            return Err(
                "Impossibile leggere il contatore del database. I dati sono conservati.".into(),
            )
        }
    };
    atomic_write_with_sync(&counter_path, b"0").map_err(|_| {
        "Impossibile azzerare il contatore del database. I dati sono conservati.".to_string()
    })?;

    if let Err(error) = fs::remove_dir_all(directory) {
        if error.kind() != std::io::ErrorKind::NotFound {
            // Restore rollback protection if deletion did not complete. The
            // error is explicit because some files may already be removed.
            let restored = match previous_counter {
                Some(bytes) => atomic_write_with_sync(&counter_path, &bytes),
                None => fs::remove_file(&counter_path).map_err(|error| error.to_string()),
            };
            if restored.is_err() {
                eprintln!(
                    "[SECURITY] Reset incomplete; previous write counter could not be restored."
                );
            }
            return Err("Eliminazione del database incompleta. Controlla i permessi e riprova il ripristino; alcuni file potrebbero essere già stati rimossi.".into());
        }
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory).map_err(|_| "Database eliminato, ma impossibile ricreare la cartella. Controlla i permessi prima di creare un nuovo archivio.".to_string())?;
    Ok(())
}

#[tauri::command]
pub(crate) fn change_password(
    state: State<AppState>,
    current_password: String,
    new_password: String,
) -> Result<Value, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
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

    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    if let Err(error) = validate_password_strength(&new_password) {
        zeroize_password(current_password);
        zeroize_password(new_password);
        return Ok(error);
    }
    let result = change_password_v4(&state, &dir, &current_password, &new_password);

    // Record failed attempt if password was wrong
    if result.is_err() {
        record_failed_attempt_locked(&state, &sec_dir);
    }
    if let Ok(ref val) = result {
        if val
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            clear_lockout(&state, &sec_dir);
        } else {
            record_failed_attempt_locked(&state, &sec_dir);
        }
    }

    zeroize_password(current_password);
    zeroize_password(new_password);
    result
}

/// Password rewrap commits the full snapshot once without changing record keys.
fn change_password_v4(
    state: &AppState,
    dir: &std::path::Path,
    current_password: &str,
    new_password: &str,
) -> Result<Value, String> {
    get_vault_dek(state)?;
    vault_engine::change_password_snapshot(dir, current_password, new_password)?;
    update_bio_password_if_needed(state, new_password);
    let _ = append_audit_log_locked(state, "Password cambiata");
    Ok(json!({"success": true}))
}

/// Update biometric keychain entry if biometric is enabled.
#[allow(unused_variables)]
fn update_bio_password_if_needed(state: &AppState, new_password: &str) {
    #[cfg(target_os = "windows")]
    {
        let directory = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // Never recreate the removed Windows credential, even if an old marker
        // survives. The password change itself has already committed safely.
        if let Err(error) = crate::bio::remove_legacy_windows_bio(&directory) {
            eprintln!("[LexFlow] {error}");
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    {
        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if dir.join(BIO_MARKER_FILE).exists() {
            let user = whoami::username();
            if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
                #[cfg(target_os = "macos")]
                let update = crate::bio::refresh_macos_bio_password(new_password);
                #[cfg(not(target_os = "macos"))]
                let update = entry.set_password(new_password).map_err(|e| e.to_string());
                if update.is_err() {
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

/// FIX-8 (audit:M-7): independent rate-limit window for verify_vault_password.
/// Caps to 5 calls / 60s per process. Distinct from the unlock_vault lockout
/// (which is shared with the legitimate unlock path) so an attacker cannot
/// trigger global lockout via this post-unlock command.
fn check_verify_rate_limit() -> Result<(), Value> {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    static VERIFY_WINDOW: OnceLock<Mutex<(Vec<Instant>, ())>> = OnceLock::new();
    let m = VERIFY_WINDOW.get_or_init(|| Mutex::new((Vec::new(), ())));
    let mut guard = m.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let window = Duration::from_secs(60);
    // Drop entries older than the window.
    guard.0.retain(|t| now.duration_since(*t) < window);
    if guard.0.len() >= 5 {
        return Err(json!({
            "valid": false,
            "error": "Troppe verifiche password ravvicinate. Attendi qualche istante e riprova."
        }));
    }
    guard.0.push(now);
    Ok(())
}

#[tauri::command]
pub(crate) fn verify_vault_password(state: State<AppState>, pwd: String) -> Result<Value, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    // FIX-8 (audit:M-7): rate-limit independently of unlock_vault lockout.
    if let Err(rl_json) = check_verify_rate_limit() {
        zeroize_password(pwd);
        return Ok(rl_json);
    }

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
        zeroize_password(pwd);
        return Ok(locked_json);
    }

    let valid = vault_engine::open_current_vault(&dir, &pwd).is_ok();

    if !valid {
        record_failed_attempt_locked(&state, &sec_dir);
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
    save_vault_field(&state, "practices", list)
}

#[tauri::command]
pub(crate) fn load_agenda(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "agenda")
}

#[tauri::command]
pub(crate) fn save_agenda(state: State<AppState>, agenda: Value) -> Result<bool, String> {
    crate::validation::validate_agenda(&agenda)?;
    save_vault_field(&state, "agenda", agenda)
}

#[tauri::command]
pub(crate) fn load_time_logs(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "timeLogs")
}

#[tauri::command]
pub(crate) fn save_time_logs(state: State<AppState>, logs: Value) -> Result<bool, String> {
    crate::validation::validate_time_logs(&logs)?;
    save_vault_field(&state, "timeLogs", logs)
}

#[tauri::command]
pub(crate) fn load_invoices(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "invoices")
}

#[tauri::command]
pub(crate) fn save_invoices(state: State<AppState>, invoices: Value) -> Result<bool, String> {
    crate::validation::validate_invoices(&invoices)?;
    save_vault_field(&state, "invoices", invoices)
}

#[tauri::command]
pub(crate) fn load_contacts(state: State<AppState>) -> Result<Value, String> {
    load_vault_field(&state, "contacts")
}

#[tauri::command]
pub(crate) fn save_contacts(state: State<AppState>, contacts: Value) -> Result<bool, String> {
    crate::validation::validate_contacts(&contacts)?;
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
    if version < 4 {
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

    let vault = vault_engine::read_authenticated_snapshot(&dir, &dek)?;
    let index = vault_engine::decrypt_index(&dek, &vault.index)?;

    // Convert to JSON array with summary for lazy list rendering
    let entries: Vec<Value> = index
        .iter()
        .map(|e| {
            let mut entry = json!({
                "id": e.id,
                "field": e.field,
                "title": e.title,
                "tags": e.tags,
                "updatedAt": e.updated_at,
            });
            // V5: include summary if available (for lazy list rendering)
            if let Some(ref summary) = e.summary {
                entry["summary"] = summary.clone();
            }
            entry
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
    if version < 4 {
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
    let vault = vault_engine::read_authenticated_snapshot(&dir, &dek)?;

    let entry = vault.records.get(&record_id).ok_or("Record non trovato")?;
    let plaintext = vault_engine::read_current_version(entry, &dek)?;
    // V7: records are serialized with MessagePack; fall back to JSON for older
    // ones that may still exist.
    vault_engine::decode_record_object(&plaintext)
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
    let vault = vault_engine::read_authenticated_snapshot(&dir, &dek)?;

    let entry = vault.records.get(&record_id).ok_or("Record non trovato")?;

    let mut history = Vec::new();
    for ver in &entry.versions {
        let block = vault_engine::EncryptedBlock {
            iv: ver.iv.clone(),
            tag: ver.tag.clone(),
            data: ver.data.clone(),
            compressed: ver.compressed,
        };
        if let Ok(plaintext) = vault_engine::decrypt_record(&dek, &block) {
            if let Ok(val) = vault_engine::decode_record_object(&plaintext) {
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
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let version = get_vault_version(&state);
    if version < 4 {
        return Err("Recovery key requires modern vault format".into());
    }
    let dek = get_vault_dek(&state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = dir.join(VAULT_FILE);
    let raw = crate::io::safe_bounded_read(&path, 500 * 1024 * 1024)?;
    let mut vault = vault_engine::deserialize_authenticated_vault(&raw, &dek)?;

    let display_key = vault_engine::generate_recovery_key(&mut vault, &dek)?;

    // Recovery fields are NOT in header MAC scope — they're optional add-ons
    // protected by their own AES-GCM-SIV authentication (wrap_dek).
    vault_engine::write_canonical_vault(&dir, &mut vault, &dek)?;
    invalidate_vault_cache(&state);

    Ok(json!({"recoveryKey": display_key}))
}

/// Unlock vault using recovery key (when password is forgotten).
#[tauri::command]
pub(crate) fn unlock_with_recovery(state: State<AppState>, recovery_key: String) -> Value {
    unlock_with_recovery_inner(&state, recovery_key)
}

fn unlock_with_recovery_inner(state: &AppState, recovery_key: String) -> Value {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let recovery_key = Zeroizing::new(recovery_key);
    invalidate_vault_cache(state);
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    // SECURITY FIX: apply rate limiting to recovery unlock too.
    // Recovery key is 128-bit random (brute-force infeasible), but defense-in-depth.
    if let Err(locked_json) = crate::lockout::check_lockout(state, &sec_dir) {
        return locked_json;
    }

    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let vault_path = dir.join(VAULT_FILE);

    if !vault_path.exists() {
        return json!({"success": false, "error": "Nessun database trovato."});
    }

    let raw = match crate::io::safe_bounded_read(&vault_path, 500 * 1024 * 1024) {
        Ok(r) => r,
        Err(_e) => {
            return json!({"success": false, "error": format!("Impossibile leggere i dati. Riprova.")})
        }
    };

    match vault_engine::open_vault_with_recovery(&recovery_key, &raw) {
        Ok((vault, dek)) => {
            if let Err(error) = enforce_vault_watermark(&sec_dir, vault.rotation.writes) {
                return json!({"success": false, "error": error});
            }
            *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(SecureKey::new(Zeroizing::new(dek.to_vec())));
            *state
                .vault_version
                .write()
                .unwrap_or_else(|e| e.into_inner()) = vault_engine::CURRENT_VAULT_VERSION;
            *state
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Instant::now();
            crate::lockout::clear_lockout(state, &sec_dir);
            let _ = append_audit_log_locked(state, "Sblocco Vault via recovery key");
            json!({"success": true})
        }
        Err(e) => {
            crate::lockout::record_failed_attempt_locked(state, &sec_dir);
            json!({"success": false, "error": e})
        }
    }
}

// ─── Vault Health (v4) ──────────────────────────────────────

#[tauri::command]
pub(crate) fn get_vault_health(state: State<AppState>) -> Result<Value, String> {
    let version = get_vault_version(&state);
    if version < 4 {
        return Ok(json!({
            "version": version,
            "format": "v2-legacy",
        }));
    }
    let dek = get_vault_dek(&state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = dir.join(VAULT_FILE);
    if !path.exists() {
        return Ok(
            json!({"version": version, "error": "Nessun database trovato. Crea un nuovo vault."}),
        );
    }
    let raw = crate::io::safe_bounded_read(&path, 500 * 1024 * 1024)?;
    let vault = vault_engine::deserialize_authenticated_vault(&raw, &dek)?;

    let rotation_due = vault_engine::needs_rotation(&vault.rotation);

    Ok(json!({
        "version": vault.version,
        "format": "v8-atomic-envelope",
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

#[cfg(test)]
mod atomic_snapshot_tests {
    use super::*;
    use crate::vault_engine::*;

    fn data(title: &str) -> Value {
        json!({"practices": [{"id": "synthetic-1", "client": title}], "agenda": []})
    }

    fn make_legacy(vault: &mut VaultData, password: &str) {
        vault.version = 7;
        let kek = derive_kek(password, &vault.kdf).unwrap();
        vault.header_mac = compute_header_mac(&kek, vault);
    }

    fn assert_title(vault: &VaultData, dek: &[u8], title: &str) {
        let bytes = read_current_version(&vault.records["practices_synthetic-1"], dek).unwrap();
        let value: Value = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(value["client"], title);
    }

    #[test]
    fn reset_then_create_lock_and_unlock_does_not_reject_new_vault_as_rollback() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("vault");
        let security = temp.path().join("security");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(&security).unwrap();
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        let _ = crate::platform::MACHINE_ID_CACHE.set("synthetic-reset-machine".into());
        crate::lockout::lockout_clear(&security);
        fs::write(security.join(LICENSE_FILE), b"synthetic license preserved").unwrap();
        let state = AppState::new(directory.clone(), security.clone());
        let password = "SyntheticOldPassword_123!";
        assert_eq!(unlock_vault_inner(&state, password.into())["success"], true);
        save_vault_field(
            &state,
            "practices",
            data("Before reset")["practices"].clone(),
        )
        .unwrap();
        state.lock_vault();
        assert_eq!(unlock_vault_inner(&state, password.into())["success"], true);
        let watermark = fs::read_to_string(security.join(".vault-writes-counter")).unwrap();
        assert!(watermark.parse::<u64>().unwrap() > 0);
        assert_eq!(reset_vault_inner(&state, password.into())["success"], true);
        assert!(get_vault_dek(&state).is_err());
        assert!(state.vault_cache.read().unwrap().is_none());
        assert_eq!(
            fs::read_to_string(security.join(".vault-writes-counter")).unwrap(),
            "0"
        );
        assert_eq!(
            fs::read(security.join(LICENSE_FILE)).unwrap(),
            b"synthetic license preserved"
        );
        let new_password = "SyntheticNewPassword_456!";
        assert_eq!(
            unlock_vault_inner(&state, new_password.into())["isNew"],
            true
        );
        state.lock_vault();
        assert_eq!(
            unlock_vault_inner(&state, new_password.into())["success"],
            true
        );
        let (opened, _) = open_current_vault(&directory, new_password).unwrap();
        assert_eq!(opened.rotation.writes, 0);
        assert!(open_current_vault(&directory, password).is_err());
    }

    #[test]
    fn reset_metadata_failure_preserves_archive_and_unrelated_security_files() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("vault");
        let security = temp.path().join("security");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(&security).unwrap();
        let vault_path = directory.join(VAULT_FILE);
        fs::write(&vault_path, b"synthetic encrypted archive bytes").unwrap();
        fs::write(security.join(LICENSE_FILE), b"synthetic license").unwrap();
        fs::create_dir(security.join(".vault-writes-counter")).unwrap();
        assert!(remove_vault_storage_for_reset(&directory, &security).is_err());
        assert_eq!(
            fs::read(vault_path).unwrap(),
            b"synthetic encrypted archive bytes"
        );
        assert_eq!(
            fs::read(security.join(LICENSE_FILE)).unwrap(),
            b"synthetic license"
        );
    }

    #[test]
    fn reset_cannot_delete_nested_security_directory() {
        let temp = tempfile::tempdir().unwrap();
        let security = temp.path().join("security");
        fs::create_dir(&security).unwrap();
        fs::write(security.join(LICENSE_FILE), b"synthetic license").unwrap();
        assert!(remove_vault_storage_for_reset(temp.path(), &security).is_err());
        assert_eq!(
            fs::read(security.join(LICENSE_FILE)).unwrap(),
            b"synthetic license"
        );
    }

    #[test]
    fn exhausted_write_counter_cannot_mutate_existing_records() {
        let (mut vault, dek) = create_vault("SyntheticPassword_123!").unwrap();
        update_vault_records(&mut vault, &dek, &data("Preserved")).unwrap();
        vault.rotation.writes = u64::MAX;
        let original = serialize_vault(&vault).unwrap();
        assert!(update_vault_records(&mut vault, &dek, &data("Must not replace")).is_err());
        assert_eq!(serialize_vault(&vault).unwrap(), original);
    }

    #[test]
    fn password_and_recovery_unlock_both_reject_older_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("vault");
        let security = temp.path().join("security");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(&security).unwrap();
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        let _ = crate::platform::MACHINE_ID_CACHE.set("synthetic-recovery-machine".into());
        crate::lockout::lockout_clear(&security);
        let password = "SyntheticPassword_123!";
        let (mut vault, dek) = create_vault(password).unwrap();
        let recovery = vault_engine::generate_recovery_key(&mut vault, &dek).unwrap();
        vault.rotation.writes = 5;
        write_canonical_vault(&directory, &mut vault, &dek).unwrap();
        fs::write(security.join(".vault-writes-counter"), b"6").unwrap();
        let state = AppState::new(directory, security.clone());
        for result in [
            unlock_vault_inner(&state, password.into()),
            unlock_with_recovery_inner(&state, recovery.clone()),
        ] {
            assert_eq!(result["success"], false);
            assert!(result["error"].as_str().unwrap().contains("rollback"));
        }
        assert!(get_vault_dek(&state).is_err());
        assert_eq!(*state.failed_attempts.lock().unwrap(), 0);
        fs::write(security.join(".vault-writes-counter"), b"5").unwrap();
        assert_eq!(
            unlock_with_recovery_inner(&state, recovery)["success"],
            true
        );
        assert!(get_vault_dek(&state).is_ok());
    }

    #[test]
    fn invalid_or_unreadable_watermark_is_not_treated_as_zero() {
        let temp = tempfile::tempdir().unwrap();
        let counter = temp.path().join(".vault-writes-counter");
        fs::write(&counter, b"invalid counter").unwrap();
        assert!(enforce_vault_watermark(temp.path(), 4).is_err());
        assert_eq!(fs::read(&counter).unwrap(), b"invalid counter");
        fs::remove_file(&counter).unwrap();
        fs::create_dir(&counter).unwrap();
        assert!(enforce_vault_watermark(temp.path(), 4).is_err());
        assert!(counter.is_dir());
    }

    #[test]
    fn atomic_snapshot_migrates_latest_split_and_survives_password_change_restart() {
        let dir = tempfile::tempdir().unwrap();
        let password = "SyntheticOldPassword_123!";
        let (mut vault, dek) = create_vault(password).unwrap();
        make_legacy(&mut vault, password);
        update_vault_records(&mut vault, &dek, &data("Old synthetic record")).unwrap();
        // Legacy bootstrap predates the newest split save.
        std::fs::write(
            dir.path().join("vault.lex.v4-backup"),
            serialize_vault(&vault).unwrap(),
        )
        .unwrap();
        update_vault_records(&mut vault, &dek, &data("Latest synthetic record")).unwrap();
        write_split_vault(dir.path(), &vault, &dek).unwrap();
        let (mut latest, key) = open_current_vault(dir.path(), password).unwrap();
        assert_title(&latest, &key, "Latest synthetic record");
        upgrade_canonical_header(&mut latest, password).unwrap();
        write_canonical_vault(dir.path(), &mut latest, &key).unwrap();
        assert!(!is_split_vault(dir.path()));
        assert!(dir.path().join("vault-data/header.enc").exists());

        change_password_snapshot(dir.path(), password, "SyntheticNewPassword_456!").unwrap();
        drop(key);
        drop(dek);
        assert!(open_current_vault(dir.path(), password).is_err());
        let (reopened, key) = open_current_vault(dir.path(), "SyntheticNewPassword_456!").unwrap();
        assert_title(&reopened, &key, "Latest synthetic record");

        // A backup is the exact current encrypted snapshot and is portable.
        let backup = std::fs::read(dir.path().join(VAULT_FILE)).unwrap();
        let (restored, key) = open_vault("SyntheticNewPassword_456!", &backup).unwrap();
        assert_title(&restored, &key, "Latest synthetic record");
        assert!(!String::from_utf8_lossy(&backup).contains("Latest synthetic record"));
    }

    #[test]
    fn atomic_snapshot_corrupted_split_never_falls_back_to_stale_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, dek) = create_vault("SyntheticPassword_123!").unwrap();
        make_legacy(&mut vault, "SyntheticPassword_123!");
        let bootstrap = serialize_vault(&vault).unwrap();
        std::fs::write(dir.path().join(VAULT_FILE), &bootstrap).unwrap();
        update_vault_records(&mut vault, &dek, &data("Latest")).unwrap();
        write_split_vault(dir.path(), &vault, &dek).unwrap();
        let record = dir
            .path()
            .join("vault-data/records/practices_synthetic-1.enc");
        let mut ciphertext = std::fs::read(&record).unwrap();
        *ciphertext.last_mut().unwrap() ^= 1;
        std::fs::write(&record, ciphertext).unwrap();
        assert!(open_current_vault(dir.path(), "SyntheticPassword_123!").is_err());
        assert_eq!(
            std::fs::read(dir.path().join(VAULT_FILE)).unwrap(),
            bootstrap
        );
        assert!(!has_canonical_vault(dir.path()));
    }

    #[test]
    fn atomic_snapshot_unchanged_save_reuses_record_ciphertext_and_retains_history() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, dek) = create_vault("SyntheticPassword_123!").unwrap();
        update_vault_records(&mut vault, &dek, &data("Unchanged")).unwrap();
        let original = serde_json::to_vec(&vault.records).unwrap();
        update_vault_records(&mut vault, &dek, &data("Unchanged")).unwrap();
        assert_eq!(serde_json::to_vec(&vault.records).unwrap(), original);
        update_vault_records(&mut vault, &dek, &data("Changed")).unwrap();
        assert_eq!(vault.records["practices_synthetic-1"].versions.len(), 2);
        write_canonical_vault(dir.path(), &mut vault, &dek).unwrap();
        let (reopened, key) = open_current_vault(dir.path(), "SyntheticPassword_123!").unwrap();
        assert_title(&reopened, &key, "Changed");
    }

    #[test]
    fn atomic_snapshot_manifest_rejects_individual_record_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let password = "SyntheticPassword_123!";
        let (mut vault, dek) = create_vault(password).unwrap();
        update_vault_records(&mut vault, &dek, &data("Old")).unwrap();
        let old_record = vault.records["practices_synthetic-1"].clone();
        update_vault_records(&mut vault, &dek, &data("Current")).unwrap();
        write_canonical_vault(dir.path(), &mut vault, &dek).unwrap();
        // The substituted old record remains valid AEAD ciphertext under DEK.
        // Only the manifest authenticates which version belongs to this snapshot.
        vault
            .records
            .insert("practices_synthetic-1".into(), old_record);
        let mut tampered = CANONICAL_MAGIC.to_vec();
        tampered.extend(serde_json::to_vec(&vault).unwrap());
        std::fs::write(dir.path().join(VAULT_FILE), &tampered).unwrap();
        assert!(deserialize_authenticated_vault(&tampered, &dek).is_err());
        assert!(open_current_vault(dir.path(), password).is_err());
    }

    #[test]
    fn atomic_snapshot_manifest_cannot_be_bypassed_by_legacy_magic() {
        let dir = tempfile::tempdir().unwrap();
        let password = "SyntheticPassword_123!";
        let (mut vault, dek) = create_vault(password).unwrap();
        let recovery = vault_engine::generate_recovery_key(&mut vault, &dek).unwrap();
        update_vault_records(&mut vault, &dek, &data("Old")).unwrap();
        let old_record = vault.records["practices_synthetic-1"].clone();
        update_vault_records(&mut vault, &dek, &data("Current")).unwrap();
        write_canonical_vault(dir.path(), &mut vault, &dek).unwrap();
        // Changing only the outer prefix retains compatibility and integrity.
        let legacy_prefix = serialize_vault(&vault).unwrap();
        assert!(open_vault(password, &legacy_prefix).is_ok());
        vault
            .records
            .insert("practices_synthetic-1".into(), old_record);
        let downgraded = serialize_vault(&vault).unwrap();
        assert!(downgraded.starts_with(vault_engine::VAULT_MAGIC));
        assert!(deserialize_authenticated_vault(&downgraded, &dek).is_err());
        assert!(open_vault(password, &downgraded).is_err());
        assert!(vault_engine::open_vault_with_recovery(&recovery, &downgraded).is_err());
    }

    #[test]
    fn atomic_snapshot_signed_version_requires_manifest_for_all_unlock_paths() {
        let dir = tempfile::tempdir().unwrap();
        let password = "SyntheticPassword_123!";
        let (mut vault, dek) = create_vault(password).unwrap();
        let recovery = vault_engine::generate_recovery_key(&mut vault, &dek).unwrap();
        update_vault_records(&mut vault, &dek, &data("Old")).unwrap();
        let old_record = vault.records["practices_synthetic-1"].clone();
        let old_entries = decrypt_index(&dek, &vault.index).unwrap();
        let historical_bare_index = encrypt_index(&dek, &old_entries).unwrap();
        update_vault_records(&mut vault, &dek, &data("Current")).unwrap();
        write_canonical_vault(dir.path(), &mut vault, &dek).unwrap();

        let mut blank_index = vault.clone();
        blank_index.index.iv.clear();
        let mut replayed_index = vault.clone();
        replayed_index.index = historical_bare_index;
        replayed_index
            .records
            .insert("practices_synthetic-1".into(), old_record);
        let mut changed_header = replayed_index.clone();
        changed_header.version = 7;
        for tampered in [blank_index, replayed_index, changed_header] {
            // Use an accepted legacy outer prefix for every attack variant.
            let bytes = serialize_vault(&tampered).unwrap();
            assert!(open_vault(password, &bytes).is_err());
            assert!(deserialize_authenticated_vault(&bytes, &dek).is_err());
            assert!(vault_engine::open_vault_with_recovery(&recovery, &bytes).is_err());
        }
    }

    #[test]
    fn atomic_snapshot_legacy_magic_never_revives_retained_split_data() {
        let dir = tempfile::tempdir().unwrap();
        let password = "SyntheticPassword_123!";
        let (mut vault, dek) = create_vault(password).unwrap();
        make_legacy(&mut vault, password);
        update_vault_records(&mut vault, &dek, &data("Old split record")).unwrap();
        write_split_vault(dir.path(), &vault, &dek).unwrap();
        upgrade_canonical_header(&mut vault, password).unwrap();
        update_vault_records(&mut vault, &dek, &data("Current atomic record")).unwrap();
        write_canonical_vault(dir.path(), &mut vault, &dek).unwrap();

        // An attacker can replace outer magic without knowing either key.
        let path = dir.path().join(VAULT_FILE);
        std::fs::write(&path, serialize_vault(&vault).unwrap()).unwrap();
        assert!(is_split_vault(dir.path())); // Untrusted storage hint only.
        let (opened, key) = open_current_vault(dir.path(), password).unwrap();
        assert_title(&opened, &key, "Current atomic record");
        let session = read_authenticated_snapshot(dir.path(), &dek).unwrap();
        assert_title(&session, &dek, "Current atomic record");

        // A damaged/missing current snapshot must fail even with readable
        // legacy split files present beside it.
        vault.index.iv.clear();
        std::fs::write(&path, serialize_vault(&vault).unwrap()).unwrap();
        assert!(open_current_vault(dir.path(), password).is_err());
        assert!(read_authenticated_snapshot(dir.path(), &dek).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(read_authenticated_snapshot(dir.path(), &dek).is_err());
    }

    #[test]
    fn atomic_snapshot_rotation_immediately_preserves_authenticated_manifest() {
        let password = "SyntheticPassword_123!";
        let (mut vault, old_dek) = create_vault(password).unwrap();
        update_vault_records(&mut vault, &old_dek, &data("Preserved across rotation")).unwrap();
        let kek = derive_kek(password, &vault.kdf).unwrap();
        let new_dek = rotate_dek(&mut vault, &kek).unwrap();
        assert_ne!(old_dek.as_slice(), new_dek.as_slice());
        // The returned object itself is valid, before any writer reseals it.
        let bytes = serialize_vault(&vault).unwrap();
        let (opened, key) = open_vault(password, &bytes).unwrap();
        assert_title(&opened, &key, "Preserved across rotation");
        assert!(deserialize_authenticated_vault(&bytes, &new_dek).is_ok());
        assert!(deserialize_authenticated_vault(&bytes, &old_dek).is_err());
    }

    #[test]
    fn atomic_snapshot_legacy_recovery_requires_explicit_password_migration() {
        let password = "SyntheticPassword_123!";
        let (mut vault, dek) = create_vault(password).unwrap();
        let recovery = vault_engine::generate_recovery_key(&mut vault, &dek).unwrap();
        make_legacy(&mut vault, password);
        let bytes = serialize_vault(&vault).unwrap();
        let error = vault_engine::open_vault_with_recovery(&recovery, &bytes).unwrap_err();
        assert!(error.contains("migrato con la password"));
        // A verified password migration makes the same recovery key usable.
        upgrade_canonical_header(&mut vault, password).unwrap();
        let bytes = serialize_vault(&vault).unwrap();
        assert!(vault_engine::open_vault_with_recovery(&recovery, &bytes).is_ok());
    }

    #[test]
    fn malformed_records_and_domains_never_replace_an_existing_snapshot() {
        let (mut vault, dek) = create_vault("SyntheticPassword_123!").unwrap();
        update_vault_records(&mut vault, &dek, &data("Preserved")).unwrap();
        let original = serialize_vault(&vault).unwrap();
        for invalid in [
            json!([]),
            json!({"practices": null}),
            json!({"practices": [[]]}),
            json!({"practices": [{"id": ""}]}),
            json!({"practices": [{"id": "same"}, {"id": "same"}]}),
        ] {
            assert!(update_vault_records(&mut vault, &dek, &invalid).is_err());
            assert_eq!(serialize_vault(&vault).unwrap(), original);
        }
        // All domains are validated before an earlier valid domain can mutate
        // the snapshot, including during import of several domains together.
        for field in ["agenda", "contacts", "timeLogs", "invoices"] {
            for records in [
                json!([{}]),
                json!([{"id": 42}]),
                json!([{"id": ""}]),
                json!([{"id": "same"}, {"id": "same"}]),
            ] {
                let mut invalid = data("Must not replace preserved record");
                invalid[field] = records;
                assert!(update_vault_records(&mut vault, &dek, &invalid).is_err());
                assert_eq!(serialize_vault(&vault).unwrap(), original);
            }
        }
        let index = decrypt_index(&dek, &vault.index).unwrap();
        for invalid in [
            json!([]),
            json!(42),
            json!({"client": "No id"}),
            json!({"id": "another-record"}),
        ] {
            let bytes = rmp_serde::to_vec(&invalid).unwrap();
            assert!(decode_indexed_record(&bytes, &index[0]).is_err());
        }
    }

    #[test]
    fn atomic_snapshot_rotation_preserves_data_and_monotonic_counter() {
        let dir = tempfile::tempdir().unwrap();
        let password = "SyntheticPassword_123!";
        let (mut vault, dek) = create_vault(password).unwrap();
        update_vault_records(&mut vault, &dek, &data("Latest")).unwrap();
        vault.rotation.writes = 10_000;
        let kek = derive_kek(password, &vault.kdf).unwrap();
        let new_key = rotate_dek(&mut vault, &kek).unwrap();
        assert_ne!(dek.as_slice(), new_key.as_slice());
        assert_eq!(vault.rotation.writes, 10_000);
        assert!(!needs_rotation(&vault.rotation));
        write_canonical_vault(dir.path(), &mut vault, &new_key).unwrap();
        let (reopened, key) = open_current_vault(dir.path(), password).unwrap();
        assert_title(&reopened, &key, "Latest");
    }

    #[test]
    fn atomic_snapshot_failed_replacement_preserves_original_and_cleans_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, dek) = create_vault("SyntheticPassword_123!").unwrap();
        // Force rename to fail after the staged file has been completely written.
        let target = dir.path().join(VAULT_FILE);
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("preserved"), b"original").unwrap();
        assert!(write_canonical_vault(dir.path(), &mut vault, &dek).is_err());
        assert_eq!(
            std::fs::read(target.join("preserved")).unwrap(),
            b"original"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
