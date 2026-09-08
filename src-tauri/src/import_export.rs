// ═══════════════════════════════════════════════════════════
//  IMPORT / EXPORT — Vault backup and restore (v2 + v4)
// ═══════════════════════════════════════════════════════════

use crate::audit::append_audit_log_locked;
use crate::constants::*;
use crate::crypto::{decrypt_data, derive_secure_key, encrypt_data};
use crate::io::atomic_write_with_sync;
use crate::state::{AppState, SecureKey};
use crate::vault_engine;
use serde_json::{json, Value};
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

/// The password must unlock the same DEK as the active session. Checking only
/// the current file could authorize an older plaintext cache after replacement.
/// Caller holds write_mutex across this verification and snapshot selection.
fn verify_export_credential(state: &AppState, password: &str) -> Result<(), String> {
    use subtle::ConstantTimeEq;
    state.document_session()?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let (_, verified_dek) = vault_engine::open_current_vault(&dir, password)
        .map_err(|_| "Password errata o database non verificabile.".to_string())?;
    let guard = state.vault_dek.lock().unwrap_or_else(|e| e.into_inner());
    let active = guard.as_ref().ok_or("Archivio bloccato.")?;
    if !bool::from(active.0.as_slice().ct_eq(verified_dek.as_slice())) {
        return Err("Il database è cambiato dalla sessione corrente. Ripeti l'accesso.".into());
    }
    Ok(())
}

/// Keep the existing anti-rollback floor until the replacement is published.
/// Once committed, the new vault is also acceptable if the process dies before
/// the sidecar update: its counter exceeds both old authenticated counters.
pub(crate) fn commit_import_snapshot(
    directory: &std::path::Path,
    security_directory: &std::path::Path,
    current_writes: u64,
    imported: &mut vault_engine::VaultData,
    current_dek: &[u8],
    dek: &[u8],
) -> Result<(), String> {
    let counter_path = security_directory.join(".vault-writes-counter");
    let stored = match std::fs::symlink_metadata(&counter_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(format!("Contatore locale non leggibile: {error}")),
        Ok(_) => {
            let raw = crate::io::safe_bounded_read(&counter_path, 64)?;
            std::str::from_utf8(&raw)
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
                .ok_or("Contatore locale non valido; database conservato.")?
        }
    };
    imported.rotation.writes = current_writes
        .max(stored)
        .max(imported.rotation.writes)
        .checked_add(1)
        .ok_or("Contatore esaurito; database conservato.")?;
    // The DEK is new, while the global write counter remains monotonic.
    imported.rotation.max_writes = imported.rotation.writes.saturating_add(10_000);
    // Preserve activity history with both key slots until the snapshot commits.
    // A preparation error must leave the original archive and session intact.
    crate::audit::prepare_audit_key_rotation(directory, current_dek, dek)?;
    vault_engine::write_canonical_vault(directory, imported, dek)?;
    // Do not return a failed import after the replacement has been committed.
    // As with normal writes, unlock can advance a still-older sidecar later.
    if atomic_write_with_sync(
        &counter_path,
        imported.rotation.writes.to_string().as_bytes(),
    )
    .is_err()
    {
        eprintln!("[import] Vault committed; anti-rollback watermark update deferred to unlock.");
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn export_vault(
    state: State<'_, AppState>,
    pwd: String,
    current_password: String,
    app: AppHandle,
) -> Result<Value, String> {
    use tauri_plugin_dialog::DialogExt;
    let pwd = Zeroizing::new(pwd);
    let current_password = Zeroizing::new(current_password);
    let session = state.document_session()?;

    let data = {
        // Authentication and snapshot selection belong to one transaction.
        let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
        state.validate_document_session(session)?;
        let sec_dir = state
            .security_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Err(error) = crate::lockout::check_lockout(&state, &sec_dir) {
            return Err(error.to_string());
        }
        // The vault credential authorizes reading the current archive. The
        // independent backup passphrase below protects the portable export.
        if let Err(error) = verify_export_credential(&state, &current_password) {
            crate::lockout::record_failed_attempt_locked(&state, &sec_dir);
            return Err(error);
        }
        crate::vault::read_vault_locked(&state)?
    };
    drop(current_password);

    // Export format: [32-byte salt] [v2-encrypted monolithic JSON]
    // This ensures backups are portable across v2 and v4 installations.
    // TODO(audit:SEC-IE-1): preserve V4/V6 format on export to retain
    // per-record HMAC and rotation metadata. The current monolithic v2-style
    // backup loses the per-record integrity tags introduced in V4 and the
    // KDF rotation metadata used by V6.
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
        // A native dialog can outlive automatic lock or a different login.
        // Serialize publication with session teardown, as document exports do.
        let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
        state.validate_document_session(session)?;
        atomic_write_with_sync(&file_path, &out).map_err(|e| e.to_string())?;
        drop(pwd);
        Ok(json!({"success": true}))
    } else {
        drop(pwd);
        Ok(json!({"success": false, "cancelled": true}))
    }
}

#[tauri::command]
pub(crate) async fn import_vault(
    state: State<'_, AppState>,
    pwd: String,
    app: AppHandle,
) -> Result<Value, String> {
    use tauri_plugin_dialog::DialogExt;
    let pwd = Zeroizing::new(pwd);
    let session = state.document_session()?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("LexFlow Backup", &["lex"])
        .pick_file(move |file_path| {
            let _ = tx.send(file_path);
        });
    let path = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    if let Some(p) = path {
        state.validate_document_session(session)?;
        let file_path = p
            .into_path()
            .map_err(|e| format!("Percorso non valido: {}", e))?;
        const MAX_IMPORT_SIZE: u64 = 500 * 1024 * 1024;
        let raw = crate::io::safe_bounded_read(&file_path, MAX_IMPORT_SIZE)?;

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
        // SEC-IE-2: validate decrypted JSON against the same domain validators
        // used on save_*. Refuse the import if any per-domain shape is wrong —
        // this prevents a malicious backup from injecting oversized strings,
        // bogus IDs, or arrays of the wrong shape into the new vault.
        if let Some(p) = val.get("practices") {
            crate::validation::validate_practices(p)?;
        }
        if let Some(a) = val.get("agenda") {
            crate::validation::validate_agenda(a)?;
        }
        if let Some(c) = val.get("contacts") {
            crate::validation::validate_contacts(c)?;
        }
        if let Some(t) = val.get("timeLogs") {
            crate::validation::validate_time_logs(t)?;
        }
        if let Some(i) = val.get("invoices") {
            crate::validation::validate_invoices(i)?;
        }

        let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
        // Never replace an archive from a dialog opened before lock/re-unlock.
        state.validate_document_session(session)?;
        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let current_dek = crate::state::get_vault_dek(&state)?;
        let current = vault_engine::read_authenticated_snapshot(&dir, &current_dek)?;

        // Import as v4 vault
        let (mut vault, dek) = vault_engine::create_vault(&pwd).map_err(|_e| {
            "Impossibile creare il database durante l'importazione. Riprova.".to_string()
        })?;

        crate::vault::update_vault_records(&mut vault, &dek, &val)?;
        // Commit the finished snapshot once. Failure leaves both the old file
        // and the in-memory session intact.
        let sec_dir = state
            .security_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        commit_import_snapshot(
            &dir,
            &sec_dir,
            current.rotation.writes,
            &mut vault,
            &current_dek,
            &dek,
        )?;
        *state.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) = Some(SecureKey::new(dek));
        *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *state
            .vault_version
            .write()
            .unwrap_or_else(|e| e.into_inner()) = vault_engine::CURRENT_VAULT_VERSION;
        crate::state::invalidate_vault_cache(&state);
        *state
            .last_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = std::time::Instant::now();

        let _ = append_audit_log_locked(&state, "Vault importato da backup (v4)");
        drop(pwd);
        Ok(json!({"success": true}))
    } else {
        drop(pwd); // SECURITY FIX: zeroize even on cancel
        Ok(json!({"success": false, "cancelled": true}))
    }
}

#[cfg(test)]
mod credential_and_commit_tests {
    use super::*;

    fn snapshot(password: &str, client: &str) -> (vault_engine::VaultData, Zeroizing<Vec<u8>>) {
        let (mut vault, dek) = vault_engine::create_vault(password).unwrap();
        crate::vault::update_vault_records(
            &mut vault,
            &dek,
            &json!({
                "practices":[{"id":"synthetic-import-1", "client":client}], "agenda":[]
            }),
        )
        .unwrap();
        (vault, dek)
    }

    #[test]
    fn export_password_cannot_authorize_a_different_cached_vault() {
        let directory = tempfile::tempdir().unwrap();
        let state = AppState::new(directory.path().into(), directory.path().into());
        let (mut current, key) = snapshot("Synthetic-current-password", "Original synthetic");
        vault_engine::write_canonical_vault(directory.path(), &mut current, &key).unwrap();
        *state.vault_dek.lock().unwrap() = Some(SecureKey::new(key));
        *state.vault_cache.write().unwrap() =
            Some(json!({"practices":[{"client":"Original synthetic"}]}));
        assert!(verify_export_credential(&state, "Synthetic-current-password").is_ok());
        assert!(verify_export_credential(&state, "Synthetic-wrong-password").is_err());
        let (mut replacement, replacement_key) =
            snapshot("Synthetic-replacement-password", "Other synthetic");
        vault_engine::write_canonical_vault(directory.path(), &mut replacement, &replacement_key)
            .unwrap();
        assert!(verify_export_credential(&state, "Synthetic-replacement-password").is_err());
        assert_eq!(
            state.vault_cache.read().unwrap().as_ref().unwrap()["practices"][0]["client"],
            "Original synthetic"
        );
        state.lock_vault();
        assert!(verify_export_credential(&state, "Synthetic-replacement-password").is_err());
    }

    #[test]
    fn import_commit_inherits_high_water_mark_and_reopens() {
        let directory = tempfile::tempdir().unwrap();
        let (mut original, original_key) = snapshot("Synthetic-old-password", "Old synthetic");
        original.rotation.writes = 20;
        vault_engine::write_canonical_vault(directory.path(), &mut original, &original_key)
            .unwrap();
        let counter = directory.path().join(".vault-writes-counter");
        std::fs::write(&counter, b"35").unwrap();
        let (mut imported, key) = snapshot("Synthetic-import-password", "Imported synthetic");
        commit_import_snapshot(
            directory.path(),
            directory.path(),
            original.rotation.writes,
            &mut imported,
            &original_key,
            &key,
        )
        .unwrap();
        let (reopened, reopened_key) =
            vault_engine::open_current_vault(directory.path(), "Synthetic-import-password")
                .unwrap();
        assert_eq!(reopened.rotation.writes, 36);
        assert_eq!(reopened.rotation.max_writes, 10_036);
        assert_eq!(std::fs::read_to_string(counter).unwrap(), "36");
        let record = vault_engine::read_current_version(
            &reopened.records["practices_synthetic-import-1"],
            &reopened_key,
        )
        .unwrap();
        assert_eq!(
            vault_engine::decode_record_object(&record).unwrap()["client"],
            "Imported synthetic"
        );
    }

    #[test]
    fn import_invalid_or_exhausted_counter_preserves_original_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let (mut original, original_key) = snapshot("Synthetic-old-password", "Keep synthetic");
        vault_engine::write_canonical_vault(directory.path(), &mut original, &original_key)
            .unwrap();
        let original_bytes = std::fs::read(directory.path().join(VAULT_FILE)).unwrap();
        let counter = directory.path().join(".vault-writes-counter");
        let (mut imported, key) = snapshot("Synthetic-import-password", "Must not appear");
        for value in ["invalid-counter".to_string(), u64::MAX.to_string()] {
            std::fs::write(&counter, value.as_bytes()).unwrap();
            assert!(commit_import_snapshot(
                directory.path(),
                directory.path(),
                1,
                &mut imported,
                &original_key,
                &key
            )
            .is_err());
            assert_eq!(
                std::fs::read(directory.path().join(VAULT_FILE)).unwrap(),
                original_bytes
            );
            assert_eq!(std::fs::read_to_string(&counter).unwrap(), value);
            assert!(
                vault_engine::open_current_vault(directory.path(), "Synthetic-old-password")
                    .is_ok()
            );
        }
    }

    #[test]
    fn corrupt_audit_aborts_import_before_replacing_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let (mut original, original_key) = snapshot("Synthetic-old-password", "Keep synthetic");
        vault_engine::write_canonical_vault(directory.path(), &mut original, &original_key)
            .unwrap();
        let original_bytes = std::fs::read(directory.path().join(VAULT_FILE)).unwrap();
        let audit_path = directory.path().join(AUDIT_LOG_FILE);
        std::fs::write(&audit_path, b"synthetic-corrupt-audit").unwrap();
        let (mut imported, new_key) = snapshot("Synthetic-new-password", "Must not publish");
        assert!(commit_import_snapshot(
            directory.path(),
            directory.path(),
            original.rotation.writes,
            &mut imported,
            &original_key,
            &new_key
        )
        .is_err());
        assert_eq!(
            std::fs::read(directory.path().join(VAULT_FILE)).unwrap(),
            original_bytes
        );
        assert_eq!(
            std::fs::read(audit_path).unwrap(),
            b"synthetic-corrupt-audit"
        );
        assert!(
            vault_engine::open_current_vault(directory.path(), "Synthetic-old-password").is_ok()
        );
    }

    #[test]
    fn import_failed_rename_does_not_lower_counter_or_publish_temp() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join(VAULT_FILE);
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("preserved"), b"synthetic-original").unwrap();
        let counter = directory.path().join(".vault-writes-counter");
        std::fs::write(&counter, b"90").unwrap();
        let (mut imported, key) = snapshot("Synthetic-import-password", "Must not publish");
        assert!(commit_import_snapshot(
            directory.path(),
            directory.path(),
            100,
            &mut imported,
            &[0; 32],
            &key
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(&counter).unwrap(), "90");
        assert_eq!(
            std::fs::read(target.join("preserved")).unwrap(),
            b"synthetic-original"
        );
        assert!(!std::fs::read_dir(directory.path())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".vault.lex.tmp.")));
    }
}
