// ═══════════════════════════════════════════════════════════
//  AUDIT — Encrypted activity history; local retention is not an external audit anchor
// ═══════════════════════════════════════════════════════════

use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::{atomic_write_with_sync, safe_bounded_read};
use crate::state::{get_vault_dek, get_vault_key, AppState};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tauri::State;
use zeroize::Zeroizing;

/// Max audit log file size: 10 MB (prevents OOM from inflated/tampered file)
const MAX_AUDIT_SIZE: u64 = 10 * 1024 * 1024;

/// Genesis prev_hash placeholder (64 hex chars of zero) for the first chain entry.
const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn warn_legacy_log_once() {
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    WARNED.get_or_init(|| {
        eprintln!(
            "[LexFlow] Legacy audit history: earlier events cannot be retroactively verified."
        )
    });
}

/// Canonical JSON serialization of an entry for HMAC computation.
///
/// `serde_json::Map` is backed by `BTreeMap` (no `preserve_order` feature in this
/// project), which means `serde_json::to_vec` already produces output with
/// alphabetically-sorted keys and no whitespace — i.e. canonical form. This is
/// the property the HMAC chain relies on for cross-process verification.
fn canonical_json(v: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(v).map_err(|e| format!("canonical_json failed: {}", e))
}

/// Compute HMAC-SHA256 over `prev_canonical || new_canonical`, keyed by the DEK.
fn compute_chain_hmac(key: &[u8], prev_canonical: &[u8], new_canonical: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(prev_canonical);
    mac.update(new_canonical);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Verify a stored hex `prev_hash` against the freshly-computed HMAC, in
/// constant time.
fn verify_chain_hmac(
    key: &[u8],
    prev_canonical: &[u8],
    new_canonical: &[u8],
    expected_hex: &str,
) -> bool {
    use hmac::{Hmac, Mac};
    let expected = match hex::decode(expected_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let mut mac = match Hmac::<sha2::Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(prev_canonical);
    mac.update(new_canonical);
    mac.verify_slice(&expected).is_ok()
}

/// True if the entry is part of the HMAC chain (has both `prev_hash` and `seq`).
fn entry_is_chained(entry: &Value) -> bool {
    entry.get("prev_hash").and_then(|v| v.as_str()).is_some()
        && entry.get("seq").and_then(|v| v.as_u64()).is_some()
}

/// Strip `prev_hash` and `seq` from an entry, returning a new Value used as the
/// HMAC input for the entry itself.
fn entry_without_chain_fields(entry: &Value) -> Value {
    match entry {
        Value::Object(map) => {
            let mut clone: Map<String, Value> = map.clone();
            clone.remove("prev_hash");
            clone.remove("seq");
            Value::Object(clone)
        }
        other => other.clone(),
    }
}

/// Verify the HMAC chain across the loaded log. Returns `Ok(())` if the log is
/// either fully chained and valid, or fully legacy (no chain fields anywhere —
/// in which case a one-time warning is emitted), or starts with legacy entries
/// followed by a contiguous chain that begins at a `audit.chain.genesis` marker
/// (the post-migration shape). On a partial/broken chain it returns `Err` and
/// the caller is expected to set the hard error state.
fn verify_chain(key: &[u8], logs: &[Value]) -> Result<(), String> {
    if logs.is_empty() {
        return Ok(());
    }

    for entry in logs {
        if !entry.is_object()
            || entry.get("event").and_then(Value::as_str).is_none()
            || entry.get("time").and_then(Value::as_str).is_none()
            || ((entry.get("prev_hash").is_some() || entry.get("seq").is_some())
                && !entry_is_chained(entry))
        {
            return Err("Audit entry schema invalid".into());
        }
    }
    let any_chained = logs.iter().any(entry_is_chained);
    if !any_chained {
        // Pure legacy log — predates the HMAC chain. Don't verify, warn once.
        warn_legacy_log_once();
        return Ok(());
    }

    // Locate the start of the chain: the first chained entry. Everything before
    // it must be legacy (no chain fields). Everything from it onward must be
    // chained, with seq starting at 0 and incrementing by 1.
    let chain_start = logs
        .iter()
        .position(entry_is_chained)
        .expect("any_chained == true implies a position");

    // Pre-chain prefix must be entirely legacy (no chain fields).
    for (idx, entry) in logs[..chain_start].iter().enumerate() {
        if entry_is_chained(entry) {
            return Err(format!(
                "audit log chain broken: chained entry {} appears before chain start",
                idx
            ));
        }
    }
    if chain_start > 0 {
        // Legacy entries precede the chain — same one-time warning.
        warn_legacy_log_once();
    }

    // From `chain_start` onward, every entry must be chained and contiguous.
    let mut prev_canonical: Vec<u8> = Vec::new(); // empty before the genesis link
    let mut expected_seq: u64 = 0;
    for (offset, entry) in logs[chain_start..].iter().enumerate() {
        if !entry_is_chained(entry) {
            return Err(format!(
                "audit log chain broken: legacy entry mixed into chain at offset {}",
                offset
            ));
        }
        let stored_prev_hash =
            entry
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    format!(
                        "audit log chain broken at chain offset {}: missing prev_hash",
                        offset
                    )
                })?;
        let stored_seq = entry.get("seq").and_then(|v| v.as_u64()).ok_or_else(|| {
            format!(
                "audit log chain broken at chain offset {}: missing seq",
                offset
            )
        })?;

        if stored_seq != expected_seq {
            return Err(format!(
                "audit log chain broken at entry {}: seq {} (expected {})",
                stored_seq, stored_seq, expected_seq
            ));
        }

        let entry_for_hash = entry_without_chain_fields(entry);
        let new_canonical = canonical_json(&entry_for_hash)
            .map_err(|e| format!("audit log chain broken at entry {}: {}", stored_seq, e))?;

        if offset == 0 {
            // Genesis link: prev_hash must equal the all-zero placeholder.
            if stored_prev_hash != GENESIS_PREV_HASH {
                return Err(format!(
                    "audit log chain broken at entry {}: non-genesis prev_hash on first chained entry",
                    stored_seq
                ));
            }
        } else if !verify_chain_hmac(key, &prev_canonical, &new_canonical, stored_prev_hash) {
            return Err(format!("audit log chain broken at entry {}", stored_seq));
        }

        prev_canonical = new_canonical;
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(())
}

const AUDIT_MAGIC: &[u8] = b"LEXFLOW_AUDIT_V2\n";
const MAX_AUDIT_ENTRIES: usize = 10_000;

/// A stable random history key survives DEK rotation. During a rotation, two
/// wrappers let either the old or the newly committed vault open the history.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEnvelope {
    wrapped_keys: Vec<String>,
    ciphertext: String,
}

struct AuditDocument {
    key: Zeroizing<Vec<u8>>,
    entries: Vec<Value>,
}

impl Drop for AuditDocument {
    fn drop(&mut self) {
        self.entries.iter_mut().for_each(crate::state::scrub_json);
    }
}

fn new_audit_key() -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0; AES_KEY_LEN]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key
}

/// Re-anchor only after an authenticated migration or intentional retention.
/// The outer AEAD authenticates the complete retained document, including seq=0.
fn reanchor_chain(entries: &mut [Value], key: &[u8]) -> Result<(), String> {
    let mut previous = Vec::new();
    for (seq, entry) in entries.iter_mut().enumerate() {
        let canonical = canonical_json(&entry_without_chain_fields(entry))?;
        let hash = if seq == 0 {
            GENESIS_PREV_HASH.into()
        } else {
            hex::encode(compute_chain_hmac(key, &previous, &canonical))
        };
        let object = entry
            .as_object_mut()
            .ok_or("Audit entry is not an object")?;
        object.insert("seq".into(), json!(seq));
        object.insert("prev_hash".into(), json!(hash));
        previous = canonical;
    }
    Ok(())
}

fn load_audit_document(path: &std::path::Path, dek: &[u8]) -> Result<AuditDocument, String> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AuditDocument {
                key: new_audit_key(),
                entries: Vec::new(),
            });
        }
        Err(_) => {
            return Err("Impossibile leggere il registro attività; originale conservato.".into())
        }
        Ok(_) => {}
    }
    let raw = safe_bounded_read(path, MAX_AUDIT_SIZE)
        .map_err(|_| "Impossibile leggere il registro attività; originale conservato.")?;
    let (key, plaintext, legacy) = if let Some(body) = raw.strip_prefix(AUDIT_MAGIC) {
        let envelope: AuditEnvelope = serde_json::from_slice(body)
            .map_err(|_| "Registro attività danneggiato; originale conservato.")?;
        if !(1..=2).contains(&envelope.wrapped_keys.len()) {
            return Err("Registro attività: numero di chiavi non valido.".into());
        }
        let key = envelope
            .wrapped_keys
            .iter()
            .filter(|wrapped| wrapped.len() <= 256)
            .find_map(|wrapped| {
                STANDARD
                    .decode(wrapped)
                    .ok()
                    .and_then(|bytes| decrypt_data(dek, &bytes).ok())
                    .filter(|key| key.len() == AES_KEY_LEN)
            })
            .ok_or("Registro attività non autenticabile; originale conservato.")?;
        let encrypted = STANDARD
            .decode(&envelope.ciphertext)
            .map_err(|_| "Registro attività danneggiato; originale conservato.")?;
        let plaintext = decrypt_data(&key, &encrypted)?;
        (key, plaintext, false)
    } else {
        (Zeroizing::new(dek.to_vec()), decrypt_data(dek, &raw)?, true)
    };
    let entries: Vec<Value> = serde_json::from_slice(&plaintext)
        .map_err(|_| "Registro attività: contenuto non valido; originale conservato.")?;
    let mut document = AuditDocument { key, entries };
    verify_chain(&document.key, &document.entries)?;
    if legacy {
        // Older files used the vault key directly. Migrate only authenticated
        // history; neither parse errors nor broken chains may reset the file.
        let key = new_audit_key();
        reanchor_chain(&mut document.entries, &key)?;
        document.key = key;
    }
    Ok(document)
}

fn write_audit_document(
    path: &std::path::Path,
    document: &AuditDocument,
    wrapping_keys: &[&[u8]],
) -> Result<(), String> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&document.entries).map_err(|_| "Audit serialization failed")?,
    );
    let wrapped_keys = wrapping_keys
        .iter()
        .map(|dek| encrypt_data(dek, &document.key).map(|bytes| STANDARD.encode(bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    let envelope = AuditEnvelope {
        wrapped_keys,
        ciphertext: STANDARD.encode(encrypt_data(&document.key, &plaintext)?),
    };
    let mut raw = AUDIT_MAGIC.to_vec();
    serde_json::to_writer(&mut raw, &envelope)
        .map_err(|_| "Audit envelope serialization failed")?;
    if raw.len() as u64 > MAX_AUDIT_SIZE {
        return Err("Registro attività troppo grande; originale conservato.".into());
    }
    atomic_write_with_sync(path, &raw)
}

fn append_event(document: &mut AuditDocument, event: &str) -> Result<(), String> {
    if event.len() > 1024 {
        return Err("Audit event too long".into());
    }
    let mut entry = json!({"event": event, "time": chrono::Local::now().to_rfc3339()});
    let previous = document
        .entries
        .last()
        .map(entry_without_chain_fields)
        .map(|value| canonical_json(&value))
        .transpose()?
        .unwrap_or_default();
    let hash = if previous.is_empty() {
        GENESIS_PREV_HASH.into()
    } else {
        hex::encode(compute_chain_hmac(
            &document.key,
            &previous,
            &canonical_json(&entry)?,
        ))
    };
    entry["seq"] = json!(document.entries.len());
    entry["prev_hash"] = json!(hash);
    document.entries.push(entry);
    if document.entries.len() > MAX_AUDIT_ENTRIES {
        let excess = document.entries.len() - MAX_AUDIT_ENTRIES;
        for mut discarded in document.entries.drain(..excess) {
            crate::state::scrub_json(&mut discarded);
        }
        reanchor_chain(&mut document.entries, &document.key)?;
    }
    Ok(())
}

/// Caller holds write_mutex. No nested lock: unlock/change/recovery already
/// serialize their transaction and must log using this entry point.
pub(crate) fn append_audit_log_locked(state: &AppState, event: &str) -> Result<(), String> {
    let dek = get_vault_dek(state).or_else(|_| get_vault_key(state))?;
    let path = state
        .data_dir
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .join(AUDIT_LOG_FILE);
    let mut document = load_audit_document(&path, &dek)?;
    append_event(&mut document, event)?;
    write_audit_document(&path, &document, &[&dek])
}

pub(crate) fn append_audit_log(state: &AppState, event: &str) -> Result<(), String> {
    let _guard = state
        .write_mutex
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    append_audit_log_locked(state, event)
}

/// Prepare before committing the rotated vault. On failure the caller must
/// retain the old vault. If the vault commit fails/crashes, its old DEK remains
/// usable; after success the new DEK works. A later append drops the old slot.
pub(crate) fn prepare_audit_key_rotation(
    directory: &std::path::Path,
    old_dek: &[u8],
    new_dek: &[u8],
) -> Result<(), String> {
    let path = directory.join(AUDIT_LOG_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Impossibile verificare il registro prima della rotazione.".into()),
        Ok(_) => {}
    }
    let document = load_audit_document(&path, old_dek)?;
    write_audit_document(&path, &document, &[old_dek, new_dek])
}

#[tauri::command]
pub(crate) fn get_audit_log(
    state: State<AppState>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<Value, String> {
    let _guard = state
        .write_mutex
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let dek = get_vault_dek(&state).or_else(|_| get_vault_key(&state))?;
    let path = state
        .data_dir
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .join(AUDIT_LOG_FILE);
    let document = load_audit_document(&path, &dek)?;
    let off = offset.unwrap_or(0);
    let end = off
        .saturating_add(limit.unwrap_or(1000).min(1000))
        .min(document.entries.len());
    if off >= end {
        return Ok(json!([]));
    }
    Ok(Value::Array(document.entries[off..end].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_vault_dek_records_events_without_a_legacy_password_key() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new(dir.path().into(), dir.path().into());
        let dek = [8u8; 32];
        *state.vault_dek.lock().unwrap() =
            Some(crate::state::SecureKey::new(Zeroizing::new(dek.to_vec())));
        assert!(state.vault_key.lock().unwrap().is_none());
        append_audit_log(&state, "first-v4-event").unwrap();
        {
            let _guard = state.write_mutex.lock().unwrap();
            append_audit_log_locked(&state, "inside-vault-transaction").unwrap();
        }
        let path = dir.path().join(AUDIT_LOG_FILE);
        let document = load_audit_document(&path, &dek).unwrap();
        assert_eq!(document.entries.len(), 2);
        state.lock_vault();
        let before = std::fs::read(&path).unwrap();
        assert!(append_audit_log(&state, "locked-event").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn audit_retention_keeps_chain_valid_after_10000_events() {
        let mut document = AuditDocument {
            key: new_audit_key(),
            entries: Vec::new(),
        };
        for i in 0..(MAX_AUDIT_ENTRIES + 2) {
            append_event(&mut document, &format!("synthetic-event-{i}")).unwrap();
        }
        assert_eq!(document.entries.len(), MAX_AUDIT_ENTRIES);
        assert_eq!(document.entries[0]["event"], "synthetic-event-2");
        verify_chain(&document.key, &document.entries).unwrap();
        document.entries[1]["event"] = json!("changed");
        assert!(verify_chain(&document.key, &document.entries).is_err());
    }

    #[test]
    fn audit_rotation_preserves_history_before_and_after_vault_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE);
        let old = [1u8; 32];
        let new = [2u8; 32];
        let mut document = load_audit_document(&path, &old).unwrap();
        append_event(&mut document, "synthetic-sensitive-event").unwrap();
        write_audit_document(&path, &document, &[&old]).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("synthetic-sensitive-event"));
        assert!(load_audit_document(&path, &new).is_err());
        prepare_audit_key_rotation(dir.path(), &old, &new).unwrap();
        // Both sides of a crash between the auxiliary write and vault commit.
        assert_eq!(
            load_audit_document(&path, &old).unwrap().entries,
            document.entries
        );
        let mut opened = load_audit_document(&path, &new).unwrap();
        assert_eq!(opened.entries, document.entries);
        append_event(&mut opened, "after-rotation").unwrap();
        write_audit_document(&path, &opened, &[&new]).unwrap();
        assert!(load_audit_document(&path, &old).is_err());
        assert_eq!(load_audit_document(&path, &new).unwrap().entries.len(), 2);
    }

    #[test]
    fn importing_a_backup_with_a_different_dek_preserves_activity_history() {
        let dir = tempfile::tempdir().unwrap();
        let current_path = dir.path().join(AUDIT_LOG_FILE);
        let (mut current, current_dek) =
            crate::vault_engine::create_vault("synthetic-current-password").unwrap();
        crate::vault_engine::write_canonical_vault(dir.path(), &mut current, &current_dek).unwrap();
        let mut history = load_audit_document(&current_path, &current_dek).unwrap();
        append_event(&mut history, "before-import").unwrap();
        write_audit_document(&current_path, &history, &[&current_dek]).unwrap();
        let (mut imported, imported_dek) =
            crate::vault_engine::create_vault("synthetic-backup-password").unwrap();
        crate::import_export::commit_import_snapshot(
            dir.path(),
            dir.path(),
            current.rotation.writes,
            &mut imported,
            &current_dek,
            &imported_dek,
        )
        .unwrap();
        let (opened_vault, opened_dek) =
            crate::vault_engine::open_current_vault(dir.path(), "synthetic-backup-password")
                .unwrap();
        assert_eq!(opened_vault.rotation.writes, imported.rotation.writes);
        let mut after_import = load_audit_document(&current_path, &opened_dek).unwrap();
        assert_eq!(after_import.entries, history.entries);
        append_event(&mut after_import, "after-import").unwrap();
        write_audit_document(&current_path, &after_import, &[&opened_dek]).unwrap();
        assert!(load_audit_document(&current_path, &current_dek).is_err());
        assert_eq!(
            load_audit_document(&current_path, &opened_dek)
                .unwrap()
                .entries
                .len(),
            2
        );
    }

    #[test]
    fn audit_corruption_or_invalid_authenticated_json_never_erases_original() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE);
        let key = [4u8; 32];
        for invalid in [
            b"broken".to_vec(),
            encrypt_data(&key, b"{}").unwrap(),
            encrypt_data(&key, br#"[{"event":"x","time":"x","seq":0}]"#).unwrap(),
        ] {
            std::fs::write(&path, &invalid).unwrap();
            assert!(load_audit_document(&path, &key).is_err());
            assert!(prepare_audit_key_rotation(dir.path(), &key, &[5u8; 32]).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), invalid);
        }
    }

    #[test]
    fn legacy_audit_history_migrates_only_after_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AUDIT_LOG_FILE);
        let key = [6u8; 32];
        let entries = vec![json!({"event":"legacy-event","time":"2026-09-08T00:00:00Z"})];
        std::fs::write(
            &path,
            encrypt_data(&key, &serde_json::to_vec(&entries).unwrap()).unwrap(),
        )
        .unwrap();
        let mut document = load_audit_document(&path, &key).unwrap();
        append_event(&mut document, "new-event").unwrap();
        write_audit_document(&path, &document, &[&key]).unwrap();
        assert!(std::fs::read(&path).unwrap().starts_with(AUDIT_MAGIC));
        let opened = load_audit_document(&path, &key).unwrap();
        assert_eq!(opened.entries[0]["event"], "legacy-event");
        assert_eq!(opened.entries[1]["event"], "new-event");
        verify_chain(&opened.key, &opened.entries).unwrap();
    }
}
