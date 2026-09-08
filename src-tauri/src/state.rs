// ═══════════════════════════════════════════════════════════
//  STATE — AppState, SecureKey, vault key access
// ═══════════════════════════════════════════════════════════

use serde_json::Value;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, RwLock,
};
use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

/// Wraps a cryptographic key with Zeroizing + mlock (prevents swap to disk).
/// On drop: munlock + zeroize automatically.
pub struct SecureKey(pub(crate) Zeroizing<Vec<u8>>, u64);

// Non-secret identity for this in-memory key allocation, not a cryptographic key.
// A new unlock receives a new identity even if the DEK bytes are unchanged.
static KEY_INSTANCE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(crate) struct DocumentSession(u64);

impl SecureKey {
    pub(crate) fn new(key: Zeroizing<Vec<u8>>) -> Self {
        // mlock the buffer to prevent it from being swapped to disk
        if !crate::security::mlock_buffer_slice(&key) {
            eprintln!(
                "[SECURITY] WARNING: mlock failed — key may be swappable to disk. \
                       Check RLIMIT_MEMLOCK (ulimit -l)."
            );
        }
        Self(key, KEY_INSTANCE_SEQUENCE.fetch_add(1, Ordering::Relaxed))
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // Wipe the locked allocation before making its pages swappable again.
        self.0.as_mut_slice().zeroize();
        crate::security::munlock_buffer_slice(&self.0);
    }
}

pub struct AppState {
    pub data_dir: RwLock<PathBuf>,
    pub security_dir: RwLock<PathBuf>,
    /// v2 legacy: vault key derived directly from password (kept for backward compat)
    pub(crate) vault_key: Mutex<Option<SecureKey>>,
    /// v4: unwrapped DEK for data encryption (zeroized on lock)
    pub(crate) vault_dek: Mutex<Option<SecureKey>>,
    /// v4: vault format version detected at unlock (4 only, v2 removed)
    pub(crate) vault_version: RwLock<u32>,
    /// PERF: in-memory cache of decrypted vault data.
    /// Invalidated on every write. Avoids re-decrypting all records on each load.
    pub(crate) vault_cache: RwLock<Option<Value>>,
    pub(crate) failed_attempts: Mutex<u32>,
    pub(crate) locked_until: Mutex<Option<Instant>>,
    pub(crate) last_activity: Mutex<Instant>,
    pub(crate) autolock_minutes: Mutex<u32>,
    pub(crate) write_mutex: Mutex<()>,
    #[allow(clippy::type_complexity)]
    pub(crate) autolock_condvar:
        Mutex<Option<std::sync::Arc<(std::sync::Mutex<()>, std::sync::Condvar)>>>,
}

impl AppState {
    pub fn new(data_dir: PathBuf, security_dir: PathBuf) -> Self {
        Self {
            data_dir: RwLock::new(data_dir),
            security_dir: RwLock::new(security_dir),
            vault_key: Mutex::new(None),
            vault_dek: Mutex::new(None),
            vault_version: RwLock::new(0),
            vault_cache: RwLock::new(None),
            failed_attempts: Mutex::new(0),
            locked_until: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            autolock_minutes: Mutex::new(5),
            write_mutex: Mutex::new(()),
            autolock_condvar: Mutex::new(None),
        }
    }

    /// Authorize document IPC without cloning key material or holding a lock
    /// across a native dialog, CPU work, or a sidecar await.
    pub(crate) fn document_session(&self) -> Result<DocumentSession, String> {
        self.vault_dek
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map(|key| DocumentSession(key.1))
            .ok_or_else(|| "Archivio bloccato. Sbloccalo per usare i documenti.".into())
    }

    /// Reject completion from an earlier session, including lock then re-unlock.
    pub(crate) fn validate_document_session(&self, session: DocumentSession) -> Result<(), String> {
        let current = self.document_session()?;
        if current.0 != session.0 {
            return Err("Sessione cambiata durante l'operazione. Riprova dopo lo sblocco.".into());
        }
        Ok(())
    }

    /// Serialize session teardown with vault reads/writes so a completing read
    /// cannot repopulate plaintext after the session has been locked.
    pub(crate) fn lock_vault(&self) {
        let _guard = self.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
        self.lock_vault_locked();
    }

    /// Caller holds write_mutex, including authentication failure and reset.
    pub(crate) fn lock_vault_locked(&self) {
        *self.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .vault_version
            .write()
            .unwrap_or_else(|e| e.into_inner()) = 0;
        invalidate_vault_cache(self);
    }
}

/// Wipe owned JSON strings, including object keys, before releasing the cache.
/// Serializing a copy and wiping that copy does not erase the original strings.
pub(crate) fn scrub_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub_json),
        Value::Object(object) => {
            for (mut key, mut value) in std::mem::take(object) {
                key.zeroize();
                scrub_json(&mut value);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}

pub(crate) fn invalidate_vault_cache(state: &AppState) {
    let mut guard = state.vault_cache.write().unwrap_or_else(|e| e.into_inner());
    if let Some(mut old) = guard.take() {
        scrub_json(&mut old);
    }
}

pub(crate) fn get_vault_key(state: &AppState) -> Result<Zeroizing<Vec<u8>>, String> {
    state
        .vault_key
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|k| Zeroizing::new(k.0.to_vec()))
        .ok_or_else(|| "Locked".into())
}

/// Get the v4 DEK (Data Encryption Key) from state.
///
/// SECURITY (BE-T2 #4): this returns a CLONE of the DEK in a Zeroizing<Vec>.
/// The clone is NOT mlock'd, so it may be paged to swap. Prefer `with_vault_dek`
/// which holds the mlock'd buffer under the lock for the duration of the
/// closure and never copies the bytes.
///
/// NOTE: kept as non-deprecated for now to allow incremental migration of all
/// call sites without forcing a CI -D warnings failure. New code MUST use
/// `with_vault_dek`. Existing call sites should migrate over time.
#[allow(dead_code)]
pub(crate) fn get_vault_dek(state: &AppState) -> Result<Zeroizing<Vec<u8>>, String> {
    state
        .vault_dek
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|k| Zeroizing::new(k.0.to_vec()))
        .ok_or_else(|| "Locked".into())
}

/// Run a closure with a borrow of the mlock'd DEK without cloning the bytes.
/// This is the preferred accessor: the key buffer never leaves its mlock'd page.
#[allow(dead_code)]
pub(crate) fn with_vault_dek<R>(state: &AppState, f: impl FnOnce(&[u8]) -> R) -> Result<R, String> {
    let dek = state.vault_dek.lock().unwrap_or_else(|e| e.into_inner());
    let key = dek.as_ref().ok_or_else(|| "Locked".to_string())?;
    Ok(f(&key.0))
}

/// Get the vault format version (2 or 4).
pub(crate) fn get_vault_version(state: &AppState) -> u32 {
    *state
        .vault_version
        .read()
        .unwrap_or_else(|e| e.into_inner())
}

/// Zeroize the password String's heap buffer.
///
/// KNOWN LIMITATION: This zeroizes the final owned String, but Tauri's IPC
/// deserializer (serde_json) may have created intermediate String copies during
/// JSON parsing that are already freed without zeroization. This is an inherent
/// limitation of the Rust/Tauri architecture — the IPC layer is outside our
/// control. The real protection is Argon2id key derivation (password never
/// stored, only the derived key) + mlock on the derived key + core dump disabled.
///
/// FE PRE-HASH POLICY (SEC-STATE-3):
/// `unlock_vault` accepts a SHA-256-prehashed password from the frontend so the
/// raw plaintext never crosses the IPC boundary. The following commands STILL
/// accept plaintext `pwd: String` directly and should be migrated to the same
/// pre-hash convention to fully close the residue window:
///   - import_vault, export_vault, change_password, reset_vault
// TODO(audit:SEC-STATE-3): extend FE pre-hash policy to import/export/change/reset
// password (currently only unlock_vault uses it).
pub(crate) fn zeroize_password(password: String) {
    let mut pwd_bytes = password.into_bytes();
    pwd_bytes.zeroize();
}

pub(crate) fn notify_autolock_condvar(state: &AppState) {
    if let Some(pair) = state
        .autolock_condvar
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        let (_lock, cvar) = &**pair;
        cvar.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn locking_clears_both_keys_version_and_cached_records() {
        let state = AppState::new(PathBuf::new(), PathBuf::new());
        *state.vault_key.lock().unwrap() = Some(SecureKey::new(Zeroizing::new(vec![1; 32])));
        *state.vault_dek.lock().unwrap() = Some(SecureKey::new(Zeroizing::new(vec![2; 32])));
        *state.vault_version.write().unwrap() = 7;
        *state.vault_cache.write().unwrap() = Some(json!({"practices": [{"client": "Private"}]}));
        state.lock_vault();
        assert!(state.vault_key.lock().unwrap().is_none());
        assert!(state.vault_dek.lock().unwrap().is_none());
        assert_eq!(*state.vault_version.read().unwrap(), 0);
        assert!(state.vault_cache.read().unwrap().is_none());
    }

    #[test]
    fn scrubbing_replaces_nested_json_without_serializing_copies() {
        let mut value = json!({"private key": ["secret", {"nested": "client"}], "number": 42});
        scrub_json(&mut value);
        assert_eq!(value, Value::Null);
    }
}

#[cfg(test)]
mod document_session_tests {
    use super::*;

    #[test]
    fn document_access_requires_unlocked_dek() {
        let state = AppState::new(PathBuf::new(), PathBuf::new());
        assert!(state.document_session().is_err());
        // A legacy KEK alone does not authorize the current document UI.
        *state.vault_key.lock().unwrap() = Some(SecureKey::new(Zeroizing::new(vec![1; 32])));
        assert!(state.document_session().is_err());
        *state.vault_dek.lock().unwrap() = Some(SecureKey::new(Zeroizing::new(vec![2; 32])));
        let session = state.document_session().unwrap();
        assert!(state.validate_document_session(session).is_ok());
    }

    #[test]
    fn document_result_cannot_cross_lock_and_new_unlock() {
        let state = AppState::new(PathBuf::new(), PathBuf::new());
        *state.vault_dek.lock().unwrap() = Some(SecureKey::new(Zeroizing::new(vec![2; 32])));
        let earlier = state.document_session().unwrap();
        state.lock_vault();
        assert!(state.validate_document_session(earlier).is_err());
        // Unlock with the exact same DEK bytes is still a different session.
        *state.vault_dek.lock().unwrap() = Some(SecureKey::new(Zeroizing::new(vec![2; 32])));
        assert!(state.validate_document_session(earlier).is_err());
        let current = state.document_session().unwrap();
        assert!(state.validate_document_session(current).is_ok());
    }
}
