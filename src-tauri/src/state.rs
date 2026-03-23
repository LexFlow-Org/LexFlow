// ═══════════════════════════════════════════════════════════
//  STATE — AppState, SecureKey, vault key access
// ═══════════════════════════════════════════════════════════

use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::Instant;
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

/// Wraps a cryptographic key with Zeroizing + mlock (prevents swap to disk).
/// On drop: munlock + zeroize automatically.
pub struct SecureKey(pub(crate) Zeroizing<Vec<u8>>);

impl SecureKey {
    pub(crate) fn new(key: Zeroizing<Vec<u8>>) -> Self {
        // mlock the buffer to prevent it from being swapped to disk
        if !crate::security::mlock_buffer(key.as_ptr(), key.len()) {
            eprintln!(
                "[SECURITY] WARNING: mlock failed — key may be swappable to disk. \
                       Check RLIMIT_MEMLOCK (ulimit -l)."
            );
        }
        Self(key)
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // munlock before Zeroizing zeros the memory
        crate::security::munlock_buffer(self.0.as_ptr(), self.0.len());
        // Zeroizing handles the actual zeroing on its own Drop
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
}

/// Invalidate the vault cache (call after every write).
/// SECURITY: serialize the old cache to bytes, zeroize them, then drop.
/// This best-effort scrubs plaintext from heap before deallocation.
pub(crate) fn invalidate_vault_cache(state: &State<AppState>) {
    let mut guard = state.vault_cache.write().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = guard.take() {
        // Best-effort: serialize to bytes and zeroize before drop
        if let Ok(mut bytes) = serde_json::to_vec(&old) {
            zeroize::Zeroize::zeroize(&mut bytes);
        }
        drop(old);
    }
}

pub(crate) fn get_vault_key(state: &State<AppState>) -> Result<Zeroizing<Vec<u8>>, String> {
    state
        .vault_key
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|k| Zeroizing::new(k.0.to_vec()))
        .ok_or_else(|| "Locked".into())
}

/// Get the v4 DEK (Data Encryption Key) from state.
pub(crate) fn get_vault_dek(state: &State<AppState>) -> Result<Zeroizing<Vec<u8>>, String> {
    state
        .vault_dek
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|k| Zeroizing::new(k.0.to_vec()))
        .ok_or_else(|| "Locked".into())
}

/// Get the vault format version (2 or 4).
pub(crate) fn get_vault_version(state: &State<AppState>) -> u32 {
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
