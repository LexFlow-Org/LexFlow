// ═══════════════════════════════════════════════════════════
//  PLATFORM — Machine ID, local encryption key, fingerprint
// ═══════════════════════════════════════════════════════════

use crate::constants::*;
use crate::crypto::decrypt_data;
use crate::io::safe_bounded_read;
use sha2::{Digest, Sha256};
use std::fs;
use zeroize::Zeroizing;

#[cfg(not(target_os = "android"))]
use crate::crypto::encrypt_data;
#[cfg(not(target_os = "android"))]
use crate::io::{atomic_write_with_sync, secure_write};

// ─── Platform UID ────────────────────────────────────────────

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn get_platform_uid() -> String {
    #[cfg(target_os = "windows")]
    {
        // SECURITY FIX: use whoami crate instead of env vars (USERDOMAIN/USERPROFILE
        // are user-controllable and can be spoofed to derive a different encryption key).
        let username = whoami::username();
        let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "WORKGROUP".to_string());
        format!("{}:{}", hostname, username)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let real_uid = unsafe { libc::getuid() };
        let username = whoami::username();
        format!("{}:{}", real_uid, username)
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn double_sha256_key(seed: &str) -> Zeroizing<Vec<u8>> {
    let h1 = <Sha256 as Digest>::digest(seed.as_bytes());
    let h2 = <Sha256 as Digest>::digest(h1);
    Zeroizing::new(h2.to_vec())
}

// ─── Machine ID cache ────────────────────────────────────────

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub(crate) static MACHINE_ID_CACHE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub(crate) fn init_machine_id() -> Result<String, String> {
    let base_dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .ok_or_else(|| "Impossibile risolvere una directory sicura per l'app".to_string())?;
    let security_dir = base_dir.join("com.pietrolongo.lexflow");
    fs::create_dir_all(&security_dir).map_err(|e| {
        format!(
            "Impossibile creare security_dir {:?}: {}. \
                Senza questa directory il machine-id non può essere persistito \
                e tutti i file cifrati locali sarebbero inaccessibili.",
            security_dir, e
        )
    })?;
    let id_path = security_dir.join(MACHINE_ID_FILE);
    // FIX: bounded read — machine-id should be exactly 64 hex chars
    if let Ok(bytes) = crate::io::safe_bounded_read(&id_path, 1024) {
        let existing = String::from_utf8_lossy(&bytes).trim().to_string();
        if !existing.is_empty() && existing.len() <= 128 {
            return Ok(existing);
        }
    }
    let mut id_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id_bytes);
    let machine_id = hex::encode(id_bytes);
    // FIX: propagate write error — if this fails, local encrypted files won't survive restart
    secure_write(&id_path, machine_id.as_bytes()).map_err(|e| {
        format!(
            "CRITICAL: impossibile salvare machine-id su {:?}: {}. \
            Tutti i file cifrati locali saranno inaccessibili al prossimo avvio.",
            id_path, e
        )
    })?;
    Ok(machine_id)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub(crate) fn get_or_create_machine_id() -> String {
    MACHINE_ID_CACHE
        .get()
        .expect("MACHINE_ID_CACHE not initialized — init_machine_id() must run in setup()")
        .clone()
}

// ─── Local encryption key (V2/V3/V4 migration chain) ─────────

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn get_local_encryption_key_v3() -> Zeroizing<Vec<u8>> {
    let user = whoami::username();
    let machine_id = get_or_create_machine_id();
    let uid = get_platform_uid();
    let seed = format!(
        "LEXFLOW-LOCAL-KEY-V3:{}:{}:{}:FORTKNOX",
        user, machine_id, uid
    );
    double_sha256_key(&seed)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn get_local_encryption_key_legacy() -> Zeroizing<Vec<u8>> {
    let user = whoami::username();
    let host = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let uid = get_platform_uid();
    let seed = format!("LEXFLOW-LOCAL-KEY-V2:{}:{}:{}:FORTKNOX", user, host, uid);
    double_sha256_key(&seed)
}

pub(crate) fn decrypt_local_with_migration(path: &std::path::Path) -> Option<Vec<u8>> {
    let enc = safe_bounded_read(path, MAX_SETTINGS_FILE_SIZE).ok()?;
    let key = get_local_encryption_key();
    if let Ok(dec) = decrypt_data(&key, &enc) {
        return Some(dec);
    }
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let v3_key = get_local_encryption_key_v3();
        if let Ok(dec) = decrypt_data(&v3_key, &enc) {
            eprintln!(
                "SECURITY NOTICE: Decrypting {:?} via V3 key. \
                Re-encrypting with V4 key...",
                path.file_name().unwrap_or_default()
            );
            if let Ok(re_enc) = encrypt_data(&key, &dec) {
                if let Err(e) = atomic_write_with_sync(path, &re_enc) {
                    eprintln!(
                        "CRITICAL WARNING: V3→V4 migration write failed for {:?}: {}. \
                        Migration will retry on next read.",
                        path.file_name().unwrap_or_default(),
                        e
                    );
                } else {
                    eprintln!(
                        "V3→V4 migration successful for {:?}.",
                        path.file_name().unwrap_or_default()
                    );
                }
            }
            return Some(dec);
        }

        let legacy_key = get_local_encryption_key_legacy();
        if let Ok(dec) = decrypt_data(&legacy_key, &enc) {
            eprintln!(
                "SECURITY NOTICE: Decrypting {:?} via LEGACY V2 key (hostname-based). \
                Re-encrypting with V4 key...",
                path.file_name().unwrap_or_default()
            );
            if let Ok(re_enc) = encrypt_data(&key, &dec) {
                if let Err(e) = atomic_write_with_sync(path, &re_enc) {
                    eprintln!(
                        "CRITICAL WARNING: V2→V4 migration write failed for {:?}: {}. \
                        The file remains decryptable with the legacy (hostname-based) key. \
                        An attacker with physical access and hostname knowledge could exploit this. \
                        Migration will retry on next read.",
                        path.file_name().unwrap_or_default(),
                        e
                    );
                } else {
                    eprintln!(
                        "V2→V4 migration successful for {:?}. Legacy key path eliminated.",
                        path.file_name().unwrap_or_default()
                    );
                }
            }
            return Some(dec);
        }
    }
    None
}

pub(crate) fn get_local_encryption_key() -> Zeroizing<Vec<u8>> {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let user = whoami::username();
        let machine_id = get_or_create_machine_id();
        let uid = get_platform_uid();
        let seed = format!(
            "LEXFLOW-LOCAL-KEY-V4:{}:{}:{}:FORTKNOX",
            user, machine_id, uid
        );
        double_sha256_key(&seed)
    }
    #[cfg(target_os = "android")]
    {
        let android_id = get_android_device_id();
        let seed = format!("LEXFLOW-ANDROID-KEY:{}:FORTKNOX", android_id);
        let h1 = <Sha256 as Digest>::digest(seed.as_bytes());
        let h2 = <Sha256 as Digest>::digest(h1);
        Zeroizing::new(h2.to_vec())
    }
}

// ─── Android device ID ──────────────────────────────────────

#[cfg(target_os = "android")]
pub(crate) static ANDROID_DEVICE_ID_CACHE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[cfg(target_os = "android")]
pub(crate) fn init_android_device_id() -> Result<String, String> {
    // FIX: env var override restricted to debug builds only
    #[cfg(debug_assertions)]
    if let Ok(id) = std::env::var("LEXFLOW_DEVICE_ID") {
        eprintln!("[LexFlow] DEBUG: using LEXFLOW_DEVICE_ID env override");
        return Ok(id);
    }
    let candidate_dirs = [
        dirs::data_dir().map(|d| d.join("com.pietrolongo.lexflow")),
        std::env::temp_dir()
            .parent()
            .map(|p| p.join("com.pietrolongo.lexflow")),
    ];
    let mut first_writable: Option<std::path::PathBuf> = None;
    for candidate in candidate_dirs.iter().flatten() {
        let id_path = candidate.join(".device_id");
        if let Some(id) = read_trimmed_file(&id_path) {
            return Ok(id);
        }
        if first_writable.is_none() {
            first_writable = Some(id_path);
        }
    }
    let mut id_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id_bytes);
    let id_hex = hex::encode(id_bytes);
    let id_path = first_writable.ok_or_else(|| {
        "Nessun percorso scrivibile trovato su Android per persistere la master key.".to_string()
    })?;
    if let Some(parent) = id_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Impossibile creare la directory per device_id: {}", e))?;
    }
    // FIX: use secure_write with 0o600 permissions instead of bare fs::write
    crate::io::secure_write(&id_path, id_hex.as_bytes())
        .map_err(|e| format!("Impossibile salvare device_id: {}", e))?;
    Ok(id_hex)
}

#[cfg(target_os = "android")]
pub(crate) fn get_android_device_id() -> String {
    ANDROID_DEVICE_ID_CACHE
        .get()
        .expect(
            "ANDROID_DEVICE_ID_CACHE not initialized — init_android_device_id() must run in setup()",
        )
        .clone()
}

#[cfg(target_os = "android")]
fn read_trimmed_file(path: &std::path::Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ─── Hardware fingerprint ──────────────────────────────────

pub(crate) fn compute_machine_fingerprint() -> String {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let user = whoami::username();
        let machine_id = get_or_create_machine_id();
        let uid = get_platform_uid();
        let seed = format!(
            "LEXFLOW-MACHINE-FP-V2:{}:{}:{}:IRONCLAD",
            user, machine_id, uid
        );
        let hash = <Sha256 as Digest>::digest(seed.as_bytes());
        hex::encode(hash)
    }
    #[cfg(target_os = "android")]
    {
        let android_id = get_android_device_id();
        let seed = format!("LEXFLOW-ANDROID-FP:{}:IRONCLAD", android_id);
        let hash = <Sha256 as Digest>::digest(seed.as_bytes());
        hex::encode(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    fn ensure_machine_id() {
        let _ = MACHINE_ID_CACHE.set("test_machine_id_for_platform_tests".to_string());
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_double_sha256_key_deterministic() {
        let k1 = double_sha256_key("test seed");
        let k2 = double_sha256_key("test seed");
        assert_eq!(*k1, *k2);
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_double_sha256_key_length() {
        let key = double_sha256_key("any seed");
        assert_eq!(key.len(), 32, "Key must be 32 bytes (SHA-256 output)");
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_double_sha256_key_different_seeds() {
        let k1 = double_sha256_key("seed_a");
        let k2 = double_sha256_key("seed_b");
        assert_ne!(*k1, *k2);
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_machine_fingerprint_deterministic() {
        ensure_machine_id();
        let fp1 = compute_machine_fingerprint();
        let fp2 = compute_machine_fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_machine_fingerprint_hex_format() {
        ensure_machine_id();
        let fp = compute_machine_fingerprint();
        assert_eq!(fp.len(), 64, "SHA-256 hex is 64 chars");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_local_encryption_key_deterministic() {
        ensure_machine_id();
        let k1 = get_local_encryption_key();
        let k2 = get_local_encryption_key();
        assert_eq!(*k1, *k2);
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_local_encryption_key_length() {
        ensure_machine_id();
        let key = get_local_encryption_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_decrypt_local_with_migration_nonexistent() {
        let result =
            decrypt_local_with_migration(std::path::Path::new("/tmp/nonexistent_lex_test"));
        assert!(result.is_none());
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_decrypt_local_with_migration_roundtrip() {
        ensure_machine_id();
        let key = get_local_encryption_key();
        let plaintext = b"test license data";
        let encrypted = crate::crypto::encrypt_data(&key, plaintext).unwrap();

        let dir = std::env::temp_dir();
        let path = dir.join(format!("lexflow_platform_test_{}", rand::random::<u64>()));
        std::fs::write(&path, &encrypted).unwrap();

        let result = decrypt_local_with_migration(&path);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), plaintext);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_decrypt_local_with_migration_corrupted() {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        ensure_machine_id();
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "lexflow_platform_corrupt_{}",
            rand::random::<u64>()
        ));
        std::fs::write(&path, b"totally corrupted garbage data").unwrap();

        let result = decrypt_local_with_migration(&path);
        assert!(result.is_none());
        std::fs::remove_file(&path).ok();
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_platform_uid_not_empty() {
        ensure_machine_id();
        let uid = get_platform_uid();
        assert!(!uid.is_empty());
        assert!(uid.contains(':'), "UID should have format 'x:username'");
    }
}
