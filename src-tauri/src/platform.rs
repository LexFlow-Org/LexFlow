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
        let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "WORKGROUP".to_string());
        let profile = std::env::var("USERPROFILE")
            .unwrap_or_else(|_| std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "0".to_string()));
        format!("{}:{}", domain, profile)
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
    if let Ok(existing) = fs::read_to_string(&id_path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() && trimmed.len() <= 128 {
            return Ok(trimmed);
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
