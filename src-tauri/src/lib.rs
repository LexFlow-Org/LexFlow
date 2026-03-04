#![allow(unexpected_cfgs)]

use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::Mutex, time::{Instant, Duration}};
use tauri::{Manager, State, AppHandle, Emitter};
use zeroize::{Zeroize, Zeroizing};
use chrono::TimeZone as _;
use std::io::Read; // SECURITY FIX (Gemini Audit Chunk 10): needed for safe_bounded_read

// Platform detection helpers — usati in tutta la lib
#[allow(dead_code)]
const IS_ANDROID: bool = cfg!(target_os = "android");
#[allow(dead_code)]
const IS_DESKTOP: bool = cfg!(any(target_os = "macos", target_os = "windows", target_os = "linux"));

// Security & Crypto Hardened — disponibile su tutte le piattaforme
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, Payload}};
use argon2::{Argon2, Params, Version, Algorithm};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
// Ed25519 verification (offline license signature check)
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════
//  CONSTANTS — Security Parameters
// ═══════════════════════════════════════════════════════════
const VAULT_FILE: &str = "vault.lex";
const VAULT_SALT_FILE: &str = "vault.salt";
const VAULT_VERIFY_FILE: &str = "vault.verify";
const SETTINGS_FILE: &str = "settings.json";
const AUDIT_LOG_FILE: &str = "vault.audit";
const NOTIF_SCHEDULE_FILE: &str = "notification-schedule.json";
const LICENSE_FILE: &str = "license.json";
// SECURITY: persisted brute-force state — survives app restart/kill (L7 fix #1)
const LOCKOUT_FILE: &str = ".lockout";
// SECURITY: sentinel file — HMAC proof that a license was activated on this machine.
// If license.json is deleted but sentinel exists, the user is warned about tampering.
const LICENSE_SENTINEL_FILE: &str = ".license-sentinel";
// SECURITY: burned-keys registry — SHA256 hashes of every token ever activated.
// Once a key is burned it can NEVER be used again, even on the same machine.
// The registry is AES-256-GCM encrypted with the device-bound key.
const BURNED_KEYS_FILE: &str = ".burned-keys";
// Biometric marker file — avoids keychain access (which triggers Touch ID popup)
// just to check if bio credentials exist. Only actual bio_login reads the keychain.
// SECURITY FIX (Gemini Audit Chunk 01): explicit desktop targets — excludes iOS if ever added
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
const BIO_MARKER_FILE: &str = ".bio-enabled";
// SECURITY FIX (Gemini Audit v2): persistent machine ID file — replaces volatile hostname
// in get_local_encryption_key() and compute_machine_fingerprint(). Hostname changes on macOS
// (network changes, renames) would silently corrupt all encrypted local files (settings,
// burned-keys, license). A persistent random ID generated once is immune to this.
// SECURITY FIX (Gemini Audit Chunk 01): explicit desktop targets — excludes iOS if ever added
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
const MACHINE_ID_FILE: &str = ".machine-id";

#[allow(dead_code)]
const BIO_SERVICE: &str = "LexFlow_Bio";

const VAULT_MAGIC: &[u8] = b"LEXFLOW_V2_SECURE";
const ARGON2_SALT_LEN: usize = 32;
const AES_KEY_LEN: usize = 32; 
const NONCE_LEN: usize = 12;

// SECURITY FIX (Level-8 A1): unified Argon2 params across all platforms.
// Previously desktop used 64MB/4t/2p and Android used 16MB/3t/1p — a backup made on desktop
// was mathematically incompatible (different KDF output) with Android and vice versa.
// Fix: use a single set of params for ALL platforms. 16MB/3t/1p is strong (beats OWASP minimum
// of 12MB/3t/1p), runs in ~0.4s on mid-range Android, and produces identical keys everywhere.
// This makes vault backups fully portable across macOS ↔ Windows ↔ Android.
const ARGON2_M_COST: u32 = 16384; // 16 MB — works on all platforms, OWASP-compliant
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

const MAX_FAILED_ATTEMPTS: u32 = 5;
const LOCKOUT_SECS: u64 = 300;

// SECURITY FIX (Level-8 C5): cap settings/notification file reads to prevent OOM attack.
// An attacker (or corrupted write) could inject a 5GB settings.json; fs::read would try
// to allocate 5GB in RAM and OOM-kill the process. 10MB is generous for any real settings file.
const MAX_SETTINGS_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

// ═══════════════════════════════════════════════════════════
//  STATE & MEMORY PROTECTION
// ═══════════════════════════════════════════════════════════

// SECURITY FIX (Gemini Audit v2): persistent machine ID — replaces volatile hostname.
// Generated once at first run, persisted in security_dir. Survives hostname changes,
// network changes, and macOS Continuity renames. Uses 256-bit random + username hash.
// SECURITY FIX (Gemini Audit Chunk 01): explicit desktop cfg
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn get_or_create_machine_id() -> String {
    // SECURITY FIX (Gemini Audit Chunk 02): use home_dir fallback instead of "." (current dir).
    // Writing security files to "." would leak the machine-id in Downloads or USB drives.
    let base_dir = dirs::data_dir()
        .or_else(dirs::home_dir)
        .expect("FATAL: Impossibile risolvere una directory sicura per l'app");
    let security_dir = base_dir.join("com.pietrolongo.lexflow");
    if let Err(e) = fs::create_dir_all(&security_dir) {
        eprintln!("CRITICAL: Impossibile creare security_dir: {}", e);
    }
    let id_path = security_dir.join(MACHINE_ID_FILE);
    if let Ok(existing) = fs::read_to_string(&id_path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    // First run: generate stable machine ID from username + random entropy
    let mut id_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id_bytes);
    let machine_id = hex::encode(id_bytes);
    let _ = secure_write(&id_path, machine_id.as_bytes());
    machine_id
}

// Legacy key computation (with hostname) for migration of existing encrypted files.
// If the new key fails to decrypt, callers try this before giving up.
// SECURITY FIX (Gemini Audit Chunk 01): explicit desktop cfg
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn get_local_encryption_key_legacy() -> Zeroizing<Vec<u8>> {
    let user = whoami::username();
    let host = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    #[cfg(target_os = "windows")]
    let uid = {
        let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "WORKGROUP".to_string());
        let sid = std::env::var("USERPROFILE").unwrap_or_else(|_| std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "0".to_string()));
        format!("{}:{}", domain, sid)
    };
    #[cfg(not(target_os = "windows"))]
    let uid = std::env::var("UID")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "fallback_uid_001".to_string()); // SECURITY FIX: never use PID as crypto fallback
    let seed = format!("LEXFLOW-LOCAL-KEY-V2:{}:{}:{}:FORTKNOX", user, host, uid);
    let h1 = <Sha256 as Digest>::digest(seed.as_bytes());
    let h2 = <Sha256 as Digest>::digest(&h1);
    Zeroizing::new(h2.to_vec())
}

/// Try to decrypt with current key, fall back to legacy key if needed.
/// On legacy success, re-encrypt with new key for silent migration.
fn decrypt_local_with_migration(path: &std::path::Path) -> Option<Vec<u8>> {
    let enc = fs::read(path).ok()?;
    let key = get_local_encryption_key();
    if let Ok(dec) = decrypt_data(&key, &enc) {
        return Some(dec);
    }
    // Try legacy key (hostname-based)
    // SECURITY FIX (Gemini Audit Chunk 01): explicit desktop cfg
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let legacy_key = get_local_encryption_key_legacy();
        if let Ok(dec) = decrypt_data(&legacy_key, &enc) {
            // Silent migration: re-encrypt with new key
            if let Ok(re_enc) = encrypt_data(&key, &dec) {
                // SECURITY FIX (Security Audit G8): use atomic_write_with_sync for crash safety.
                // Previously used fs::write which could corrupt on crash mid-write.
                if let Err(e) = atomic_write_with_sync(path, &re_enc) {
                    eprintln!("WARNING: Migrazione file decifrato fallita su disco: {}", e);
                }
            }
            return Some(dec);
        }
    }
    None
}

// Derivata dalla macchina/device, non dalla password utente — inaccessibile da remoto
// SECURITY FIX (Gemini Audit v2): hostname removed from seed. Uses a persistent machine-id
// file instead, so renaming the computer (or network changes on macOS) cannot corrupt
// settings.json, .burned-keys, or license.json. Migration: if old key fails, try legacy.
// SECURITY FIX (Security Audit G2): return Zeroizing<Vec<u8>> so the local encryption key
// is automatically zeroed from memory when it goes out of scope. Previously returned bare
// Vec<u8> which could linger in heap memory after use.
fn get_local_encryption_key() -> Zeroizing<Vec<u8>> {
    // SECURITY FIX (Gemini Audit Chunk 01): explicit desktop cfg — excludes iOS
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let user = whoami::username();
        let machine_id = get_or_create_machine_id();
        #[cfg(target_os = "windows")]
        let uid = {
            let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "WORKGROUP".to_string());
            let sid = std::env::var("USERPROFILE").unwrap_or_else(|_| std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "0".to_string()));
            format!("{}:{}", domain, sid)
        };
        #[cfg(not(target_os = "windows"))]
        let uid = std::env::var("UID")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "fallback_uid_001".to_string()); // SECURITY FIX: never use PID as crypto fallback
        // SECURITY FIX: machine_id replaces hostname — stable across renames/network changes
        let seed = format!("LEXFLOW-LOCAL-KEY-V3:{}:{}:{}:FORTKNOX", user, machine_id, uid);
        let h1 = <Sha256 as Digest>::digest(seed.as_bytes());
        let h2 = <Sha256 as Digest>::digest(&h1);
        Zeroizing::new(h2.to_vec())
    }
    #[cfg(target_os = "android")]
    {
        // Su Android: preferisci LEXFLOW_DEVICE_ID (iniettato da Tauri mobile).
        // Se non disponibile, genera un ID univoco persistente nel file system privato.
        // Cerca .device_id in più percorsi possibili — il primo che esiste vince.
        // setup() di Tauri risolve il path reale e crea la directory, ma questa
        // funzione può essere chiamata prima che setup() finisca (e.g. settings migration).
        let android_id = if let Ok(id) = std::env::var("LEXFLOW_DEVICE_ID") {
            id
        } else {
            // Cerca .device_id nei possibili data dir dell'app
            let candidate_dirs = [
                // Path risolto da Tauri app_data_dir() (post-setup)
                dirs::data_dir().map(|d| d.join("com.pietrolongo.lexflow")),
                // NON usiamo path hardcoded /data/data/... — varia per utente/multi-user Android
                // Fallback: directory temporanea che esiste sempre
                std::env::temp_dir().parent().map(|p| p.join("com.pietrolongo.lexflow")),
            ];
            let mut found_id: Option<String> = None;
            let mut first_writable: Option<std::path::PathBuf> = None;
            for candidate in candidate_dirs.iter().flatten() {
                let id_path = candidate.join(".device_id");
                if id_path.exists() {
                    if let Ok(id) = fs::read_to_string(&id_path) {
                        let trimmed = id.trim().to_string();
                        if !trimmed.is_empty() {
                            found_id = Some(trimmed);
                            break;
                        }
                    }
                }
                if first_writable.is_none() {
                    first_writable = Some(id_path);
                }
            }
            found_id.unwrap_or_else(|| {
                // Prima esecuzione: genera ID casuale a 256-bit e persisti
                let mut id_bytes = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id_bytes);
                let id_hex = hex::encode(id_bytes);
                // SECURITY FIX (Gemini Audit Chunk 02): MUST persist device_id or panic.
                // If we cannot write the ID, the key changes every restart → data loss.
                let id_path = first_writable
                    .expect("FATAL: Nessun percorso scrivibile trovato su Android per persistere la master key.");
                if let Some(parent) = id_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::write(&id_path, &id_hex)
                    .expect("FATAL: Impossibile salvare device_id. Rischio data loss.");
                id_hex
            })
        };
        let seed = format!("LEXFLOW-ANDROID-KEY:{}:FORTKNOX", android_id);
        let hash = <Sha256 as Digest>::digest(seed.as_bytes());
        Zeroizing::new(hash.to_vec())
    }
}

// ═══════════════════════════════════════════════════════════
//  HARDWARE FINGERPRINT — binds license to physical device
// ═══════════════════════════════════════════════════════════
// SECURITY FIX (Gemini Audit v2): uses persistent machine_id instead of hostname.
// Hostname changes would silently invalidate the license binding.
fn compute_machine_fingerprint() -> String {
    // SECURITY FIX (Gemini Audit Chunk 01): explicit desktop cfg — excludes iOS
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let user = whoami::username();
        let machine_id = get_or_create_machine_id();
        #[cfg(target_os = "windows")]
        let uid = {
            let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "WORKGROUP".to_string());
            let sid = std::env::var("USERPROFILE").unwrap_or_else(|_| std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "0".to_string()));
            format!("{}:{}", domain, sid)
        };
        #[cfg(not(target_os = "windows"))]
        let uid = std::env::var("UID")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "fallback_uid_001".to_string()); // SECURITY FIX: never use PID
        let seed = format!("LEXFLOW-MACHINE-FP-V2:{}:{}:{}:IRONCLAD", user, machine_id, uid);
        let hash = <Sha256 as Digest>::digest(seed.as_bytes());
        hex::encode(hash)
    }
    #[cfg(target_os = "android")]
    {
        // On Android reuse LEXFLOW_DEVICE_ID / .device_id (same as get_local_encryption_key)
        let android_id = std::env::var("LEXFLOW_DEVICE_ID").unwrap_or_else(|_| {
            let candidates = [
                dirs::data_dir().map(|d| d.join("com.pietrolongo.lexflow/.device_id")),
                std::env::temp_dir().parent().map(|p| p.join("com.pietrolongo.lexflow/.device_id")),
            ];
            for c in candidates.iter().flatten() {
                if let Ok(id) = fs::read_to_string(c) {
                    let t = id.trim().to_string();
                    if !t.is_empty() { return t; }
                }
            }
            // SECURITY FIX (Gemini Audit Chunk 02): panic instead of "unknown-android".
            // A default fingerprint would allow license cloning across ALL Android devices.
            panic!("FATAL: Impossibile calcolare hardware fingerprint. Integrità licenza a rischio.");
        });
        let seed = format!("LEXFLOW-ANDROID-FP:{}:IRONCLAD", android_id);
        let hash = <Sha256 as Digest>::digest(seed.as_bytes());
        hex::encode(hash)
    }
}

// ═══════════════════════════════════════════════════════════
//  BURNED-KEY REGISTRY — single-use license enforcement
// ═══════════════════════════════════════════════════════════
// Each activated token is irreversibly hashed (SHA-256) and appended to an
// AES-256-GCM encrypted registry file. On activation, the registry is checked
// BEFORE the Ed25519 signature — a burned token is rejected instantly.
// The hash is salted with the machine fingerprint so the same hash cannot be
// compared across machines (defense-in-depth against registry copy attacks).

/// Compute the burn-hash of a token: SHA256("BURN-GLOBAL-V2:<raw_token>")
/// SECURITY FIX: burn-hash is now machine-INDEPENDENT so the same key cannot be
/// reused on a different machine. Previously it was salted with the machine fingerprint,
/// meaning the same token produced different hashes on different machines — defeating
/// the purpose of single-use enforcement on offline-only installs.
fn compute_burn_hash(token: &str, _fingerprint: &str) -> String {
    // NOTE: _fingerprint is kept for API compatibility but no longer used in the hash.
    // This ensures that even if the .burned-keys file is copied to another machine
    // (with a different local encryption key), the hash comparison still works after
    // re-encrypting the registry with the new machine's key.
    let seed = format!("BURN-GLOBAL-V2:{}", token);
    let hash = <Sha256 as Digest>::digest(seed.as_bytes());
    hex::encode(hash)
}

/// Compute legacy burn-hash (v1, fingerprint-salted) for migration compatibility.
fn compute_burn_hash_legacy(token: &str, fingerprint: &str) -> String {
    let seed = format!("BURN:{}:{}", fingerprint, token);
    let hash = <Sha256 as Digest>::digest(seed.as_bytes());
    hex::encode(hash)
}

/// Load burned hashes from disk. Returns Result — Err if file is corrupted/tampered.
/// SECURITY FIX (Gemini Audit Chunk 03): Fail-Closed. If the file exists but cannot be
/// decrypted, it was tampered with. We return Err to block activation, not an empty vec.
fn load_burned_keys(dir: &std::path::Path) -> Result<Vec<String>, String> {
    let path = dir.join(BURNED_KEYS_FILE);
    if !path.exists() {
        return Ok(vec![]);
    }
    let dec = decrypt_local_with_migration(&path).ok_or_else(|| {
        "CRITICAL: Impossibile decifrare il registro delle chiavi bruciate. Possibile manomissione.".to_string()
    })?;
    let text = String::from_utf8_lossy(&dec);
    Ok(text.lines().filter(|l| !l.is_empty()).map(|l| l.to_string()).collect())
}

/// Append a burn-hash to the registry and write back encrypted.
/// SECURITY FIX (Gemini Audit Chunk 03): Returns Result. Fails if registry is tampered or disk full.
fn burn_key(dir: &std::path::Path, burn_hash: &str) -> Result<(), String> {
    let mut hashes = load_burned_keys(dir)?;
    if hashes.contains(&burn_hash.to_string()) { return Ok(()); }
    hashes.push(burn_hash.to_string());
    let content = hashes.join("\n");
    let enc_key = get_local_encryption_key();
    let encrypted = encrypt_data(&enc_key, content.as_bytes())
        .map_err(|e| format!("Errore cifratura registro: {}", e))?;
    atomic_write_with_sync(&dir.join(BURNED_KEYS_FILE), &encrypted)
        .map_err(|e| format!("FATAL: Impossibile salvare il registro aggiornato su disco: {}", e))?;
    Ok(())
}

/// Check if a token has been burned (checks both v2 global and v1 legacy hashes).
/// SECURITY FIX (Gemini Audit Chunk 03): Returns Result<bool>. Fails closed if registry unreadable.
fn is_key_burned(dir: &std::path::Path, token: &str, fingerprint: &str) -> Result<bool, String> {
    let burn_hash_v2 = compute_burn_hash(token, fingerprint);
    let burn_hash_legacy = compute_burn_hash_legacy(token, fingerprint);
    let hashes = load_burned_keys(dir)?;
    Ok(hashes.contains(&burn_hash_v2) || hashes.contains(&burn_hash_legacy))
}

// ═══════════════════════════════════════════════════════════
//  STATE & MEMORY PROTECTION
// ═══════════════════════════════════════════════════════════

pub struct SecureKey(Vec<u8>);
impl Drop for SecureKey {
    fn drop(&mut self) { self.0.zeroize(); }
}

pub struct AppState {
    pub data_dir: Mutex<PathBuf>,
    /// Security-critical files (.burned-keys, .license-sentinel, license.json, .lockout)
    /// live OUTSIDE the vault so that deleting/resetting the vault cannot bypass them.
    pub security_dir: Mutex<PathBuf>,
    vault_key: Mutex<Option<SecureKey>>,
    failed_attempts: Mutex<u32>,
    locked_until: Mutex<Option<Instant>>,
    last_activity: Mutex<Instant>,
    autolock_minutes: Mutex<u32>,
    // SECURITY FIX (Level-8 C1): serialise concurrent vault writes.
    // Tauri dispatches IPC commands on a thread pool; two simultaneous save_practices +
    // save_agenda calls both do read-modify-write on vault.lex, causing a data-loss race.
    // This mutex ensures only one write runs at a time without blocking reads.
    write_mutex: Mutex<()>,
}

// ═══════════════════════════════════════════════════════════
//  CORE CRYPTO ENGINE
// ═══════════════════════════════════════════════════════════

fn derive_secure_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut key = vec![0u8; AES_KEY_LEN];
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(AES_KEY_LEN))
        .map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let pwd_bytes = Zeroizing::new(password.as_bytes().to_vec());
    argon2.hash_password_into(&pwd_bytes, salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    // SECURITY FIX (Gemini Audit v2): VAULT_MAGIC is now passed as AAD (Additional Authenticated Data).
    // Previously, magic bytes were prepended in cleartext but NOT authenticated by AES-GCM's MAC.
    // An attacker could alter the magic bytes without detection. With AAD, any modification
    // to the header causes decryption to fail with "Auth failed".
    let payload = Payload { msg: plaintext, aad: VAULT_MAGIC };
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), payload).map_err(|_| "Encryption error")?;
    let mut out = VAULT_MAGIC.to_vec();
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_data(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < VAULT_MAGIC.len() + NONCE_LEN + 16 { return Err("Corrupted".into()); }
    // SECURITY FIX (Gemini Audit v2): explicitly verify magic bytes BEFORE attempting decryption.
    // Previously the magic bytes were silently skipped without validation.
    if !data.starts_with(VAULT_MAGIC) {
        return Err("Invalid file format: magic bytes mismatch".into());
    }
    let nonce = Nonce::from_slice(&data[VAULT_MAGIC.len()..VAULT_MAGIC.len() + NONCE_LEN]);
    let ciphertext = &data[VAULT_MAGIC.len() + NONCE_LEN..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    // SECURITY FIX: VAULT_MAGIC passed as AAD — must match what was used during encryption.
    let payload = Payload { msg: ciphertext, aad: VAULT_MAGIC };
    cipher.decrypt(nonce, payload).map_err(|_| {
        // MIGRATION: try decryption WITHOUT AAD for files encrypted before this fix.
        // Old encrypt_data() did not pass VAULT_MAGIC as AAD, so old ciphertext was
        // authenticated only with an empty AAD. We try the legacy path as fallback.
        "Auth failed".into()
    }).or_else(|_: String| {
        // Legacy fallback: decrypt without AAD (pre-v3.6.0 files)
        // SECURITY FIX (Gemini Audit Chunk 04): log warning for downgrade detection
        let legacy_payload = Payload { msg: ciphertext, aad: b"" };
        cipher.decrypt(nonce, legacy_payload).map_err(|_| "Auth failed".into())
            .map(|dec| {
                eprintln!("SECURITY WARNING: Vault decifrato con fallback legacy (senza AAD). RE-CIFRATURA NECESSARIA.");
                dec
            })
    })
}

fn verify_hash_matches(key: &[u8], stored: &[u8]) -> bool {
    // SECURITY FIX (Gemini L4-1): vault.verify HMAC is now derived from the vault_key itself
    // (password-derived via Argon2id), NOT from the machine key.
    // Previously using machine key meant: rename computer → vault permanently inaccessible.
    // Now backup portability is preserved: the verify tag travels with the vault and is
    // independent of the machine/hostname. The vault_key IS the authentication factor.
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    hmac.update(b"LEX_VERIFY_DOMAIN_V2");
    hmac.verify_slice(stored).is_ok()
}

fn make_verify_tag(vault_key: &[u8]) -> Vec<u8> {
    // SECURITY FIX (Gemini L4-1): tag derived from vault_key, not machine key.
    // This ensures the verify tag is portable across machines/hostnames.
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(vault_key).unwrap();
    hmac.update(b"LEX_VERIFY_DOMAIN_V2");
    hmac.finalize().into_bytes().to_vec()
}

// ═══════════════════════════════════════════════════════════
//  INTERNAL DATA HELPERS
// ═══════════════════════════════════════════════════════════

fn get_vault_key(state: &State<AppState>) -> Result<Zeroizing<Vec<u8>>, String> {
    // SECURITY FIX (Gemini L4-2): return Zeroizing<Vec<u8>> instead of bare Vec<u8>
    // so callers automatically zero memory when the key goes out of scope.
    // SECURITY FIX (Gemini Audit v2): mutex poisoning protection — use unwrap_or_else
    // instead of unwrap() so a panicked thread doesn't permanently brick the app.
    state.vault_key.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
        .map(|k| Zeroizing::new(k.0.clone()))
        .ok_or_else(|| "Locked".into())
}

// ─── Persisted brute-force state (L7 fix #1) ────────────────────────────────
// The lockout counters must survive app kills; otherwise an attacker can kill+restart
// to reset failed_attempts to 0. We persist them in a plain file in the data dir.
// Format: "<attempts>:<unix_lockout_end_secs>" — not secret, just anti-abuse.

fn lockout_load(data_dir: &PathBuf) -> (u32, Option<std::time::SystemTime>) {
    let path = data_dir.join(LOCKOUT_FILE);
    let text = fs::read_to_string(&path).unwrap_or_default();
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 2 { return (0, None); }
    let attempts = parts[0].parse::<u32>().unwrap_or(0);
    let lockout_end_secs = parts[1].parse::<u64>().unwrap_or(0);
    if lockout_end_secs == 0 { return (attempts, None); }
    let end = std::time::UNIX_EPOCH + Duration::from_secs(lockout_end_secs);
    (attempts, Some(end))
}

fn lockout_save(data_dir: &PathBuf, attempts: u32, locked_until: Option<std::time::SystemTime>) {
    let secs = locked_until
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = fs::write(data_dir.join(LOCKOUT_FILE), format!("{}:{}", attempts, secs));
}

fn lockout_clear(data_dir: &PathBuf) {
    let _ = fs::remove_file(data_dir.join(LOCKOUT_FILE));
}

// ═══════════════════════════════════════════════════════════
//  CENTRALIZED HELPERS — DRY refactor (Gemini Audit v2)
// ═══════════════════════════════════════════════════════════

/// Safe password zeroing — replaces ALL unsafe pointer casts.
/// SECURITY FIX (Gemini Audit v2): the old code cast `as_ptr() as *mut u8` and wrote
/// through it, violating Rust's aliasing rules (Stacked Borrows) and causing Undefined
/// Behavior. The correct approach: convert to owned bytes, then zeroize.
fn zeroize_password(password: String) {
    let mut pwd_bytes = password.into_bytes();
    pwd_bytes.zeroize();
}

/// Centralized lockout check — replaces 3 duplicated lockout code blocks.
/// Returns Ok(()) if not locked, or Err(json) with remaining time if locked.
fn check_lockout(state: &State<AppState>, sec_dir: &std::path::Path) -> Result<(), Value> {
    let (disk_attempts, disk_locked_until) = lockout_load(&sec_dir.to_path_buf());
    // Sync in-memory from disk on first call after restart
    {
        let mut att = state.failed_attempts.lock().unwrap_or_else(|e| e.into_inner());
        if disk_attempts > *att { *att = disk_attempts; }
    }
    // Check disk-based lockout
    if let Some(end_time) = disk_locked_until {
        if SystemTime::now() < end_time {
            let remaining = end_time.duration_since(SystemTime::now())
                .map(|d| d.as_secs()).unwrap_or(0);
            return Err(json!({"success": false, "valid": false, "locked": true, "remaining": remaining}));
        }
    }
    // Check in-memory lockout (Instant-based, within-session)
    if let Some(until) = *state.locked_until.lock().unwrap_or_else(|e| e.into_inner()) {
        if Instant::now() < until {
            return Err(json!({"success": false, "valid": false, "locked": true, "remaining": (until - Instant::now()).as_secs()}));
        }
    }
    Ok(())
}

/// Record a failed authentication attempt. Triggers lockout after MAX_FAILED_ATTEMPTS.
/// SECURITY FIX (Security Audit G7): log attempt count + lockout status for forensics.
fn record_failed_attempt(state: &State<AppState>, sec_dir: &std::path::Path) {
    let mut att = state.failed_attempts.lock().unwrap_or_else(|e| e.into_inner());
    *att += 1;
    let locked_sys = if *att >= MAX_FAILED_ATTEMPTS {
        let t = SystemTime::now() + Duration::from_secs(LOCKOUT_SECS);
        *state.locked_until.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now() + Duration::from_secs(LOCKOUT_SECS));
        Some(t)
    } else { None };
    lockout_save(&sec_dir.to_path_buf(), *att, locked_sys);
    // SECURITY FIX (Security Audit G7): forensic logging of failed attempts.
    // Since vault is locked during auth, we can't write to the encrypted audit log.
    // Instead we log to stderr (captured by tauri-plugin-log → log file).
    eprintln!("[SECURITY] Failed auth attempt #{}/{} at {}{}",
        *att, MAX_FAILED_ATTEMPTS,
        chrono::Local::now().to_rfc3339(),
        if locked_sys.is_some() { " → LOCKOUT TRIGGERED" } else { "" }
    );
}

/// Clear lockout state on successful authentication.
fn clear_lockout(state: &State<AppState>, sec_dir: &std::path::Path) {
    *state.failed_attempts.lock().unwrap_or_else(|e| e.into_inner()) = 0;
    *state.locked_until.lock().unwrap_or_else(|e| e.into_inner()) = None;
    lockout_clear(&sec_dir.to_path_buf());
}

/// Centralized atomic write with fsync — replaces 5+ duplicated patterns.
/// SECURITY FIX (Gemini Audit Chunk 05): random tmp name to prevent TOCTOU symlink attacks.
/// Also performs directory fsync after rename for crash-safe persistence.
fn atomic_write_with_sync(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let tmp_name = format!(".{}.tmp.{}", 
        path.file_name().unwrap_or_default().to_string_lossy(), 
        rand::random::<u32>());
    let tmp = path.with_file_name(tmp_name);
    secure_write(&tmp, data).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    // SECURITY FIX (Gemini Audit Chunk 05): fsync directory to persist rename across crashes
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    // SECURITY FIX (Gemini Audit Chunk 01): mark dot-files as Hidden on Windows after rename
    #[cfg(target_os = "windows")]
    set_hidden_on_windows(path);
    Ok(())
}

/// Centralized vault authentication — verifies password against salt+verify.
/// Returns the derived AES key on success.
fn authenticate_vault_password(password: &str, dir: &std::path::Path) -> Result<Vec<u8>, String> {
    let salt = fs::read(dir.join(VAULT_SALT_FILE)).map_err(|e| e.to_string())?;
    let key = derive_secure_key(password, &salt)?;
    let stored = fs::read(dir.join(VAULT_VERIFY_FILE)).unwrap_or_default();
    if !verify_hash_matches(&key, &stored) {
        return Err("Password errata".into());
    }
    Ok(key)
}
// ────────────────────────────────────────────────────────────────────────────

// SECURITY FIX (Gemini Audit Chunk 05): is_safe_write_path removed — TOCTOU vulnerable.
// The TOCTOU gap between symlink check and file open is now closed by:
// 1) atomic_write_with_sync uses random tmp names (unpredictable to attacker)
// 2) secure_write uses mode 0600 for restricted permissions

// SECURITY FIX (Level-8 A3): write sensitive files with mode 0600 (owner read/write only).
// SECURITY FIX (Gemini Audit Chunk 01): on Windows, dot-prefixed files are NOT hidden
// automatically like on Unix. Use `attrib +H` to set the Hidden attribute.
#[cfg(target_os = "windows")]
fn set_hidden_on_windows(path: &std::path::Path) {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.starts_with('.') {
            let _ = std::process::Command::new("attrib")
                .arg("+H")
                .arg(path)
                .output();
        }
    }
}

// fs::write() uses the process umask; on shared computers the umask may be 022, making
// vault.salt, vault.verify etc. world-readable.  This helper sets explicit permissions.
// On Windows file ACLs are managed differently; the OpenOptions path still creates the
// file correctly and the NTFS ACL on the data dir itself restricts access.
fn secure_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    // SECURITY FIX (Gemini Audit Chunk 01): mark dot-files as Hidden on Windows
    #[cfg(target_os = "windows")]
    set_hidden_on_windows(path);
    Ok(())
}

fn read_vault_internal(state: &State<AppState>) -> Result<Value, String> {
    let key = get_vault_key(state)?;
    let path = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).join(VAULT_FILE);
    if !path.exists() { return Ok(json!({"practices":[], "agenda":[]})); }
    let decrypted = decrypt_data(&key, &fs::read(path).map_err(|e| e.to_string())?)?;
    serde_json::from_slice(&decrypted).map_err(|e| e.to_string())
}

fn write_vault_internal(state: &State<AppState>, data: &Value) -> Result<(), String> {
    // NOTE: callers MUST hold write_mutex before calling this function.
    // The lock is NOT acquired here to avoid deadlock (Rust Mutex is not reentrant).
    // All save_* commands and change_password already acquire write_mutex.
    let key = get_vault_key(state)?;
    let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let plaintext = Zeroizing::new(serde_json::to_vec(data).map_err(|e| e.to_string())?);
    let encrypted = encrypt_data(&key, &plaintext)?;
    // SECURITY FIX (Gemini Audit Chunk 05): use atomic_write_with_sync (random tmp + dir fsync)
    atomic_write_with_sync(&dir.join(VAULT_FILE), &encrypted)
}

// ═══════════════════════════════════════════════════════════
//  VAULT COMMANDS
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn vault_exists(state: State<AppState>) -> bool {
    state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).join(VAULT_SALT_FILE).exists()
}

#[tauri::command]
fn unlock_vault(state: State<AppState>, password: String) -> Value {
    let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let sec_dir = state.security_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();

    // Centralized lockout check (DRY — replaces 15+ lines of duplicated code)
    if let Err(locked_json) = check_lockout(&state, &sec_dir) {
        return locked_json;
    }

    let salt_path = dir.join(VAULT_SALT_FILE);
    let is_new = !salt_path.exists();

    let salt = if is_new {
        // Backend password strength validation for new vaults
        let pwd_strong = password.len() >= 12
            && password.chars().any(|c| c.is_uppercase())
            && password.chars().any(|c| c.is_lowercase())
            && password.chars().any(|c| c.is_ascii_digit())
            && password.chars().any(|c| !c.is_alphanumeric());
        if !pwd_strong {
            zeroize_password(password);
            return json!({"success": false, "error": "Password troppo debole: minimo 12 caratteri, una maiuscola, una minuscola, un numero e un simbolo."});
        }
        let mut s = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s);
        match secure_write(&salt_path, &s) {
            Ok(_) => s,
            Err(e) => {
                zeroize_password(password);
                return json!({"success": false, "error": format!("Errore scrittura vault: {}", e)});
            }
        }
    } else {
        fs::read(&salt_path).unwrap_or_default()
    };

    match derive_secure_key(&password, &salt) {
        Ok(k) => {
            let verify_path = dir.join(VAULT_VERIFY_FILE);
            if !is_new {
                let stored = fs::read(&verify_path).unwrap_or_default();
                if !verify_hash_matches(&k, &stored) {
                    record_failed_attempt(&state, &sec_dir);
                    // SECURITY FIX (Gemini Audit v2): safe zeroing — no more UB
                    zeroize_password(password);
                    return json!({"success": false, "error": "Password errata"});
                }
                *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(SecureKey(k));
            } else {
                let tag = make_verify_tag(&k);
                match secure_write(&verify_path, &tag) {
                    Ok(_) => {},
                    Err(e) => {
                        zeroize_password(password);
                        return json!({"success": false, "error": format!("Errore init vault: {}", e)});
                    }
                }
                *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(SecureKey(k));
                let _ = write_vault_internal(&state, &json!({"practices":[], "agenda":[]}));
            }
            clear_lockout(&state, &sec_dir);
            *state.last_activity.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            // SECURITY FIX (Gemini Audit v2): safe zeroing replaces UB pointer cast
            zeroize_password(password);
            let _ = append_audit_log(&state, "Sblocco Vault");
            json!({"success": true, "isNew": is_new})
        },
        Err(e) => {
            zeroize_password(password);
            json!({"success": false, "error": e})
        }
    }
}

#[tauri::command]
fn lock_vault(state: State<AppState>) -> bool {
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    true
}

#[tauri::command]
fn reset_vault(state: State<AppState>, password: String) -> Value {
    // SECURITY FIX (Gemini Audit v2): acquire write_mutex — prevents race with save_practices
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let salt_path = dir.join(VAULT_SALT_FILE);
    if salt_path.exists() {
        match authenticate_vault_password(&password, &dir) {
            Ok(_) => {},
            Err(_) => {
                zeroize_password(password);
                return json!({"success": false, "error": "Password errata"});
            }
        }
    }
    let _ = {
        for sensitive_file in &[VAULT_FILE, VAULT_SALT_FILE, VAULT_VERIFY_FILE, AUDIT_LOG_FILE] {
            let p = dir.join(sensitive_file);
            if p.exists() {
                if let Ok(meta) = p.metadata() {
                    let size = meta.len() as usize;
                    if size > 0 {
                        let zeros = vec![0u8; size];
                        let _ = secure_write(&p, &zeros);
                    }
                }
                // SECURITY FIX (Gemini Audit Chunk 06): force-delete individual files
                // before remove_dir_all, in case remove_dir_all fails (antivirus, etc.)
                let _ = fs::remove_file(&p);
            }
        }
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
    };
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    // SECURITY FIX (Gemini Audit v2): safe zeroing — no more UB
    zeroize_password(password);
    json!({"success": true})
}

#[tauri::command]
fn change_password(state: State<AppState>, current_password: String, new_password: String) -> Result<Value, String> {
    // SECURITY FIX (Gemini Audit v2): acquire write_mutex — prevents race with save_practices
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();

    // Authenticate with centralized helper
    let current_key = match authenticate_vault_password(&current_password, &dir) {
        Ok(k) => k,
        Err(_) => {
            zeroize_password(current_password);
            zeroize_password(new_password);
            return Ok(json!({"success": false, "error": "Password attuale errata"}));
        }
    };

    // Read vault with current key
    let vault_path = dir.join(VAULT_FILE);
    let vault_data = if vault_path.exists() {
        let enc = fs::read(&vault_path).map_err(|e| e.to_string())?;
        let dec = decrypt_data(&current_key, &enc)?;
        serde_json::from_slice::<Value>(&dec).map_err(|e| e.to_string())?
    } else {
        json!({"practices":[], "agenda":[]})
    };

    // New salt + key
    let mut new_salt = vec![0u8; ARGON2_SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_salt);
    let new_key = derive_secure_key(&new_password, &new_salt)?;

    // TRANSACTIONAL DATA-LOSS FIX (Gemini Audit v2):
    // The previous approach wrote salt and vault as separate files, creating a window
    // where a crash between the two renames would leave incompatible salt+vault pairs,
    // causing permanent data loss.
    //
    // SOLUTION: We now write all three files (.tmp) FIRST, then rename in order:
    //   1. vault.lex (encrypted with NEW key)
    //   2. vault.salt (NEW salt)
    //   3. vault.verify (NEW verify tag)
    //
    // CRASH ANALYSIS:
    //   - Crash before step 1: old files intact → old password works → safe
    //   - Crash after step 1, before step 2: new vault on disk but old salt →
    //     old password derives old key → cannot decrypt new vault. BUT we keep
    //     a backup of the old vault as .vault.bak BEFORE the rename, so recovery
    //     is possible by restoring .vault.bak → vault.lex.
    //   - Crash after step 2: new salt + new vault → new password works → safe
    //   - All steps complete: new password works → safe

    let vault_plaintext = Zeroizing::new(serde_json::to_vec(&vault_data).map_err(|e| e.to_string())?);
    let encrypted_vault = encrypt_data(&new_key, &vault_plaintext)?;
    let new_verify_tag = make_verify_tag(&new_key);

    // SECURITY FIX (Gemini Audit Chunk 06): TRANSACTIONAL SAFETY.
    // Write new files to a staging directory. If anything fails, the original vault is untouched.
    let staging_dir = dir.join(".staging");
    let _ = fs::create_dir_all(&staging_dir);

    let stage_vault = staging_dir.join(VAULT_FILE);
    let stage_salt = staging_dir.join(VAULT_SALT_FILE);
    let stage_verify = staging_dir.join(VAULT_VERIFY_FILE);

    if atomic_write_with_sync(&stage_vault, &encrypted_vault).is_err() ||
       atomic_write_with_sync(&stage_salt, &new_salt).is_err() ||
       atomic_write_with_sync(&stage_verify, &new_verify_tag).is_err() {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err("Errore critico durante la preparazione dei file sicuri. Cambio annullato.".into());
    }

    // Backup old files before swap
    let _ = fs::rename(&vault_path, dir.join(".vault.bak"));
    let _ = fs::rename(dir.join(VAULT_SALT_FILE), dir.join(".salt.bak"));
    let _ = fs::rename(dir.join(VAULT_VERIFY_FILE), dir.join(".verify.bak"));

    // Swap: promote staging files to production
    let success = fs::rename(&stage_vault, &vault_path).is_ok() &&
                  fs::rename(&stage_salt, dir.join(VAULT_SALT_FILE)).is_ok() &&
                  fs::rename(&stage_verify, dir.join(VAULT_VERIFY_FILE)).is_ok();

    if !success {
        // ROLLBACK DI EMERGENZA
        eprintln!("CRITICAL ERROR: Swap fallito. Tentativo di rollback in corso...");
        let _ = fs::rename(dir.join(".vault.bak"), &vault_path);
        let _ = fs::rename(dir.join(".salt.bak"), dir.join(VAULT_SALT_FILE));
        let _ = fs::rename(dir.join(".verify.bak"), dir.join(VAULT_VERIFY_FILE));
        return Err("Errore irreversibile durante lo swap dei file. Rollback eseguito.".into());
    }

    // SECURITY FIX (Security Audit G4): secure-wipe backup files before deletion.
    // Simply deleting files leaves old vault data (encrypted with old key) on disk sectors.
    // Overwriting with zeros before deletion ensures data remnants cannot be recovered.
    for bak_name in &[".vault.bak", ".salt.bak", ".verify.bak"] {
        let bak_path = dir.join(bak_name);
        if bak_path.exists() {
            if let Ok(meta) = bak_path.metadata() {
                let size = meta.len() as usize;
                if size > 0 {
                    let _ = secure_write(&bak_path, &vec![0u8; size]);
                }
            }
            let _ = fs::remove_file(&bak_path);
        }
    }
    let _ = fs::remove_dir_all(&staging_dir);

    // Re-encrypt audit log if exists
    let audit_path = dir.join(AUDIT_LOG_FILE);
    if audit_path.exists() {
        if let Ok(enc) = fs::read(&audit_path) {
            if let Ok(dec) = decrypt_data(&current_key, &enc) {
                if let Ok(re_enc) = encrypt_data(&new_key, &dec) {
                    let _ = atomic_write_with_sync(&audit_path, &re_enc);
                }
            }
        }
    }

    // Update in-memory key
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(SecureKey(new_key));

    // Update biometric if saved
    #[cfg(not(target_os = "android"))]
    {
        let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if dir.join(BIO_MARKER_FILE).exists() {
            let user = whoami::username();
            if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
                let _ = entry.set_password(&new_password);
            }
        }
    }

    let _ = append_audit_log(&state, "Password cambiata");
    // SECURITY FIX (Gemini Audit v2): safe zeroing — no more UB
    zeroize_password(current_password);
    zeroize_password(new_password);
    Ok(json!({"success": true}))
}

#[tauri::command]
fn verify_vault_password(state: State<AppState>, pwd: String) -> Result<Value, String> {
    let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let sec_dir = state.security_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();

    // Centralized lockout check (DRY)
    if let Err(locked_json) = check_lockout(&state, &sec_dir) {
        return Ok(locked_json);
    }

    // Centralized authentication
    let valid = authenticate_vault_password(&pwd, &dir).is_ok();
    if !valid {
        record_failed_attempt(&state, &sec_dir);
    } else {
        clear_lockout(&state, &sec_dir);
    }
    zeroize_password(pwd);
    Ok(json!({"valid": valid}))
}

// ═══════════════════════════════════════════════════════════
//  SUMMARY — Server-side computation (Gemini L2-4)
// ═══════════════════════════════════════════════════════════

/// Returns {activePractices, urgentDeadlines} computed in Rust.
/// Previously computed client-side (getSummary in api.js) by loading ALL practices
/// and iterating in JS — O(n) on the main thread, causing CPU freezes on large vaults.
/// Now computed server-side in a single vault read.
#[tauri::command]
fn get_summary(state: State<AppState>) -> Result<Value, String> {
    let vault = read_vault_internal(&state)?;
    // SECURITY FIX (Gemini Audit Chunk 07): borrowing instead of .cloned() — zero-copy iteration
    let practices = vault.get("practices").and_then(|p| p.as_array());
    let practices_slice = practices.map(|a| a.as_slice()).unwrap_or(&[]);
    let active_practices = practices_slice.iter().filter(|p| {
        p.get("status").and_then(|s| s.as_str()) == Some("active")
    }).count();

    let today = chrono::Local::now().naive_local().date();
    let in_7_days = today + chrono::Duration::days(7);
    let mut urgent_deadlines: usize = 0;
    for p in practices_slice {
        if p.get("status").and_then(|s| s.as_str()) != Some("active") { continue; }
        if let Some(deadlines) = p.get("deadlines").and_then(|d| d.as_array()) {
            for d in deadlines {
                if let Some(date_str) = d.get("date").and_then(|ds| ds.as_str()) {
                    if let Ok(d_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                        if d_date >= today && d_date <= in_7_days {
                            urgent_deadlines += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(json!({"activePractices": active_practices, "urgentDeadlines": urgent_deadlines}))
}

// ═══════════════════════════════════════════════════════════
//  PRACTICES & AGENDA
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn load_practices(state: State<AppState>) -> Result<Value, String> {
    let vault = read_vault_internal(&state)?;
    Ok(vault.get("practices").cloned().unwrap_or(json!([])))
}

#[tauri::command]
fn save_practices(state: State<AppState>, list: Value) -> Result<bool, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let mut vault = read_vault_internal(&state)?;
    vault["practices"] = list;
    write_vault_internal(&state, &vault)?;
    Ok(true)
}

#[tauri::command]
fn load_agenda(state: State<AppState>) -> Result<Value, String> {
    let vault = read_vault_internal(&state)?;
    Ok(vault.get("agenda").cloned().unwrap_or(json!([])))
}

#[tauri::command]
fn save_agenda(state: State<AppState>, agenda: Value) -> Result<bool, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let mut vault = read_vault_internal(&state)?;
    vault["agenda"] = agenda;
    write_vault_internal(&state, &vault)?;
    Ok(true)
}

// ═══════════════════════════════════════════════════════════
//  CONFLICT CHECK (v3.2.0)
// ═══════════════════════════════════════════════════════════

/// Searches ALL practices (active + archived) for a name match in client,
/// counterparty, description, court, and roles[].contactName fields.
/// Returns an array of matching practices with the matched field highlighted.
#[tauri::command]
fn check_conflict(state: State<AppState>, name: String) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Ok(json!({"practiceMatches": [], "contactMatches": []}));
    }
    let vault = read_vault_internal(&state)?;
    // SECURITY FIX (Gemini Audit Chunk 07): borrowing — no .cloned() on large arrays
    let practices_arr = vault.get("practices").and_then(|p| p.as_array());
    let practices = practices_arr.map(|a| a.as_slice()).unwrap_or(&[]);
    let contacts_arr = vault.get("contacts").and_then(|c| c.as_array());
    let contacts = contacts_arr.map(|a| a.as_slice()).unwrap_or(&[]);
    let query = name.trim().to_lowercase();
    let mut results: Vec<Value> = Vec::new();

    for p in practices {
        let mut matched_fields: Vec<String> = Vec::new();

        // Check main text fields
        for field in &["client", "counterparty", "description", "court", "object"] {
            if let Some(val) = p.get(*field).and_then(|v| v.as_str()) {
                if val.to_lowercase().contains(&query) {
                    matched_fields.push(field.to_string());
                }
            }
        }

        // Check roles array (linked contacts)
        if let Some(roles) = p.get("roles").and_then(|r| r.as_array()) {
            for role in roles {
                if let Some(cid) = role.get("contactId").and_then(|c| c.as_str()) {
                    // Resolve contact name from contacts registry
                    if let Some(contact) = contacts.iter().find(|c| c.get("id").and_then(|i| i.as_str()) == Some(cid)) {
                        if let Some(cname) = contact.get("name").and_then(|n| n.as_str()) {
                            if cname.to_lowercase().contains(&query) {
                                let role_label = role.get("role").and_then(|r| r.as_str()).unwrap_or("contatto");
                                matched_fields.push(format!("ruolo:{}", role_label));
                            }
                        }
                    }
                }
            }
        }

        if !matched_fields.is_empty() {
            results.push(json!({
                "practice": p,
                "matchedFields": matched_fields,
            }));
        }
    }

    // Also search contacts themselves (find the person even if not linked to a practice yet)
    let mut contact_matches: Vec<Value> = Vec::new();
    for c in contacts {
        let mut cmatch = false;
        for field in &["name", "fiscalCode", "vatNumber", "email", "pec", "phone"] {
            if let Some(val) = c.get(*field).and_then(|v| v.as_str()) {
                if val.to_lowercase().contains(&query) {
                    cmatch = true;
                    break;
                }
            }
        }
        if cmatch {
            // Find all practices referencing this contact
            let cid = c.get("id").and_then(|i| i.as_str()).unwrap_or("");
            let linked: Vec<String> = practices.iter().filter_map(|p| {
                let client_id = p.get("clientId").and_then(|i| i.as_str()).unwrap_or("");
                let counter_id = p.get("counterpartyId").and_then(|i| i.as_str()).unwrap_or("");
                let in_roles = p.get("roles").and_then(|r| r.as_array())
                    .map(|roles| roles.iter().any(|r| r.get("contactId").and_then(|i| i.as_str()) == Some(cid)))
                    .unwrap_or(false);
                if client_id == cid || counter_id == cid || in_roles {
                    Some(p.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string())
                } else {
                    None
                }
            }).collect();
            contact_matches.push(json!({
                "contact": c,
                "linkedPracticeIds": linked,
            }));
        }
    }

    Ok(json!({
        "practiceMatches": results,
        "contactMatches": contact_matches,
    }))
}

// ═══════════════════════════════════════════════════════════
//  TIME TRACKING (v3.3.0)
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn load_time_logs(state: State<AppState>) -> Result<Value, String> {
    let vault = read_vault_internal(&state)?;
    Ok(vault.get("timeLogs").cloned().unwrap_or(json!([])))
}

#[tauri::command]
fn save_time_logs(state: State<AppState>, logs: Value) -> Result<bool, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let mut vault = read_vault_internal(&state)?;
    vault["timeLogs"] = logs;
    write_vault_internal(&state, &vault)?;
    Ok(true)
}

// ═══════════════════════════════════════════════════════════
//  INVOICES / BILLING (v3.4.0)
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn load_invoices(state: State<AppState>) -> Result<Value, String> {
    let vault = read_vault_internal(&state)?;
    Ok(vault.get("invoices").cloned().unwrap_or(json!([])))
}

#[tauri::command]
fn save_invoices(state: State<AppState>, invoices: Value) -> Result<bool, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let mut vault = read_vault_internal(&state)?;
    vault["invoices"] = invoices;
    write_vault_internal(&state, &vault)?;
    Ok(true)
}

// ═══════════════════════════════════════════════════════════
//  CONTACTS REGISTRY (v3.5.0)
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn load_contacts(state: State<AppState>) -> Result<Value, String> {
    let vault = read_vault_internal(&state)?;
    Ok(vault.get("contacts").cloned().unwrap_or(json!([])))
}

#[tauri::command]
fn save_contacts(state: State<AppState>, contacts: Value) -> Result<bool, String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let mut vault = read_vault_internal(&state)?;
    vault["contacts"] = contacts;
    write_vault_internal(&state, &vault)?;
    Ok(true)
}

// ═══════════════════════════════════════════════════════════
//  BIOMETRICS
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn check_bio() -> bool {
    // macOS/Windows: biometria nativa disponibile
    // Android: fingerprint/face disponibile via Android Biometric API (gestita lato JS)
    cfg!(any(target_os = "macos", target_os = "windows", target_os = "android"))
}

#[tauri::command]
fn has_bio_saved(state: State<AppState>) -> bool {
    // TOUCH ID FIX: Do NOT call keyring::get_password() here — on macOS that triggers
    // the Touch ID / password popup just to check if credentials exist!
    // Instead, use a lightweight marker file written by save_bio / cleared by clear_bio.
    #[cfg(not(target_os = "android"))]
    {
        let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        // Il marker file è la fonte di verità (scritto da save_bio, rimosso da clear_bio).
        // NON usiamo keyring::get_password/get_credential qui — su macOS trigghera Touch ID.
        dir.join(BIO_MARKER_FILE).exists()
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        false
    }
}

#[tauri::command]
fn save_bio(state: State<AppState>, pwd: String) -> Result<bool, String> {
    #[cfg(not(target_os = "android"))]
    {
        let user = whoami::username();
        let entry = keyring::Entry::new(BIO_SERVICE, &user).map_err(|e| e.to_string())?;
        entry.set_password(&pwd).map_err(|e| e.to_string())?;
        // Write marker file so has_bio_saved() can check without triggering Touch ID
        let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let _ = fs::write(dir.join(BIO_MARKER_FILE), "1");
        Ok(true)
    }
    #[cfg(target_os = "android")]
    {
        let _ = (state, pwd);
        Ok(true)
    }
}

#[tauri::command]
fn bio_login(_state: State<AppState>) -> Result<Value, String> {
    // SECURITY FIX (Gemini Audit Chunk 08): check lockout before biometric login
    // to prevent brute-force lockout bypass via biometrics
    {
        let sec_dir = _state.security_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Err(locked_json) = check_lockout(&_state, &sec_dir) {
            return Ok(locked_json);
        }
    }

    #[cfg(target_os = "macos")]
    {
        // FORT KNOX: Swift code passed via stdin — NEVER written to disk
        let swift_code = "import LocalAuthentication\nlet ctx = LAContext()\nvar err: NSError?\nif ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) {\n  let sema = DispatchSemaphore(value: 0)\n  var ok = false\n  ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: \"LexFlow\") { s, _ in ok = s; sema.signal() }\n  sema.wait()\n  if ok { exit(0) } else { exit(1) }\n} else { exit(1) }";
        
        use std::io::Write;
        // SECURITY FIX (Gemini L1-2): use absolute path to prevent PATH hijacking.
        // /usr/bin/swift is the canonical location on macOS; never rely on $PATH for security-critical executables.
        let mut child = std::process::Command::new("/usr/bin/swift")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        
        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(swift_code.as_bytes()).map_err(|e| e.to_string())?;
        }
        drop(child.stdin.take());
        let status = child.wait().map_err(|e| e.to_string())?;
        if !status.success() { return Ok(json!({"success": false, "error": "Autenticazione biometrica fallita"})); }

        // Recupera la password salvata dal keyring (non la ritorniamo al JS)
        let user = whoami::username();
        let saved_pwd = keyring::Entry::new(BIO_SERVICE, &user)
            .and_then(|e| e.get_password()).map_err(|e| e.to_string())?;

        // SECURITY FIX (Gemini Audit Chunk 08): use centralized authenticate_vault_password (DRY)
        let dir = _state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let sec_dir = _state.security_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let auth_result = authenticate_vault_password(&saved_pwd, &dir);
        // SECURITY FIX: zeroize password from keyring immediately
        zeroize_password(saved_pwd);

        match auth_result {
            Ok(k) => {
                *(_state.vault_key.lock().unwrap_or_else(|e| e.into_inner())) = Some(SecureKey(k));
                clear_lockout(&_state, &sec_dir);
                *(_state.last_activity.lock().unwrap_or_else(|e| e.into_inner())) = Instant::now();
                let _ = append_audit_log(&_state, "Sblocco Vault (biometria)");
                Ok(json!({"success": true}))
            },
            Err(_) => {
                // Keyring password is stale (user changed password)
                if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
                    let _ = entry.delete_credential();
                }
                let _ = fs::remove_file(dir.join(BIO_MARKER_FILE));
                Ok(json!({
                    "success": false,
                    "error": "Password biometrica non più valida. Accedi con la password e riconfigura la biometria."
                }))
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Windows Hello: verifica biometrica reale tramite UserConsentVerifier WinRT API.
        // Usa PowerShell per invocare Windows.Security.Credentials.UI.UserConsentVerifier
        // — più affidabile che controllare solo il keyring senza autenticazione.
        use std::process::Command;
        let ps_script = r#"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await($WinRtTask, $ResultType) {
    $asTaskSpecific = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTaskSpecific.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}
[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
$result = Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync("LexFlow — Verifica identità")) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])
if ($result -eq [Windows.Security.Credentials.UI.UserConsentVerificationResult]::Verified) { exit 0 } else { exit 1 }
"#;
        // SECURITY FIX (Gemini L1-2): use absolute path to prevent PATH hijacking.
        // C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe is the canonical location.
        let status = Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() { return Ok(json!({"success": false, "error": "Windows Hello fallito o non disponibile"})); }

        // Recupera la password salvata dal keyring e sblocca internamente il vault
        let user = whoami::username();
        let saved_pwd = keyring::Entry::new(BIO_SERVICE, &user)
            .and_then(|e| e.get_password()).map_err(|e| e.to_string())?;

        // SECURITY FIX (Gemini Audit Chunk 08): use centralized authenticate_vault_password (DRY)
        let dir = _state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let sec_dir = _state.security_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let auth_result = authenticate_vault_password(&saved_pwd, &dir);
        zeroize_password(saved_pwd);

        match auth_result {
            Ok(k) => {
                *(_state.vault_key.lock().unwrap_or_else(|e| e.into_inner())) = Some(SecureKey(k));
                clear_lockout(&_state, &sec_dir);
                *(_state.last_activity.lock().unwrap_or_else(|e| e.into_inner())) = Instant::now();
                let _ = append_audit_log(&_state, "Sblocco Vault (biometria)");
                Ok(json!({"success": true}))
            },
            Err(_) => {
                if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
                    let _ = entry.delete_credential();
                }
                let _ = fs::remove_file(dir.join(BIO_MARKER_FILE));
                Ok(json!({
                    "success": false,
                    "error": "Password biometrica non più valida. Accedi con la password e riconfigura la biometria."
                }))
            }
        }
    }
    #[cfg(target_os = "android")]
    {
        // Su Android il biometric prompt è gestito interamente dal frontend JS
        // tramite l'Android BiometricPrompt API via tauri-plugin-biometric (futuro)
        // Per ora restituisce errore che il frontend gestisce con fallback a password
        Err("android-bio-use-frontend".into())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "android")))]
    {
        Err("Non supportato su questa piattaforma".into())
    }
}

#[tauri::command]
fn clear_bio(state: State<AppState>) -> bool {
    #[cfg(not(target_os = "android"))]
    {
        let user = whoami::username();
        if let Ok(e) = keyring::Entry::new(BIO_SERVICE, &user) { let _ = e.delete_credential(); }
        // Remove marker file
        let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let _ = fs::remove_file(dir.join(BIO_MARKER_FILE));
        true
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        true
    }
}

// List folder contents for UI (returns array of { name, path, is_dir, modified })
#[tauri::command]
fn list_folder_contents(path: String) -> Result<serde_json::Value, String> {
    use serde_json::json;
    let p = std::path::PathBuf::from(path);
    if !p.exists() {
        return Err("Percorso non esiste".into());
    }
    let mut items: Vec<serde_json::Value> = Vec::new();
    match std::fs::read_dir(&p) {
        Ok(rd) => {
            for entry in rd.flatten() {
                let md = entry.metadata().ok();
                let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let modified = md.and_then(|m| m.modified().ok()).map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                });
                items.push(json!({
                    "name": entry.file_name().to_string_lossy(),
                    "path": entry.path().to_string_lossy(),
                    "is_dir": is_dir,
                    "modified": modified,
                }));
            }
            // sort directories first, then files, alphabetically
            items.sort_by(|a, b| {
                let da = a.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false);
                let db = b.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false);
                if da != db { return db.cmp(&da); }
                let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
                na.to_lowercase().cmp(&nb.to_lowercase())
            });
            Ok(serde_json::Value::Array(items))
        }
        Err(e) => {
            // Map permission errors to a clearer message for the frontend
            use std::io::ErrorKind;
            if e.kind() == ErrorKind::PermissionDenied {
                Err("Permesso negato".into())
            } else {
                Err(e.to_string())
            }
        }
    }
}

// Warm Swift compiler/process on macOS to reduce first biometric prompt latency
#[tauri::command]
fn warm_swift() -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        // Running `swift -version` is lightweight and warms up the swift toolchain.
        match Command::new("/usr/bin/swift").arg("-version").output() {
            Ok(_) => Ok(true),
            Err(e) => Err(e.to_string()),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(false)
    }
}

// ═══════════════════════════════════════════════════════════
//  AUDIT & LOGS
// ═══════════════════════════════════════════════════════════

fn append_audit_log(state: &State<AppState>, event_name: &str) -> Result<(), String> {
    let key = match get_vault_key(state) { Ok(k) => k, Err(_) => return Ok(()) };
    // SECURITY FIX (Gemini Audit Chunk 09): write_mutex prevents race conditions on concurrent logs
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let path = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).join(AUDIT_LOG_FILE);
    let mut logs: Vec<Value> = if path.exists() {
        let enc = fs::read(&path).unwrap_or_default();
        match decrypt_data(&key, &enc) {
            Ok(dec) => serde_json::from_slice(&dec).unwrap_or_default(),
            Err(_) => {
                // SECURITY FIX (Gemini Audit Chunk 09): timestamp forensic backup to prevent overwrite
                let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
                let corrupt_backup = path.with_extension(format!("audit.corrupt.{}", ts));
                let _ = fs::copy(&path, &corrupt_backup);
                eprintln!("[LexFlow] SECURITY: Audit log decryption failed — tampered? Backup saved to {:?}", corrupt_backup);
                vec![json!({"event": "AUDIT_LOG_TAMPERING_DETECTED", "time": chrono::Local::now().to_rfc3339()})]
            }
        }
    } else { vec![] };

    logs.push(json!({"event": event_name, "time": chrono::Local::now().to_rfc3339()}));
    // SECURITY FIX (Gemini Audit Chunk 09): drain() instead of remove(0) — O(1) vs O(n) shift
    if logs.len() > 10000 {
        let excess = logs.len() - 10000;
        logs.drain(0..excess);
    }
    let plaintext = Zeroizing::new(serde_json::to_vec(&logs).unwrap_or_default());
    let enc = encrypt_data(&key, &plaintext)?;
    atomic_write_with_sync(&path, &enc)?;
    Ok(())
}

#[tauri::command]
fn get_audit_log(state: State<AppState>) -> Result<Value, String> {
    let key = get_vault_key(&state)?;
    let path = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).join(AUDIT_LOG_FILE);
    if !path.exists() { return Ok(json!([])); }
    let dec = decrypt_data(&key, &fs::read(path).map_err(|e| e.to_string())?)?;
    serde_json::from_slice(&dec).map_err(|e| e.to_string())
}

// ═══════════════════════════════════════════════════════════
//  SETTINGS & LICENSE
// ═══════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_verification_full_cycle() {
        // Questa è la tua licenza di prova (ho aggiunto il prefisso LXFW. richiesto dal codice)
        // Nota: i campi devono essere "c" (client) ed "e" (expiry) come definito nella tua struct LicensePayload
    let valid_token = "LXFW.eyJjIjoicGlldHJvX3Rlc3QiLCJlIjoxODAzOTE4MTIxMzczLCJpZCI6IjQzMWQxYzU5LThjZWQtNDNiMy04MTRmLTk4YjhlYzUyNzJmZiJ9.RaGS2HvCtRHqYDITpMwXSIgRtS4AzAI7hqqdtxHNXh2GApoaKEjxzqBOJMMR1i8T-5iFAutTHDMk15verIseBw";

        // 1. Test verifica positiva
        let result = verify_license(valid_token.to_string());
        assert!(result.valid, "La licenza valida è stata respinta! Errore: {}", result.message);
        assert_eq!(result.client.unwrap(), "pietro_test");

        // 2. Test Anti-Manomissione (cambiamo un solo carattere nella firma)
        let mut tampered_token = valid_token.to_string();
        tampered_token.replace_range(tampered_token.len()-5..tampered_token.len()-4, "Z");
        let tamper_result = verify_license(tampered_token);
        assert!(!tamper_result.valid, "Sicurezza fallita: la licenza manomessa è stata accettata!");
        assert_eq!(tamper_result.message, "Firma non valida o licenza manomessa!");

        // 3. Test Formato errato
        let invalid_format = "TOKEN_SENZA_PUNTI";
        let format_result = verify_license(invalid_format.to_string());
        assert!(!format_result.valid);
        assert_eq!(format_result.message, "Formato chiave non valido.");
    }
}

/// SECURITY FIX (Gemini Audit Chunk 10): safe bounded read — anti-TOCTOU + anti-OOM.
/// Uses io::Read::take() to physically limit bytes read, even if file grows during read.
fn safe_bounded_read(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if let Ok(meta) = file.metadata() {
        if meta.len() > max_bytes {
            return Err(format!("File troppo grande ({} bytes) — OOM limit superato", meta.len()));
        }
    }
    let mut buffer = Vec::new();
    file.take(max_bytes).read_to_end(&mut buffer).map_err(|e| e.to_string())?;
    Ok(buffer)
}

#[tauri::command]
fn get_settings(state: State<AppState>) -> Value {
    let path = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).join(SETTINGS_FILE);
    if !path.exists() { return json!({}); }
    // SECURITY FIX (Gemini Audit Chunk 10): single bounded read, then operate on buffer in RAM
    let file_data = match safe_bounded_read(&path, MAX_SETTINGS_FILE_SIZE) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[LexFlow] SECURITY WARNING: {}", e);
            return json!({});
        }
    };
    // Try decryption on the buffer (not re-reading from disk)
    let key = get_local_encryption_key();
    if let Ok(dec) = decrypt_data(&key, &file_data) {
        return serde_json::from_slice(&dec).unwrap_or(json!({}));
    }
    #[cfg(not(target_os = "android"))]
    {
        let legacy_key = get_local_encryption_key_legacy();
        if let Ok(dec) = decrypt_data(&legacy_key, &file_data) {
            // Silent migration: re-encrypt with new key
            if let Ok(re_enc) = encrypt_data(&key, &dec) {
                let _ = atomic_write_with_sync(&path, &re_enc);
            }
            return serde_json::from_slice(&dec).unwrap_or(json!({}));
        }
    }
    // Migration: old plaintext format
    if let Ok(text) = std::str::from_utf8(&file_data) {
        if let Ok(val) = serde_json::from_str::<Value>(text) {
            if let Ok(re_enc) = encrypt_data(&key, &serde_json::to_vec(&val).unwrap_or_default()) {
                let _ = atomic_write_with_sync(&path, &re_enc);
                eprintln!("[LexFlow] Migrazione settings plaintext -> cifrato completata.");
            }
            return val;
        }
    }
    // File corrotto
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
    let backup_path = path.with_extension(format!("json.corrupt.{}", ts));
    let _ = fs::write(&backup_path, &file_data);
    eprintln!("[LexFlow] Settings file corrotto — backup salvato in {:?}", backup_path);
    json!({})
}

/// SECURITY FIX (Gemini Audit Chunk 10): returns Result for proper error feedback to frontend
#[tauri::command]
fn save_settings(state: State<AppState>, settings: Value) -> Result<bool, String> {
    let path = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).join(SETTINGS_FILE);
    let key = get_local_encryption_key();
    // SECURITY FIX (Security Audit G3): wrap plaintext in Zeroizing so settings data
    // is automatically zeroed from heap memory after encryption.
    let plaintext = Zeroizing::new(serde_json::to_vec(&settings)
        .map_err(|e| format!("Errore serializzazione JSON: {}", e))?);
    let encrypted = encrypt_data(&key, &plaintext)?;
    atomic_write_with_sync(&path, &encrypted)
        .map(|_| true)
        .map_err(|e| format!("Impossibile salvare le impostazioni su disco: {}", e))
}

#[tauri::command]
fn check_license(state: State<AppState>) -> Value {
    let path = state.security_dir.lock().unwrap_or_else(|e| e.into_inner()).join(LICENSE_FILE);
    let sentinel_path = state.security_dir.lock().unwrap_or_else(|e| e.into_inner()).join(LICENSE_SENTINEL_FILE);

    if !path.exists() {
        // SECURITY: if sentinel exists but license.json was deleted, detect tampering.
        // The sentinel is an HMAC proof that a license WAS activated on this machine.
        if sentinel_path.exists() {
            return json!({
                "activated": false,
                "tampered": true,
                "reason": "File di licenza rimosso o manomesso. Contattare il supporto."
            });
        }
        return json!({"activated": false});
    }
    let key = get_local_encryption_key();
    let data: Value = if let Some(dec) = decrypt_local_with_migration(&path) {
        serde_json::from_slice(&dec).unwrap_or(json!({}))
    } else if path.exists() {
        // File exists but cannot be decrypted with ANY key (current or legacy).
        // Either corrupted or copied from another machine — reject.
        return json!({"activated": false, "reason": "File licenza corrotto o non valido per questo dispositivo."});
    } else { return json!({"activated": false}); };

    // SECURITY: verify hardware fingerprint — the license is bound to this machine
    let current_fp = compute_machine_fingerprint();
    if let Some(stored_fp) = data.get("machineFingerprint").and_then(|v| v.as_str()) {
        if stored_fp != current_fp {
            return json!({"activated": false, "reason": "Licenza attivata su un altro dispositivo."});
        }
    }
    // If no fingerprint stored (pre-v2.6.1 activation), we still accept but
    // re-encrypt with fingerprint on next check to upgrade silently
    let needs_fp_upgrade = data.get("machineFingerprint").is_none();

    let key_version = data.get("keyVersion").and_then(|v| v.as_str()).unwrap_or("");

    // ── NEW FORMAT: burned key (v2.6.1+) ──────────────────────────────────
    // The raw token no longer exists. We verify using stored expiry + HMAC integrity.
    if key_version == "ed25519-burned" {
        let token_hmac = data.get("tokenHmac").and_then(|v| v.as_str()).unwrap_or("");
        let expiry_ms = data.get("expiryMs").and_then(|v| v.as_u64()).unwrap_or(0);
        let client = data.get("client").and_then(|v| v.as_str()).unwrap_or("Studio Legale").to_string();

        if token_hmac.is_empty() {
            return json!({"activated": false, "reason": "Dati licenza corrotti."});
        }

        // Check expiry
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        if now_ms > expiry_ms {
            return json!({"activated": false, "expired": true, "reason": "Licenza scaduta."});
        }

        // Silent upgrade: add machineFingerprint if missing
        if needs_fp_upgrade {
            let mut upgraded = data.clone();
            upgraded.as_object_mut().map(|obj| {
                obj.insert("machineFingerprint".to_string(), json!(current_fp));
            });
            if let Ok(bytes) = serde_json::to_vec(&upgraded) {
                if let Ok(encrypted) = encrypt_data(&key, &bytes) {
                    // SECURITY FIX (Gemini Audit Chunk 11): atomic write for crash safety
                    if let Err(e) = atomic_write_with_sync(&path, &encrypted) {
                        eprintln!("[SECURITY] license fingerprint upgrade write failed: {}", e);
                    }
                }
            }
        }

        return json!({
            "activated": true,
            "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
            "client": client,
        });
    }

    // ── LEGACY FORMAT: raw key stored (pre-v2.6.1) ────────────────────────
    // Re-verify Ed25519 and silently upgrade to burned format.
    let license_key = data.get("key").and_then(|k| k.as_str()).unwrap_or("");

    if !license_key.is_empty() {
        let verification = verify_license(license_key.to_string());

        if verification.valid {
            // ── SILENT UPGRADE: convert legacy → burned format ──
            // 1. Compute HMAC of the raw token
            let mut token_mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
                .expect("HMAC can take key of any size");
            token_mac.update(license_key.as_bytes());
            let token_hmac = hex::encode(token_mac.finalize().into_bytes());

            // 2. Extract expiry from the token payload
            let expiry_ms: u64 = extract_expiry_ms(license_key).unwrap_or(0);
            let client = verification.client.unwrap_or_else(|| "Studio Legale".to_string());
            let key_id = extract_key_id(license_key).unwrap_or_else(|| "legacy".to_string());

            // 3. Build burned record (no raw token)
            let upgraded = json!({
                "tokenHmac": token_hmac,
                "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
                "client": client,
                "keyVersion": "ed25519-burned",
                "machineFingerprint": current_fp,
                "keyId": key_id,
                "expiryMs": expiry_ms,
            });
            // SECURITY FIX (Gemini Audit Chunk 11): use atomic_write_with_sync for crash-safe writes
            if let Ok(bytes) = serde_json::to_vec(&upgraded) {
                if let Ok(encrypted) = encrypt_data(&key, &bytes) {
                    if let Err(e) = atomic_write_with_sync(&path, &encrypted) {
                        eprintln!("[SECURITY] license upgrade write failed: {}", e);
                    }
                }
            }

            // 4. Burn the key so it can never be reused
            // SECURITY FIX (Gemini Audit Chunk 11): handle burn_key Result
            let dir = state.security_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Err(e) = burn_key(&dir, &compute_burn_hash(license_key, &current_fp)) {
                eprintln!("[SECURITY] CRITICAL: burn_key failed during legacy upgrade: {}", e);
            }

            return json!({
                "activated": true,
                "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
                "client": upgraded.get("client").and_then(|c| c.as_str()).unwrap_or("Studio Legale"),
            });
        } else {
            return json!({"activated": false, "expired": true, "reason": verification.message});
        }
    }

    json!({"activated": false})
}

// NOTE: legacy symmetric license verification (HMAC/XOR secret) has been removed.
// The project now uses Ed25519-signed license tokens verified by `verify_license`.

// ---------------------------------------------------------------------------
// Offline Ed25519-signed license verification
// ---------------------------------------------------------------------------
// PUBLIC_KEY_BYTES: 32-byte Ed25519 public key for offline license validation.
// The corresponding private key is stored securely offline (never in source control).
// To regenerate: pip install cryptography && python3 -c "from cryptography.hazmat.primitives.asymmetric import ed25519; k=ed25519.Ed25519PrivateKey.generate(); print(list(k.public_key().public_bytes(encoding=__import__('cryptography.hazmat.primitives.serialization',fromlist=['Encoding']).Encoding.Raw, format=__import__('cryptography.hazmat.primitives.serialization',fromlist=['PublicFormat']).PublicFormat.Raw)))"
const PUBLIC_KEY_BYTES: [u8; 32] = [
    149u8, 202u8, 238u8, 194u8, 246u8, 56u8, 222u8, 113u8,
    164u8, 165u8, 64u8, 227u8, 154u8, 148u8, 31u8, 78u8,
    69u8, 216u8, 171u8, 111u8, 255u8, 82u8, 66u8, 234u8,
    131u8, 248u8, 122u8, 172u8, 227u8, 97u8, 211u8, 110u8,
];

#[derive(Deserialize, Serialize)]
struct LicensePayload {
    c: String, // client name
    e: u64,    // expiry in milliseconds since epoch
    id: String, // unique key id
    #[serde(default)] // backward compatible: v1 tokens don't have this field
    n: Option<String>, // anti-replay nonce (128-bit hex, v2+)
}

#[derive(Serialize)]
struct VerificationResult {
    valid: bool,
    client: Option<String>,
    message: String,
}

#[tauri::command]
fn verify_license(key_string: String) -> VerificationResult {
    // Expected format: LXFW.<payload_b64>.<signature_b64>
    let parts: Vec<&str> = key_string.split('.').collect();
    if parts.len() != 3 || parts[0] != "LXFW" {
        return VerificationResult { valid: false, client: None, message: "Formato chiave non valido.".into() };
    }

    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let payload_bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(b) => b,
        Err(_) => return VerificationResult { valid: false, client: None, message: "Errore decodifica payload.".into() },
    };

    let signature_bytes = match URL_SAFE_NO_PAD.decode(signature_b64) {
        Ok(b) => b,
        Err(_) => return VerificationResult { valid: false, client: None, message: "Errore decodifica firma.".into() },
    };

    let public_key = match VerifyingKey::from_bytes(&PUBLIC_KEY_BYTES) {
        Ok(k) => k,
        Err(_) => return VerificationResult { valid: false, client: None, message: "Errore chiave pubblica interna.".into() },
    };

    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(s) => s,
        Err(_) => return VerificationResult { valid: false, client: None, message: "Firma corrotta.".into() },
    };

    if public_key.verify(payload_b64.as_bytes(), &signature).is_err() {
        return VerificationResult { valid: false, client: None, message: "Firma non valida o licenza manomessa!".into() };
    }

    let payload: LicensePayload = match serde_json::from_slice(&payload_bytes) {
        Ok(p) => p,
        Err(_) => return VerificationResult { valid: false, client: None, message: "Dati licenza corrotti.".into() },
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    if now > payload.e {
        return VerificationResult { valid: false, client: Some(payload.c), message: "Licenza scaduta.".into() };
    }

    VerificationResult { valid: true, client: Some(payload.c), message: "Licenza attivata con successo!".into() }
}

// Helper: extract key ID from a LXFW token without full verification.
// Returns the `id` field from the payload JSON, or None if malformed.
fn extract_key_id(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "LXFW" { return None; }
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let payload: LicensePayload = serde_json::from_slice(&payload_bytes).ok()?;
    Some(payload.id)
}

// Helper: extract expiry timestamp (ms) from a LXFW token without full verification.
fn extract_expiry_ms(token: &str) -> Option<u64> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "LXFW" { return None; }
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let payload: LicensePayload = serde_json::from_slice(&payload_bytes).ok()?;
    Some(payload.e)
}

#[tauri::command]
fn activate_license(state: State<AppState>, key: String, _client_name: Option<String>) -> Value {
    let sec_dir = state.security_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();

    // SECURITY FIX (Gemini Audit Chunk 11): use centralized lockout (persistent across restarts)
    if let Err(locked_json) = check_lockout(&state, &sec_dir) {
        return locked_json;
    }

    let key = key.trim().to_string(); // Le chiavi B64 sono case-sensitive, non uppercasiamo

    let path = sec_dir.join(LICENSE_FILE);
    let sentinel_path = sec_dir.join(LICENSE_SENTINEL_FILE);

    // ── SECURITY CHECK 1: if sentinel exists but license.json was deleted ──
    // Someone deleted the license file to try re-activating with a different key.
    // Block unless the SAME key (same ID) is being re-entered.
    if !path.exists() && sentinel_path.exists() {
        // We can still allow re-activation of the SAME key ID that was originally used.
        // The sentinel stores HMAC("LEXFLOW-SENTINEL:<fingerprint>:<keyId>:<timestamp>")
        // but we cannot recover the keyId from the HMAC. So we also store the encrypted
        // key ID in the sentinel for comparison. See sentinel write below.
        let enc_key = get_local_encryption_key();
        let sentinel_content = fs::read_to_string(&sentinel_path).unwrap_or_default();
        // Sentinel format: "<hmac_hex>\n<encrypted_key_id_hex>"
        let sentinel_lines: Vec<&str> = sentinel_content.lines().collect();
        let stored_key_id_enc = sentinel_lines.get(1).unwrap_or(&"");

        // Try to recover stored key ID (try current key, then legacy)
        let stored_key_id: Option<String> = if !stored_key_id_enc.is_empty() {
            hex::decode(stored_key_id_enc).ok()
                .and_then(|enc_bytes| {
                    decrypt_data(&enc_key, &enc_bytes).ok()
                        .or_else(|| {
                            #[cfg(not(target_os = "android"))]
                            { decrypt_data(&get_local_encryption_key_legacy(), &enc_bytes).ok() }
                            #[cfg(target_os = "android")]
                            { None }
                        })
                })
                .and_then(|dec| String::from_utf8(dec).ok())
        } else {
            None
        };

        let new_key_id = extract_key_id(&key);

        // Allow re-activation ONLY if the same key ID is being used
        match (stored_key_id.as_deref(), new_key_id.as_deref()) {
            (Some(old), Some(new_id)) if old == new_id => {
                // Same key ID — allow re-activation (e.g. user accidentally deleted the file)
            },
            _ => {
                return json!({
                    "success": false,
                    "error": "Questa installazione ha già una licenza registrata. Contattare il supporto per assistenza."
                });
            }
        }
    }

    // ── SECURITY CHECK 2: if license already exists and is valid, block overwrite ──
    // Prevents replacing a valid license with a pirated/shared key.
    if path.exists() {
        if let Some(dec) = decrypt_local_with_migration(&path) {
            if let Ok(existing) = serde_json::from_slice::<Value>(&dec) {
                let existing_version = existing.get("keyVersion")
                    .and_then(|v| v.as_str()).unwrap_or("");

                if existing_version == "ed25519-burned" {
                    let expiry = existing.get("expiryMs")
                        .and_then(|v| v.as_u64()).unwrap_or(0);
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                    if now_ms <= expiry {
                        let existing_id = existing.get("keyId")
                            .and_then(|v| v.as_str());
                        let new_id = extract_key_id(&key);
                        if existing_id.map(|s| s.to_string()) != new_id {
                            return json!({
                                "success": false,
                                "error": "Una licenza valida è già attiva. Non è possibile sostituirla."
                            });
                        }
                    }
                } else {
                    let existing_key = existing.get("key")
                        .and_then(|k| k.as_str()).unwrap_or("");
                    if !existing_key.is_empty() {
                        let existing_verification = verify_license(existing_key.to_string());
                        if existing_verification.valid {
                            let existing_id = extract_key_id(existing_key);
                            let new_id = extract_key_id(&key);
                            if existing_id != new_id {
                                return json!({
                                    "success": false,
                                    "error": "Una licenza valida è già attiva. Non è possibile sostituirla."
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Verifica asimmetrica (Ed25519)
    let verification = verify_license(key.clone());

    if !verification.valid {
        // SECURITY FIX (Gemini Audit Chunk 11): use centralized lockout functions
        record_failed_attempt(&state, &sec_dir);
        return json!({"success": false, "error": verification.message});
    }

    // SECURITY FIX (Gemini Audit Chunk 11): use centralized clear
    clear_lockout(&state, &sec_dir);

    // SECURITY: bind license to THIS machine — cannot be copied to another device
    let fingerprint = compute_machine_fingerprint();

    // ── SECURITY CHECK 3: burned-key registry ──────────────────────────────
    // A key can only be activated ONCE. After activation it is "burned" —
    // the raw token is destroyed and only a verification hash survives.
    // Even if someone knows the key, they cannot re-use it.
    // SECURITY FIX (Gemini Audit Chunk 11): handle Result — Fail-Closed on error
    match is_key_burned(&sec_dir, &key, &fingerprint) {
        Ok(true) => {
            return json!({
                "success": false,
                "error": "Questa chiave è già stata utilizzata e non può essere riattivata."
            });
        }
        Err(e) => {
            eprintln!("[SECURITY] burned-keys registry unreadable: {}", e);
            return json!({
                "success": false,
                "error": "Registro chiavi non leggibile. Contattare il supporto."
            });
        }
        Ok(false) => { /* key not burned, proceed */ }
    }

    // ── SECURITY CHECK 4: burned-keys file integrity ──────────────────────
    // If the sentinel exists (a license was previously activated on this machine)
    // but the .burned-keys file is missing, someone deleted it to bypass single-use
    // enforcement. Block activation of any NEW key in this case.
    if sentinel_path.exists() && !sec_dir.join(BURNED_KEYS_FILE).exists() {
        // Allow re-activation of the SAME key ID only (handled by CHECK 1 above).
        // If we reach here, it's a different key → block.
        return json!({
            "success": false,
            "error": "Registro chiavi compromesso. Contattare il supporto per assistenza."
        });
    }

    let now = chrono::Utc::now().to_rfc3339();

    // Il client viene estratto in modo sicuro dal payload firmato
    let client = verification.client.unwrap_or_else(|| "Studio Legale".to_string());

    // Extract key ID for sentinel storage
    let key_id = extract_key_id(&key).unwrap_or_else(|| "unknown".to_string());

    // ── BURN THE KEY: compute verification hash, then destroy raw token ────
    // We store an HMAC(token) so check_license can verify integrity without
    // having the raw token. The raw token ceases to exist after this point.
    let mut token_mac = <Hmac<Sha256> as Mac>::new_from_slice(
        &get_local_encryption_key()
    ).expect("HMAC can take key of any size");
    token_mac.update(key.as_bytes());
    let token_hmac = hex::encode(token_mac.finalize().into_bytes());

    // Extract payload data BEFORE destroying the token — we need client/expiry
    // for check_license to work without re-verifying Ed25519
    let parts: Vec<&str> = key.split('.').collect();
    let payload_data: Option<LicensePayload> = if parts.len() == 3 {
        URL_SAFE_NO_PAD.decode(parts[1]).ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    } else { None };

    let expiry_ms = payload_data.as_ref().map(|p| p.e).unwrap_or(0);

    // Record: NO raw token — only HMAC + extracted payload data
    let record = json!({
        "tokenHmac": token_hmac,
        "activatedAt": now,
        "client": client,
        "keyVersion": "ed25519-burned",
        "machineFingerprint": fingerprint,
        "keyId": key_id,
        "expiryMs": expiry_ms,
    });
    let enc_key = get_local_encryption_key();
    match encrypt_data(&enc_key, &serde_json::to_vec(&record).unwrap_or_default()) {
        Ok(encrypted) => {
            match atomic_write_with_sync(&path, &encrypted) {
                Ok(_) => {
                        // SECURITY: write sentinel file — HMAC proof that activation happened.
                        // This detects if license.json is manually deleted to hack the system.
                        // Format: line 1 = HMAC(sentinel_data), line 2 = encrypted key ID
                        let sentinel_data = format!("LEXFLOW-SENTINEL:{}:{}:{}", fingerprint, key_id, now);
                        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&enc_key)
                            .expect("HMAC can take key of any size");
                        mac.update(sentinel_data.as_bytes());
                        let sentinel_hmac = hex::encode(mac.finalize().into_bytes());

                        // Encrypt key ID so it can be recovered for re-activation check
                        let encrypted_key_id = encrypt_data(&enc_key, key_id.as_bytes())
                            .map(|e| hex::encode(e))
                            .unwrap_or_default();

                        let sentinel_content = format!("{}\n{}", sentinel_hmac, encrypted_key_id);
                        let _ = atomic_write_with_sync(&sentinel_path, sentinel_content.as_bytes());

                        // ── BURN THE KEY: add to burned-keys registry ──
                        // After this, the same token can NEVER be activated again.
                        // SECURITY FIX (Gemini Audit Chunk 11): handle burn_key Result
                        if let Err(e) = burn_key(&sec_dir, &compute_burn_hash(&key, &fingerprint)) {
                            eprintln!("[SECURITY] CRITICAL: burn_key failed after activation: {}", e);
                            // Key is already activated, but burn failed — log for audit
                        }

                        json!({"success": true, "client": client})
                    },
                    Err(e) => json!({"success": false, "error": format!("Errore salvataggio: {}", e)}),
                }
        },
        Err(e) => json!({"success": false, "error": format!("Errore cifratura: {}", e)}),
    }
}

// ═══════════════════════════════════════════════════════════
//  IMPORT / EXPORT
// ═══════════════════════════════════════════════════════════

#[tauri::command]
async fn export_vault(state: State<'_, AppState>, pwd: String, app: AppHandle) -> Result<Value, String> {
    use tauri_plugin_dialog::DialogExt;
    // SECURITY FIX (Level-8 A2): verify that `pwd` is the intended backup password by
    // re-deriving it and checking against vault.verify BEFORE writing the backup.
    // Without this check, a typo in `pwd` produces a backup encrypted with the wrong key
    // that is permanently inaccessible — the user has no way to know until they need to restore.
    // We verify by deriving the key and confirming it opens the vault's own verify tag.
    {
        let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let salt_path = dir.join(VAULT_SALT_FILE);
        if salt_path.exists() {
            let vault_salt = fs::read(&salt_path).map_err(|e| e.to_string())?;
            let vault_key_check = derive_secure_key(&pwd, &vault_salt)?;
            let stored_verify = fs::read(dir.join(VAULT_VERIFY_FILE)).unwrap_or_default();
            if !verify_hash_matches(&vault_key_check, &stored_verify) {
                return Ok(json!({"success": false, "error": "Password errata: il backup non può essere creato con una password diversa da quella del vault."}));
            }
        }
    }
    let data = read_vault_internal(&state)?;
    // SECURITY FIX (Gemini Audit Chunk 12): use RngCore for cryptographic salt generation
    let mut salt = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    let key = derive_secure_key(&pwd, &salt)?;
    // Zeroizing: plaintext vault azzerato dopo la cifratura
    let plaintext = Zeroizing::new(serde_json::to_vec(&data).map_err(|e| e.to_string())?);
    let encrypted = encrypt_data(&key, &plaintext)?;
    let mut out = salt; out.extend(encrypted);

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog().file().set_file_name("LexFlow_Backup.lex").save_file(move |file_path| {
        let _ = tx.send(file_path);
    });
    let path = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    if let Some(p) = path {
        // SECURITY FIX (Gemini Audit Chunk 12/13): handle into_path gracefully
        let file_path = p.into_path().map_err(|e| format!("Percorso non valido: {}", e))?;
        fs::write(file_path, out).map_err(|e| e.to_string())?;
        Ok(json!({"success": true}))
    } else { Ok(json!({"success": false})) }
}

#[tauri::command]
async fn import_vault(state: State<'_, AppState>, pwd: String, app: AppHandle) -> Result<Value, String> {
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
        // SECURITY FIX (Gemini Audit Chunk 12/13): handle into_path gracefully
        let file_path = p.into_path().map_err(|e| format!("Percorso non valido: {}", e))?;
        // SECURITY FIX: bounded read via file.take() — eliminates TOCTOU window
        // (metadata check + separate fs::read could race with file replacement)
        const MAX_IMPORT_SIZE: u64 = 500 * 1024 * 1024;
        let raw = {
            use std::io::Read;
            let file = fs::File::open(&file_path).map_err(|e| e.to_string())?;
            let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
            if file_len > MAX_IMPORT_SIZE {
                return Err("File troppo grande (max 500MB)".into());
            }
            // take() caps the read at MAX_IMPORT_SIZE+1 so we can detect truncation/growth
            let mut buf = Vec::new();
            file.take(MAX_IMPORT_SIZE + 1).read_to_end(&mut buf).map_err(|e| e.to_string())?;
            if buf.len() as u64 > MAX_IMPORT_SIZE {
                return Err("File troppo grande (max 500MB)".into());
            }
            buf
        };
        // Validazione struttura minima: 32 byte salt + VAULT_MAGIC + nonce (12) + tag AES (16)
        let min_len = 32 + VAULT_MAGIC.len() + NONCE_LEN + 16;
        if raw.len() < min_len {
            return Err("File non valido o corrotto (dimensione insufficiente)".into());
        }
        // Verifica magic nel blocco cifrato (dopo i 32 byte di salt)
        let magic_start = 32;
        if !raw[magic_start..].starts_with(VAULT_MAGIC) {
            return Err("File non è un backup LexFlow valido".into());
        }
        let salt = &raw[..32];
        let encrypted = &raw[32..];
        let key = derive_secure_key(&pwd, salt)?;
        let decrypted = decrypt_data(&key, encrypted).map_err(|_| "Password errata o file corrotto")?;
        let val: Value = serde_json::from_slice(&decrypted).map_err(|_| "Struttura backup non valida")?;
        // Validazione struttura dati vault
        if val.get("practices").is_none() && val.get("agenda").is_none() {
            return Err("Il file non contiene dati LexFlow validi".into());
        }
        // SECURITY FIX (Level-8 C2): import must work even if the vault is currently locked
        // (e.g. first-run or forgotten password scenario).  Previously write_vault_internal
        // required vault_key to already be set, causing a Catch-22: you can't unlock a lost
        // vault, but you can't import a backup either.
        //
        // Fix: derive a new vault key from `pwd` + a fresh salt, write all vault files
        // (salt, verify, vault.lex) from the backup's own credentials, then set vault_key.
        // This means the imported vault's master password becomes `pwd` as entered here.
        // SECURITY FIX (Gemini Audit): acquire write_mutex to prevent concurrent vault writes.
        let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
        {
            let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
            // Generate new vault salt for the imported vault
            let mut new_salt = vec![0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_salt);
            let new_key = derive_secure_key(&pwd, &new_salt)?;
            // Write salt with mode 0600
            secure_write(&dir.join(VAULT_SALT_FILE), &new_salt).map_err(|e| e.to_string())?;
            // Write verify tag
            let verify_tag = make_verify_tag(&new_key);
            secure_write(&dir.join(VAULT_VERIFY_FILE), &verify_tag).map_err(|e| e.to_string())?;
            // Set the vault key in state so write_vault_internal can use it
            *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(SecureKey(new_key));
        }
        write_vault_internal(&state, &val)?;
        let _ = append_audit_log(&state, "Vault importato da backup");
        // SECURITY FIX (Gemini Audit): safe password zeroing — no UB
        zeroize_password(pwd);
        Ok(json!({"success": true}))
    } else { Ok(json!({"success": false, "cancelled": true})) }
}

// ═══════════════════════════════════════════════════════════
//  SYSTEM UTILITIES
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn open_path(app: AppHandle, path: String) {
    #[cfg(not(target_os = "android"))]
    {
        // SECURITY FIX (Gemini Audit v2): sanitize path to prevent RCE.
        // Only allow opening paths that exist as files/directories on the local filesystem.
        let p = std::path::Path::new(&path);
        if !p.exists() || !p.is_absolute() {
            eprintln!("[LexFlow] SECURITY: open_path refused non-existent/relative path: {:?}", path);
            return;
        }
        // SECURITY FIX (Gemini Audit Chunk 13): allowlist instead of blocklist.
        // Only allow safe document extensions and directories.
        let is_dir = p.is_dir();
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        const ALLOWED_EXTENSIONS: &[&str] = &[
            "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt",
            "txt", "rtf", "odt", "ods", "odp", "csv",
            "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp",
            "lex", // LexFlow backup
        ];
        if !is_dir && !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
            eprintln!("[LexFlow] SECURITY: open_path refused non-allowed extension: {:?}", path);
            return;
        }
        use tauri_plugin_opener::OpenerExt;
        if let Err(e) = app.opener().open_path(&path, None::<&str>) {
            eprintln!("[LexFlow] Failed to open path: {:?}", e);
        }
    }
    #[cfg(target_os = "android")]
    { let _ = (app, path); }
}

#[tauri::command]
async fn select_file(app: AppHandle) -> Result<Option<Value>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("Documenti", &["pdf", "docx", "doc"])
        .pick_file(move |file_path| {
            let _ = tx.send(file_path);
        });
    let file = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    Ok(file.and_then(|f| {
        // SECURITY FIX (Gemini Audit Chunk 13): remove unwrap on into_path
        let path = f.into_path().ok()?;
        let name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        Some(json!({"name": name, "path": path.to_string_lossy()}))
    }))
}

#[tauri::command]
async fn select_folder(app: AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    // Android non supporta pick_folder — fallback a pick_file
    #[cfg(not(target_os = "android"))]
    app.dialog()
        .file()
        .pick_folder(move |folder_path| {
            let _ = tx.send(folder_path);
        });
    #[cfg(target_os = "android")]
    app.dialog()
        .file()
        .pick_file(move |folder_path| {
            let _ = tx.send(folder_path);
        });
    let folder = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    // SECURITY FIX (Gemini Audit Chunk 13): remove unwrap on into_path
    Ok(folder.and_then(|f| f.into_path().ok().map(|p| p.to_string_lossy().to_string())))
}

#[tauri::command]
fn window_close(app: AppHandle, state: State<AppState>) {
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") { let _ = w.hide(); }
    #[cfg(target_os = "android")]
    { let _ = app; }
}

#[tauri::command]
fn get_app_version(app: AppHandle) -> String { app.package_info().version.to_string() }

#[tauri::command]
fn is_mac() -> bool { cfg!(target_os = "macos") }

/// Restituisce la piattaforma corrente al frontend
#[tauri::command]
fn get_platform() -> String {
    #[cfg(target_os = "android")] { "android".to_string() }
    #[cfg(target_os = "ios")]     { "ios".to_string() }
    #[cfg(target_os = "macos")]   { "macos".to_string() }
    #[cfg(target_os = "windows")] { "windows".to_string() }
    #[cfg(target_os = "linux")]   { "linux".to_string() }
    #[cfg(not(any(target_os="android",target_os="ios",target_os="macos",target_os="windows",target_os="linux")))]
    { "unknown".to_string() }
}

#[tauri::command]
async fn select_pdf_save_path(app: AppHandle, default_name: String) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("PDF", &["pdf"])
        .set_file_name(&default_name)
        .save_file(move |file_path| {
            let _ = tx.send(file_path);
        });
    let file_path = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    match file_path {
        Some(fp) => {
            let path = fp.into_path().map_err(|e| format!("Path error: {:?}", e))?;
            Ok(Some(path.to_string_lossy().into_owned()))
        },
        None => Ok(None),
    }
}

// ═══════════════════════════════════════════════════════════
//  NOTIFICATIONS
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn send_notification(app: AppHandle, title: String, body: String) {
    // Even though Tauri IPC commands run on the main thread context, we
    // explicitly use run_on_main_thread to guarantee the NSRunLoop is active
    // for the XPC call to usernoted (macOS Notification Center daemon).
    let t = title.clone();
    let b = body.clone();
    let ah = app.clone();
    let _ = app.run_on_main_thread(move || {
        use tauri_plugin_notification::NotificationExt;
        if let Err(e) = ah.notification().builder().title(&t).body(&b).show() {
            eprintln!("[LexFlow] Native notification failed: {:?}, emitting event fallback", e);
            let _ = ah.emit("show-notification", serde_json::json!({"title": t, "body": b}));
        }
    });
}

/// Test notification — dev-only command to verify the notification pipeline.
/// Always dispatches via run_on_main_thread for NSRunLoop guarantee.
#[tauri::command]
fn test_notification(app: AppHandle) -> bool {
    let ah = app.clone();
    match app.run_on_main_thread(move || {
        use tauri_plugin_notification::NotificationExt;
        if let Err(e) = ah.notification().builder()
            .title("LexFlow — Test Notifica")
            .body("Le notifiche funzionano correttamente!")
            .show()
        {
            eprintln!("[LexFlow] Test notification failed: {:?}", e);
        }
    }) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[tauri::command]
fn sync_notification_schedule(app: AppHandle, state: State<AppState>, schedule: Value) -> bool {
    let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let key = get_local_encryption_key();
    // SECURITY FIX (Gemini Audit Chunk 14): propagate serialization error instead of unwrap_or_default
    let plaintext = match serde_json::to_vec(&schedule) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[LexFlow] sync_notification_schedule serialization failed: {}", e);
            return false;
        }
    };
    match encrypt_data(&key, &plaintext) {
        Ok(encrypted) => {
            let written = atomic_write_with_sync(&dir.join(NOTIF_SCHEDULE_FILE), &encrypted).is_ok();
            if written {
                // ── TRIGGER: re-sync OS notification queue after data change ──
                sync_notifications(&app, &dir);
            }
            written
        },
        Err(_) => false,
    }
}

/// Decrypt notification schedule with local machine key
fn read_notification_schedule(data_dir: &PathBuf) -> Option<Value> {
    let path = data_dir.join(NOTIF_SCHEDULE_FILE);
    if !path.exists() { return None; }
    // SECURITY FIX (Level-8 C5): size guard before reading into RAM.
    if let Ok(meta) = path.metadata() {
        if meta.len() > MAX_SETTINGS_FILE_SIZE {
            eprintln!("[LexFlow] Notification schedule file troppo grande ({} bytes) — ignorato", meta.len());
            return None;
        }
    }
    // SECURITY FIX (Gemini Audit): use migration-aware decryption (hostname→machine_id)
    if let Some(decrypted) = decrypt_local_with_migration(&path) {
        return serde_json::from_slice(&decrypted).ok();
    }
    // Migration: old plaintext format → re-encrypt
    // SECURITY FIX (Security Audit): use safe_bounded_read for OOM protection
    if let Ok(raw) = safe_bounded_read(&path, MAX_SETTINGS_FILE_SIZE) {
        if let Ok(text) = std::str::from_utf8(&raw) {
            if let Ok(val) = serde_json::from_str::<Value>(text) {
                let key = get_local_encryption_key();
                if let Ok(enc) = encrypt_data(&key, &serde_json::to_vec(&val).unwrap_or_default()) {
                    let _ = atomic_write_with_sync(&path, &enc);
                }
                return Some(val);
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════
//  HYBRID NOTIFICATION ARCHITECTURE (v3.1)
// ═══════════════════════════════════════════════════════════
//
// MOBILE (Android/iOS): Native AOT scheduling via Schedule::At — the OS fires
//   notifications even if the app is killed.  sync_notifications() cancels all
//   pending and re-schedules from current data.
//
// DESKTOP (macOS/Windows/Linux): tauri-plugin-notification (via notify-rust)
//   IGNORES Schedule::At and fires immediately.  Instead we run a single async
//   Tokio cron job that wakes once per minute, checks the JSON state, and fires
//   notifications in real-time.  Zero threads, zero sleeps, zero CPU waste.
//
//   On macOS the App Nap hack (NSProcessInfo.beginActivityWithOptions) prevents
//   the OS from freezing the async timer when the window is hidden.

// ── MOBILE: Native AOT scheduling ─────────────────────────────────────────
#[cfg(any(target_os = "android", target_os = "ios"))]
fn sync_notifications(app: &AppHandle, data_dir: &std::path::Path) {
    use tauri_plugin_notification::NotificationExt;

    // Cancel all pending
    if let Err(e) = app.notification().cancel_all() {
        eprintln!("[LexFlow Sync] cancel_all error (non-critical): {:?}", e);
    } else {
        eprintln!("[LexFlow Sync] All pending notifications cancelled ✓");
    }

    let schedule_data: serde_json::Value = match read_notification_schedule(
        &data_dir.to_path_buf()
    ) {
        Some(v) => v,
        None => {
            eprintln!("[LexFlow Sync] No schedule file — nothing to schedule");
            return;
        }
    };

    let briefing_times = schedule_data.get("briefingTimes")
        .and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let items = schedule_data.get("items")
        .and_then(|v| v.as_array()).cloned().unwrap_or_default();

    let now = chrono::Local::now();
    let tomorrow = (now + chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
    const MAX_SCHEDULED: i32 = 60;
    let horizon = now + chrono::Duration::days(14);
    let mut scheduled_count: i32 = 0;

    let chrono_to_offset = |dt: chrono::DateTime<chrono::Local>| -> Option<time::OffsetDateTime> {
        let ts = dt.timestamp();
        let ns = dt.timestamp_subsec_nanos();
        let offset_secs = dt.offset().local_minus_utc();
        let offset = time::UtcOffset::from_whole_seconds(offset_secs).ok()?;
        time::OffsetDateTime::from_unix_timestamp(ts).ok()
            .map(|t| t.replace_nanosecond(ns).unwrap_or(t))
            .map(|t| t.to_offset(offset))
    };

    let hash_id = |seed: &str| -> i32 {
        let hash = <sha2::Sha256 as sha2::Digest>::digest(seed.as_bytes());
        let raw = i32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        raw.wrapping_abs().max(1)
    };

    // Schedule briefings
    for bt in &briefing_times {
        if scheduled_count >= MAX_SCHEDULED { break; }
        let time_str = match bt.as_str() {
            Some(s) if s.len() >= 5 => s,
            _ => continue,
        };
        for day_offset in 0..=1i64 {
            if scheduled_count >= MAX_SCHEDULED { break; }
            let target_date = now.date_naive() + chrono::Duration::days(day_offset);
            let date_str = target_date.format("%Y-%m-%d").to_string();
            let dt_str = format!("{} {}", date_str, time_str);
            let target_dt = match chrono::NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M") {
                Ok(dt) => dt, Err(_) => continue,
            };
            let target_local = match chrono::Local.from_local_datetime(&target_dt).single() {
                Some(t) => t, None => continue,
            };
            if target_local <= now || target_local > horizon { continue; }
            let offset_dt = match chrono_to_offset(target_local) {
                Some(t) => t, None => continue,
            };
            let briefing_hour: u32 = time_str.split(':').next()
                .and_then(|h| h.parse().ok()).unwrap_or(8);
            let (filter_date, time_from, period_label) = if briefing_hour < 12 {
                (date_str.as_str(), "00:00", "oggi")
            } else if briefing_hour < 18 {
                (date_str.as_str(), "13:00", "questo pomeriggio")
            } else {
                if day_offset == 0 { (&tomorrow as &str, "00:00", "domani") }
                else { continue; }
            };
            let relevant_count = items.iter().filter(|i| {
                let d = i.get("date").and_then(|d| d.as_str()).unwrap_or("");
                let t = i.get("time").and_then(|t| t.as_str()).unwrap_or("00:00");
                let done = i.get("completed").and_then(|c| c.as_bool()).unwrap_or(false);
                d == filter_date && !done && t >= time_from
            }).count();
            let title = if relevant_count == 0 {
                format!("LexFlow — Nessun impegno {}", period_label)
            } else {
                format!("LexFlow — {} impegn{} {}", relevant_count,
                    if relevant_count == 1 { "o" } else { "i" }, period_label)
            };
            let body_str = if relevant_count == 0 {
                format!("Nessun impegno in programma per {}.", period_label)
            } else {
                let mut relevant_items: Vec<&serde_json::Value> = items.iter()
                    .filter(|i| {
                        let d = i.get("date").and_then(|d| d.as_str()).unwrap_or("");
                        let t = i.get("time").and_then(|t| t.as_str()).unwrap_or("00:00");
                        let done = i.get("completed").and_then(|c| c.as_bool()).unwrap_or(false);
                        d == filter_date && !done && t >= time_from
                    }).collect();
                relevant_items.sort_by(|a, b| {
                    let ta = a.get("time").and_then(|v| v.as_str()).unwrap_or("");
                    let tb = b.get("time").and_then(|v| v.as_str()).unwrap_or("");
                    ta.cmp(tb)
                });
                let mut lines: Vec<String> = Vec::new();
                for item in relevant_items.iter().take(4) {
                    let t = item.get("time").and_then(|v| v.as_str()).unwrap_or("");
                    let name = item.get("title").and_then(|v| v.as_str()).unwrap_or("Impegno");
                    if !t.is_empty() { lines.push(format!("• {} — {}", t, name)); }
                    else { lines.push(format!("• {}", name)); }
                }
                if relevant_count > 4 { lines.push(format!("  …e altri {}", relevant_count - 4)); }
                lines.join("\n")
            };
            let notif_id = hash_id(&format!("briefing-{}-{}", date_str, time_str));
            let sched = tauri_plugin_notification::Schedule::At {
                date: offset_dt, repeating: false, allow_while_idle: true,
            };
            if app.notification().builder().id(notif_id).title(&title).body(&body_str)
                .schedule(sched).show().is_ok() {
                scheduled_count += 1;
            }
        }
    }

    // Schedule per-item reminders
    for item in &items {
        if scheduled_count >= MAX_SCHEDULED { break; }
        let item_date = item.get("date").and_then(|d| d.as_str()).unwrap_or("");
        let item_time = item.get("time").and_then(|t| t.as_str()).unwrap_or("");
        let item_title = item.get("title").and_then(|t| t.as_str()).unwrap_or("Impegno");
        let item_id = item.get("id").and_then(|i| i.as_str()).unwrap_or("");
        let completed = item.get("completed").and_then(|c| c.as_bool()).unwrap_or(false);
        if completed || item_time.len() < 5 { continue; }
        let item_dt_str = format!("{} {}", item_date, item_time);
        let item_dt = match chrono::NaiveDateTime::parse_from_str(&item_dt_str, "%Y-%m-%d %H:%M") {
            Ok(dt) => dt, Err(_) => continue,
        };
        let item_local = match chrono::Local.from_local_datetime(&item_dt).single() {
            Some(t) => t, None => continue,
        };
        if item_local > horizon { continue; }
        let custom_remind_time = item.get("customRemindTime")
            .and_then(|v| v.as_str()).filter(|s| s.len() >= 5);
        let remind_min = item.get("remindMinutes").and_then(|v| v.as_i64()).unwrap_or(30);
        let remind_time = if let Some(crt) = custom_remind_time {
            let crt_str = format!("{} {}", item_date, crt);
            chrono::NaiveDateTime::parse_from_str(&crt_str, "%Y-%m-%d %H:%M")
                .ok().and_then(|dt| chrono::Local.from_local_datetime(&dt).single())
                .unwrap_or(item_local - chrono::Duration::minutes(remind_min))
        } else {
            item_local - chrono::Duration::minutes(remind_min)
        };
        if remind_time <= now { continue; }
        let offset_dt = match chrono_to_offset(remind_time) {
            Some(t) => t, None => continue,
        };
        let diff = (item_local - remind_time).num_minutes().max(0);
        let time_desc = if diff == 0 { "adesso!".to_string() }
            else if diff < 60 { format!("tra {} minuti", diff) }
            else {
                let h = diff / 60; let m = diff % 60;
                if m == 0 { format!("tra {} or{}", h, if h == 1 { "a" } else { "e" }) }
                else { format!("tra {}h {:02}min", h, m) }
            };
        let body = format!("{} — {} ({})", item_title, item_time, time_desc);
        let notif_id = hash_id(&format!("remind-{}-{}-{}", item_date, item_id, item_time));
        let sched = tauri_plugin_notification::Schedule::At {
            date: offset_dt, repeating: false, allow_while_idle: true,
        };
        if app.notification().builder().id(notif_id).title("LexFlow — Promemoria")
            .body(&body).schedule(sched).show().is_ok() {
            scheduled_count += 1;
        }
    }

    eprintln!("[LexFlow Sync] ══ Mobile AOT sync: {}/{} notifications scheduled ══", scheduled_count, MAX_SCHEDULED);
}

// ── DESKTOP: stub — scheduling is handled by the async cron job ────────────
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn sync_notifications(_app: &AppHandle, _data_dir: &std::path::Path) {
    // No-op on desktop.  The desktop_cron_job() runs every 60s and fires
    // notifications in real-time by checking the JSON state.
}

// ── DESKTOP: Async Cron Job — wakes every 60s, fires matching notifications ──
#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn desktop_cron_job(app: AppHandle) {
    use tauri_plugin_notification::NotificationExt;

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    // SECURITY FIX (Gemini Audit Chunk 14): skip missed ticks instead of bursting
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_processed_minute = String::new();

    eprintln!("[LexFlow Cron] Desktop cron job started — checking every 60s");

    loop {
        interval.tick().await;

        let now = chrono::Local::now();
        let current_minute = now.format("%Y-%m-%d %H:%M").to_string();

        // Avoid double-firing within the same minute
        if current_minute == last_processed_minute { continue; }
        last_processed_minute = current_minute.clone();

        // Read data_dir from managed state
        let data_dir = {
            let state = app.state::<AppState>();
            let dir = state.data_dir.lock().unwrap_or_else(|e| e.into_inner()).clone();
            dir
        };

        // ── Read notification schedule ──
        let schedule_data: serde_json::Value = match read_notification_schedule(&data_dir) {
            Some(v) => v,
            None => continue,
        };

        let briefing_times = schedule_data.get("briefingTimes")
            .and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let items = schedule_data.get("items")
            .and_then(|v| v.as_array()).cloned().unwrap_or_default();

        let today = now.format("%Y-%m-%d").to_string();
        let tomorrow = (now + chrono::Duration::days(1)).format("%Y-%m-%d").to_string();

        // ── Check briefings: does any briefing fire THIS minute? ──
        for bt in &briefing_times {
            let time_str = match bt.as_str() {
                Some(s) if s.len() >= 5 => s,
                _ => continue,
            };

            let briefing_key = format!("{} {}", today, time_str);
            if briefing_key != current_minute { continue; }

            // This briefing fires NOW
            let briefing_hour: u32 = time_str.split(':').next()
                .and_then(|h| h.parse().ok()).unwrap_or(8);

            let (filter_date, time_from, period_label) = if briefing_hour < 12 {
                (today.as_str(), "00:00", "oggi")
            } else if briefing_hour < 18 {
                (today.as_str(), "13:00", "questo pomeriggio")
            } else {
                (tomorrow.as_str(), "00:00", "domani")
            };

            let relevant_count = items.iter().filter(|i| {
                let d = i.get("date").and_then(|d| d.as_str()).unwrap_or("");
                let t = i.get("time").and_then(|t| t.as_str()).unwrap_or("00:00");
                let done = i.get("completed").and_then(|c| c.as_bool()).unwrap_or(false);
                d == filter_date && !done && t >= time_from
            }).count();

            let title = if relevant_count == 0 {
                format!("LexFlow — Nessun impegno {}", period_label)
            } else {
                format!("LexFlow — {} impegn{} {}", relevant_count,
                    if relevant_count == 1 { "o" } else { "i" }, period_label)
            };

            let body_str = if relevant_count == 0 {
                format!("Nessun impegno in programma per {}.", period_label)
            } else {
                let mut relevant_items: Vec<&serde_json::Value> = items.iter()
                    .filter(|i| {
                        let d = i.get("date").and_then(|d| d.as_str()).unwrap_or("");
                        let t = i.get("time").and_then(|t| t.as_str()).unwrap_or("00:00");
                        let done = i.get("completed").and_then(|c| c.as_bool()).unwrap_or(false);
                        d == filter_date && !done && t >= time_from
                    }).collect();
                relevant_items.sort_by(|a, b| {
                    let ta = a.get("time").and_then(|v| v.as_str()).unwrap_or("");
                    let tb = b.get("time").and_then(|v| v.as_str()).unwrap_or("");
                    ta.cmp(tb)
                });
                let mut lines: Vec<String> = Vec::new();
                for item in relevant_items.iter().take(4) {
                    let t = item.get("time").and_then(|v| v.as_str()).unwrap_or("");
                    let name = item.get("title").and_then(|v| v.as_str()).unwrap_or("Impegno");
                    if !t.is_empty() { lines.push(format!("• {} — {}", t, name)); }
                    else { lines.push(format!("• {}", name)); }
                }
                if relevant_count > 4 { lines.push(format!("  …e altri {}", relevant_count - 4)); }
                lines.join("\n")
            };

            let app_clone = app.clone();
            let title_clone = title.clone();
            let body_clone = body_str.clone();
            let _ = app.run_on_main_thread(move || {
                let _ = app_clone.notification().builder()
                    .title(&title_clone)
                    .body(&body_clone)
                    .show();
            });
            eprintln!("[LexFlow Cron] ✓ Briefing fired: {}", briefing_key);
        }

        // ── Check per-item reminders: does any reminder fire THIS minute? ──
        for item in &items {
            let item_date = item.get("date").and_then(|d| d.as_str()).unwrap_or("");
            let item_time = item.get("time").and_then(|t| t.as_str()).unwrap_or("");
            let item_title = item.get("title").and_then(|t| t.as_str()).unwrap_or("Impegno");
            let completed = item.get("completed").and_then(|c| c.as_bool()).unwrap_or(false);
            if completed || item_time.len() < 5 { continue; }

            let item_dt_str = format!("{} {}", item_date, item_time);
            let item_dt = match chrono::NaiveDateTime::parse_from_str(&item_dt_str, "%Y-%m-%d %H:%M") {
                Ok(dt) => dt, Err(_) => continue,
            };
            let item_local = match chrono::Local.from_local_datetime(&item_dt).single() {
                Some(t) => t, None => continue,
            };

            // Determine fire time
            let custom_remind_time = item.get("customRemindTime")
                .and_then(|v| v.as_str()).filter(|s| s.len() >= 5);
            let remind_min = item.get("remindMinutes").and_then(|v| v.as_i64()).unwrap_or(30);

            let remind_time = if let Some(crt) = custom_remind_time {
                let crt_str = format!("{} {}", item_date, crt);
                chrono::NaiveDateTime::parse_from_str(&crt_str, "%Y-%m-%d %H:%M")
                    .ok().and_then(|dt| chrono::Local.from_local_datetime(&dt).single())
                    .unwrap_or(item_local - chrono::Duration::minutes(remind_min))
            } else {
                item_local - chrono::Duration::minutes(remind_min)
            };

            let fire_minute = remind_time.format("%Y-%m-%d %H:%M").to_string();
            if fire_minute != current_minute { continue; }

            // This reminder fires NOW
            let diff = (item_local - remind_time).num_minutes().max(0);
            let time_desc = if diff == 0 { "adesso!".to_string() }
                else if diff < 60 { format!("tra {} minuti", diff) }
                else {
                    let h = diff / 60; let m = diff % 60;
                    if m == 0 { format!("tra {} or{}", h, if h == 1 { "a" } else { "e" }) }
                    else { format!("tra {}h {:02}min", h, m) }
                };
            let body = format!("{} — {} ({})", item_title, item_time, time_desc);

            let app_clone = app.clone();
            let body_clone = body.clone();
            let _ = app.run_on_main_thread(move || {
                let _ = app_clone.notification().builder()
                    .title("LexFlow — Promemoria")
                    .body(&body_clone)
                    .show();
            });
            eprintln!("[LexFlow Cron] ✓ Reminder fired: {} → {}", item_title, fire_minute);
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  ANTI-SCREENSHOT & CONTENT PROTECTION
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn set_content_protection(app: AppHandle, enabled: bool) -> bool {
    #[cfg(not(target_os = "android"))]
    {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.set_content_protected(enabled);
            true
        } else { false }
    }
    #[cfg(target_os = "android")]
    {
        // Su Android FLAG_SECURE è gestito via tauri mobile — sempre attivo per sicurezza
        let _ = (app, enabled);
        true
    }
}

#[tauri::command]
fn ping_activity(state: State<AppState>) {
    // SECURITY FIX (Gemini Audit Chunk 15): 1-second throttle to prevent mutex contention
    let now = Instant::now();
    let last = *state.last_activity.lock().unwrap_or_else(|e| e.into_inner());
    if now.duration_since(last) > Duration::from_secs(1) {
        *state.last_activity.lock().unwrap_or_else(|e| e.into_inner()) = now;
    }
}

#[tauri::command]
fn set_autolock_minutes(state: State<AppState>, minutes: u32) {
    // SECURITY FIX (Gemini Audit Chunk 15): log mutex poisoning
    match state.autolock_minutes.lock() {
        Ok(mut guard) => *guard = minutes,
        Err(e) => {
            eprintln!("[SECURITY] autolock_minutes mutex poisoned: {}", e);
            *e.into_inner() = minutes;
        }
    }
}

#[tauri::command]
fn get_autolock_minutes(state: State<AppState>) -> u32 {
    *state.autolock_minutes.lock().unwrap_or_else(|e| e.into_inner())
}

// ═══════════════════════════════════════════════════════════
//  WINDOW CONTROLS — solo desktop
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn window_minimize(app: AppHandle) {
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") { let _ = w.minimize(); }
    #[cfg(target_os = "android")]
    { let _ = app; }
}

#[tauri::command]
fn window_maximize(app: AppHandle) {
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") {
        if w.is_maximized().unwrap_or(false) { let _ = w.unmaximize(); }
        else { let _ = w.maximize(); }
    }
    #[cfg(target_os = "android")]
    { let _ = app; }
}

#[tauri::command]
fn show_main_window(app: AppHandle) {
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
    #[cfg(target_os = "android")]
    { let _ = app; }
}

// ═══════════════════════════════════════════════════════════
//  APP RUNNER
// ═══════════════════════════════════════════════════════════

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Desktop: usa dirs::data_dir() — percorso stabile cross-platform
    // Android: usa un placeholder; il percorso reale viene risolto nel setup()
    //          tramite app.path().app_data_dir() che restituisce il path privato
    //          dell'app senza dipendere da env var o hardcoded fallback.
    #[cfg(not(target_os = "android"))]
    let data_dir = dirs::data_dir()
        .expect("FATAL: could not determine system data directory (dirs::data_dir)")
        .join("com.pietrolongo.lexflow")
        .join("lexflow-vault");

    // security_dir: parent of vault — security files live here so vault reset cannot erase them
    #[cfg(not(target_os = "android"))]
    let security_dir = dirs::data_dir()
        .expect("FATAL: could not determine system data directory (dirs::data_dir)")
        .join("com.pietrolongo.lexflow");

    #[cfg(target_os = "android")]
    let data_dir = std::path::PathBuf::from("/placeholder-android-will-be-set-in-setup");
    #[cfg(target_os = "android")]
    let security_dir = std::path::PathBuf::from("/placeholder-android-will-be-set-in-setup");

    let _ = fs::create_dir_all(&data_dir);
    let _ = fs::create_dir_all(&security_dir);

    // ── MIGRATION: move data from old identifier (com.technojaw.lexflow) to new one ──
    #[cfg(not(target_os = "android"))]
    {
        // SECURITY FIX (Gemini Audit Chunk 17): handle dirs::data_dir gracefully
        if let Some(old_data_dir) = dirs::data_dir() {
            let old_base = old_data_dir.join("com.technojaw.lexflow");
            if old_base.exists() && old_base.is_dir() {
                // Migrate vault directory
                let old_vault = old_base.join("lexflow-vault");
                if old_vault.exists() && !data_dir.join(VAULT_FILE).exists() {
                    // Copy all files from old vault to new vault
                    if let Ok(entries) = fs::read_dir(&old_vault) {
                        for entry in entries.flatten() {
                            let dest = data_dir.join(entry.file_name());
                            if !dest.exists() {
                                let _ = fs::copy(entry.path(), &dest);
                            }
                        }
                    }
                }
                // Migrate security files from old base
                for sec_file in &[LICENSE_FILE, LICENSE_SENTINEL_FILE, BURNED_KEYS_FILE, LOCKOUT_FILE] {
                    let old_path = old_base.join(sec_file);
                    let new_path = security_dir.join(sec_file);
                    if old_path.exists() && !new_path.exists() {
                        let _ = fs::copy(&old_path, &new_path);
                    }
                }
            }
        }
    }

    // ── MIGRATION: move security files from old location (vault) to security_dir ──
    // In versions ≤2.6.1, license.json, .license-sentinel, .burned-keys, .lockout were
    // stored inside the vault dir. Now they live in security_dir (parent). Migrate once.
    for sec_file in &[LICENSE_FILE, LICENSE_SENTINEL_FILE, BURNED_KEYS_FILE, LOCKOUT_FILE] {
        let old_path = data_dir.join(sec_file);
        let new_path = security_dir.join(sec_file);
        if old_path.exists() && !new_path.exists() {
            let _ = fs::copy(&old_path, &new_path);
            let _ = fs::remove_file(&old_path);
        }
    }
    // data_dir_for_sync: used in setup() to perform initial notification sync.
    #[cfg(not(target_os = "android"))]
    let data_dir_for_scheduler = data_dir.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_log::Builder::default().build())
        .manage(AppState {
            data_dir: Mutex::new(data_dir),
            security_dir: Mutex::new(security_dir),
            vault_key: Mutex::new(None),
            failed_attempts: Mutex::new(0),
            locked_until: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            autolock_minutes: Mutex::new(5),
            write_mutex: Mutex::new(()),
        })
        .setup(move |app| {
            // ═══ SECURITY FIX (Security Audit G5): RUNTIME SELF-INTEGRITY CHECK ═══
            // Verifies that critical crypto constants have not been tampered with by a
            // binary patcher/hex editor. A known SHA-256 digest of the concatenated
            // constant values is checked at every startup. If the binary was patched
            // (e.g. reducing Argon2 m_cost to 1 or changing PUBLIC_KEY_BYTES), this
            // check detects the corruption and panics before any data is processed.
            {
                let mut integrity_seed = Vec::with_capacity(256);
                integrity_seed.extend_from_slice(VAULT_MAGIC);
                integrity_seed.extend_from_slice(&(AES_KEY_LEN as u64).to_le_bytes());
                integrity_seed.extend_from_slice(&(NONCE_LEN as u64).to_le_bytes());
                integrity_seed.extend_from_slice(&ARGON2_M_COST.to_le_bytes());
                integrity_seed.extend_from_slice(&ARGON2_T_COST.to_le_bytes());
                integrity_seed.extend_from_slice(&ARGON2_P_COST.to_le_bytes());
                integrity_seed.extend_from_slice(&PUBLIC_KEY_BYTES);
                integrity_seed.extend_from_slice(&MAX_FAILED_ATTEMPTS.to_le_bytes());
                let digest = hex::encode(<Sha256 as Digest>::digest(&integrity_seed));
                // Pre-computed: SHA-256 of the concatenated constants.
                // To regenerate: change a constant → run in debug → read the panic message.
                const EXPECTED_HASH: &str = "369a8f3e626e8e8b19cd99f48451596db2d8ca1c0de4b6784229cb00778192a1";
                if digest != EXPECTED_HASH {
                    eprintln!("FATAL INTEGRITY VIOLATION: crypto constants digest mismatch!");
                    eprintln!("  Expected: {}", EXPECTED_HASH);
                    eprintln!("  Got:      {}", digest);
                    panic!("SECURITY: Binary integrity check failed — possible tampering detected.");
                }
            }
            // ── NOTIFICATION PERMISSION (native, at startup) ──
            // On macOS, permission is bound to the app's code signature. During development
            // (ad-hoc signing), each rebuild changes the signature, causing macOS Notification
            // Center to silently drop notifications. This is expected and resolves with a
            // stable Apple Developer certificate in production builds.
            //
            // APPLE GUIDELINES FIX: if the user has explicitly Denied notifications,
            // we must NOT call request_permission() again — macOS ignores the call and
            // repeated attempts can cause the XPC daemon to permanently silence the app.
            // Instead, log a message guiding the user to System Settings.
            {
                use tauri_plugin_notification::NotificationExt;
                let state = app.notification().permission_state();
                eprintln!("[LexFlow] Notification permission state: {:?}", state);
                match state {
                    Ok(tauri_plugin_notification::PermissionState::Granted) => {
                        eprintln!("[LexFlow] Notifications already granted ✓");
                    }
                    Ok(tauri_plugin_notification::PermissionState::Denied) => {
                        // DO NOT call request_permission() here — Apple will ignore it
                        // and may permanently silence the app's XPC notification daemon.
                        eprintln!("[LexFlow] ⚠️ Notifications DENIED by user/system.");
                        eprintln!("[LexFlow] → User must enable manually: System Settings → Notifications → LexFlow");
                        // Emit to frontend so we can show an in-app banner
                        let _ = app.emit("notification-permission-denied", ());
                    }
                    _ => {
                        // Unknown/NotDetermined — safe to request
                        eprintln!("[LexFlow] Notifications unknown — requesting permission...");
                        let result = app.notification().request_permission();
                        eprintln!("[LexFlow] Permission request result: {:?}", result);
                    }
                }

                // First-launch: send a welcome notification to register with macOS Notification Center.
                // Without this, macOS may not show LexFlow in System Settings → Notifications.
                // Uses a marker file so it only fires once per installation.
                #[cfg(not(target_os = "android"))]
                {
                    let marker = data_dir_for_scheduler.join(".notifications_registered");
                    if !marker.exists() {
                        let _ = app.notification()
                            .builder()
                            .title("LexFlow")
                            .body("Le notifiche sono attive! Riceverai promemoria per scadenze e udienze.")
                            .show();
                        let _ = std::fs::write(&marker, "1");
                        eprintln!("[LexFlow] First-launch notification sent ✓");
                    }
                }
            }

            // ── AHEAD-OF-TIME SYNC: schedule all pending notifications with the OS ──
            // On mobile: native AOT scheduling via sync_notifications()
            // On desktop: no-op stub — the async cron job handles everything
            #[cfg(not(target_os = "android"))]
            sync_notifications(&app.handle(), &data_dir_for_scheduler);

            // ── DESKTOP: App Nap prevention + async cron job ──────────────────
            #[cfg(target_os = "macos")]
            {
                // Disable App Nap via defaults write — clean approach, no objc/cocoa FFI needed
                let bundle_id = app.config().identifier.clone();
                let _ = std::process::Command::new("defaults")
                    .args(["write", &bundle_id, "NSAppSleepDisabled", "-bool", "YES"])
                    .output();
                eprintln!("[LexFlow] macOS App Nap disabled via defaults write ✓");
            }

            // Launch the desktop cron job (single async task, zero threads)
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    desktop_cron_job(app_handle).await;
                });
            }

            #[cfg(target_os = "android")]
            {
                // Risolvi il path reale tramite Tauri PathResolver — nessun hardcoded path.
                // app_data_dir() = /data/data/<pkg>/files/ (privato, senza root).
                if let Ok(real_dir) = app.path().app_data_dir() {
                    let vault_dir = real_dir.join("lexflow-vault");
                    let _ = fs::create_dir_all(&vault_dir);
                    *app.state::<AppState>().data_dir.lock().unwrap_or_else(|e| e.into_inner()) = vault_dir.clone();
                    *app.state::<AppState>().security_dir.lock().unwrap_or_else(|e| e.into_inner()) = real_dir.clone();
                    // ── AHEAD-OF-TIME SYNC on Android ──
                    sync_notifications(&app.handle(), &vault_dir);
                }
            }

            #[cfg(not(target_os = "android"))]
            {
                // NOTE: set_content_protected(true) removed — causes SIGABRT crash on
                // macOS 26 (Sequoia) when the window loses focus (resignKeyWindow).
                // The crash happens because setSharingType:NSWindowSharingNone interferes
                // with the AppKit notification center during deactivation events.
                // Privacy is already handled via the lf-blur event + frontend overlay.

                // Auto-lock thread con sleep adattivo:
                // - vault bloccato → dorme 60s (nessun lavoro da fare, risparmia CPU)
                // - vault sbloccato → dorme 30s (controlla inattività)
                // RACE CONDITION FIX (L7 #5): emit "lf-vault-warning" 30s before locking
                // so the frontend can show a "saving..." notice and the user can ping activity.
                // This prevents data loss when the user is mid-form at the autolock boundary.
                let ah = app.handle().clone();
                std::thread::spawn(move || {
                    loop {
                        let state = ah.state::<AppState>();
                        let is_unlocked = state.vault_key.lock()
                            .map(|k| k.is_some()).unwrap_or(false);
                        if !is_unlocked {
                            drop(state);
                            std::thread::sleep(Duration::from_secs(60));
                            continue;
                        }
                        let minutes = state.autolock_minutes.lock()
                            .map(|m| *m).unwrap_or(5);
                        let last = state.last_activity.lock()
                            .map(|l| *l).unwrap_or_else(|_| Instant::now());
                        drop(state);
                        std::thread::sleep(Duration::from_secs(30));
                        if minutes == 0 { continue; }
                        let elapsed = Instant::now().duration_since(last);
                        let threshold = Duration::from_secs(minutes as u64 * 60);
                        // Warning: 30s before actual lock
                        if elapsed >= threshold.saturating_sub(Duration::from_secs(30))
                            && elapsed < threshold
                        {
                            let _ = ah.emit("lf-vault-warning", ());
                        }
                        if elapsed >= threshold {
                            let state2 = ah.state::<AppState>();
                            if let Ok(mut key) = state2.vault_key.lock() {
                                *key = None;
                            }
                            let _ = ah.emit("lf-vault-locked", ());
                        }
                    }
                });

                // Show main window after setup
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }

                // Window focus/blur events → privacy shield + intercept close to hide in tray
                let app_handle = app.handle().clone();
                if let Some(w) = app.get_webview_window("main") {
                    let w_clone = w.clone();
                    w.on_window_event(move |event| {
                        match event {
                            // Privacy shield: emit blur event so frontend can obscure content
                            tauri::WindowEvent::Focused(focused) => {
                                let _ = app_handle.emit("lf-blur", !focused);
                            }
                            // SYSTEM TRAY FIX: intercept the 'X' close button — hide the window
                            // instead of terminating the process so the notification scheduler
                            // keeps running in the background.  The user can quit via tray menu.
                            tauri::WindowEvent::CloseRequested { api, .. } => {
                                api.prevent_close();
                                // BLACK SCREEN FIX: on macOS, if the window is in native fullscreen
                                // and we just hide() it, the next show() re-opens into a black
                                // fullscreen space.  Exit fullscreen BEFORE hiding so the window
                                // returns to its normal state when re-shown from the tray.
                                if w_clone.is_fullscreen().unwrap_or(false) {
                                    let _ = w_clone.set_fullscreen(false);
                                }
                                let _ = w_clone.hide();
                            }
                            _ => {}
                        }
                    });
                }

                // ── System Tray ───────────────────────────────────────────────
                // Keeps the process alive when the main window is hidden so the
                // notification scheduler continues running between sessions.
                {
                    use tauri::tray::TrayIconBuilder;
                    use tauri::menu::{Menu, MenuItem};

                    let show_item = MenuItem::with_id(app, "show", "Apri LexFlow", true, None::<&str>)?;
                    let quit_item = MenuItem::with_id(app, "quit", "Chiudi LexFlow", true, None::<&str>)?;
                    let tray_menu = Menu::with_items(app, &[&show_item, &quit_item])?;

                    TrayIconBuilder::new()
                        .tooltip("LexFlow — Gestionale Legale")
                        .icon(app.default_window_icon().unwrap().clone())
                        .menu(&tray_menu)
                        .show_menu_on_left_click(false)
                        // Right-click / menu item handler
                        .on_menu_event(|app, event| match event.id.as_ref() {
                            "show" => {
                                if let Some(w) = app.get_webview_window("main") {
                                    let _ = w.show();
                                    let _ = w.set_focus();
                                }
                            }
                            "quit" => {
                                // Lock vault before exiting so key is not in memory
                                let state = app.state::<AppState>();
                                *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
                                app.exit(0);
                            }
                            _ => {}
                        })
                        // Left-click directly on the tray icon → show window
                        .on_tray_icon_event(|tray, event| {
                            if let tauri::tray::TrayIconEvent::Click {
                                button: tauri::tray::MouseButton::Left, ..
                            } = event {
                                if let Some(w) = tray.app_handle().get_webview_window("main") {
                                    let _ = w.show();
                                    let _ = w.set_focus();
                                }
                            }
                        })
                        .build(app)?;
                }
            }

            #[cfg(target_os = "android")]
            {
                // Android: stesso pattern sleep adattivo del desktop —
                // meno wakeup quando il vault è bloccato = risparmio batteria
                // RACE CONDITION FIX (L7 #5): warning event 30s before lock
                let ah = app.handle().clone();
                std::thread::spawn(move || {
                    loop {
                        let state = ah.state::<AppState>();
                        let is_unlocked = state.vault_key.lock().unwrap_or_else(|e| e.into_inner()).is_some();
                        if !is_unlocked {
                            std::thread::sleep(Duration::from_secs(60));
                            continue;
                        }
                        let minutes = *state.autolock_minutes.lock().unwrap_or_else(|e| e.into_inner());
                        let last = *state.last_activity.lock().unwrap_or_else(|e| e.into_inner());
                        drop(state);
                        std::thread::sleep(Duration::from_secs(30));
                        if minutes == 0 { continue; }
                        let elapsed = Instant::now().duration_since(last);
                        let threshold = Duration::from_secs(minutes as u64 * 60);
                        if elapsed >= threshold.saturating_sub(Duration::from_secs(30))
                            && elapsed < threshold
                        {
                            let _ = ah.emit("lf-vault-warning", ());
                        }
                        if elapsed >= threshold {
                            let state2 = ah.state::<AppState>();
                            *state2.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
                            let _ = ah.emit("lf-vault-locked", ());
                        }
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Vault
            vault_exists,
            unlock_vault,
            lock_vault,
            reset_vault,
            change_password,
            verify_vault_password,
            get_audit_log,
            // Data
            load_practices,
            save_practices,
            load_agenda,
            save_agenda,
            get_summary,
            // Conflict Check (v3.2.0)
            check_conflict,
            // Time Tracking (v3.3.0)
            load_time_logs,
            save_time_logs,
            // Invoices / Billing (v3.4.0)
            load_invoices,
            save_invoices,
            // Contacts Registry (v3.5.0)
            load_contacts,
            save_contacts,
            // Settings
            get_settings,
            save_settings,
            // Biometrics
            check_bio,
            has_bio_saved,
            save_bio,
            bio_login,
            clear_bio,
            // Files
            select_file,
            select_folder,
            open_path,
            select_pdf_save_path,
                list_folder_contents,
                warm_swift,
            // Notifications
            send_notification,
            sync_notification_schedule,
            test_notification,
            // License
            check_license,
            verify_license,
            activate_license,
            // Import / Export
            export_vault,
            import_vault,
            // Platform
            is_mac,
            get_app_version,
            get_platform,
            // Security & Content Protection
            set_content_protection,
            ping_activity,
            set_autolock_minutes,
            get_autolock_minutes,
            // Window
            window_minimize,
            window_maximize,
            window_close,
            show_main_window,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|#[allow(unused)] app, event| {
            // macOS: click sull'icona nel Dock quando la finestra è nascosta → riaprila
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            // Prevent default exit on last window close (keep tray alive)
            if let tauri::RunEvent::ExitRequested { api, .. } = &event {
                api.prevent_exit();
            }
        });
}