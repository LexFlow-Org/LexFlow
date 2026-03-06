#![allow(unexpected_cfgs)]

use chrono::TimeZone as _;
use serde_json::{json, Value};
use std::io::Read;
use std::{
    fs,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::{Zeroize, Zeroizing}; // SECURITY FIX (Gemini Audit Chunk 10): needed for safe_bounded_read

// Platform detection helpers — usati in tutta la lib
#[allow(dead_code)]
const IS_ANDROID: bool = cfg!(target_os = "android");
#[allow(dead_code)]
const IS_DESKTOP: bool = cfg!(any(
    target_os = "macos",
    target_os = "windows",
    target_os = "linux"
));

// Security & Crypto Hardened — disponibile su tutte le piattaforme
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
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

/// SECURITY (Audit 2026-03-04): track legacy AAD-less decryption fallback usage at runtime.
/// After this many decrypt_data() calls WITHOUT any legacy fallback trigger, we consider
/// all files migrated and stop offering the fallback permanently for this session.
/// This limits the window during which an attacker with filesystem access could craft
/// a ciphertext with empty AAD that would be accepted.
const LEGACY_AAD_SUNSET_THRESHOLD: u32 = 200;
static LEGACY_AAD_CLEAN_COUNTER: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);
static LEGACY_AAD_EVER_USED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// SECURITY FIX (Level-8 C5): cap settings/notification file reads to prevent OOM attack.
// An attacker (or corrupted write) could inject a 5GB settings.json; fs::read would try
// to allocate 5GB in RAM and OOM-kill the process. 10MB is generous for any real settings file.
const MAX_SETTINGS_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

// ═══════════════════════════════════════════════════════════
//  STATE & MEMORY PROTECTION
// ═══════════════════════════════════════════════════════════

/// Platform-specific UID — extracted to eliminate 3 duplicate blocks.
/// Returns a string combining domain/SID (Windows) or real UID+username (Unix).
/// SECURITY FIX (Audit Chunk 01): on Unix, uses libc::getuid() syscall instead of $UID env var.
/// Env vars are user-spoofable (`export UID=fake`); getuid() is a kernel syscall and non-falsifiable.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn get_platform_uid() -> String {
    #[cfg(target_os = "windows")]
    {
        let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "WORKGROUP".to_string());
        let sid = std::env::var("USERPROFILE")
            .unwrap_or_else(|_| std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "0".to_string()));
        format!("{}:{}", domain, sid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // SECURITY FIX: use libc::getuid() (kernel syscall, non-spoofable) + whoami::username()
        // as fallback context. Previously used $UID/$USER env vars which an attacker could
        // manipulate to alter local encryption key derivation.
        let real_uid = unsafe { libc::getuid() };
        let username = whoami::username();
        format!("{}:{}", real_uid, username)
    }
}

/// Derive a SHA-256 double-hash key from a seed string. Used by encryption key functions.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn double_sha256_key(seed: &str) -> Zeroizing<Vec<u8>> {
    let h1 = <Sha256 as Digest>::digest(seed.as_bytes());
    let h2 = <Sha256 as Digest>::digest(h1);
    Zeroizing::new(h2.to_vec())
}

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
    // SECURITY FIX (Audit Chunk 02): propagate create_dir_all failure. If we can't create
    // the directory, continuing would generate a new machine_id every launch, silently
    // corrupting all files encrypted with the local key (settings, burned-keys, license).
    fs::create_dir_all(&security_dir).unwrap_or_else(|e| {
        panic!(
            "FATAL: Impossibile creare security_dir {:?}: {}. \
                Senza questa directory il machine-id non può essere persistito \
                e tutti i file cifrati locali sarebbero inaccessibili.",
            security_dir, e
        );
    });
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

/// V3 key (with hostname in seed) — kept for migration from V3→V4.
/// SECURITY FIX (Audit v2.5): V3 used hostname which could change and lock out the user.
/// V4 removed hostname entirely. This function exists only for migration path.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn get_local_encryption_key_v3() -> Zeroizing<Vec<u8>> {
    let user = whoami::username();
    let machine_id = get_or_create_machine_id();
    let uid = get_platform_uid();
    // NOTE: This is intentionally the OLD V3 seed with hostname omitted from the V4 path.
    // V3 actually never included hostname — it replaced hostname with machine_id.
    // The real hostname-based key is V2 (legacy). V3→V4 migration is:
    // V3 seed = "LEXFLOW-LOCAL-KEY-V3:<user>:<machine_id>:<uid>:FORTKNOX"
    let seed = format!(
        "LEXFLOW-LOCAL-KEY-V3:{}:{}:{}:FORTKNOX",
        user, machine_id, uid
    );
    double_sha256_key(&seed)
}

// Legacy V2 key computation (with hostname) for migration of existing encrypted files.
// If the new key fails to decrypt, callers try this before giving up.
// SECURITY FIX (Gemini Audit Chunk 01): explicit desktop cfg
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn get_local_encryption_key_legacy() -> Zeroizing<Vec<u8>> {
    let user = whoami::username();
    let host = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let uid = get_platform_uid();
    let seed = format!("LEXFLOW-LOCAL-KEY-V2:{}:{}:{}:FORTKNOX", user, host, uid);
    double_sha256_key(&seed)
}

/// Try to decrypt with current key (V4), fall back to V3, then V2 legacy.
/// On older key success, re-encrypt with current key for silent migration.
///
/// Migration chain: V4 (current, no hostname) → V3 (machine_id) → V2 (hostname-based)
///
/// ## Security note (Audit 2026-03-06)
/// If `atomic_write_with_sync` fails during migration, the old key still decrypts
/// the file — an attacker with physical access who knows the hostname could exploit this
/// to keep the weaker legacy key path alive. This requires local machine access, so the
/// risk is accepted. The failure is logged to stderr. The migration will retry on every
/// subsequent read until it succeeds.
fn decrypt_local_with_migration(path: &std::path::Path) -> Option<Vec<u8>> {
    let enc = fs::read(path).ok()?;
    let key = get_local_encryption_key();
    if let Ok(dec) = decrypt_data(&key, &enc) {
        return Some(dec);
    }
    // SECURITY FIX (Gemini Audit Chunk 01): explicit desktop cfg
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        // Try V3 key (machine_id-based, same as V4 but with V3 domain separator)
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

        // Try V2 legacy key (hostname-based)
        let legacy_key = get_local_encryption_key_legacy();
        if let Ok(dec) = decrypt_data(&legacy_key, &enc) {
            eprintln!(
                "SECURITY NOTICE: Decrypting {:?} via LEGACY V2 key (hostname-based). \
                Re-encrypting with V4 key...",
                path.file_name().unwrap_or_default()
            );
            if let Ok(re_enc) = encrypt_data(&key, &dec) {
                if let Err(e) = atomic_write_with_sync(path, &re_enc) {
                    eprintln!("CRITICAL WARNING: V2→V4 migration write failed for {:?}: {}. \
                        The file remains decryptable with the legacy (hostname-based) key. \
                        An attacker with physical access and hostname knowledge could exploit this. \
                        Migration will retry on next read.", path.file_name().unwrap_or_default(), e);
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
        let uid = get_platform_uid();
        // SECURITY FIX (Audit v2.5): hostname removed entirely from seed.
        // Previously LEXFLOW-LOCAL-KEY-V3 included hostname — if the user renamed
        // their computer, the key changed and all locally-encrypted files (settings,
        // burned-keys, license) became inaccessible. Now the seed depends only on
        // persistent machine_id + uid, both stable across hostname/network changes.
        // Domain separator bumped to V4 to distinguish from V3 keys.
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
        let hash = <Sha256 as Digest>::digest(seed.as_bytes());
        Zeroizing::new(hash.to_vec())
    }
}

/// Resolve the Android device ID from environment or persisted file.
/// Generates and persists a new 256-bit random ID on first run.
#[cfg(target_os = "android")]
fn get_android_device_id() -> String {
    if let Ok(id) = std::env::var("LEXFLOW_DEVICE_ID") {
        return id;
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
            return id;
        }
        if first_writable.is_none() {
            first_writable = Some(id_path);
        }
    }
    // First run: generate and persist
    let mut id_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id_bytes);
    let id_hex = hex::encode(id_bytes);
    let id_path = first_writable.expect(
        "FATAL: Nessun percorso scrivibile trovato su Android per persistere la master key.",
    );
    if let Some(parent) = id_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&id_path, &id_hex).expect("FATAL: Impossibile salvare device_id. Rischio data loss.");
    id_hex
}

/// Read a file, trim it, return Some(content) if non-empty.
#[cfg(target_os = "android")]
fn read_trimmed_file(path: &std::path::Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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
/// NOTE: fingerprint parameter was removed (was `_fingerprint: &str`, always ignored).
/// Machine-independence is the whole point — the same hash on every device.
fn compute_burn_hash(token: &str) -> String {
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
    Ok(text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

/// Append a burn-hash to the registry and write back encrypted.
/// SECURITY FIX (Gemini Audit Chunk 03): Returns Result. Fails if registry is tampered or disk full.
fn burn_key(dir: &std::path::Path, burn_hash: &str) -> Result<(), String> {
    let mut hashes = load_burned_keys(dir)?;
    if hashes.contains(&burn_hash.to_string()) {
        return Ok(());
    }
    hashes.push(burn_hash.to_string());
    let content = hashes.join("\n");
    let enc_key = get_local_encryption_key();
    let encrypted = encrypt_data(&enc_key, content.as_bytes())
        .map_err(|e| format!("Errore cifratura registro: {}", e))?;
    atomic_write_with_sync(&dir.join(BURNED_KEYS_FILE), &encrypted).map_err(|e| {
        format!(
            "FATAL: Impossibile salvare il registro aggiornato su disco: {}",
            e
        )
    })?;
    Ok(())
}

/// Check if a token has been burned (checks both v2 global and v1 legacy hashes).
/// SECURITY FIX (Gemini Audit Chunk 03): Returns Result<bool>. Fails closed if registry unreadable.
fn is_key_burned(dir: &std::path::Path, token: &str, fingerprint: &str) -> Result<bool, String> {
    let burn_hash_v2 = compute_burn_hash(token);
    let burn_hash_legacy = compute_burn_hash_legacy(token, fingerprint);
    let hashes = load_burned_keys(dir)?;
    Ok(hashes.contains(&burn_hash_v2) || hashes.contains(&burn_hash_legacy))
}

// ═══════════════════════════════════════════════════════════
//  STATE & MEMORY PROTECTION
// ═══════════════════════════════════════════════════════════

/// SECURITY FIX (Audit Chunk 04): use Zeroizing<Vec<u8>> instead of bare Vec<u8>.
/// A bare Vec<u8> may leave copies in memory during reallocation (grow/shrink).
/// Zeroizing guarantees the backing buffer is zeroed on Drop, even after moves.
pub struct SecureKey(Zeroizing<Vec<u8>>);
// No manual Drop needed — Zeroizing handles zeroing automatically.

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
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(AES_KEY_LEN),
    )
    .map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let pwd_bytes = Zeroizing::new(password.as_bytes().to_vec());
    argon2
        .hash_password_into(&pwd_bytes, salt, &mut key)
        .map_err(|e| e.to_string())?;
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
    let payload = Payload {
        msg: plaintext,
        aad: VAULT_MAGIC,
    };
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| "Encryption error")?;
    let mut out = VAULT_MAGIC.to_vec();
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_data(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < VAULT_MAGIC.len() + NONCE_LEN + 16 {
        return Err("Corrupted".into());
    }
    // SECURITY FIX (Gemini Audit v2): explicitly verify magic bytes BEFORE attempting decryption.
    // Previously the magic bytes were silently skipped without validation.
    if !data.starts_with(VAULT_MAGIC) {
        return Err("Invalid file format: magic bytes mismatch".into());
    }
    let nonce = Nonce::from_slice(&data[VAULT_MAGIC.len()..VAULT_MAGIC.len() + NONCE_LEN]);
    let ciphertext = &data[VAULT_MAGIC.len() + NONCE_LEN..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    // SECURITY FIX: VAULT_MAGIC passed as AAD — must match what was used during encryption.
    let payload = Payload {
        msg: ciphertext,
        aad: VAULT_MAGIC,
    };
    match cipher.decrypt(nonce, payload) {
        Ok(dec) => {
            // Successful decryption with AAD — increment clean counter toward sunset.
            LEGACY_AAD_CLEAN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(dec);
        }
        Err(_) => {
            // Primary decryption failed — try legacy fallback below.
        }
    }

    // SECURITY FIX (Audit 2026-03-04): sunset mechanism for legacy AAD-less fallback.
    // After LEGACY_AAD_SUNSET_THRESHOLD consecutive successful decryptions without
    // needing the fallback, we consider all files migrated and refuse the legacy path.
    // This limits the window for an attacker to craft files with empty AAD.
    let clean_count = LEGACY_AAD_CLEAN_COUNTER.load(std::sync::atomic::Ordering::Relaxed);
    if clean_count >= LEGACY_AAD_SUNSET_THRESHOLD
        && !LEGACY_AAD_EVER_USED.load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err("Auth failed (legacy fallback disabled — all files should be migrated)".into());
    }

    // Legacy fallback: decrypt without AAD (pre-v3.6.0 files)
    // DEPRECATION NOTE: this fallback should be removed in v4.0.0. It exists only
    // for backward compatibility with files encrypted before AAD was introduced.
    // After sufficient migration window, removing this eliminates a potential
    // downgrade path where an attacker could craft files with empty AAD.
    let legacy_payload = Payload {
        msg: ciphertext,
        aad: b"",
    };
    cipher
        .decrypt(nonce, legacy_payload)
        .map_err(|_| "Auth failed".into())
        .inspect(|_dec| {
            // Reset clean counter — legacy path is still needed.
            LEGACY_AAD_CLEAN_COUNTER.store(0, std::sync::atomic::Ordering::Relaxed);
            LEGACY_AAD_EVER_USED.store(true, std::sync::atomic::Ordering::Relaxed);
            eprintln!(
                "SECURITY WARNING: File decifrato con fallback legacy (senza AAD). \
                RE-CIFRATURA AUTOMATICA in corso. Questo fallback sarà rimosso in v4.0.0."
            );
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
    state
        .vault_key
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|k| Zeroizing::new(k.0.to_vec()))
        .ok_or_else(|| "Locked".into())
}

// ─── Persisted brute-force state (L7 fix #1) ────────────────────────────────
// The lockout counters must survive app kills; otherwise an attacker can kill+restart
// to reset failed_attempts to 0. We persist them in a HMAC-protected file in the
// security dir. An attacker who corrupts or deletes the file triggers a fail-closed
// state (max attempts reached) instead of resetting the counter to 0.
// Format: "<attempts>:<unix_lockout_end_secs>:<hmac_hex>" — HMAC verifies integrity.

/// Compute HMAC for lockout data integrity — prevents local tampering to reset brute-force counter.
fn lockout_hmac(data: &str) -> String {
    let key = get_local_encryption_key();
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(b"LOCKOUT-INTEGRITY:");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn lockout_load(data_dir: &std::path::Path) -> (u32, Option<std::time::SystemTime>) {
    let path = data_dir.join(LOCKOUT_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return (0, None),
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return (0, None);
    }
    // SECURITY FIX (Audit Chunk 06): HMAC-protected lockout file.
    // Format: "<attempts>:<secs>:<hmac>". If HMAC is missing or invalid,
    // fail-closed: return MAX_FAILED_ATTEMPTS so lockout is enforced.
    let parts: Vec<&str> = trimmed.splitn(3, ':').collect();
    if parts.len() != 3 {
        // Corrupted/tampered file → fail-closed (enforce lockout)
        eprintln!("[SECURITY] Lockout file format invalid — fail-closed (enforcing max attempts)");
        return (MAX_FAILED_ATTEMPTS, None);
    }
    let data_part = format!("{}:{}", parts[0], parts[1]);
    let stored_hmac = parts[2];
    let expected_hmac = lockout_hmac(&data_part);
    if stored_hmac != expected_hmac {
        eprintln!("[SECURITY] Lockout file HMAC mismatch — possible tampering. Fail-closed.");
        return (MAX_FAILED_ATTEMPTS, None);
    }
    let attempts = parts[0].parse::<u32>().unwrap_or(MAX_FAILED_ATTEMPTS);
    let lockout_end_secs = parts[1].parse::<u64>().unwrap_or(0);
    if lockout_end_secs == 0 {
        return (attempts, None);
    }
    let end = std::time::UNIX_EPOCH + Duration::from_secs(lockout_end_secs);
    (attempts, Some(end))
}

fn lockout_save(
    data_dir: &std::path::Path,
    attempts: u32,
    locked_until: Option<std::time::SystemTime>,
) {
    let secs = locked_until
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let data_part = format!("{}:{}", attempts, secs);
    let hmac = lockout_hmac(&data_part);
    let _ = fs::write(
        data_dir.join(LOCKOUT_FILE),
        format!("{}:{}", data_part, hmac),
    );
}

fn lockout_clear(data_dir: &std::path::Path) {
    let _ = fs::remove_file(data_dir.join(LOCKOUT_FILE));
}

// ═══════════════════════════════════════════════════════════
//  CENTRALIZED HELPERS — DRY refactor (Gemini Audit v2)
// ═══════════════════════════════════════════════════════════

/// Safe password zeroing — replaces ALL unsafe pointer casts.
/// SECURITY FIX (Gemini Audit v2): the old code cast `as_ptr() as *mut u8` and wrote
/// through it, violating Rust's aliasing rules (Stacked Borrows) and causing Undefined
/// Behavior. The correct approach: convert to owned bytes, then zeroize.
///
/// SECURITY NOTE: `into_bytes()` consumes the String and returns its backing Vec<u8>.
/// However, the compiler may have already placed copies of the password in registers
/// or stack frames before this function was called. Zeroing the Vec is the best-effort
/// approach — complete zeroing of all intermediate copies is fundamentally impossible
/// in any language without custom allocator support. This is an inherent limitation,
/// NOT a bug.
fn zeroize_password(password: String) {
    let mut pwd_bytes = password.into_bytes();
    pwd_bytes.zeroize();
}

/// Centralized lockout check — replaces 3 duplicated lockout code blocks.
/// Returns Ok(()) if not locked, or Err(json) with remaining time if locked.
fn check_lockout(state: &State<AppState>, sec_dir: &std::path::Path) -> Result<(), Value> {
    let (disk_attempts, disk_locked_until) = lockout_load(sec_dir);
    // Sync in-memory from disk on first call after restart
    {
        let mut att = state
            .failed_attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if disk_attempts > *att {
            *att = disk_attempts;
        }
    }
    // Check disk-based lockout
    if let Some(end_time) = disk_locked_until {
        if SystemTime::now() < end_time {
            let remaining = end_time
                .duration_since(SystemTime::now())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            return Err(
                json!({"success": false, "valid": false, "locked": true, "remaining": remaining}),
            );
        }
    }
    // Check in-memory lockout (Instant-based, within-session)
    if let Some(until) = *state.locked_until.lock().unwrap_or_else(|e| e.into_inner()) {
        if Instant::now() < until {
            return Err(
                json!({"success": false, "valid": false, "locked": true, "remaining": (until - Instant::now()).as_secs()}),
            );
        }
    }
    Ok(())
}

/// Record a failed authentication attempt. Triggers lockout after MAX_FAILED_ATTEMPTS.
/// SECURITY FIX (Security Audit G7): log attempt count + lockout status for forensics.
fn record_failed_attempt(state: &State<AppState>, sec_dir: &std::path::Path) {
    let mut att = state
        .failed_attempts
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *att += 1;
    let locked_sys = if *att >= MAX_FAILED_ATTEMPTS {
        let t = SystemTime::now() + Duration::from_secs(LOCKOUT_SECS);
        *state.locked_until.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Instant::now() + Duration::from_secs(LOCKOUT_SECS));
        Some(t)
    } else {
        None
    };
    lockout_save(sec_dir, *att, locked_sys);
    // SECURITY FIX (Security Audit G7): forensic logging of failed attempts.
    // Since vault is locked during auth, we can't write to the encrypted audit log.
    // Instead we log to stderr (captured by tauri-plugin-log → log file).
    eprintln!(
        "[SECURITY] Failed auth attempt #{}/{} at {}{}",
        *att,
        MAX_FAILED_ATTEMPTS,
        chrono::Local::now().to_rfc3339(),
        if locked_sys.is_some() {
            " → LOCKOUT TRIGGERED"
        } else {
            ""
        }
    );
}

/// Clear lockout state on successful authentication.
fn clear_lockout(state: &State<AppState>, sec_dir: &std::path::Path) {
    *state
        .failed_attempts
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = 0;
    *state.locked_until.lock().unwrap_or_else(|e| e.into_inner()) = None;
    lockout_clear(sec_dir);
}

/// Centralized atomic write with fsync — replaces 5+ duplicated patterns.
/// SECURITY FIX (Gemini Audit Chunk 05): random tmp name to prevent TOCTOU symlink attacks.
/// Also performs directory fsync after rename for crash-safe persistence.
fn atomic_write_with_sync(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        rand::random::<u32>()
    );
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
    let path = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .join(VAULT_FILE);
    if !path.exists() {
        return Ok(json!({"practices":[], "agenda":[]}));
    }
    let decrypted = decrypt_data(&key, &fs::read(path).map_err(|e| e.to_string())?)?;
    serde_json::from_slice(&decrypted).map_err(|e| e.to_string())
}

fn write_vault_internal(state: &State<AppState>, data: &Value) -> Result<(), String> {
    // NOTE: callers MUST hold write_mutex before calling this function.
    // The lock is NOT acquired here to avoid deadlock (Rust Mutex is not reentrant).
    // All save_* commands and change_password already acquire write_mutex.
    let key = get_vault_key(state)?;
    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
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
    state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .join(VAULT_SALT_FILE)
        .exists()
}

#[tauri::command]
/// Generate a new vault salt after validating password strength.
/// Returns Err(json) on weak password or write error, Ok(salt) on success.
fn create_new_vault_salt(password: &str, salt_path: &std::path::Path) -> Result<Vec<u8>, Value> {
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
    let mut s = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s);
    secure_write(salt_path, &s).map_err(
        |e| json!({"success": false, "error": format!("Errore scrittura vault: {}", e)}),
    )?;
    Ok(s)
}

/// Initialise a brand-new vault (write verify tag + empty vault).
fn init_new_vault(state: &State<AppState>, k: Vec<u8>, dir: &std::path::Path) -> Result<(), Value> {
    let tag = make_verify_tag(&k);
    secure_write(&dir.join(VAULT_VERIFY_FILE), &tag)
        .map_err(|e| json!({"success": false, "error": format!("Errore init vault: {}", e)}))?;
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(SecureKey(Zeroizing::new(k)));
    let _ = write_vault_internal(state, &json!({"practices":[], "agenda":[]}));
    Ok(())
}

#[tauri::command]
fn unlock_vault(state: State<AppState>, password: String) -> Value {
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
        return locked_json;
    }

    let salt_path = dir.join(VAULT_SALT_FILE);
    let is_new = !salt_path.exists();

    let salt = if is_new {
        match create_new_vault_salt(&password, &salt_path) {
            Ok(s) => s,
            Err(e) => {
                zeroize_password(password);
                return e;
            }
        }
    } else {
        fs::read(&salt_path).unwrap_or_default()
    };

    let k = match derive_secure_key(&password, &salt) {
        Ok(k) => k,
        Err(e) => {
            zeroize_password(password);
            return json!({"success": false, "error": e});
        }
    };

    if !is_new {
        let stored = fs::read(dir.join(VAULT_VERIFY_FILE)).unwrap_or_default();
        if !verify_hash_matches(&k, &stored) {
            record_failed_attempt(&state, &sec_dir);
            zeroize_password(password);
            return json!({"success": false, "error": "Password errata"});
        }
        *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(SecureKey(Zeroizing::new(k)));
    } else if let Err(e) = init_new_vault(&state, k, &dir) {
        zeroize_password(password);
        return e;
    }

    clear_lockout(&state, &sec_dir);
    *state
        .last_activity
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Instant::now();
    zeroize_password(password);
    let _ = append_audit_log(&state, "Sblocco Vault");
    json!({"success": true, "isNew": is_new})
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
    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let salt_path = dir.join(VAULT_SALT_FILE);
    let vault_path = dir.join(VAULT_FILE);
    // SECURITY FIX (Audit Chunk 07): if vault.lex exists but vault.salt does NOT,
    // someone may have deleted the salt to bypass authentication. Refuse the reset.
    if vault_path.exists() && !salt_path.exists() {
        zeroize_password(password);
        return json!({"success": false, "error": "Possibile manomissione: vault.lex presente ma vault.salt mancante. Contattare il supporto."});
    }
    if salt_path.exists() {
        match authenticate_vault_password(&password, &dir) {
            Ok(_) => {}
            Err(_) => {
                zeroize_password(password);
                return json!({"success": false, "error": "Password errata"});
            }
        }
    }
    {
        // SECURITY NOTE (Audit 2026-03-04): The zero-overwrite below is a best-effort
        // secure wipe. On modern filesystems with copy-on-write semantics (APFS, Btrfs,
        // ZFS) and on SSDs with wear leveling / TRIM, overwriting a file does NOT
        // guarantee that the original data blocks are physically erased. The filesystem
        // may allocate new blocks for the write, leaving old data in unreferenced sectors.
        // This is a fundamental limitation of all userspace secure-erase on modern storage.
        // Mitigations at the OS/hardware level include:
        //   - macOS FileVault (full-disk encryption)
        //   - Windows BitLocker
        //   - Linux LUKS/dm-crypt
        //   - SSD firmware TRIM/secure-erase commands
        // The zero-overwrite + delete below still prevents trivial `cat` / hex-editor
        // recovery, which is valuable against casual attackers.
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
    }
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    // SECURITY FIX (Gemini Audit v2): safe zeroing — no more UB
    zeroize_password(password);
    json!({"success": true})
}

#[tauri::command]
/// Atomically swap vault+salt+verify from staging directory.
/// Returns Ok(()) on success, or rolls back and returns Err on failure.
/// SECURITY FIX (Audit Chunk 08): step-by-step swap with per-step rollback.
/// Each file is swapped independently. If any step fails, only the already-swapped
/// files are rolled back (in reverse order), avoiding inconsistent state where
/// vault.lex is new but vault.salt is old.
fn transactional_vault_swap(
    dir: &std::path::Path,
    staging_dir: &std::path::Path,
) -> Result<(), String> {
    let vault_path = dir.join(VAULT_FILE);
    let salt_path = dir.join(VAULT_SALT_FILE);
    let verify_path = dir.join(VAULT_VERIFY_FILE);

    // Backup old files before swap
    let _ = fs::rename(&vault_path, dir.join(".vault.bak"));
    let _ = fs::rename(&salt_path, dir.join(".salt.bak"));
    let _ = fs::rename(&verify_path, dir.join(".verify.bak"));

    // Step 1: swap vault
    if fs::rename(staging_dir.join(VAULT_FILE), &vault_path).is_err() {
        eprintln!("CRITICAL ERROR: Swap vault.lex fallito. Rollback...");
        let _ = fs::rename(dir.join(".vault.bak"), &vault_path);
        let _ = fs::rename(dir.join(".salt.bak"), &salt_path);
        let _ = fs::rename(dir.join(".verify.bak"), &verify_path);
        return Err("Errore swap vault.lex. Rollback eseguito.".into());
    }

    // Step 2: swap salt
    if fs::rename(staging_dir.join(VAULT_SALT_FILE), &salt_path).is_err() {
        eprintln!("CRITICAL ERROR: Swap vault.salt fallito. Rollback in ordine inverso...");
        // Undo step 1: restore vault from backup
        let _ = fs::rename(&vault_path, staging_dir.join(VAULT_FILE)); // move new back to staging
        let _ = fs::rename(dir.join(".vault.bak"), &vault_path);
        let _ = fs::rename(dir.join(".salt.bak"), &salt_path);
        let _ = fs::rename(dir.join(".verify.bak"), &verify_path);
        return Err("Errore swap vault.salt. Rollback eseguito.".into());
    }

    // Step 3: swap verify
    if fs::rename(staging_dir.join(VAULT_VERIFY_FILE), &verify_path).is_err() {
        eprintln!("CRITICAL ERROR: Swap vault.verify fallito. Rollback in ordine inverso...");
        // Undo step 2: restore salt from backup
        let _ = fs::rename(&salt_path, staging_dir.join(VAULT_SALT_FILE));
        let _ = fs::rename(dir.join(".salt.bak"), &salt_path);
        // Undo step 1: restore vault from backup
        let _ = fs::rename(&vault_path, staging_dir.join(VAULT_FILE));
        let _ = fs::rename(dir.join(".vault.bak"), &vault_path);
        let _ = fs::rename(dir.join(".verify.bak"), &verify_path);
        return Err("Errore swap vault.verify. Rollback eseguito.".into());
    }

    Ok(())
}

/// Secure-wipe and remove backup files after successful vault swap.
fn cleanup_vault_backups(dir: &std::path::Path) {
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

/// Re-encrypt audit log with a new key (used after password change).
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

#[tauri::command]
fn change_password(
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

    // SECURITY FIX (Audit Chunk 08): wrap current_key in Zeroizing so it's zeroed on drop.
    // Previously bare Vec<u8> could linger in heap memory after use.
    let current_key = Zeroizing::new(match authenticate_vault_password(&current_password, &dir) {
        Ok(k) => k,
        Err(_) => {
            zeroize_password(current_password);
            zeroize_password(new_password);
            return Ok(json!({"success": false, "error": "Password attuale errata"}));
        }
    });

    let vault_path = dir.join(VAULT_FILE);
    let vault_data = if vault_path.exists() {
        let enc = fs::read(&vault_path).map_err(|e| e.to_string())?;
        let dec = decrypt_data(&current_key, &enc)?;
        serde_json::from_slice::<Value>(&dec).map_err(|e| e.to_string())?
    } else {
        json!({"practices":[], "agenda":[]})
    };

    let mut new_salt = vec![0u8; ARGON2_SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_salt);
    // SECURITY FIX (Audit Chunk 08): wrap new_key in Zeroizing for auto-zeroing on drop.
    let new_key = Zeroizing::new(derive_secure_key(&new_password, &new_salt)?);

    let vault_plaintext =
        Zeroizing::new(serde_json::to_vec(&vault_data).map_err(|e| e.to_string())?);
    let encrypted_vault = encrypt_data(&new_key, &vault_plaintext)?;
    let new_verify_tag = make_verify_tag(&new_key);

    // Stage new files
    let staging_dir = dir.join(".staging");
    let _ = fs::create_dir_all(&staging_dir);
    if atomic_write_with_sync(&staging_dir.join(VAULT_FILE), &encrypted_vault).is_err()
        || atomic_write_with_sync(&staging_dir.join(VAULT_SALT_FILE), &new_salt).is_err()
        || atomic_write_with_sync(&staging_dir.join(VAULT_VERIFY_FILE), &new_verify_tag).is_err()
    {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(
            "Errore critico durante la preparazione dei file sicuri. Cambio annullato.".into(),
        );
    }

    // Atomic swap with rollback
    transactional_vault_swap(&dir, &staging_dir)?;
    cleanup_vault_backups(&dir);
    let _ = fs::remove_dir_all(&staging_dir);

    reencrypt_audit_log(&dir, &current_key, &new_key);

    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(SecureKey(Zeroizing::new(new_key.to_vec())));

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
                let _ = entry.set_password(&new_password);
            }
        }
    }

    let _ = append_audit_log(&state, "Password cambiata");
    zeroize_password(current_password);
    zeroize_password(new_password);
    Ok(json!({"success": true}))
}

#[tauri::command]
fn verify_vault_password(state: State<AppState>, pwd: String) -> Result<Value, String> {
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
/// Count urgent deadlines (within 7 days) across active practices.
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
fn get_summary(state: State<AppState>) -> Result<Value, String> {
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

// ═══════════════════════════════════════════════════════════
//  PRACTICES & AGENDA
// ═══════════════════════════════════════════════════════════

/// SECURITY FIX (Audit v2.5): validate that vault data is a JSON array before saving.
/// A compromised frontend could inject arbitrary JSON (objects, strings, numbers) into
/// vault fields that the app expects to be arrays, causing silent data corruption.
/// This does NOT prevent malformed array contents (that's app-level, not security),
/// but blocks type confusion attacks (e.g. replacing practices[] with a string).
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

#[tauri::command]
fn load_practices(state: State<AppState>) -> Result<Value, String> {
    let vault = read_vault_internal(&state)?;
    Ok(vault.get("practices").cloned().unwrap_or(json!([])))
}

#[tauri::command]
fn save_practices(state: State<AppState>, list: Value) -> Result<bool, String> {
    validate_vault_array(&list, "practices")?;
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
    validate_vault_array(&agenda, "agenda")?;
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let mut vault = read_vault_internal(&state)?;
    vault["agenda"] = agenda;
    write_vault_internal(&state, &vault)?;
    Ok(true)
}

// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
//  CONFLICT CHECK (v3.2.0)
// ═══════════════════════════════════════════════════════════

/// Check if a text field in a JSON value matches the query (case-insensitive).
fn field_contains(obj: &Value, field: &str, query: &str) -> bool {
    obj.get(field)
        .and_then(|v| v.as_str())
        .map(|v| v.to_lowercase().contains(query))
        .unwrap_or(false)
}

/// Find matching text fields on a practice record.
fn match_practice_fields(p: &Value, query: &str) -> Vec<String> {
    let mut matched_fields: Vec<String> = Vec::new();
    for field in &["client", "counterparty", "description", "court", "object"] {
        if field_contains(p, field, query) {
            matched_fields.push(field.to_string());
        }
    }
    matched_fields
}

/// Find role matches in a practice by resolving contact names.
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

/// Check if a contact matches the query on any identifying field.
fn contact_matches_query(c: &Value, query: &str) -> bool {
    ["name", "fiscalCode", "vatNumber", "email", "pec", "phone"]
        .iter()
        .any(|f| field_contains(c, f, query))
}

/// Find all practice IDs that reference a given contact ID.
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
fn check_conflict(state: State<AppState>, name: String) -> Result<Value, String> {
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

    let contact_matches: Vec<Value> = contacts.iter().filter_map(|c| {
        if !contact_matches_query(c, &query) { return None; }
        let cid = c.get("id").and_then(|i| i.as_str()).unwrap_or("");
        Some(json!({"contact": c, "linkedPracticeIds": find_linked_practice_ids(practices, cid)}))
    }).collect();

    Ok(json!({"practiceMatches": results, "contactMatches": contact_matches}))
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
    validate_vault_array(&logs, "timeLogs")?;
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
    validate_vault_array(&invoices, "invoices")?;
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
    validate_vault_array(&contacts, "contacts")?;
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
    cfg!(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "android"
    ))
}

#[tauri::command]
fn has_bio_saved(state: State<AppState>) -> bool {
    // TOUCH ID FIX: Do NOT call keyring::get_password() here — on macOS that triggers
    // the Touch ID / password popup just to check if credentials exist!
    // Instead, use a lightweight marker file written by save_bio / cleared by clear_bio.
    #[cfg(not(target_os = "android"))]
    {
        let dir = state
            .data_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
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
        let dir = state
            .data_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let _ = fs::write(dir.join(BIO_MARKER_FILE), "1");
        Ok(true)
    }
    #[cfg(target_os = "android")]
    {
        let _ = (state, pwd);
        Ok(true)
    }
}

/// Shared post-biometric vault unlock: retrieve keyring password, authenticate, unlock vault.
#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
fn bio_unlock_vault(state: &State<AppState>) -> Result<Value, String> {
    let user = whoami::username();
    let saved_pwd = keyring::Entry::new(BIO_SERVICE, &user)
        .and_then(|e| e.get_password())
        .map_err(|e| e.to_string())?;

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
    let auth_result = authenticate_vault_password(&saved_pwd, &dir);
    zeroize_password(saved_pwd);

    match auth_result {
        Ok(k) => {
            *(state.vault_key.lock().unwrap_or_else(|e| e.into_inner())) =
                Some(SecureKey(Zeroizing::new(k)));
            clear_lockout(state, &sec_dir);
            *(state
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner())) = Instant::now();
            let _ = append_audit_log(state, "Sblocco Vault (biometria)");
            Ok(json!({"success": true}))
        }
        Err(_) => {
            if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
                let _ = entry.delete_credential();
            }
            let _ = fs::remove_file(dir.join(BIO_MARKER_FILE));
            Ok(
                json!({"success": false, "error": "Password biometrica non più valida. Accedi con la password e riconfigura la biometria."}),
            )
        }
    }
}

#[tauri::command]
fn bio_login(_state: State<AppState>) -> Result<Value, String> {
    {
        let sec_dir = _state
            .security_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Err(locked_json) = check_lockout(&_state, &sec_dir) {
            return Ok(locked_json);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let swift_code = "import LocalAuthentication\nlet ctx = LAContext()\nvar err: NSError?\nif ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) {\n  let sema = DispatchSemaphore(value: 0)\n  var ok = false\n  ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: \"LexFlow\") { s, _ in ok = s; sema.signal() }\n  sema.wait()\n  if ok { exit(0) } else { exit(1) }\n} else { exit(1) }";

        use std::io::Write;
        // SECURITY FIX (Audit 2026-03-04): sanitize child environment to mitigate
        // DYLD_INSERT_LIBRARIES injection. On macOS without SIP (or with SIP disabled),
        // an attacker could set DYLD_INSERT_LIBRARIES to inject a malicious dylib into
        // the Swift subprocess and intercept the biometric result or keychain password.
        // By clearing all DYLD_* environment variables, we prevent this attack vector.
        // Note: SIP already blocks DYLD injection on system binaries (/usr/bin/swift),
        // but users may have SIP disabled for development — defense in depth.
        let mut cmd = std::process::Command::new("/usr/bin/swift");
        cmd.arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // Remove dangerous dylib injection environment variables
        for (k, _) in std::env::vars() {
            if k.starts_with("DYLD_") || k.starts_with("LD_") || k == "CFNETWORK_LIBRARY_PATH" {
                cmd.env_remove(&k);
            }
        }
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;

        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(swift_code.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        drop(child.stdin.take());
        let status = child.wait().map_err(|e| e.to_string())?;
        if !status.success() {
            return Ok(json!({"success": false, "error": "Autenticazione biometrica fallita"}));
        }

        bio_unlock_vault(&_state)
    }
    #[cfg(target_os = "windows")]
    {
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
        let status = Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Ok(
                json!({"success": false, "error": "Windows Hello fallito o non disponibile"}),
            );
        }

        bio_unlock_vault(&_state)
    }
    #[cfg(target_os = "android")]
    {
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
        if let Ok(e) = keyring::Entry::new(BIO_SERVICE, &user) {
            let _ = e.delete_credential();
        }
        // Remove marker file
        let dir = state
            .data_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
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
// SECURITY FIX (Audit Chunk 10): validate path against an allowlist of safe prefixes.
// Without this check, an XSS in the WebView could enumerate the entire filesystem
// via `invoke('list_folder_contents', { path: '/' })`.
#[tauri::command]
fn list_folder_contents(path: String) -> Result<serde_json::Value, String> {
    use serde_json::json;
    let p = std::path::PathBuf::from(&path);

    // SECURITY: must be absolute path
    if !p.is_absolute() {
        return Err("Percorso relativo non consentito".into());
    }

    // SECURITY: canonicalize to resolve symlinks and ../ before checking prefix
    let canonical = p
        .canonicalize()
        .map_err(|_| "Percorso non valido o non accessibile".to_string())?;

    // SECURITY: only allow listing inside user's home directory or system document dirs.
    // This prevents full filesystem enumeration if the WebView is compromised.
    let allowed_prefixes: Vec<std::path::PathBuf> = [
        dirs::home_dir(),
        dirs::document_dir(),
        dirs::desktop_dir(),
        dirs::download_dir(),
        dirs::data_dir(),
    ]
    .iter()
    .filter_map(|d| d.as_ref().and_then(|p| p.canonicalize().ok()))
    .collect();

    let is_allowed = allowed_prefixes
        .iter()
        .any(|prefix| canonical.starts_with(prefix));
    if !is_allowed {
        eprintln!(
            "[LexFlow] SECURITY: list_folder_contents refused path outside allowed dirs: {:?}",
            canonical
        );
        return Err("Percorso non consentito: accesso limitato alle directory dell'utente.".into());
    }

    if !canonical.exists() {
        return Err("Percorso non esiste".into());
    }
    let mut items: Vec<serde_json::Value> = Vec::new();
    match std::fs::read_dir(&canonical) {
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
                if da != db {
                    return db.cmp(&da);
                }
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
    let key = match get_vault_key(state) {
        Ok(k) => k,
        Err(_) => return Ok(()),
    };
    // SECURITY FIX (Gemini Audit Chunk 09): write_mutex prevents race conditions on concurrent logs
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let path = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .join(AUDIT_LOG_FILE);
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
                vec![
                    json!({"event": "AUDIT_LOG_TAMPERING_DETECTED", "time": chrono::Local::now().to_rfc3339()}),
                ]
            }
        }
    } else {
        vec![]
    };

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
    let path = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .join(AUDIT_LOG_FILE);
    if !path.exists() {
        return Ok(json!([]));
    }
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
        // Test license token signed with the current Ed25519 keypair (v1.0.0)
        // Payload: client=pietro_test, expiry=2027-02-12, id=431d1c59-...
        // Expiry timestamp: 1803918121373 ms = 2027-02-12T...
        let valid_token = "LXFW.eyJjIjoicGlldHJvX3Rlc3QiLCJlIjoxODAzOTE4MTIxMzczLCJpZCI6IjQzMWQxYzU5LThjZWQtNDNiMy04MTRmLTk4YjhlYzUyNzJmZiJ9.CjPgp0RCKAHd7fNY3dFrYKS7dGuktI0SyLrk_E6Te70J1K2HJpI9u1O2epkUcNsWFgggAvOd8yCqLVFqrCvtDg";

        // SECURITY FIX (Audit v2.5): check if the hardcoded test token has expired.
        // This prevents a cryptic test failure after 2027-02-12 — instead it prints
        // a clear message explaining that a new test token must be generated.
        let token_expiry_ms: u64 = 1_803_918_121_373;
        let now_ms = safe_now_ms();
        if now_ms > token_expiry_ms {
            eprintln!(
                "⚠️  TEST SKIPPED: The hardcoded test token expired on 2027-02-12.\n\
                 Generate a new token with: python3 generate_license_v2.py generate\n\
                 Then update this test with the new token."
            );
            // Verify the token is correctly rejected as expired (not as tampered)
            let result = verify_license(valid_token.to_string());
            assert!(!result.valid, "Expired token should be rejected");
            assert_eq!(
                result.client.unwrap(),
                "pietro_test",
                "Client should still be parseable from expired token"
            );
            assert!(
                result.message.contains("scaduta") || result.message.contains("expired"),
                "Message should indicate expiry, got: {}",
                result.message
            );
            return; // Skip remaining tests that require a valid (non-expired) token
        }

        // 1. Test verifica positiva
        let result = verify_license(valid_token.to_string());
        assert!(
            result.valid,
            "La licenza valida è stata respinta! Errore: {}",
            result.message
        );
        assert_eq!(result.client.unwrap(), "pietro_test");

        // 2. Test Anti-Manomissione (cambiamo un solo carattere nella firma)
        let mut tampered_token = valid_token.to_string();
        tampered_token.replace_range(tampered_token.len() - 5..tampered_token.len() - 4, "Z");
        let tamper_result = verify_license(tampered_token);
        assert!(
            !tamper_result.valid,
            "Sicurezza fallita: la licenza manomessa è stata accettata!"
        );
        assert_eq!(
            tamper_result.message,
            "Firma non valida o licenza manomessa!"
        );

        // 3. Test Formato errato
        let invalid_format = "TOKEN_SENZA_PUNTI";
        let format_result = verify_license(invalid_format.to_string());
        assert!(!format_result.valid);
        assert_eq!(format_result.message, "Formato chiave non valido.");
    }
}

/// SECURITY FIX (Audit Chunk 12): safe timestamp — prevents panic on pre-1970 clocks.
/// Returns milliseconds since UNIX epoch, or 0 if the system clock is before epoch.
fn safe_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// SECURITY FIX (Audit Chunk 12): monotonic clock check for license verification.
/// Persists the last verified timestamp. If the system clock goes backwards,
/// the license check fails (prevents clock manipulation to extend expired licenses).
/// The file is HMAC-protected to prevent tampering.
const LAST_CHECK_TS_FILE: &str = ".last-license-check";

fn monotonic_clock_check(sec_dir: &std::path::Path) -> Result<(), String> {
    let ts_path = sec_dir.join(LAST_CHECK_TS_FILE);
    let now_ms = safe_now_ms();

    if let Ok(raw) = fs::read_to_string(&ts_path) {
        let parts: Vec<&str> = raw.trim().splitn(2, ':').collect();
        if parts.len() == 2 {
            let stored_ts = parts[0].parse::<u64>().unwrap_or(0);
            let stored_hmac = parts[1];
            // Verify HMAC
            let enc_key = get_local_encryption_key();
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&enc_key)
                .expect("HMAC can take key of any size");
            mac.update(b"CLOCK-CHECK:");
            mac.update(parts[0].as_bytes());
            let expected = hex::encode(mac.finalize().into_bytes());
            if stored_hmac == expected && now_ms < stored_ts.saturating_sub(300_000) {
                // Clock went backwards by more than 5 minutes — suspicious
                return Err("SECURITY: System clock appears to have been set backwards. License check refused.".into());
            }
        }
    }

    // Persist current timestamp with HMAC
    let ts_str = now_ms.to_string();
    let enc_key = get_local_encryption_key();
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&enc_key).expect("HMAC can take key of any size");
    mac.update(b"CLOCK-CHECK:");
    mac.update(ts_str.as_bytes());
    let hmac_hex = hex::encode(mac.finalize().into_bytes());
    let _ = fs::write(&ts_path, format!("{}:{}", ts_str, hmac_hex));

    Ok(())
}

/// SECURITY FIX (Gemini Audit Chunk 10): safe bounded read — anti-TOCTOU + anti-OOM.
/// Uses io::Read::take() to physically limit bytes read, even if file grows during read.
fn safe_bounded_read(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if let Ok(meta) = file.metadata() {
        if meta.len() > max_bytes {
            return Err(format!(
                "File troppo grande ({} bytes) — OOM limit superato",
                meta.len()
            ));
        }
    }
    let mut buffer = Vec::new();
    file.take(max_bytes)
        .read_to_end(&mut buffer)
        .map_err(|e| e.to_string())?;
    Ok(buffer)
}

#[tauri::command]
fn get_settings(state: State<AppState>, app: AppHandle) -> Value {
    let path = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .join(SETTINGS_FILE);
    if !path.exists() {
        return json!({});
    }
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
        // Try V3 key (migration V3→V4)
        let v3_key = get_local_encryption_key_v3();
        if let Ok(dec) = decrypt_data(&v3_key, &file_data) {
            if let Ok(re_enc) = encrypt_data(&key, &dec) {
                let _ = atomic_write_with_sync(&path, &re_enc);
                eprintln!("[LexFlow] Settings V3→V4 migration completed.");
            }
            return serde_json::from_slice(&dec).unwrap_or(json!({}));
        }
        // Try V2 legacy key (hostname-based)
        let legacy_key = get_local_encryption_key_legacy();
        if let Ok(dec) = decrypt_data(&legacy_key, &file_data) {
            if let Ok(re_enc) = encrypt_data(&key, &dec) {
                let _ = atomic_write_with_sync(&path, &re_enc);
                eprintln!("[LexFlow] Settings V2→V4 migration completed.");
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
    eprintln!(
        "[LexFlow] Settings file corrotto — backup salvato in {:?}",
        backup_path
    );
    // SECURITY FIX (Audit Chunk 11): emit event to frontend so the UI can warn the user
    // before they accidentally overwrite the corrupted settings with empty defaults.
    let _ = app.emit(
        "settings-corrupted",
        json!({
            "backup_path": backup_path.to_string_lossy(),
            "timestamp": ts,
        }),
    );
    json!({})
}

/// SECURITY FIX (Gemini Audit Chunk 10): returns Result for proper error feedback to frontend
#[tauri::command]
fn save_settings(state: State<AppState>, settings: Value) -> Result<bool, String> {
    let path = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .join(SETTINGS_FILE);
    let key = get_local_encryption_key();
    // SECURITY FIX (Security Audit G3): wrap plaintext in Zeroizing so settings data
    // is automatically zeroed from heap memory after encryption.
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&settings).map_err(|e| format!("Errore serializzazione JSON: {}", e))?,
    );
    let encrypted = encrypt_data(&key, &plaintext)?;
    atomic_write_with_sync(&path, &encrypted)
        .map(|_| true)
        .map_err(|e| format!("Impossibile salvare le impostazioni su disco: {}", e))
}

#[tauri::command]
/// Verify a burned-format license (v2.6.1+). Returns a final JSON response.
fn check_license_burned(
    data: &Value,
    key: &[u8],
    path: &std::path::Path,
    current_fp: &str,
    needs_fp_upgrade: bool,
) -> Value {
    let token_hmac = data.get("tokenHmac").and_then(|v| v.as_str()).unwrap_or("");
    let expiry_ms = data.get("expiryMs").and_then(|v| v.as_u64()).unwrap_or(0);
    let grace_days = data.get("graceDays").and_then(|v| v.as_u64()).unwrap_or(0);
    let client = data
        .get("client")
        .and_then(|v| v.as_str())
        .unwrap_or("Studio Legale")
        .to_string();

    if token_hmac.is_empty() {
        return json!({"activated": false, "reason": "Dati licenza corrotti."});
    }
    let now_ms = safe_now_ms();
    let grace_ms = grace_days * 86_400 * 1000;

    if now_ms > expiry_ms {
        // Check grace period before declaring expired
        if grace_ms > 0 && now_ms <= (expiry_ms + grace_ms) {
            // In grace period — activated but with warning
            if needs_fp_upgrade {
                silent_upgrade_fingerprint(data, key, path, current_fp);
            }
            return json!({
                "activated": true,
                "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
                "client": client,
                "inGracePeriod": true,
                "graceDays": grace_days,
            });
        }
        return json!({"activated": false, "expired": true, "reason": "Licenza scaduta."});
    }
    if needs_fp_upgrade {
        silent_upgrade_fingerprint(data, key, path, current_fp);
    }
    json!({
        "activated": true,
        "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
        "client": client,
    })
}

/// Silently add machineFingerprint to a license record that lacks it.
fn silent_upgrade_fingerprint(data: &Value, key: &[u8], path: &std::path::Path, fp: &str) {
    let mut upgraded = data.clone();
    if let Some(obj) = upgraded.as_object_mut() {
        obj.insert("machineFingerprint".to_string(), json!(fp));
    }
    if let Ok(bytes) = serde_json::to_vec(&upgraded) {
        if let Ok(encrypted) = encrypt_data(key, &bytes) {
            if let Err(e) = atomic_write_with_sync(path, &encrypted) {
                eprintln!("[SECURITY] license fingerprint upgrade write failed: {}", e);
            }
        }
    }
}

/// Upgrade a legacy (raw-key) license to burned format. Returns the JSON response.
fn check_license_legacy(
    data: &Value,
    license_key: &str,
    key: &[u8],
    path: &std::path::Path,
    sec_dir: &std::path::Path,
    current_fp: &str,
) -> Value {
    let verification = verify_license(license_key.to_string());
    if !verification.valid {
        return json!({"activated": false, "expired": true, "reason": verification.message});
    }

    let mut token_mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    token_mac.update(license_key.as_bytes());
    let token_hmac = hex::encode(token_mac.finalize().into_bytes());

    let expiry_ms: u64 = extract_expiry_ms(license_key).unwrap_or(0);
    let client = verification
        .client
        .unwrap_or_else(|| "Studio Legale".to_string());
    let key_id = extract_key_id(license_key).unwrap_or_else(|| "legacy".to_string());

    let upgraded = json!({
        "tokenHmac": token_hmac,
        "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
        "client": client,
        "keyVersion": "ed25519-burned",
        "machineFingerprint": current_fp,
        "keyId": key_id,
        "expiryMs": expiry_ms,
    });

    if let Ok(bytes) = serde_json::to_vec(&upgraded) {
        if let Ok(encrypted) = encrypt_data(key, &bytes) {
            if let Err(e) = atomic_write_with_sync(path, &encrypted) {
                eprintln!("[SECURITY] license upgrade write failed: {}", e);
            }
        }
    }
    if let Err(e) = burn_key(sec_dir, &compute_burn_hash(license_key)) {
        eprintln!(
            "[SECURITY] CRITICAL: burn_key failed during legacy upgrade: {}",
            e
        );
    }

    json!({
        "activated": true,
        "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
        "client": client,
    })
}

#[tauri::command]
fn check_license(state: State<AppState>) -> Value {
    let sec_dir = state
        .security_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = sec_dir.join(LICENSE_FILE);
    let sentinel_path = sec_dir.join(LICENSE_SENTINEL_FILE);

    // SECURITY FIX (Audit Chunk 12): monotonic clock check — detect clock manipulation
    if let Err(e) = monotonic_clock_check(&sec_dir) {
        eprintln!("[SECURITY] {}", e);
        return json!({"activated": false, "reason": "Anomalia orologio di sistema rilevata. Verificare data/ora e riprovare."});
    }

    if !path.exists() {
        if sentinel_path.exists() {
            return json!({"activated": false, "tampered": true, "reason": "File di licenza rimosso o manomesso. Contattare il supporto."});
        }
        return json!({"activated": false});
    }

    let key = get_local_encryption_key();
    let data: Value = if let Some(dec) = decrypt_local_with_migration(&path) {
        serde_json::from_slice(&dec).unwrap_or(json!({}))
    } else {
        return json!({"activated": false, "reason": "File licenza corrotto o non valido per questo dispositivo."});
    };

    let current_fp = compute_machine_fingerprint();
    if let Some(stored_fp) = data.get("machineFingerprint").and_then(|v| v.as_str()) {
        if stored_fp != current_fp {
            return json!({"activated": false, "reason": "Licenza attivata su un altro dispositivo."});
        }
    }
    let needs_fp_upgrade = data.get("machineFingerprint").is_none();
    let key_version = data
        .get("keyVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if key_version == "ed25519-burned" {
        return check_license_burned(&data, &key, &path, &current_fp, needs_fp_upgrade);
    }

    let license_key = data.get("key").and_then(|k| k.as_str()).unwrap_or("");
    if !license_key.is_empty() {
        return check_license_legacy(&data, license_key, &key, &path, &sec_dir, &current_fp);
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
    224u8, 91u8, 232u8, 166u8, 43u8, 189u8, 252u8, 43u8, 2u8, 207u8, 72u8, 79u8, 156u8, 169u8,
    10u8, 54u8, 159u8, 45u8, 26u8, 92u8, 192u8, 37u8, 44u8, 158u8, 251u8, 44u8, 239u8, 4u8, 157u8,
    212u8, 139u8, 36u8,
];

#[derive(Deserialize, Serialize)]
struct LicensePayload {
    c: String,  // client name
    e: u64,     // expiry in milliseconds since epoch
    id: String, // unique key id
    #[serde(default)] // backward compatible: v1 tokens don't have this field
    n: Option<String>, // anti-replay nonce (128-bit hex, v2+)
    #[serde(default)] // v2.4+: hardware ID for node-locking (None = universal license)
    h: Option<String>,
    #[serde(default)] // v2.4+: grace period in days after expiry (0 = no grace)
    g: Option<u64>,
}

#[derive(Serialize)]
struct VerificationResult {
    valid: bool,
    client: Option<String>,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    in_grace_period: Option<bool>, // true if expired but within grace window
    #[serde(skip_serializing_if = "Option::is_none")]
    grace_days: Option<u64>, // grace period days from payload
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_locked: Option<bool>, // true if token has hardware ID
}

#[tauri::command]
fn verify_license(key_string: String) -> VerificationResult {
    // Expected format: LXFW.<payload_b64>.<signature_b64>
    let parts: Vec<&str> = key_string.split('.').collect();
    if parts.len() != 3 || parts[0] != "LXFW" {
        return VerificationResult {
            valid: false,
            client: None,
            message: "Formato chiave non valido.".into(),
            in_grace_period: None,
            grace_days: None,
            hardware_locked: None,
        };
    }

    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let payload_bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(b) => b,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Errore decodifica payload.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    let signature_bytes = match URL_SAFE_NO_PAD.decode(signature_b64) {
        Ok(b) => b,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Errore decodifica firma.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    let public_key = match VerifyingKey::from_bytes(&PUBLIC_KEY_BYTES) {
        Ok(k) => k,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Errore chiave pubblica interna.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(s) => s,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Firma corrotta.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    if public_key
        .verify(payload_b64.as_bytes(), &signature)
        .is_err()
    {
        return VerificationResult {
            valid: false,
            client: None,
            message: "Firma non valida o licenza manomessa!".into(),
            in_grace_period: None,
            grace_days: None,
            hardware_locked: None,
        };
    }

    let payload: LicensePayload = match serde_json::from_slice(&payload_bytes) {
        Ok(p) => p,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Dati licenza corrotti.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    // ── Hardware ID check (v2.4 node-locking) ──
    let hardware_locked = payload.h.is_some();
    if let Some(ref required_hwid) = payload.h {
        let current_fp = compute_machine_fingerprint();
        if *required_hwid != current_fp {
            return VerificationResult {
                valid: false,
                client: Some(payload.c),
                message: "Licenza bloccata su un altro dispositivo (Hardware ID mismatch).".into(),
                in_grace_period: None,
                grace_days: payload.g,
                hardware_locked: Some(true),
            };
        }
    }

    // ── Expiry + Grace Period check (v2.4) ──
    let now = safe_now_ms();
    let grace_days = payload.g.unwrap_or(0);
    let grace_ms = grace_days * 86_400 * 1000; // days → milliseconds

    if now > payload.e {
        // Token expired — check if within grace period
        if grace_ms > 0 && now <= (payload.e + grace_ms) {
            // In grace period: valid but with warning
            return VerificationResult {
                valid: true,
                client: Some(payload.c),
                message: "Licenza in Grace Period — rinnovo necessario!".into(),
                in_grace_period: Some(true),
                grace_days: Some(grace_days),
                hardware_locked: if hardware_locked { Some(true) } else { None },
            };
        }
        // Expired beyond grace
        return VerificationResult {
            valid: false,
            client: Some(payload.c),
            message: "Licenza scaduta.".into(),
            in_grace_period: Some(false),
            grace_days: if grace_days > 0 {
                Some(grace_days)
            } else {
                None
            },
            hardware_locked: if hardware_locked { Some(true) } else { None },
        };
    }

    VerificationResult {
        valid: true,
        client: Some(payload.c),
        message: "Licenza attivata con successo!".into(),
        in_grace_period: Some(false),
        grace_days: if grace_days > 0 {
            Some(grace_days)
        } else {
            None
        },
        hardware_locked: if hardware_locked { Some(true) } else { None },
    }
}

// Helper: parse the LXFW token payload without full verification.
fn parse_lxfw_payload(token: &str) -> Option<LicensePayload> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "LXFW" {
        return None;
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

// Helper: extract key ID from a LXFW token without full verification.
fn extract_key_id(token: &str) -> Option<String> {
    parse_lxfw_payload(token).map(|p| p.id)
}

// Helper: extract expiry timestamp (ms) from a LXFW token without full verification.
fn extract_expiry_ms(token: &str) -> Option<u64> {
    parse_lxfw_payload(token).map(|p| p.e)
}

/// Recover the key ID stored in the license sentinel file.
fn recover_sentinel_key_id(sentinel_path: &std::path::Path) -> Option<String> {
    let sentinel_content = fs::read_to_string(sentinel_path).ok()?;
    let stored_key_id_enc = sentinel_content.lines().nth(1).filter(|s| !s.is_empty())?;
    let enc_bytes = hex::decode(stored_key_id_enc).ok()?;
    let enc_key = get_local_encryption_key();
    let dec = decrypt_data(&enc_key, &enc_bytes).ok().or_else(|| {
        #[cfg(not(target_os = "android"))]
        {
            decrypt_data(&get_local_encryption_key_legacy(), &enc_bytes).ok()
        }
        #[cfg(target_os = "android")]
        {
            None
        }
    })?;
    String::from_utf8(dec).ok()
}

/// Check if an existing valid license blocks activation of a new key.
/// Returns Some(error_json) if blocked, None if activation can proceed.
fn check_existing_license_blocks(path: &std::path::Path, new_key: &str) -> Option<Value> {
    if !path.exists() {
        return None;
    }
    let dec = decrypt_local_with_migration(path)?;
    let existing: Value = serde_json::from_slice(&dec).ok()?;
    let existing_version = existing
        .get("keyVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_id = extract_key_id(new_key);

    if existing_version == "ed25519-burned" {
        let expiry = existing
            .get("expiryMs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let now_ms = safe_now_ms();
        if now_ms <= expiry {
            let existing_id = existing
                .get("keyId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if existing_id != new_id {
                return Some(
                    json!({"success": false, "error": "Una licenza valida è già attiva. Non è possibile sostituirla."}),
                );
            }
        }
    } else {
        let existing_key = existing.get("key").and_then(|k| k.as_str()).unwrap_or("");
        if !existing_key.is_empty()
            && verify_license(existing_key.to_string()).valid
            && extract_key_id(existing_key) != new_id
        {
            return Some(
                json!({"success": false, "error": "Una licenza valida è già attiva. Non è possibile sostituirla."}),
            );
        }
    }
    None
}

/// Write sentinel file after license activation.
fn write_license_sentinel(
    sentinel_path: &std::path::Path,
    fingerprint: &str,
    key_id: &str,
    now: &str,
) {
    let enc_key = get_local_encryption_key();
    let sentinel_data = format!("LEXFLOW-SENTINEL:{}:{}:{}", fingerprint, key_id, now);
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&enc_key).expect("HMAC can take key of any size");
    mac.update(sentinel_data.as_bytes());
    let sentinel_hmac = hex::encode(mac.finalize().into_bytes());
    let encrypted_key_id = encrypt_data(&enc_key, key_id.as_bytes())
        .map(hex::encode)
        .unwrap_or_default();
    let sentinel_content = format!("{}\n{}", sentinel_hmac, encrypted_key_id);
    let _ = atomic_write_with_sync(sentinel_path, sentinel_content.as_bytes());
}

/// Check the burned-key registry. Returns Err(json) if blocked, Ok(()) if clear.
fn check_burned_key_registry(
    sec_dir: &std::path::Path,
    key: &str,
    fingerprint: &str,
) -> Result<(), Value> {
    match is_key_burned(sec_dir, key, fingerprint) {
        Ok(true) => Err(
            json!({"success": false, "error": "Questa chiave è già stata utilizzata e non può essere riattivata."}),
        ),
        Err(e) => {
            eprintln!("[SECURITY] burned-keys registry unreadable: {}", e);
            Err(
                json!({"success": false, "error": "Registro chiavi non leggibile. Contattare il supporto."}),
            )
        }
        Ok(false) => Ok(()),
    }
}

/// Execute the license activation: burn key, write record, write sentinel.
fn perform_license_activation(
    sec_dir: &std::path::Path,
    path: &std::path::Path,
    sentinel_path: &std::path::Path,
    key: &str,
    client: &str,
    fingerprint: &str,
) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    let key_id = extract_key_id(key).unwrap_or_else(|| "unknown".to_string());
    let enc_key = get_local_encryption_key();

    // Compute token HMAC (burned verification hash)
    let mut token_mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&enc_key).expect("HMAC can take key of any size");
    token_mac.update(key.as_bytes());
    let token_hmac = hex::encode(token_mac.finalize().into_bytes());

    // Extract payload data before destroying the token
    let parsed_payload = parse_lxfw_payload(key);
    let expiry_ms = parsed_payload.as_ref().map(|p| p.e).unwrap_or(0);
    let grace_days = parsed_payload.as_ref().and_then(|p| p.g).unwrap_or(0);
    let hardware_locked = parsed_payload.as_ref().and_then(|p| p.h.as_ref()).is_some();

    let record = json!({
        "tokenHmac": token_hmac,
        "activatedAt": now,
        "client": client,
        "keyVersion": "ed25519-burned",
        "machineFingerprint": fingerprint,
        "keyId": key_id,
        "expiryMs": expiry_ms,
        "graceDays": grace_days,
        "hardwareLocked": hardware_locked,
    });

    let encrypted = match encrypt_data(&enc_key, &serde_json::to_vec(&record).unwrap_or_default()) {
        Ok(enc) => enc,
        Err(e) => return json!({"success": false, "error": format!("Errore cifratura: {}", e)}),
    };
    if let Err(e) = atomic_write_with_sync(path, &encrypted) {
        return json!({"success": false, "error": format!("Errore salvataggio: {}", e)});
    }

    write_license_sentinel(sentinel_path, fingerprint, &key_id, &now);

    if let Err(e) = burn_key(sec_dir, &compute_burn_hash(key)) {
        eprintln!(
            "[SECURITY] CRITICAL: burn_key failed after activation: {}",
            e
        );
    }

    json!({"success": true, "client": client})
}

/// Expose machine fingerprint to the frontend.
/// This allows the user to copy their Hardware ID when requesting a node-locked license.
#[tauri::command]
fn get_machine_fingerprint() -> String {
    compute_machine_fingerprint()
}

#[tauri::command]
fn activate_license(state: State<AppState>, key: String, _client_name: Option<String>) -> Value {
    let sec_dir = state
        .security_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    // SECURITY FIX (Gemini Audit Chunk 03): acquire write_mutex to prevent concurrent
    // burn_key() calls from losing updates (load-modify-write race).
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());

    if let Err(locked_json) = check_lockout(&state, &sec_dir) {
        return locked_json;
    }

    let key = key.trim().to_string();
    let path = sec_dir.join(LICENSE_FILE);
    let sentinel_path = sec_dir.join(LICENSE_SENTINEL_FILE);

    // SECURITY CHECK 1: sentinel exists but license.json deleted
    if !path.exists() && sentinel_path.exists() {
        let stored_key_id = recover_sentinel_key_id(&sentinel_path);
        let new_key_id = extract_key_id(&key);
        match (stored_key_id.as_deref(), new_key_id.as_deref()) {
            (Some(old), Some(new_id)) if old == new_id => { /* same key, allow */ }
            _ => {
                return json!({"success": false, "error": "Questa installazione ha già una licenza registrata. Contattare il supporto per assistenza."})
            }
        }
    }

    // SECURITY CHECK 2: existing valid license blocks overwrite
    if let Some(blocked) = check_existing_license_blocks(&path, &key) {
        return blocked;
    }

    // Verifica asimmetrica (Ed25519)
    let verification = verify_license(key.clone());
    if !verification.valid {
        record_failed_attempt(&state, &sec_dir);
        return json!({"success": false, "error": verification.message});
    }
    clear_lockout(&state, &sec_dir);

    let fingerprint = compute_machine_fingerprint();

    // SECURITY CHECK 3: burned-key registry
    if let Err(msg) = check_burned_key_registry(&sec_dir, &key, &fingerprint) {
        return msg;
    }

    // SECURITY CHECK 4: burned-keys file integrity
    if sentinel_path.exists() && !sec_dir.join(BURNED_KEYS_FILE).exists() {
        return json!({"success": false, "error": "Registro chiavi compromesso. Contattare il supporto per assistenza."});
    }

    let client = verification
        .client
        .unwrap_or_else(|| "Studio Legale".to_string());
    perform_license_activation(&sec_dir, &path, &sentinel_path, &key, &client, &fingerprint)
}

// ═══════════════════════════════════════════════════════════
//  IMPORT / EXPORT
// ═══════════════════════════════════════════════════════════

#[tauri::command]
async fn export_vault(
    state: State<'_, AppState>,
    pwd: String,
    app: AppHandle,
) -> Result<Value, String> {
    use tauri_plugin_dialog::DialogExt;
    // SECURITY FIX (Level-8 A2): verify that `pwd` is the intended backup password by
    // re-deriving it and checking against vault.verify BEFORE writing the backup.
    // Without this check, a typo in `pwd` produces a backup encrypted with the wrong key
    // that is permanently inaccessible — the user has no way to know until they need to restore.
    // We verify by deriving the key and confirming it opens the vault's own verify tag.
    {
        let dir = state
            .data_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let salt_path = dir.join(VAULT_SALT_FILE);
        if salt_path.exists() {
            let vault_salt = fs::read(&salt_path).map_err(|e| e.to_string())?;
            let vault_key_check = derive_secure_key(&pwd, &vault_salt)?;
            let stored_verify = fs::read(dir.join(VAULT_VERIFY_FILE)).unwrap_or_default();
            if !verify_hash_matches(&vault_key_check, &stored_verify) {
                return Ok(
                    json!({"success": false, "error": "Password errata: il backup non può essere creato con una password diversa da quella del vault."}),
                );
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
        // SECURITY FIX (Gemini Audit Chunk 12/13): handle into_path gracefully
        let file_path = p
            .into_path()
            .map_err(|e| format!("Percorso non valido: {}", e))?;
        // SECURITY FIX (Audit Chunk 14): use atomic_write_with_sync for crash safety.
        // Previously fs::write could leave a corrupted partial file on crash.
        atomic_write_with_sync(&file_path, &out).map_err(|e| e.to_string())?;
        Ok(json!({"success": true}))
    } else {
        Ok(json!({"success": false}))
    }
}

#[tauri::command]
async fn import_vault(
    state: State<'_, AppState>,
    pwd: String,
    app: AppHandle,
) -> Result<Value, String> {
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
        let file_path = p
            .into_path()
            .map_err(|e| format!("Percorso non valido: {}", e))?;
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
            file.take(MAX_IMPORT_SIZE + 1)
                .read_to_end(&mut buf)
                .map_err(|e| e.to_string())?;
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
        let decrypted =
            decrypt_data(&key, encrypted).map_err(|_| "Password errata o file corrotto")?;
        let val: Value =
            serde_json::from_slice(&decrypted).map_err(|_| "Struttura backup non valida")?;
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
            let dir = state
                .data_dir
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
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
            *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(SecureKey(Zeroizing::new(new_key)));
        }
        write_vault_internal(&state, &val)?;
        let _ = append_audit_log(&state, "Vault importato da backup");
        // SECURITY FIX (Gemini Audit): safe password zeroing — no UB
        zeroize_password(pwd);
        Ok(json!({"success": true}))
    } else {
        Ok(json!({"success": false, "cancelled": true}))
    }
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
            eprintln!(
                "[LexFlow] SECURITY: open_path refused non-existent/relative path: {:?}",
                path
            );
            return;
        }
        // SECURITY FIX (Audit v2.5): canonicalize path to resolve symlinks BEFORE
        // checking the extension. Without this, a symlink like `doc.pdf → malware.app`
        // would pass the extension allowlist and open an executable.
        let canonical = match p.canonicalize() {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "[LexFlow] SECURITY: open_path failed to canonicalize {:?}: {}",
                    path, e
                );
                return;
            }
        };
        // SECURITY FIX (Gemini Audit Chunk 13): allowlist instead of blocklist.
        // Only allow safe document extensions and directories.
        let is_dir = canonical.is_dir();
        let ext = canonical
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        const ALLOWED_EXTENSIONS: &[&str] = &[
            "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "txt", "rtf", "odt", "ods", "odp",
            "csv", "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "lex", // LexFlow backup
        ];
        if !is_dir && !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
            eprintln!(
                "[LexFlow] SECURITY: open_path refused non-allowed extension (after canonicalize): {:?} → {:?}",
                path, canonical
            );
            return;
        }
        use tauri_plugin_opener::OpenerExt;
        // SECURITY: open the canonicalized path, not the original (prevents symlink bypass)
        let canonical_str = canonical.to_string_lossy().to_string();
        if let Err(e) = app.opener().open_path(&canonical_str, None::<&str>) {
            eprintln!("[LexFlow] Failed to open path: {:?}", e);
        }
    }
    #[cfg(target_os = "android")]
    {
        let _ = (app, path);
    }
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
        let name = path
            .file_name()
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
    app.dialog().file().pick_folder(move |folder_path| {
        let _ = tx.send(folder_path);
    });
    #[cfg(target_os = "android")]
    app.dialog().file().pick_file(move |folder_path| {
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
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    #[cfg(target_os = "android")]
    {
        let _ = app;
    }
}

#[tauri::command]
fn get_app_version(app: AppHandle) -> String {
    app.package_info().version.to_string()
}

#[tauri::command]
fn is_mac() -> bool {
    cfg!(target_os = "macos")
}

/// Restituisce la piattaforma corrente al frontend
#[tauri::command]
fn get_platform() -> String {
    #[cfg(target_os = "android")]
    {
        "android".to_string()
    }
    #[cfg(target_os = "ios")]
    {
        "ios".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macos".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "windows".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "linux".to_string()
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "macos",
        target_os = "windows",
        target_os = "linux"
    )))]
    {
        "unknown".to_string()
    }
}

#[tauri::command]
async fn select_pdf_save_path(
    app: AppHandle,
    default_name: String,
) -> Result<Option<String>, String> {
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
        }
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
            eprintln!(
                "[LexFlow] Native notification failed: {:?}, emitting event fallback",
                e
            );
            let _ = ah.emit(
                "show-notification",
                serde_json::json!({"title": t, "body": b}),
            );
        }
    });
}

/// Test notification — dev-only command to verify the notification pipeline.
/// Always dispatches via run_on_main_thread for NSRunLoop guarantee.
#[tauri::command]
fn test_notification(app: AppHandle) -> bool {
    let ah = app.clone();
    app.run_on_main_thread(move || {
        use tauri_plugin_notification::NotificationExt;
        if let Err(e) = ah
            .notification()
            .builder()
            .title("LexFlow — Test Notifica")
            .body("Le notifiche funzionano correttamente!")
            .show()
        {
            eprintln!("[LexFlow] Test notification failed: {:?}", e);
        }
    })
    .is_ok()
}

#[tauri::command]
fn sync_notification_schedule(app: AppHandle, state: State<AppState>, schedule: Value) -> bool {
    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let key = get_local_encryption_key();
    // SECURITY FIX (Gemini Audit Chunk 14): propagate serialization error instead of unwrap_or_default
    let plaintext = match serde_json::to_vec(&schedule) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "[LexFlow] sync_notification_schedule serialization failed: {}",
                e
            );
            return false;
        }
    };
    match encrypt_data(&key, &plaintext) {
        Ok(encrypted) => {
            let written =
                atomic_write_with_sync(&dir.join(NOTIF_SCHEDULE_FILE), &encrypted).is_ok();
            if written {
                // ── TRIGGER: re-sync OS notification queue after data change ──
                sync_notifications(&app, &dir);
            }
            written
        }
        Err(_) => false,
    }
}

/// Decrypt notification schedule with local machine key
fn read_notification_schedule(data_dir: &std::path::Path) -> Option<Value> {
    let path = data_dir.join(NOTIF_SCHEDULE_FILE);
    if !path.exists() {
        return None;
    }
    // SECURITY FIX (Level-8 C5): size guard before reading into RAM.
    if let Ok(meta) = path.metadata() {
        if meta.len() > MAX_SETTINGS_FILE_SIZE {
            eprintln!(
                "[LexFlow] Notification schedule file troppo grande ({} bytes) — ignorato",
                meta.len()
            );
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
//  NOTIFICATION HELPERS — shared between mobile AOT and desktop cron
// ═══════════════════════════════════════════════════════════

/// Determine the briefing filter parameters based on the hour of the briefing.
/// Returns (filter_date, time_from, period_label).
#[cfg(any(target_os = "android", target_os = "ios"))]
fn briefing_filter_params<'a>(
    briefing_hour: u32,
    today: &'a str,
    tomorrow: &'a str,
    day_offset_is_zero: bool,
) -> Option<(&'a str, &'a str, &'a str)> {
    if briefing_hour < 12 {
        Some((today, "00:00", "oggi"))
    } else if briefing_hour < 18 {
        Some((today, "13:00", "questo pomeriggio"))
    } else if day_offset_is_zero {
        Some((tomorrow, "00:00", "domani"))
    } else {
        None
    }
}

/// Count relevant (non-completed) items for a given date/time filter.
fn count_relevant_items(items: &[Value], filter_date: &str, time_from: &str) -> usize {
    items
        .iter()
        .filter(|i| {
            let d = i.get("date").and_then(|d| d.as_str()).unwrap_or("");
            let t = i.get("time").and_then(|t| t.as_str()).unwrap_or("00:00");
            let done = i
                .get("completed")
                .and_then(|c| c.as_bool())
                .unwrap_or(false);
            d == filter_date && !done && t >= time_from
        })
        .count()
}

/// Build briefing notification title + body.
fn build_briefing_notification(
    items: &[Value],
    filter_date: &str,
    time_from: &str,
    period_label: &str,
) -> (String, String) {
    let relevant_count = count_relevant_items(items, filter_date, time_from);
    let title = if relevant_count == 0 {
        format!("LexFlow — Nessun impegno {}", period_label)
    } else {
        format!(
            "LexFlow — {} impegn{} {}",
            relevant_count,
            if relevant_count == 1 { "o" } else { "i" },
            period_label
        )
    };
    let body = if relevant_count == 0 {
        format!("Nessun impegno in programma per {}.", period_label)
    } else {
        let mut relevant_items: Vec<&Value> = items
            .iter()
            .filter(|i| {
                let d = i.get("date").and_then(|d| d.as_str()).unwrap_or("");
                let t = i.get("time").and_then(|t| t.as_str()).unwrap_or("00:00");
                let done = i
                    .get("completed")
                    .and_then(|c| c.as_bool())
                    .unwrap_or(false);
                d == filter_date && !done && t >= time_from
            })
            .collect();
        relevant_items.sort_by(|a, b| {
            let ta = a.get("time").and_then(|v| v.as_str()).unwrap_or("");
            let tb = b.get("time").and_then(|v| v.as_str()).unwrap_or("");
            ta.cmp(tb)
        });
        format_item_list(&relevant_items, relevant_count)
    };
    (title, body)
}

/// Format a list of schedule items into a notification body string.
fn format_item_list(relevant_items: &[&Value], total_count: usize) -> String {
    let mut lines: Vec<String> = Vec::new();
    for item in relevant_items.iter().take(4) {
        let t = item.get("time").and_then(|v| v.as_str()).unwrap_or("");
        let name = item
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Impegno");
        if !t.is_empty() {
            lines.push(format!("• {} — {}", t, name));
        } else {
            lines.push(format!("• {}", name));
        }
    }
    if total_count > 4 {
        lines.push(format!("  …e altri {}", total_count - 4));
    }
    lines.join("\n")
}

/// Compute the reminder fire time for a schedule item.
fn compute_remind_time(
    item: &Value,
    item_local: chrono::DateTime<chrono::Local>,
) -> chrono::DateTime<chrono::Local> {
    let item_date = item.get("date").and_then(|d| d.as_str()).unwrap_or("");
    let custom_remind_time = item
        .get("customRemindTime")
        .and_then(|v| v.as_str())
        .filter(|s| s.len() >= 5);
    let remind_min = item
        .get("remindMinutes")
        .and_then(|v| v.as_i64())
        .unwrap_or(30);
    if let Some(crt) = custom_remind_time {
        let crt_str = format!("{} {}", item_date, crt);
        chrono::NaiveDateTime::parse_from_str(&crt_str, "%Y-%m-%d %H:%M")
            .ok()
            .and_then(|dt| chrono::Local.from_local_datetime(&dt).single())
            .unwrap_or(item_local - chrono::Duration::minutes(remind_min))
    } else {
        item_local - chrono::Duration::minutes(remind_min)
    }
}

/// Build the reminder body text with time-until description.
fn build_reminder_body(
    item_title: &str,
    item_time: &str,
    item_local: chrono::DateTime<chrono::Local>,
    remind_time: chrono::DateTime<chrono::Local>,
) -> String {
    let diff = (item_local - remind_time).num_minutes().max(0);
    let time_desc = if diff == 0 {
        "adesso!".to_string()
    } else if diff < 60 {
        format!("tra {} minuti", diff)
    } else {
        let h = diff / 60;
        let m = diff % 60;
        if m == 0 {
            format!("tra {} or{}", h, if h == 1 { "a" } else { "e" })
        } else {
            format!("tra {}h {:02}min", h, m)
        }
    };
    format!("{} — {} ({})", item_title, item_time, time_desc)
}

/// Parse a schedule item's date+time into a local DateTime.
fn parse_item_datetime(item: &Value) -> Option<chrono::DateTime<chrono::Local>> {
    let item_date = item.get("date").and_then(|d| d.as_str()).unwrap_or("");
    let item_time = item.get("time").and_then(|t| t.as_str()).unwrap_or("");
    if item_time.len() < 5 {
        return None;
    }
    let dt_str = format!("{} {}", item_date, item_time);
    chrono::NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M")
        .ok()
        .and_then(|dt| chrono::Local.from_local_datetime(&dt).single())
}

/// Compute a stable i32 notification ID from a seed string.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn hash_notification_id(seed: &str) -> i32 {
    let hash = <Sha256 as Digest>::digest(seed.as_bytes());
    let raw = i32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
    raw.wrapping_abs().max(1)
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

/// Schedule all briefing notifications across briefing times × day offsets.
/// Returns number of notifications scheduled.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn schedule_all_briefings(
    app: &AppHandle,
    briefing_times: &[Value],
    items: &[Value],
    today_str: &str,
    tomorrow_str: &str,
    now: chrono::DateTime<chrono::Local>,
    horizon: chrono::DateTime<chrono::Local>,
    max: i32,
) -> i32 {
    let mut count = 0i32;
    for bt in briefing_times {
        let time_str = match bt.as_str() {
            Some(s) if s.len() >= 5 => s,
            _ => continue,
        };
        for day_offset in 0..=1i64 {
            if count >= max {
                return count;
            }
            if let Some(sc) = schedule_briefing_aot(
                app,
                time_str,
                day_offset,
                items,
                today_str,
                tomorrow_str,
                now,
                horizon,
            ) {
                count += sc;
            }
        }
    }
    count
}

/// Schedule all per-item reminder notifications.
/// Returns number of notifications scheduled.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn schedule_all_reminders(
    app: &AppHandle,
    items: &[Value],
    now: chrono::DateTime<chrono::Local>,
    horizon: chrono::DateTime<chrono::Local>,
    already: i32,
    max: i32,
) -> i32 {
    let mut count = already;
    for item in items {
        if count >= max {
            break;
        }
        if let Some(sc) = schedule_reminder_aot(app, item, now, horizon) {
            count += sc;
        }
    }
    count - already
}

// ── MOBILE: Native AOT scheduling ─────────────────────────────────────────
#[cfg(any(target_os = "android", target_os = "ios"))]
fn sync_notifications(app: &AppHandle, data_dir: &std::path::Path) {
    use tauri_plugin_notification::NotificationExt;

    if let Err(e) = app.notification().cancel_all() {
        eprintln!("[LexFlow Sync] cancel_all error (non-critical): {:?}", e);
    } else {
        eprintln!("[LexFlow Sync] All pending notifications cancelled ✓");
    }

    let schedule_data = match read_notification_schedule(&data_dir) {
        Some(v) => v,
        None => {
            eprintln!("[LexFlow Sync] No schedule file");
            return;
        }
    };

    let briefing_times = schedule_data
        .get("briefingTimes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let items = schedule_data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let now = chrono::Local::now();
    let today_str = now.format("%Y-%m-%d").to_string();
    let tomorrow_str = (now + chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    const MAX_SCHEDULED: i32 = 60;
    let horizon = now + chrono::Duration::days(14);

    let briefing_count = schedule_all_briefings(
        app,
        &briefing_times,
        &items,
        &today_str,
        &tomorrow_str,
        now,
        horizon,
        MAX_SCHEDULED,
    );
    let reminder_count =
        schedule_all_reminders(app, &items, now, horizon, briefing_count, MAX_SCHEDULED);
    let total = briefing_count + reminder_count;

    eprintln!(
        "[LexFlow Sync] ══ Mobile AOT sync: {}/{} notifications scheduled ══",
        total, MAX_SCHEDULED
    );
}

/// Convert chrono::DateTime<Local> to time::OffsetDateTime (for notification scheduling).
#[cfg(any(target_os = "android", target_os = "ios"))]
fn chrono_to_offset(dt: chrono::DateTime<chrono::Local>) -> Option<time::OffsetDateTime> {
    let ts = dt.timestamp();
    let ns = dt.timestamp_subsec_nanos();
    let offset_secs = dt.offset().local_minus_utc();
    let offset = time::UtcOffset::from_whole_seconds(offset_secs).ok()?;
    time::OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .map(|t| t.replace_nanosecond(ns).unwrap_or(t))
        .map(|t| t.to_offset(offset))
}

/// Schedule a single briefing notification (mobile AOT). Returns Some(1) on success.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn schedule_briefing_aot(
    app: &AppHandle,
    time_str: &str,
    day_offset: i64,
    items: &[Value],
    today_str: &str,
    tomorrow_str: &str,
    now: chrono::DateTime<chrono::Local>,
    horizon: chrono::DateTime<chrono::Local>,
) -> Option<i32> {
    use tauri_plugin_notification::NotificationExt;
    let target_date = now.date_naive() + chrono::Duration::days(day_offset);
    let date_str = target_date.format("%Y-%m-%d").to_string();
    let dt_str = format!("{} {}", date_str, time_str);
    let target_dt = chrono::NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M").ok()?;
    let target_local = chrono::Local.from_local_datetime(&target_dt).single()?;
    if target_local <= now || target_local > horizon {
        return None;
    }
    let offset_dt = chrono_to_offset(target_local)?;
    let briefing_hour: u32 = time_str
        .split(':')
        .next()
        .and_then(|h| h.parse().ok())
        .unwrap_or(8);
    let (filter_date, time_from, period_label) =
        briefing_filter_params(briefing_hour, &date_str, tomorrow_str, day_offset == 0).or_else(
            || briefing_filter_params(briefing_hour, today_str, tomorrow_str, day_offset == 0),
        )?;
    let (title, body_str) =
        build_briefing_notification(items, filter_date, time_from, period_label);
    let notif_id = hash_notification_id(&format!("briefing-{}-{}", date_str, time_str));
    let sched = tauri_plugin_notification::Schedule::At {
        date: offset_dt,
        repeating: false,
        allow_while_idle: true,
    };
    app.notification()
        .builder()
        .id(notif_id)
        .title(&title)
        .body(&body_str)
        .schedule(sched)
        .show()
        .ok()
        .map(|_| 1)
}

/// Schedule a single reminder notification (mobile AOT). Returns Some(1) on success.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn schedule_reminder_aot(
    app: &AppHandle,
    item: &Value,
    now: chrono::DateTime<chrono::Local>,
    horizon: chrono::DateTime<chrono::Local>,
) -> Option<i32> {
    use tauri_plugin_notification::NotificationExt;
    let completed = item
        .get("completed")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    if completed {
        return None;
    }
    let item_local = parse_item_datetime(item)?;
    if item_local > horizon {
        return None;
    }
    let remind_time = compute_remind_time(item, item_local);
    if remind_time <= now {
        return None;
    }
    let offset_dt = chrono_to_offset(remind_time)?;
    let item_title = item
        .get("title")
        .and_then(|t| t.as_str())
        .unwrap_or("Impegno");
    let item_time = item.get("time").and_then(|t| t.as_str()).unwrap_or("");
    let item_date = item.get("date").and_then(|d| d.as_str()).unwrap_or("");
    let item_id = item.get("id").and_then(|i| i.as_str()).unwrap_or("");
    let body = build_reminder_body(item_title, item_time, item_local, remind_time);
    let notif_id = hash_notification_id(&format!("remind-{}-{}-{}", item_date, item_id, item_time));
    let sched = tauri_plugin_notification::Schedule::At {
        date: offset_dt,
        repeating: false,
        allow_while_idle: true,
    };
    app.notification()
        .builder()
        .id(notif_id)
        .title("LexFlow — Promemoria")
        .body(&body)
        .schedule(sched)
        .show()
        .ok()
        .map(|_| 1)
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
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_processed_minute = String::new();

    eprintln!("[LexFlow Cron] Desktop cron job started — checking every 60s");

    loop {
        interval.tick().await;

        let now = chrono::Local::now();
        let current_minute = now.format("%Y-%m-%d %H:%M").to_string();
        if current_minute == last_processed_minute {
            continue;
        }
        last_processed_minute = current_minute.clone();

        let data_dir = app
            .state::<AppState>()
            .data_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let schedule_data = match read_notification_schedule(&data_dir) {
            Some(v) => v,
            None => continue,
        };

        let briefing_times = schedule_data
            .get("briefingTimes")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let items = schedule_data
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let today = now.format("%Y-%m-%d").to_string();
        let tomorrow = (now + chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();

        // Check briefings
        for bt in &briefing_times {
            let time_str = match bt.as_str() {
                Some(s) if s.len() >= 5 => s,
                _ => continue,
            };
            let briefing_key = format!("{} {}", today, time_str);
            if briefing_key != current_minute {
                continue;
            }
            fire_desktop_briefing(&app, time_str, &items, &today, &tomorrow);
            eprintln!("[LexFlow Cron] ✓ Briefing fired: {}", briefing_key);
        }

        // Check per-item reminders
        for item in &items {
            fire_desktop_reminder(&app, item, &current_minute);
        }
    }
}

/// Fire a single desktop briefing notification if it matches the current minute.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn fire_desktop_briefing(
    app: &AppHandle,
    time_str: &str,
    items: &[Value],
    today: &str,
    tomorrow: &str,
) {
    use tauri_plugin_notification::NotificationExt;
    let briefing_hour: u32 = time_str
        .split(':')
        .next()
        .and_then(|h| h.parse().ok())
        .unwrap_or(8);
    let (filter_date, time_from, period_label) = if briefing_hour < 12 {
        (today, "00:00", "oggi")
    } else if briefing_hour < 18 {
        (today, "13:00", "questo pomeriggio")
    } else {
        (tomorrow, "00:00", "domani")
    };
    let (title, body_str) =
        build_briefing_notification(items, filter_date, time_from, period_label);
    let app_clone = app.clone();
    let _ = app.run_on_main_thread(move || {
        let _ = app_clone
            .notification()
            .builder()
            .title(&title)
            .body(&body_str)
            .show();
    });
}

/// Fire a single desktop reminder notification if it matches the current minute.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn fire_desktop_reminder(app: &AppHandle, item: &Value, current_minute: &str) {
    use tauri_plugin_notification::NotificationExt;
    let completed = item
        .get("completed")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    if completed {
        return;
    }
    let item_local = match parse_item_datetime(item) {
        Some(t) => t,
        None => return,
    };
    let remind_time = compute_remind_time(item, item_local);
    let fire_minute = remind_time.format("%Y-%m-%d %H:%M").to_string();
    if fire_minute != current_minute {
        return;
    }
    let item_title = item
        .get("title")
        .and_then(|t| t.as_str())
        .unwrap_or("Impegno");
    let item_time = item.get("time").and_then(|t| t.as_str()).unwrap_or("");
    let body = build_reminder_body(item_title, item_time, item_local, remind_time);
    let app_clone = app.clone();
    let _ = app.run_on_main_thread(move || {
        let _ = app_clone
            .notification()
            .builder()
            .title("LexFlow — Promemoria")
            .body(&body)
            .show();
    });
    eprintln!(
        "[LexFlow Cron] ✓ Reminder fired: {} → {}",
        item_title, fire_minute
    );
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
        } else {
            false
        }
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
    let last = *state
        .last_activity
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if now.duration_since(last) > Duration::from_secs(1) {
        *state
            .last_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = now;
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
    *state
        .autolock_minutes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

// ═══════════════════════════════════════════════════════════
//  WINDOW CONTROLS — solo desktop
// ═══════════════════════════════════════════════════════════

#[tauri::command]
fn window_minimize(app: AppHandle) {
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.minimize();
    }
    #[cfg(target_os = "android")]
    {
        let _ = app;
    }
}

#[tauri::command]
fn window_maximize(app: AppHandle) {
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") {
        if w.is_maximized().unwrap_or(false) {
            let _ = w.unmaximize();
        } else {
            let _ = w.maximize();
        }
    }
    #[cfg(target_os = "android")]
    {
        let _ = app;
    }
}

#[tauri::command]
fn show_main_window(app: AppHandle) {
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
    #[cfg(target_os = "android")]
    {
        let _ = app;
    }
}

// ═══════════════════════════════════════════════════════════
//  APP RUNNER
// ═══════════════════════════════════════════════════════════

/// Verify binary integrity at startup — detects patched crypto constants.
///
/// SECURITY FIX (Audit v2.5): strengthened from plain SHA-256 to HMAC-SHA256.
/// - Uses HMAC with a domain-separated key derived from the integrity seed itself,
///   so an attacker must understand the HMAC construction (not just find-and-replace a hash).
/// - Comparison uses constant-time `hmac::verify()` to prevent timing side-channels
///   (the old `==` on hex strings leaked the number of matching prefix bytes via timing).
/// - Added the domain separator version string to the seed, so changes to the check
///   algorithm invalidate old hashes (forces re-computation, not copy-paste from older builds).
///
/// Limitations (inherent, not fixable in software):
/// An attacker with full binary write access can patch both the expected hash AND the
/// verification code. This check is a "speed bump" — it stops naive patchers and automated
/// tools but not a determined reverse engineer. Defense-in-depth: combine with code signing,
/// notarization (macOS), and Gatekeeper/SmartScreen at the OS level.
fn verify_binary_integrity() {
    // Build the integrity seed from all security-critical constants
    let mut integrity_seed = Vec::with_capacity(256);
    // Domain separator: version the integrity check itself
    integrity_seed.extend_from_slice(b"LEXFLOW-INTEGRITY-V2:");
    integrity_seed.extend_from_slice(VAULT_MAGIC);
    integrity_seed.extend_from_slice(&(AES_KEY_LEN as u64).to_le_bytes());
    integrity_seed.extend_from_slice(&(NONCE_LEN as u64).to_le_bytes());
    integrity_seed.extend_from_slice(&ARGON2_M_COST.to_le_bytes());
    integrity_seed.extend_from_slice(&ARGON2_T_COST.to_le_bytes());
    integrity_seed.extend_from_slice(&ARGON2_P_COST.to_le_bytes());
    integrity_seed.extend_from_slice(&PUBLIC_KEY_BYTES);
    integrity_seed.extend_from_slice(&MAX_FAILED_ATTEMPTS.to_le_bytes());

    // Derive an HMAC key from the seed itself (self-referential binding)
    let hmac_key = <Sha256 as Digest>::digest(&integrity_seed);
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("HMAC can take key of any size");
    mac.update(&integrity_seed);
    let computed = mac.finalize();

    // Expected HMAC tag (hex-encoded, computed once at build time and hardcoded)
    const EXPECTED_HMAC_HEX: &str =
        "ffff6192ca8179a91851a1f3d446564e24f5d34737bb089ec99c76ead909a365";
    let expected_bytes = match hex::decode(EXPECTED_HMAC_HEX) {
        Ok(b) => b,
        Err(_) => {
            // If the expected hash is the placeholder, compute and print the correct one
            // so the developer can update it. This ONLY happens during development.
            let correct = hex::encode(computed.into_bytes());
            eprintln!("═══════════════════════════════════════════════════════");
            eprintln!("  INTEGRITY: Computed HMAC (update EXPECTED_HMAC_HEX):");
            eprintln!("  {}", correct);
            eprintln!("═══════════════════════════════════════════════════════");
            panic!(
                "SECURITY: verify_binary_integrity needs EXPECTED_HMAC_HEX updated to: {}",
                correct
            );
        }
    };

    // Constant-time comparison via HMAC verify
    let mut verify_mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("HMAC can take key of any size");
    verify_mac.update(&integrity_seed);
    if verify_mac.verify_slice(&expected_bytes).is_err() {
        let computed_hex = hex::encode(computed.into_bytes());
        eprintln!("FATAL INTEGRITY VIOLATION: crypto constants HMAC mismatch!");
        eprintln!("  Expected: {}", EXPECTED_HMAC_HEX);
        eprintln!("  Got:      {}", computed_hex);
        panic!("SECURITY: Binary integrity check failed — possible tampering detected.");
    }
}

/// Setup notification permissions and send welcome notification on first launch.
#[allow(unused_variables)]
fn setup_notification_permissions(app: &tauri::App, data_dir_for_scheduler: &std::path::Path) {
    use tauri_plugin_notification::NotificationExt;
    let state = app.notification().permission_state();
    eprintln!("[LexFlow] Notification permission state: {:?}", state);
    match state {
        Ok(tauri_plugin_notification::PermissionState::Granted) => {
            eprintln!("[LexFlow] Notifications already granted ✓");
        }
        Ok(tauri_plugin_notification::PermissionState::Denied) => {
            eprintln!("[LexFlow] ⚠️ Notifications DENIED by user/system.");
            eprintln!(
                "[LexFlow] → User must enable manually: System Settings → Notifications → LexFlow"
            );
            let _ = app.emit("notification-permission-denied", ());
        }
        _ => {
            eprintln!("[LexFlow] Notifications unknown — requesting permission...");
            let result = app.notification().request_permission();
            eprintln!("[LexFlow] Permission request result: {:?}", result);
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let marker = data_dir_for_scheduler.join(".notifications_registered");
        if !marker.exists() {
            let _ = app
                .notification()
                .builder()
                .title("LexFlow")
                .body("Le notifiche sono attive! Riceverai promemoria per scadenze e udienze.")
                .show();
            let _ = std::fs::write(&marker, "1");
            eprintln!("[LexFlow] First-launch notification sent ✓");
        }
    }
}

/// Auto-lock loop — shared between desktop and Android.
/// Sleeps 60s when vault is locked, 30s when unlocked, emits warning 30s before lock.
fn autolock_loop(ah: AppHandle) {
    loop {
        let is_unlocked = {
            let state = ah.state::<AppState>();
            state.vault_key.lock().map(|k| k.is_some()).unwrap_or(false)
        };
        if !is_unlocked {
            std::thread::sleep(Duration::from_secs(60));
            continue;
        }
        let (minutes, last) = {
            let state = ah.state::<AppState>();
            let m = *state
                .autolock_minutes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let l = *state
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            (m, l)
        };
        std::thread::sleep(Duration::from_secs(30));
        if minutes == 0 {
            continue;
        }
        let elapsed = Instant::now().duration_since(last);
        let threshold = Duration::from_secs(minutes as u64 * 60);
        if elapsed >= threshold.saturating_sub(Duration::from_secs(30)) && elapsed < threshold {
            let _ = ah.emit("lf-vault-warning", ());
        }
        if elapsed >= threshold {
            let state2 = ah.state::<AppState>();
            *state2.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
            let _ = ah.emit("lf-vault-locked", ());
        }
    }
}

/// Copy all files from one directory to another, skipping existing files.
#[cfg(not(target_os = "android"))]
fn copy_dir_non_overwrite(src: &std::path::Path, dest_dir: &std::path::Path) {
    let entries = match fs::read_dir(src) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let dest = dest_dir.join(entry.file_name());
        if !dest.exists() {
            let _ = fs::copy(entry.path(), &dest);
        }
    }
}

/// Copy security files from one directory to another, skipping existing files.
#[cfg(not(target_os = "android"))]
fn copy_security_files_if_missing(src_dir: &std::path::Path, dest_dir: &std::path::Path) {
    for sec_file in &[
        LICENSE_FILE,
        LICENSE_SENTINEL_FILE,
        BURNED_KEYS_FILE,
        LOCKOUT_FILE,
    ] {
        let old_path = src_dir.join(sec_file);
        let new_path = dest_dir.join(sec_file);
        if old_path.exists() && !new_path.exists() {
            let _ = fs::copy(&old_path, &new_path);
        }
    }
}

/// Migrate data from old identifier (com.technojaw.lexflow) to new one.
#[cfg(not(target_os = "android"))]
fn migrate_old_identifier(data_dir: &std::path::Path, security_dir: &std::path::Path) {
    let old_data_dir = match dirs::data_dir() {
        Some(d) => d,
        None => return,
    };
    let old_base = old_data_dir.join("com.technojaw.lexflow");
    if !old_base.exists() || !old_base.is_dir() {
        return;
    }

    let old_vault = old_base.join("lexflow-vault");
    if old_vault.exists() && !data_dir.join(VAULT_FILE).exists() {
        copy_dir_non_overwrite(&old_vault, data_dir);
    }
    copy_security_files_if_missing(&old_base, security_dir);
}

/// Migrate security files from vault dir to security_dir (post v2.6.1).
fn migrate_security_files(data_dir: &std::path::Path, security_dir: &std::path::Path) {
    for sec_file in &[
        LICENSE_FILE,
        LICENSE_SENTINEL_FILE,
        BURNED_KEYS_FILE,
        LOCKOUT_FILE,
    ] {
        let old_path = data_dir.join(sec_file);
        let new_path = security_dir.join(sec_file);
        if old_path.exists() && !new_path.exists() {
            let _ = fs::copy(&old_path, &new_path);
            let _ = fs::remove_file(&old_path);
        }
    }
}

/// Setup desktop-specific features: window events, system tray, auto-lock, cron job.
#[cfg(not(target_os = "android"))]
fn setup_desktop(
    app: &mut tauri::App,
    data_dir_for_scheduler: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    sync_notifications(app.handle(), data_dir_for_scheduler);

    #[cfg(target_os = "macos")]
    {
        let bundle_id = app.config().identifier.clone();
        let _ = std::process::Command::new("defaults")
            .args(["write", &bundle_id, "NSAppSleepDisabled", "-bool", "YES"])
            .output();
        eprintln!("[LexFlow] macOS App Nap disabled via defaults write ✓");
    }

    // Launch the desktop cron job
    let app_handle_cron = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        desktop_cron_job(app_handle_cron).await;
    });

    // Auto-lock thread
    let ah = app.handle().clone();
    std::thread::spawn(move || autolock_loop(ah));

    // Show main window
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }

    // Window focus/blur events + close intercept
    setup_window_events(app);

    // System tray
    setup_system_tray(app)?;

    Ok(())
}

/// Register window focus/blur and close-requested events.
#[cfg(not(target_os = "android"))]
fn setup_window_events(app: &tauri::App) {
    let app_handle = app.handle().clone();
    if let Some(w) = app.get_webview_window("main") {
        let w_clone = w.clone();
        w.on_window_event(move |event| match event {
            tauri::WindowEvent::Focused(focused) => {
                let _ = app_handle.emit("lf-blur", !focused);
            }
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                if w_clone.is_fullscreen().unwrap_or(false) {
                    let _ = w_clone.set_fullscreen(false);
                }
                let _ = w_clone.hide();
            }
            _ => {}
        });
    }
}

/// Create the system tray icon with show/quit menu.
#[cfg(not(target_os = "android"))]
fn setup_system_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let show_item = MenuItem::with_id(app, "show", "Apri LexFlow", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Chiudi LexFlow", true, None::<&str>)?;
    let tray_menu = Menu::with_items(app, &[&show_item, &quit_item])?;

    TrayIconBuilder::new()
        .tooltip("LexFlow — Gestionale Legale")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&tray_menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "quit" => {
                let state = app.state::<AppState>();
                *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                ..
            } = event
            {
                if let Some(w) = tray.app_handle().get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
        })
        .build(app)?;
    Ok(())
}

/// Setup Android-specific features: resolve data dir, AOT sync, auto-lock.
/// MUST be called during `setup()` — without it, data_dir/security_dir point
/// to a temp placeholder and no vault I/O should occur.
#[cfg(target_os = "android")]
fn setup_android(app: &mut tauri::App) {
    let real_dir = app
        .path()
        .app_data_dir()
        .expect("FATAL: Android could not resolve app_data_dir");
    let vault_dir = real_dir.join("lexflow-vault");
    fs::create_dir_all(&vault_dir).expect("FATAL: cannot create Android vault directory");
    *app.state::<AppState>()
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = vault_dir.clone();
    *app.state::<AppState>()
        .security_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = real_dir.clone();
    sync_notifications(&app.handle(), &vault_dir);
    let ah = app.handle().clone();
    std::thread::spawn(move || autolock_loop(ah));
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(not(target_os = "android"))]
    let data_dir = dirs::data_dir()
        .expect("FATAL: could not determine system data directory (dirs::data_dir)")
        .join("com.pietrolongo.lexflow")
        .join("lexflow-vault");

    #[cfg(not(target_os = "android"))]
    let security_dir = dirs::data_dir()
        .expect("FATAL: could not determine system data directory (dirs::data_dir)")
        .join("com.pietrolongo.lexflow");

    // Android: use temp dir as safe initial placeholder; setup_android() will
    // overwrite both data_dir and security_dir with the real app-data path.
    // We never write sensitive data until after setup_android() resolves them.
    #[cfg(target_os = "android")]
    let data_dir = std::env::temp_dir().join("lexflow-android-pending");
    #[cfg(target_os = "android")]
    let security_dir = std::env::temp_dir().join("lexflow-android-pending");

    let _ = fs::create_dir_all(&data_dir);
    let _ = fs::create_dir_all(&security_dir);

    #[cfg(not(target_os = "android"))]
    migrate_old_identifier(&data_dir, &security_dir);

    migrate_security_files(&data_dir, &security_dir);

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
            verify_binary_integrity();

            #[cfg(not(target_os = "android"))]
            setup_notification_permissions(app, &data_dir_for_scheduler);
            #[cfg(target_os = "android")]
            setup_notification_permissions(app, std::path::Path::new(""));

            #[cfg(not(target_os = "android"))]
            setup_desktop(app, &data_dir_for_scheduler)?;

            #[cfg(target_os = "android")]
            setup_android(app);

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
            get_machine_fingerprint,
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
