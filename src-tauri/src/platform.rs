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

// FIX-B12: cache the random hostname fallback so a transient hostname lookup
// failure inside a single process always yields the SAME UID. Without this,
// every call to `get_platform_uid()` after a failure would derive a different
// encryption key, locking the user out of their own files.
#[cfg(target_os = "windows")]
static HOSTNAME_FALLBACK: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn get_platform_uid() -> String {
    #[cfg(target_os = "windows")]
    {
        // SECURITY FIX: use whoami crate instead of env vars (USERDOMAIN/USERPROFILE
        // are user-controllable and can be spoofed to derive a different encryption key).
        let username = whoami::username();
        let hostname = match whoami::fallible::hostname() {
            Ok(h) => h,
            Err(_) => HOSTNAME_FALLBACK
                .get_or_init(|| format!("UNKNOWN_{:08x}", rand::random::<u32>()))
                .clone(),
        };
        format!("{}:{}", hostname, username)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let real_uid = unsafe { libc::getuid() };
        let username = whoami::username();
        format!("{}:{}", real_uid, username)
    }
}

/// Derive a 32-byte key from a seed string using double SHA-256.
///
/// THREAT MODEL: This is NOT a password-based KDF (no salt, no memory-hard iterations).
/// Its security relies on the secrecy of `machine_id` — a random 32-byte value stored
/// in a 0o600 file under the user's data directory. Since `machine_id` has 256 bits of
/// entropy from OsRng, brute-forcing the seed is infeasible regardless of KDF hardness.
/// This is machine-binding, not password protection — Argon2id is used separately for
/// the vault password (see vault_engine.rs).
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
        if existing.len() == 64 && existing.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(existing);
        }
        if !existing.is_empty() {
            eprintln!(
                "[SECURITY] WARNING: machine_id file has invalid format ({} chars, expected 64 hex). Regenerating.",
                existing.len()
            );
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

/// FIX-B11 + FIX-S21: machine-id accessor.
///
/// In debug builds, a missing `MACHINE_ID_CACHE` panics so the misuse is
/// loud and easy to catch in tests. In release builds we keep the legacy
/// behaviour of falling back to an ephemeral id (race-free via
/// `get_or_init`) but emit a CRITICAL log line — a hard failure here would
/// brick the running app for end users when the ephemeral path is at least
/// internally consistent for the current session.
///
/// All call-sites that previously consumed a `String` continue to work; the
/// signature is kept identical to avoid touching crypto.rs / license.rs.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub(crate) fn get_or_create_machine_id() -> String {
    if let Some(id) = MACHINE_ID_CACHE.get() {
        return id.clone();
    }

    #[cfg(debug_assertions)]
    {
        panic!(
            "machine_id non inizializzato — chiama init_machine_id() in setup() prima dell'uso"
        );
    }
    #[cfg(not(debug_assertions))]
    {
        eprintln!(
            "[SECURITY] CRITICAL: MACHINE_ID_CACHE not initialized — \
            init_machine_id() must run in setup(). Generating ephemeral machine ID. \
            Local encrypted files may become inaccessible after restart!"
        );
        // FIX-B11: race-free init via get_or_init — concurrent callers all
        // observe the same ephemeral id within this process.
        MACHINE_ID_CACHE
            .get_or_init(|| {
                let mut id_bytes = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id_bytes);
                hex::encode(id_bytes)
            })
            .clone()
    }
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

// ─────────────────────────────────────────────────────────────────────────────
// LEGACY V2 KEY DERIVATION — SUNSET TRACKING
// ─────────────────────────────────────────────────────────────────────────────
//
// HISTORY
//   This code path was introduced in the v1.x line ("V2 era") when the local
//   encryption key was derived from `username + hostname + uid`. Subsequent
//   releases moved to V3 (machine_id-based) and finally V4 (current). The V2
//   formula is weak: an attacker with read access to the user's home directory
//   AND knowledge of the current hostname can reproduce the key without ever
//   touching the `machine_id` file.
//
// WHY IT IS STILL HERE
//   Removing this function today would lock out any installation whose local
//   encrypted files were last written under the V2 derivation and have not
//   yet been opened (and thereby silently re-encrypted to V4) since upgrading.
//   The migration branch in `decrypt_local_with_migration` performs that
//   one-shot rewrite, so the legacy key is needed at most ONCE per stale file.
//
// SUNSET PLAN
//   - Status: DEPRECATED as of v1.1.0
//   - Hard removal: v2.0.0 (target date 2026-12-31)
//   - Pre-conditions for removal:
//       1. Telemetry below shows zero V2 unlocks for ≥2 consecutive minor
//          releases.
//       2. Release notes for the two prior versions warned users on V2 to
//          unlock their vault at least once before upgrading.
//   - On removal, also delete the V2 branch in `decrypt_local_with_migration`
//     and the `~/.lexflow/v2-migrations.log` writer below.
//
// AUDIT REFERENCES
//   - BE-11 S20: "V2 hostname-based key derivation should be removed after
//     a sunset window."
//   - D4: "Legacy key path retains attacker-friendly derivation requiring
//     only username + hostname."
//
// DO NOT INLINE OR REMOVE THIS FUNCTION BEFORE v2.0.0 WITHOUT COORDINATING
// WITH THE RELEASE OWNER.
// ─────────────────────────────────────────────────────────────────────────────

/// Sunset deadline for the V2 legacy key path, expressed as a Unix timestamp
/// (seconds, UTC). 2026-12-31T00:00:00Z. After this point the function below
/// must be deleted in the next release; the test
/// `tests::test_legacy_v2_sunset_not_passed` will start failing in CI to
/// force the action. A stronger compile-time check belongs in `build.rs`
/// (owned by a sibling subagent); if/when added there, prefer that.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[allow(dead_code)]
pub(crate) const LEGACY_V2_SUNSET_UNIX: i64 = 1_798_761_600;

/// Records that a V2-encrypted artefact was just successfully decrypted with
/// the legacy key. Writes a single timestamped line to
/// `<data_dir>/com.pietrolongo.lexflow/v2-migrations.log` so support can
/// surface "Vault migrated from V2 to V4 on <date>" in the UI and so we can
/// tell whether any installs are still on V2 as the sunset date approaches.
///
/// Best-effort: any IO error is swallowed (logged in debug builds only).
/// Never panics, never blocks the migration path.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub(crate) fn record_v2_migration(file_label: &str) {
    use std::io::Write;
    let Some(base_dir) = dirs::data_dir().or_else(dirs::home_dir) else {
        #[cfg(debug_assertions)]
        eprintln!("[V2-SUNSET] cannot resolve data_dir for v2-migrations.log");
        return;
    };
    let dir = base_dir.join("com.pietrolongo.lexflow");
    if let Err(_e) = fs::create_dir_all(&dir) {
        #[cfg(debug_assertions)]
        eprintln!("[V2-SUNSET] cannot create dir {:?}: {}", dir, _e);
        return;
    }
    let log_path = dir.join("v2-migrations.log");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{}\t{}\n", now, file_label);
    match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(mut f) => {
            let _ = f.write_all(line.as_bytes());
        }
        Err(_e) => {
            #[cfg(debug_assertions)]
            eprintln!("[V2-SUNSET] cannot append to {:?}: {}", log_path, _e);
        }
    }
}

/// Legacy V2 local-encryption key derivation (hostname-based).
///
/// **DEPRECATED.** Retained only to migrate stale V2-encrypted files to V4
/// on first read. See the block comment above for the full sunset plan.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[deprecated(
    since = "1.1.0",
    note = "V2 key derivation is retained for one-time migration only. \
            Will be removed in v2.0.0 (planned 2026-12-31). \
            Users still on V2 vault format must unlock at least once before that date. \
            See block comment in platform.rs and audit findings BE-11 S20 / D4."
)]
#[allow(deprecated)]
pub(crate) fn get_local_encryption_key_legacy() -> Zeroizing<Vec<u8>> {
    // Debug-gated telemetry: a hit here means a stale V2 vault was found in
    // the wild. Useful when triaging "should we extend the sunset window?".
    #[cfg(debug_assertions)]
    eprintln!(
        "[V2-SUNSET] legacy V2 key derivation invoked — sunset target 2026-12-31"
    );

    let user = whoami::username();
    let host = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let uid = get_platform_uid();
    let seed = format!("LEXFLOW-LOCAL-KEY-V2:{}:{}:{}:FORTKNOX", user, host, uid);
    double_sha256_key(&seed)
}

pub(crate) fn decrypt_local_with_migration(
    path: &std::path::Path,
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
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

        // SUNSET: this branch is scheduled for removal in v2.0.0 (2026-12-31).
        // See the block comment above `get_local_encryption_key_legacy` for the
        // full plan and audit references (BE-11 S20, D4).
        #[allow(deprecated)]
        let legacy_key = get_local_encryption_key_legacy();
        if let Ok(dec) = decrypt_data(&legacy_key, &enc) {
            let label = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<unknown>".to_string());
            eprintln!(
                "SECURITY NOTICE: Decrypting {:?} via LEGACY V2 key (hostname-based). \
                Re-encrypting with V4 key...",
                path.file_name().unwrap_or_default()
            );
            // Telemetry: record that a V2 artefact was found in the wild so
            // the UI can surface a "migrated from V2 on <date>" notice and
            // so we can decide whether to extend the sunset window.
            record_v2_migration(&label);
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
        // KNOWN LIMITATION: Key derivation relies solely on device_id (a random value
        // persisted in app-private storage). Ideally we would use the Android Keystore
        // (hardware-backed key storage) to wrap the local encryption key, providing
        // tamper resistance and binding to the device's TEE/SE.
        // TODO: Integrate Android Keystore for key wrapping in a future release.
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
    // FIX-S22: only consider app-private storage; the temp_dir().parent()
    // fallback was dropped because it could point anywhere on the device
    // (including world-readable locations on some Android variants).
    // TODO(audit:S22): wire `tauri::AppHandle` into setup() so we can prefer
    // `app.path().app_local_data_dir()` over the platform-default
    // `dirs::data_dir()`. Doing it here would change this function's
    // signature and cascade into setup.rs, which is out of scope for the
    // file-local audit pass.
    let candidate_dirs = [
        dirs::data_dir().map(|d| d.join("com.pietrolongo.lexflow")),
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
    // Use bounded read to prevent unbounded memory allocation from malicious files
    crate::io::safe_bounded_read(path, 1024)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
        .filter(|s| !s.is_empty())
}

// ─── Hardware fingerprint ──────────────────────────────────
//
// TODO: SECURITY LIMITATION — The hardware fingerprint relies on the secrecy
// of the machine_id file. An attacker with read access to this file can
// reproduce the fingerprint on another machine. Improving this would require
// platform-specific hardware serial APIs (e.g., IOKit on macOS, WMI on
// Windows) which introduce portability and permission challenges.

// FIX-S25: machine fingerprint uses double SHA-256 to match the key
// derivation chain in `double_sha256_key`. Single-pass SHA-256 is fine for
// integrity but using the same construction everywhere makes the threat
// model uniform: an attacker who reproduces the seed reproduces both the
// key AND the fingerprint via the same primitive, so we don't accidentally
// leak any bias by mixing primitives.
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
        let h1 = <Sha256 as Digest>::digest(seed.as_bytes());
        let h2 = <Sha256 as Digest>::digest(h1);
        hex::encode(h2)
    }
    #[cfg(target_os = "android")]
    {
        let android_id = get_android_device_id();
        let seed = format!("LEXFLOW-ANDROID-FP:{}:IRONCLAD", android_id);
        let h1 = <Sha256 as Digest>::digest(seed.as_bytes());
        let h2 = <Sha256 as Digest>::digest(h1);
        hex::encode(h2)
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

    /// SUNSET ENFORCEMENT: this test fails the build (`cargo test`) once the
    /// V2 sunset date has passed AND the legacy function is still present.
    /// At that point the developer must delete:
    ///   - `get_local_encryption_key_legacy`
    ///   - `record_v2_migration`
    ///   - the V2 branch in `decrypt_local_with_migration`
    ///   - this test
    /// See audit BE-11 S20 / D4.
    ///
    /// We can't drop a hard `compile_error!` at module scope (it would block
    /// hot-fixes for users still on V2 if the date slips), so a test failure
    /// is the right "loud but recoverable" signal. If `build.rs` later gains
    /// a date-based check, prefer that.
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn test_legacy_v2_sunset_not_passed() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        assert!(
            now < LEGACY_V2_SUNSET_UNIX,
            "V2 legacy key derivation has reached its sunset date \
             ({}). Remove `get_local_encryption_key_legacy`, the V2 \
             branch in `decrypt_local_with_migration`, and this test. \
             See audit BE-11 S20 / D4.",
            LEGACY_V2_SUNSET_UNIX
        );
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
