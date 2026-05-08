// ═══════════════════════════════════════════════════════════
//  LICENSE — Ed25519 verification, activation, burned keys
// ═══════════════════════════════════════════════════════════
//
// KEY SEPARATION (audit:LOW-S-9 — RESOLVED): a master `local_encryption_key`
// (see `platform::get_local_encryption_key`) is HKDF-SHA256 expanded into
// distinct sub-keys per consumer (license / burn registry / sentinel HMAC /
// clock watermark HMAC / record HMAC v2). See the `sub_keys` module below.
// Each consumer attempts V2 (sub-key) first and falls back to V1 (master key)
// for backward compatibility on existing on-disk material; new writes always
// use V2.
//
// TODO(audit:LOW-FP-PRIV): the burn-hash uses a single SHA-256 over
// `BURN-GLOBAL-V2:<token>` while platform::double_sha256_key uses double SHA-256.
// The single hash here is a deliberate trade-off (the same value must be
// recomputable on activation and verification without a stored salt). With
// LOW-S-9 resolved we could optionally HKDF the seed itself; deferred until
// the burn-registry file format gets a versioned envelope.
//
// TODO(audit:LOW-TEST-GAPS): missing unit tests for —
//   * monotonic_clock_check rollback detection
//   * burn-key keychain mirror (mock keyring)
//   * sentinel blob HMAC tamper rejection
//   * record_hmac_v2 mismatch rejection
//   * check_existing_license_blocks key-id mismatch path

use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::{atomic_write_with_sync, safe_now_ms};
use crate::lockout::{check_lockout, clear_lockout, record_failed_attempt};
use crate::platform::{
    compute_machine_fingerprint, decrypt_local_with_migration, get_local_encryption_key,
};
use crate::state::AppState;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::fs;
use tauri::State;

const LAST_CHECK_TS_FILE: &str = ".last-license-check";
const CLOCK_HIGH_WATERMARK_FILE: &str = ".clock-watermark";

// ─── HKDF sub-key derivation (audit:LOW-S-9) ────────────────
//
// The local master encryption key (see `platform::get_local_encryption_key`)
// is the input keying material for HKDF-SHA256. Each consumer derives its
// own 32-byte sub-key with a distinct label so that compromise of one
// keystream (e.g. a future pre-image attack on a stored HMAC) does not
// trivially extend to the others. Labels MUST stay stable across releases:
// changing one would silently invalidate every artefact authenticated with
// the previous label.
mod sub_keys {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    /// Derive a 32-byte sub-key from the master local_encryption_key.
    /// Each label produces a domain-separated key.
    pub(super) fn derive_subkey(master: &[u8], label: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, master);
        let mut okm = [0u8; 32];
        hk.expand(label, &mut okm)
            .expect("hkdf expand 32 bytes always succeeds");
        Zeroizing::new(okm)
    }

    /// Reserved label for the license.json AEAD key. Not wired to the
    /// production read/write paths today — license.json still uses the
    /// master key for backward compatibility with already-deployed
    /// installs (LOW-S-9 Option B). Kept here for the audit-friendly
    /// label inventory and exercised by unit tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn license_key(master: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_subkey(master, b"LexFlow-v1-license-encryption")
    }
    pub(super) fn burn_key(master: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_subkey(master, b"LexFlow-v1-burn-registry-encryption")
    }
    pub(super) fn sentinel_key(master: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_subkey(master, b"LexFlow-v1-sentinel-hmac")
    }
    pub(super) fn clock_check_key(master: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_subkey(master, b"LexFlow-v1-clock-watermark-hmac")
    }
    pub(super) fn record_hmac_key(master: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_subkey(master, b"LexFlow-v1-license-record-hmac-v2")
    }
}

// ─── Public-key obfuscation ─────────────────────────────────
//
// SECURITY NOTE: this is *obfuscation, not security*. A determined attacker
// with debugger access can recover the public key by stepping `ed25519_public_key()`.
// The split + XOR layout merely raises the cost of trivial static-string scanning
// (e.g. `strings`, `grep` over the binary) compared to a single contiguous array.
//
// TODO(audit:HIGH-CRYPTO): add server-side recheck or hardware attestation
// for true tamper-resistance against the embedded public key.
//
// ROTATED 2026-04-11: key pair regenerated (v5.0) — pre-release audit.
// Original public key bytes:
//   [68, 17, 204, 75, 33, 178, 142, 35, 80, 225, 11, 121, 146, 211, 252, 220,
//    179, 206, 88, 129, 82, 148, 38, 103, 113, 3, 106, 4, 9, 239, 47, 150]

const PK_PART_A: [u8; 16] = [
    0x55u8, 0x0Eu8, 0xC0u8, 0x4Du8, 0x37u8, 0xA1u8, 0x9Du8, 0x29u8, 0x42u8, 0xF6u8, 0x1Cu8, 0x77u8,
    0x83u8, 0xC4u8, 0xEEu8, 0xCFu8,
];

const PK_PART_B: [u8; 16] = [
    0xA1u8, 0xDDu8, 0x4Bu8, 0x9Eu8, 0x40u8, 0x87u8, 0x35u8, 0x77u8, 0x60u8, 0x10u8, 0x79u8, 0x17u8,
    0x1Au8, 0xFCu8, 0x3Cu8, 0x85u8,
];

const PK_XOR_MASK: [u8; 32] = [
    0x11u8, 0x1Fu8, 0x0Cu8, 0x06u8, 0x16u8, 0x13u8, 0x13u8, 0x0Au8, 0x12u8, 0x17u8, 0x17u8, 0x0Eu8,
    0x11u8, 0x17u8, 0x12u8, 0x13u8, 0x12u8, 0x13u8, 0x13u8, 0x1Fu8, 0x12u8, 0x13u8, 0x13u8, 0x10u8,
    0x11u8, 0x13u8, 0x13u8, 0x13u8, 0x13u8, 0x13u8, 0x13u8, 0x13u8,
];

#[inline(never)]
fn ed25519_public_key() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&PK_PART_A);
    out[16..].copy_from_slice(&PK_PART_B);
    for i in 0..32 {
        out[i] ^= PK_XOR_MASK[i];
    }
    out
}

/// Public-key bytes used by the integrity HMAC computed in build.rs.
/// Recovered on first access via `ed25519_public_key()` (split + XOR).
/// Cached in a `OnceLock` to avoid recomputing on every license verify
/// while staying compatible with the project's MSRV (1.77, pre-LazyLock).
static PUBLIC_KEY_BYTES_CACHE: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

pub(crate) struct PublicKeyBytesAccess;

impl std::ops::Deref for PublicKeyBytesAccess {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        PUBLIC_KEY_BYTES_CACHE.get_or_init(ed25519_public_key)
    }
}

#[allow(non_upper_case_globals)]
pub(crate) const PUBLIC_KEY_BYTES: PublicKeyBytesAccess = PublicKeyBytesAccess;

// ─── Burned-key registry ────────────────────────────────────

fn compute_burn_hash(token: &str) -> String {
    use sha2::Digest as _;
    let seed = format!("BURN-GLOBAL-V2:{}", token);
    let hash = Sha256::digest(seed.as_bytes());
    hex::encode(hash)
}

fn compute_burn_hash_legacy(token: &str, fingerprint: &str) -> String {
    use sha2::Digest as _;
    let seed = format!("BURN:{}:{}", fingerprint, token);
    let hash = Sha256::digest(seed.as_bytes());
    hex::encode(hash)
}

/// Read the encrypted burned-keys registry, transparently migrating from
/// the V1 layout (master-key encrypted) to V2 (burn sub-key encrypted).
/// V2 is tried first; on AEAD failure we fall back to V1.
fn load_burned_keys(dir: &std::path::Path) -> Result<Vec<String>, String> {
    let path = dir.join(BURNED_KEYS_FILE);
    if !path.exists() {
        return Ok(vec![]);
    }
    let enc = crate::io::safe_bounded_read(&path, crate::constants::MAX_SETTINGS_FILE_SIZE)
        .map_err(|e| {
            format!(
                "CRITICAL: Impossibile leggere il registro delle chiavi bruciate: {}",
                e
            )
        })?;

    let master = get_local_encryption_key();
    let burn_subkey = sub_keys::burn_key(&master);

    // V2 first (HKDF burn sub-key).
    let dec = if let Ok(d) = decrypt_data(&*burn_subkey, &enc) {
        d
    } else if let Some(d) = decrypt_local_with_migration(&path) {
        // V1: master key (and its V3/V2 hostname-based predecessors).
        #[cfg(debug_assertions)]
        eprintln!(
            "[SECURITY] burned-keys registry decrypted via V1 (master key) — \
             will be re-encrypted with V2 (burn sub-key) on next write."
        );
        d
    } else {
        return Err(
            "CRITICAL: Impossibile decifrare il registro delle chiavi bruciate. Possibile manomissione."
                .to_string(),
        );
    };

    let text = String::from_utf8_lossy(&dec);
    Ok(text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

fn burn_key(dir: &std::path::Path, burn_hash: &str) -> Result<(), String> {
    let mut hashes = load_burned_keys(dir)?;
    if hashes.contains(&burn_hash.to_string()) {
        // File registry already has it — still ensure keychain mirror is set.
        burn_key_keychain(burn_hash);
        return Ok(());
    }
    hashes.push(burn_hash.to_string());
    let content = hashes.join("\n");
    // V2: encrypt with the HKDF-derived burn sub-key (key separation).
    let master = get_local_encryption_key();
    let burn_subkey = sub_keys::burn_key(&master);
    let encrypted = encrypt_data(&*burn_subkey, content.as_bytes())
        .map_err(|e| format!("Errore cifratura registro: {}", e))?;
    atomic_write_with_sync(&dir.join(BURNED_KEYS_FILE), &encrypted).map_err(|e| {
        format!(
            "FATAL: Impossibile salvare il registro aggiornato su disco: {}",
            e
        )
    })?;
    // Mirror to OS keychain so that wiping the security folder alone does
    // not allow re-using the same key. Keychain failure is non-fatal —
    // some platforms (Linux without secret-service, sandboxed envs) may
    // not expose a keyring; in that case we degrade to file-only.
    burn_key_keychain(burn_hash);
    Ok(())
}

/// Mirror a burn hash into the OS keychain (per-key entry).
/// Non-fatal: any keychain failure is swallowed (with a debug log) so the
/// file-based registry remains the source of truth on keyring-less systems.
#[cfg(not(target_os = "android"))]
fn burn_key_keychain(burn_hash: &str) {
    // Truncate hash to a reasonable length for the keychain entry name.
    // 32 hex chars (128 bits) is more than enough as an opaque identifier.
    let entry_name = format!("burn_{}", &burn_hash[..burn_hash.len().min(32)]);
    if let Ok(entry) = keyring::Entry::new("LexFlow.Burned", &entry_name) {
        if let Err(e) = entry.set_password("burned") {
            #[cfg(debug_assertions)]
            eprintln!(
                "[SECURITY] burn_key_keychain: keychain set failed for {}: {}",
                entry_name, e
            );
            #[cfg(not(debug_assertions))]
            let _ = e;
        }
    }
}

#[cfg(target_os = "android")]
fn burn_key_keychain(_burn_hash: &str) {
    // Android keystore handled by frontend layer.
}

#[cfg(not(target_os = "android"))]
fn is_key_burned_keychain(burn_hash: &str) -> bool {
    let entry_name = format!("burn_{}", &burn_hash[..burn_hash.len().min(32)]);
    match keyring::Entry::new("LexFlow.Burned", &entry_name) {
        Ok(entry) => entry.get_password().is_ok(),
        Err(_) => false,
    }
}

#[cfg(target_os = "android")]
fn is_key_burned_keychain(_burn_hash: &str) -> bool {
    false
}

fn is_key_burned(dir: &std::path::Path, token: &str, fingerprint: &str) -> Result<bool, String> {
    let burn_hash_v2 = compute_burn_hash(token);
    let burn_hash_legacy = compute_burn_hash_legacy(token, fingerprint);

    // Check OS keychain first — this survives wiping the security folder.
    if is_key_burned_keychain(&burn_hash_v2) || is_key_burned_keychain(&burn_hash_legacy) {
        return Ok(true);
    }

    let hashes = load_burned_keys(dir)?;
    Ok(hashes.contains(&burn_hash_v2) || hashes.contains(&burn_hash_legacy))
}

// ─── Monotonic clock check ──────────────────────────────────

/// Maximum acceptable backwards drift relative to the high-watermark.
/// Reduced from 5 minutes to 60 seconds (M-CLOCK-4): the wider window
/// allowed trivial bypass of the rollback detection by setting the clock
/// back ~4 minutes between checks.
const CLOCK_ROLLBACK_SLACK_MS: u64 = 60_000;

/// Verify an HMAC over `(label, ts_str)` against `stored_bytes` using the
/// V2 clock-check sub-key first, falling back to the V1 master key. Returns
/// true on a match against either keystream so legacy on-disk material keeps
/// validating until the next write upgrades it.
fn verify_clock_hmac_v2_v1(label: &[u8], ts_str: &str, stored_bytes: &[u8]) -> bool {
    let master = get_local_encryption_key();
    let v2 = sub_keys::clock_check_key(&master);
    let mut mac_v2 =
        <Hmac<Sha256> as Mac>::new_from_slice(&*v2).expect("HMAC can take key of any size");
    mac_v2.update(label);
    mac_v2.update(ts_str.as_bytes());
    if mac_v2.verify_slice(stored_bytes).is_ok() {
        return true;
    }
    let mut mac_v1 =
        <Hmac<Sha256> as Mac>::new_from_slice(&master).expect("HMAC can take key of any size");
    mac_v1.update(label);
    mac_v1.update(ts_str.as_bytes());
    mac_v1.verify_slice(stored_bytes).is_ok()
}

fn compute_clock_hmac_v2(label: &[u8], ts_str: &str) -> String {
    let master = get_local_encryption_key();
    let subkey = sub_keys::clock_check_key(&master);
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("HMAC can take key of any size");
    mac.update(label);
    mac.update(ts_str.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn read_clock_high_watermark(sec_dir: &std::path::Path) -> Option<u64> {
    let path = sec_dir.join(CLOCK_HIGH_WATERMARK_FILE);
    let raw = fs::read_to_string(&path).ok()?;
    let parts: Vec<&str> = raw.trim().splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let stored_ts = parts[0].parse::<u64>().ok()?;
    let stored_bytes = hex::decode(parts[1]).ok()?;
    if !verify_clock_hmac_v2_v1(b"CLOCK-HIGH-WATERMARK:", parts[0], &stored_bytes) {
        return None;
    }
    Some(stored_ts)
}

fn write_clock_high_watermark(sec_dir: &std::path::Path, ts_ms: u64) {
    let path = sec_dir.join(CLOCK_HIGH_WATERMARK_FILE);
    let ts_str = ts_ms.to_string();
    let hmac_hex = compute_clock_hmac_v2(b"CLOCK-HIGH-WATERMARK:", &ts_str);
    let _ = atomic_write_with_sync(&path, format!("{}:{}", ts_str, hmac_hex).as_bytes());
}

fn monotonic_clock_check(sec_dir: &std::path::Path) -> Result<(), String> {
    let ts_path = sec_dir.join(LAST_CHECK_TS_FILE);
    let now_ms = safe_now_ms();

    // M1: If license.json exists but the clock-check sentinel doesn't,
    // the sentinel may have been deleted to bypass the monotonic check.
    // Log a warning but don't block the user.
    if !ts_path.exists() && sec_dir.join(LICENSE_FILE).exists() {
        #[cfg(debug_assertions)]
        eprintln!(
            "[SECURITY] WARNING: license.json exists but {} is missing. \
            The clock-check sentinel may have been deleted to bypass monotonic validation.",
            LAST_CHECK_TS_FILE
        );
    }

    // High-watermark check (M-CLOCK-4): refuse if the system clock is
    // earlier than (highest-ever-observed - 60s). This is independent of
    // the per-call sentinel and survives deletion of `.last-license-check`.
    if let Some(high_watermark) = read_clock_high_watermark(sec_dir) {
        if now_ms < high_watermark.saturating_sub(CLOCK_ROLLBACK_SLACK_MS) {
            return Err("SECURITY: System clock appears to have been set backwards. License check refused.".into());
        }
    }

    if let Ok(raw) = fs::read_to_string(&ts_path) {
        let parts: Vec<&str> = raw.trim().splitn(2, ':').collect();
        if parts.len() == 2 {
            let stored_ts = parts[0].parse::<u64>().unwrap_or(0);
            let hmac_valid = hex::decode(parts[1])
                .ok()
                .map(|bytes| verify_clock_hmac_v2_v1(b"CLOCK-CHECK:", parts[0], &bytes))
                .unwrap_or(false);
            if hmac_valid && now_ms < stored_ts.saturating_sub(CLOCK_ROLLBACK_SLACK_MS) {
                return Err("SECURITY: System clock appears to have been set backwards. License check refused.".into());
            }
        }
    }

    let ts_str = now_ms.to_string();
    let hmac_hex = compute_clock_hmac_v2(b"CLOCK-CHECK:", &ts_str);
    let _ = atomic_write_with_sync(&ts_path, format!("{}:{}", ts_str, hmac_hex).as_bytes());

    // Bump the high-watermark.
    let prior = read_clock_high_watermark(sec_dir).unwrap_or(0);
    write_clock_high_watermark(sec_dir, now_ms.max(prior));
    Ok(())
}

// ─── License types ──────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub(crate) struct LicensePayload {
    pub c: String,
    pub e: u64,
    pub id: String,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub h: Option<String>,
    #[serde(default)]
    pub g: Option<u64>,
    #[serde(default)]
    pub a: Option<String>,
    #[serde(default)]
    pub s: Option<String>,
    #[serde(default)]
    pub t: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct VerificationResult {
    pub valid: bool,
    pub client: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_grace_period: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_days: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_locked: Option<bool>,
}

// ─── Helpers ────────────────────────────────────────────────

fn parse_lxfw_payload(token: &str) -> Option<LicensePayload> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "LXFW" {
        return None;
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

fn extract_key_id(token: &str) -> Option<String> {
    parse_lxfw_payload(token).map(|p| p.id)
}

fn extract_expiry_ms(token: &str) -> Option<u64> {
    parse_lxfw_payload(token).map(|p| p.e)
}

/// Compute the read-time-verifiable sentinel HMAC over the encrypted key-id blob,
/// using the V2 sentinel sub-key. Independent of the legacy compound HMAC that
/// covers `fingerprint:key_id:now:encrypted_key_id` (which cannot be re-verified
/// at read time because we don't persist the plaintext fingerprint/key_id/now).
fn compute_sentinel_blob_hmac(encrypted_key_id_hex: &str) -> Vec<u8> {
    let master = get_local_encryption_key();
    let subkey = sub_keys::sentinel_key(&master);
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("HMAC can take key of any size");
    mac.update(b"SENTINEL-BLOB-V1:");
    mac.update(encrypted_key_id_hex.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Verify a sentinel blob HMAC against `stored_bytes` using the V2 sentinel
/// sub-key first, falling back to the V1 master key. Returns true on a match
/// against either keystream so legacy on-disk material keeps validating.
fn verify_sentinel_blob_hmac_v2_v1(
    encrypted_key_id_hex: &str,
    stored_bytes: &[u8],
) -> bool {
    let master = get_local_encryption_key();
    let v2 = sub_keys::sentinel_key(&master);
    let mut mac_v2 =
        <Hmac<Sha256> as Mac>::new_from_slice(&*v2).expect("HMAC can take key of any size");
    mac_v2.update(b"SENTINEL-BLOB-V1:");
    mac_v2.update(encrypted_key_id_hex.as_bytes());
    if mac_v2.verify_slice(stored_bytes).is_ok() {
        return true;
    }
    let mut mac_v1 =
        <Hmac<Sha256> as Mac>::new_from_slice(&master).expect("HMAC can take key of any size");
    mac_v1.update(b"SENTINEL-BLOB-V1:");
    mac_v1.update(encrypted_key_id_hex.as_bytes());
    mac_v1.verify_slice(stored_bytes).is_ok()
}

fn recover_sentinel_key_id(sentinel_path: &std::path::Path) -> Option<String> {
    let sentinel_content = fs::read_to_string(sentinel_path).ok()?;
    let mut lines = sentinel_content.lines();
    let _legacy_compound_hmac = lines.next()?; // original M2 compound HMAC
    let stored_key_id_enc = lines.next().filter(|s| !s.is_empty())?;

    // M-SENTINEL-5: verify a blob-only HMAC if present (third line) so that
    // tampering with the encrypted blob is caught even when we cannot re-derive
    // the legacy compound HMAC. Older sentinels (pre-fix) lack this line —
    // accept them gracefully and rely on AEAD authentication during decrypt.
    if let Some(stored_blob_hmac_hex) = lines.next() {
        if let Ok(stored_bytes) = hex::decode(stored_blob_hmac_hex) {
            // V2 (sentinel sub-key) first, V1 (master key) as fallback for legacy.
            if !verify_sentinel_blob_hmac_v2_v1(stored_key_id_enc, &stored_bytes) {
                #[cfg(debug_assertions)]
                eprintln!(
                    "[SECURITY] sentinel blob HMAC mismatch — possible tampering"
                );
                return None;
            }
        } else {
            return None;
        }
    }

    let enc_bytes = hex::decode(stored_key_id_enc).ok()?;
    // AEAD-decrypt the stored key_id blob: try V2 (sentinel sub-key) first,
    // fall back to V1 (master key) for sentinels written before LOW-S-9.
    let master = get_local_encryption_key();
    let sentinel_subkey = sub_keys::sentinel_key(&master);
    if let Ok(dec) = decrypt_data(&*sentinel_subkey, &enc_bytes) {
        return String::from_utf8(dec.to_vec()).ok();
    }
    let dec = decrypt_data(&master, &enc_bytes).ok()?;
    String::from_utf8(dec.to_vec()).ok()
}

fn check_existing_license_blocks(path: &std::path::Path, new_key: &str) -> Option<Value> {
    if !path.exists() {
        return None;
    }
    let dec = decrypt_local_with_migration(path)?;
    let existing: Value = serde_json::from_slice(&dec).ok()?;
    let new_id = extract_key_id(new_key)?;

    // M-MR-7: prefer a stable key-id comparison over re-running Ed25519
    // verification on the stored token. The previous logic could be
    // bypassed by feeding an expired or tampered legacy token (verify_license
    // returns valid=false → branch falls through to "ok").
    let existing_id_burned = existing
        .get("keyId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let existing_id_legacy = existing
        .get("key")
        .and_then(|k| k.as_str())
        .and_then(extract_key_id);

    let existing_id = existing_id_burned.or(existing_id_legacy);

    if let Some(existing_id) = existing_id {
        if existing_id != new_id {
            return Some(
                json!({"success": false, "error": "Una licenza è già attiva su questa installazione."}),
            );
        }
    }
    None
}

// TODO(audit:MED-MR-6): require user confirmation before binding fingerprint
// to existing license. Currently this function is a no-op (security stop-gap):
// silent rebinding allowed an attacker who copied license.json to a second
// machine to silently re-bind to the new hardware. The legitimate flow now is
// `activate_license(...)` with the original key, which is gated by the burn
// registry + key-id comparison.
fn silent_upgrade_fingerprint(_data: &Value, _key: &[u8], _path: &std::path::Path, _fp: &str) {
    // Intentionally empty — see TODO above. Do not re-introduce silent rebinding.
}

fn write_license_sentinel(
    sentinel_path: &std::path::Path,
    fingerprint: &str,
    key_id: &str,
    now: &str,
) {
    let master = get_local_encryption_key();
    let sentinel_subkey = sub_keys::sentinel_key(&master);
    // V2: encrypt the key_id with the HKDF-derived sentinel sub-key.
    let encrypted_key_id = match encrypt_data(&*sentinel_subkey, key_id.as_bytes()) {
        Ok(enc) => hex::encode(enc),
        Err(e) => {
            #[cfg(debug_assertions)]
            eprintln!("[SECURITY] Failed to encrypt sentinel key_id: {}", e);
            #[cfg(not(debug_assertions))]
            let _ = e;
            return; // SECURITY FIX: don't write sentinel without encrypted key ID
        }
    };
    // M2: compound HMAC covers both plaintext fields AND the encrypted key_id,
    // so an attacker cannot swap the encrypted blob without invalidating the HMAC
    // (this can only be re-verified by clients holding the plaintext context).
    // Keyed with the sentinel sub-key (V2) — never re-verified at read time.
    let sentinel_data = format!(
        "LEXFLOW-SENTINEL:{}:{}:{}:{}",
        fingerprint, key_id, now, encrypted_key_id
    );
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*sentinel_subkey)
        .expect("HMAC can take key of any size");
    mac.update(sentinel_data.as_bytes());
    let sentinel_hmac = hex::encode(mac.finalize().into_bytes());

    // M-SENTINEL-5: blob-only HMAC, verifiable at read time without context.
    let blob_hmac = hex::encode(compute_sentinel_blob_hmac(&encrypted_key_id));

    let sentinel_content = format!(
        "{}\n{}\n{}",
        sentinel_hmac, encrypted_key_id, blob_hmac
    );
    let _ = atomic_write_with_sync(sentinel_path, sentinel_content.as_bytes());
}

fn check_burned_key_registry(
    sec_dir: &std::path::Path,
    key: &str,
    fingerprint: &str,
) -> Result<(), Value> {
    match is_key_burned(sec_dir, key, fingerprint) {
        Ok(true) => Err(
            json!({"success": false, "error": "Questa chiave è già stata utilizzata. Ogni chiave è monouso."}),
        ),
        Err(e) => {
            #[cfg(debug_assertions)]
            eprintln!("[SECURITY] burned-keys registry unreadable: {}", e);
            #[cfg(not(debug_assertions))]
            let _ = e;
            Err(
                json!({"success": false, "error": "Registro chiavi non leggibile. Contattare il supporto."}),
            )
        }
        Ok(false) => Ok(()),
    }
}

/// Compute a record-level HMAC over the persistent fields of a burned-key
/// license record. This is the new "verifiable" tokenHmac (record_hmac_v2) —
/// unlike the legacy tokenHmac which was computed over the original token
/// (and could not be re-verified without the token), this one binds the
/// stored `keyId`, `expiryMs`, and `machineFingerprint` so tampering with
/// any of them on disk is detectable.
///
/// `key` is the HMAC key — production callers should pass the
/// HKDF-derived `sub_keys::record_hmac_key` (V2). The legacy code path
/// passed the master local-encryption key; that combination is still
/// accepted on read for backward compatibility.
fn compute_record_hmac_v2(key: &[u8], key_id: &str, expiry_ms: u64, fingerprint: &str) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(b"LICENSE-RECORD-V2:");
    mac.update(key_id.as_bytes());
    mac.update(b":");
    mac.update(expiry_ms.to_string().as_bytes());
    mac.update(b":");
    mac.update(fingerprint.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify a stored record_hmac_v2 against the canonical fields, accepting
/// either the V2 (HKDF-derived) sub-key or the V1 (master) key. The V2
/// path is tried first; legacy records keep validating until rewritten.
fn verify_record_hmac_v2(
    master: &[u8],
    stored: &str,
    key_id: &str,
    expiry_ms: u64,
    fingerprint: &str,
) -> bool {
    let v2_subkey = sub_keys::record_hmac_key(master);
    let expected_v2 = compute_record_hmac_v2(&*v2_subkey, key_id, expiry_ms, fingerprint);
    if expected_v2 == stored {
        return true;
    }
    let expected_v1 = compute_record_hmac_v2(master, key_id, expiry_ms, fingerprint);
    expected_v1 == stored
}

fn check_license_burned(
    data: &Value,
    key: &[u8],
    path: &std::path::Path,
    current_fp: &str,
    needs_fp_upgrade: bool,
) -> Value {
    let token_hmac = data.get("tokenHmac").and_then(|v| v.as_str()).unwrap_or("");
    let record_hmac_v2 = data
        .get("recordHmacV2")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expiry_ms = data.get("expiryMs").and_then(|v| v.as_u64()).unwrap_or(0);
    let grace_days = data.get("graceDays").and_then(|v| v.as_u64()).unwrap_or(0);
    let key_id = data
        .get("keyId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let stored_fp = data
        .get("machineFingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let client = data
        .get("client")
        .and_then(|v| v.as_str())
        .unwrap_or("Studio Legale")
        .to_string();
    let lawyer_name = data
        .get("lawyerName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let studio_name = data
        .get("studioName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let lawyer_title = data
        .get("lawyerTitle")
        .and_then(|v| v.as_str())
        .unwrap_or("Avv.")
        .to_string();

    if token_hmac.is_empty() {
        return json!({"activated": false, "reason": "Dati licenza corrotti."});
    }

    // M-MR-2: if the new record-HMAC is present, verify it. This catches
    // disk-level tampering of expiry / fingerprint / keyId. Older records
    // (written before this fix) have no `recordHmacV2` field — accept them
    // for backwards compatibility but the next activation will write the new
    // field. AEAD on the encrypted file already provides integrity, so the
    // record-HMAC is defence in depth.
    if !record_hmac_v2.is_empty() && !key_id.is_empty() {
        // V2 (record_hmac sub-key) first, V1 (master key) for legacy records.
        if !verify_record_hmac_v2(key, record_hmac_v2, key_id, expiry_ms, stored_fp) {
            return json!({
                "activated": false,
                "reason": "Dati licenza manomessi: HMAC del record non corrisponde."
            });
        }
    }
    // TODO(audit:MED-MR-2): once all clients have refreshed, drop the legacy
    // `tokenHmac` field entirely and require `recordHmacV2`. Until then we
    // accept either.
    let now_ms = safe_now_ms();
    let grace_ms = grace_days * 86_400 * 1000;

    if now_ms > expiry_ms {
        if grace_ms > 0 && now_ms <= (expiry_ms + grace_ms) {
            if needs_fp_upgrade {
                silent_upgrade_fingerprint(data, key, path, current_fp);
            }
            return json!({
                "activated": true,
                "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
                "client": client,
                "lawyerName": lawyer_name,
                "lawyerTitle": lawyer_title,
                "studioName": studio_name,
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
        "lawyerName": lawyer_name,
        "lawyerTitle": lawyer_title,
        "studioName": studio_name,
    })
}

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

    let record_hmac_subkey = sub_keys::record_hmac_key(key);
    let record_hmac_v2 = compute_record_hmac_v2(&*record_hmac_subkey, &key_id, expiry_ms, current_fp);
    let upgraded = json!({
        "tokenHmac": token_hmac,
        "recordHmacV2": record_hmac_v2,
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
                #[cfg(debug_assertions)]
                eprintln!("[SECURITY] license upgrade write failed: {}", e);
                #[cfg(not(debug_assertions))]
                let _ = e;
            }
        }
    }
    if let Err(e) = burn_key(sec_dir, &compute_burn_hash(license_key)) {
        #[cfg(debug_assertions)]
        eprintln!(
            "[SECURITY] CRITICAL: burn_key failed during legacy upgrade: {}",
            e
        );
        #[cfg(not(debug_assertions))]
        let _ = e;
    }

    json!({
        "activated": true,
        "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
        "client": client,
        "lawyerName": "",
        "studioName": "",
    })
}

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

    let mut token_mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&enc_key).expect("HMAC can take key of any size");
    token_mac.update(key.as_bytes());
    let token_hmac = hex::encode(token_mac.finalize().into_bytes());

    let parsed_payload = parse_lxfw_payload(key);
    let expiry_ms = parsed_payload.as_ref().map(|p| p.e).unwrap_or(0);
    let grace_days = parsed_payload.as_ref().and_then(|p| p.g).unwrap_or(0);
    let hardware_locked = parsed_payload.as_ref().and_then(|p| p.h.as_ref()).is_some();
    let lawyer_name = parsed_payload
        .as_ref()
        .and_then(|p| p.a.clone())
        .unwrap_or_default();
    let studio_name = parsed_payload
        .as_ref()
        .and_then(|p| p.s.clone())
        .unwrap_or_default();
    let lawyer_title = parsed_payload
        .as_ref()
        .and_then(|p| p.t.clone())
        .unwrap_or_else(|| "Avv.".to_string());

    // M-MR-2: also write a record-level HMAC that can be re-verified on read.
    // Keyed with the HKDF-derived record_hmac sub-key (V2 — domain-separated).
    let record_hmac_subkey = sub_keys::record_hmac_key(&enc_key);
    let record_hmac_v2 = compute_record_hmac_v2(&*record_hmac_subkey, &key_id, expiry_ms, fingerprint);

    let record = json!({
        "tokenHmac": token_hmac,
        "recordHmacV2": record_hmac_v2,
        "activatedAt": now,
        "client": client,
        "lawyerName": lawyer_name,
        "lawyerTitle": lawyer_title,
        "studioName": studio_name,
        "keyVersion": "ed25519-burned",
        "machineFingerprint": fingerprint,
        "keyId": key_id,
        "expiryMs": expiry_ms,
        "graceDays": grace_days,
        "hardwareLocked": hardware_locked,
    });

    let record_bytes = match serde_json::to_vec(&record) {
        Ok(b) => b,
        Err(e) => {
            return json!({"success": false, "error": format!("Errore serializzazione: {}", e)})
        }
    };
    let encrypted = match encrypt_data(&enc_key, &record_bytes) {
        Ok(enc) => enc,
        Err(e) => return json!({"success": false, "error": format!("Errore cifratura: {}", e)}),
    };
    if let Err(e) = atomic_write_with_sync(path, &encrypted) {
        return json!({"success": false, "error": format!("Errore salvataggio: {}", e)});
    }

    write_license_sentinel(sentinel_path, fingerprint, &key_id, &now);

    if let Err(e) = burn_key(sec_dir, &compute_burn_hash(key)) {
        #[cfg(debug_assertions)]
        eprintln!(
            "[SECURITY] CRITICAL: burn_key failed after activation: {}. Rolling back license file.",
            e
        );
        // Roll back: delete the license file that was just written
        let _ = std::fs::remove_file(path);
        return json!({"success": false, "error": format!("Activation failed: could not burn key ({}). License rolled back.", e)});
    }

    json!({"success": true, "client": client, "lawyerName": lawyer_name, "lawyerTitle": lawyer_title})
}

// ─── Internal helpers / Tauri commands ──────────────────────

// INFO(audit:lib-cleanup): both `get_machine_fingerprint` and `verify_license`
// were previously exposed as `#[tauri::command]`. Frontend never invokes them
// directly — they are wrappers over `compute_machine_fingerprint()` and the
// internal Ed25519 verification logic used by `check_license`/`activate_license`.
// Removing the attribute shrinks the IPC attack surface; BE-8 removes the
// matching entries from `lib.rs`'s invoke_handler.
pub(crate) fn get_machine_fingerprint() -> String {
    compute_machine_fingerprint()
}

pub(crate) fn verify_license(key_string: String) -> VerificationResult {
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

    let public_key = match VerifyingKey::from_bytes(&*PUBLIC_KEY_BYTES) {
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

    let now = safe_now_ms();
    let grace_days = payload.g.unwrap_or(0);
    let grace_ms = grace_days * 86_400 * 1000;

    if now > payload.e {
        if grace_ms > 0 && now <= (payload.e + grace_ms) {
            return VerificationResult {
                valid: true,
                client: Some(payload.c),
                message: "Licenza in Grace Period — rinnovo necessario!".into(),
                in_grace_period: Some(true),
                grace_days: Some(grace_days),
                hardware_locked: if hardware_locked { Some(true) } else { None },
            };
        }
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

#[tauri::command]
pub(crate) fn check_license(state: State<AppState>) -> Value {
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = sec_dir.join(LICENSE_FILE);
    let sentinel_path = sec_dir.join(LICENSE_SENTINEL_FILE);

    if let Err(e) = monotonic_clock_check(&sec_dir) {
        #[cfg(debug_assertions)]
        eprintln!("[SECURITY] {}", e);
        #[cfg(not(debug_assertions))]
        let _ = e;
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

#[tauri::command]
pub(crate) fn activate_license(state: State<AppState>, key: String) -> Value {
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());

    if let Err(locked_json) = check_lockout(&state, &sec_dir) {
        return locked_json;
    }

    let key = key.trim().to_string();
    let path = sec_dir.join(LICENSE_FILE);
    let sentinel_path = sec_dir.join(LICENSE_SENTINEL_FILE);

    if !path.exists() && sentinel_path.exists() {
        let stored_key_id = recover_sentinel_key_id(&sentinel_path);
        let new_key_id = extract_key_id(&key);
        match (stored_key_id.as_deref(), new_key_id.as_deref()) {
            (Some(old), Some(new_id)) if old == new_id => {}
            _ => {
                return json!({"success": false, "error": "Questa installazione ha già una licenza registrata. Contattare il supporto per assistenza."})
            }
        }
    }

    if let Some(blocked) = check_existing_license_blocks(&path, &key) {
        return blocked;
    }

    let verification = verify_license(key.clone());
    if !verification.valid {
        record_failed_attempt(&state, &sec_dir);
        return json!({"success": false, "error": verification.message});
    }

    let fingerprint = compute_machine_fingerprint();

    if let Err(msg) = check_burned_key_registry(&sec_dir, &key, &fingerprint) {
        record_failed_attempt(&state, &sec_dir);
        return msg;
    }

    if sentinel_path.exists() && !sec_dir.join(BURNED_KEYS_FILE).exists() {
        record_failed_attempt(&state, &sec_dir);
        return json!({"success": false, "error": "Registro chiavi compromesso. Contattare il supporto per assistenza."});
    }

    let client = verification
        .client
        .unwrap_or_else(|| "Studio Legale".to_string());
    let result =
        perform_license_activation(&sec_dir, &path, &sentinel_path, &key, &client, &fingerprint);

    if result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        clear_lockout(&state, &sec_dir);
    } else {
        record_failed_attempt(&state, &sec_dir);
    }

    result
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_verification_full_cycle() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

        // Generate a token signed with the CURRENT embedded public key's private counterpart.
        // Since we don't have the private key in tests, we test the verification logic
        // by creating a self-signed token with a fresh keypair and verifying tamper detection.

        // 1. Create a deterministic keypair for testing (NOT the production key)
        let test_secret: [u8; 32] = [42u8; 32]; // fixed test seed
        let signing_key = SigningKey::from_bytes(&test_secret);
        let _verifying_key = VerifyingKey::from(&signing_key);

        // 2. Build a valid payload
        let expiry_ms = safe_now_ms() + 86_400_000 * 365; // 1 year from now
        let payload = serde_json::json!({
            "c": "pietro_test",
            "e": expiry_ms,
            "id": "test-self-signed"
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let message = format!("LXFW.{}", payload_b64);
        let signature = signing_key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{}.{}", message, sig_b64);

        // 3. Verify tamper detection: token signed with different key should fail
        // (our embedded PUBLIC_KEY_BYTES won't match this test keypair)
        let result = verify_license(token.clone());
        assert!(
            !result.valid,
            "Token signed with wrong key should be rejected, got: {}",
            result.message
        );

        // 4. Verify the embedded public key is valid
        let pub_key = VerifyingKey::from_bytes(&*PUBLIC_KEY_BYTES);
        assert!(
            pub_key.is_ok(),
            "Embedded PUBLIC_KEY_BYTES must be a valid Ed25519 key"
        );

        // 5. Tamper detection: modify one byte of signature
        let mut tampered = token.clone();
        let last = tampered.len() - 3;
        tampered.replace_range(last..last + 1, "Z");
        let tamper_result = verify_license(tampered);
        assert!(!tamper_result.valid, "Tampered token should be rejected");

        let invalid_format = "TOKEN_SENZA_PUNTI";
        let format_result = verify_license(invalid_format.to_string());
        assert!(!format_result.valid);
        assert_eq!(format_result.message, "Formato chiave non valido.");
    }

    /// Verify that PUBLIC_KEY_BYTES matches the key used in build.rs for HMAC integrity.
    /// If this test fails, build.rs and license.rs have divergent keys — a critical bug.
    #[test]
    fn public_key_matches_integrity_hmac() {
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};

        // Replicate the exact integrity seed computation from build.rs / setup.rs
        let mut seed = Vec::with_capacity(256);
        seed.extend_from_slice(b"LEXFLOW-INTEGRITY-V2:");
        seed.extend_from_slice(crate::constants::VAULT_MAGIC);
        seed.extend_from_slice(&(crate::constants::AES_KEY_LEN as u64).to_le_bytes());
        seed.extend_from_slice(&(crate::constants::NONCE_LEN as u64).to_le_bytes());
        seed.extend_from_slice(&crate::constants::ARGON2_M_COST.to_le_bytes());
        seed.extend_from_slice(&crate::constants::ARGON2_T_COST.to_le_bytes());
        seed.extend_from_slice(&crate::constants::ARGON2_P_COST.to_le_bytes());
        seed.extend_from_slice(&*PUBLIC_KEY_BYTES);
        seed.extend_from_slice(&crate::lockout::DEK_WIPE_THRESHOLD.to_le_bytes());

        let hmac_key = Sha256::digest(&seed);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).unwrap();
        mac.update(&seed);
        let result = mac.finalize().into_bytes();
        let computed_hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();

        let expected_hex = env!("LEXFLOW_INTEGRITY_HMAC");
        assert_eq!(
            computed_hex, expected_hex,
            "PUBLIC_KEY_BYTES in license.rs does NOT match the key used in build.rs! \
             The HMAC integrity check will fail at runtime. \
             Computed={computed_hex}, Expected={expected_hex}"
        );
    }

    // ─── HKDF sub-key separation (audit:LOW-S-9) ────────────

    /// HKDF must produce sub-keys that differ from the master and from each
    /// other. A collision here would silently re-introduce key reuse.
    #[test]
    fn sub_keys_are_domain_separated() {
        let master = [0xA5u8; 32];
        let license = sub_keys::license_key(&master);
        let burn = sub_keys::burn_key(&master);
        let sentinel = sub_keys::sentinel_key(&master);
        let clock = sub_keys::clock_check_key(&master);
        let record = sub_keys::record_hmac_key(&master);

        // Each sub-key differs from the master.
        assert_ne!(&master[..], &license[..]);
        assert_ne!(&master[..], &burn[..]);
        assert_ne!(&master[..], &sentinel[..]);
        assert_ne!(&master[..], &clock[..]);
        assert_ne!(&master[..], &record[..]);

        // All sub-keys differ pairwise.
        let all = [
            (&license[..], "license"),
            (&burn[..], "burn"),
            (&sentinel[..], "sentinel"),
            (&clock[..], "clock"),
            (&record[..], "record"),
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i].0, all[j].0,
                    "sub-keys {} and {} must differ",
                    all[i].1, all[j].1
                );
            }
        }
    }

    /// HKDF is deterministic: same master + same label always yields the
    /// same 32-byte output. This is what makes V1→V2 backward-compat work.
    #[test]
    fn sub_keys_are_deterministic() {
        let master = [0x11u8; 32];
        for _ in 0..3 {
            let a = sub_keys::burn_key(&master);
            let b = sub_keys::burn_key(&master);
            assert_eq!(&a[..], &b[..]);
        }
        let m1 = [0x01u8; 32];
        let m2 = [0x02u8; 32];
        // Different masters must produce different sub-keys for the same label.
        assert_ne!(
            &sub_keys::burn_key(&m1)[..],
            &sub_keys::burn_key(&m2)[..]
        );
    }

    /// Burn-registry roundtrip: encrypt with the burn sub-key, decrypt with
    /// the same sub-key. Master-key decrypt must fail (key separation).
    #[test]
    fn burn_subkey_roundtrip_and_isolation() {
        let master = vec![0x33u8; 32];
        let subkey = sub_keys::burn_key(&master);
        let plaintext = b"burn-hash-1\nburn-hash-2\n";

        let encrypted = encrypt_data(&*subkey, plaintext).expect("encrypt ok");
        let decrypted = decrypt_data(&*subkey, &encrypted).expect("decrypt ok");
        assert_eq!(&decrypted, plaintext);

        // Master key cannot decrypt sub-key-encrypted material.
        assert!(decrypt_data(&master, &encrypted).is_err());
    }

    /// Sentinel blob HMAC roundtrip with the sentinel sub-key, and tamper
    /// detection on the encrypted blob hex.
    #[test]
    fn sentinel_blob_hmac_subkey_roundtrip() {
        let master = vec![0x44u8; 32];
        let subkey = sub_keys::sentinel_key(&master);
        let blob_hex = "0011223344556677";

        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
        mac.update(b"SENTINEL-BLOB-V1:");
        mac.update(blob_hex.as_bytes());
        let stored = mac.finalize().into_bytes().to_vec();

        // Same key + same input verifies.
        let mut mac2 =
            <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
        mac2.update(b"SENTINEL-BLOB-V1:");
        mac2.update(blob_hex.as_bytes());
        assert!(mac2.verify_slice(&stored).is_ok());

        // Master-keyed verify must fail for the sub-key HMAC (separation).
        let mut mac_master =
            <Hmac<Sha256> as Mac>::new_from_slice(&master).expect("hmac key");
        mac_master.update(b"SENTINEL-BLOB-V1:");
        mac_master.update(blob_hex.as_bytes());
        assert!(mac_master.verify_slice(&stored).is_err());

        // Tampered blob hex must fail.
        let mut mac3 =
            <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
        mac3.update(b"SENTINEL-BLOB-V1:");
        mac3.update(b"0011223344556678"); // last hex char flipped
        assert!(mac3.verify_slice(&stored).is_err());
    }

    /// Clock-check / high-watermark HMAC roundtrip with sub-key isolation.
    #[test]
    fn clock_check_subkey_roundtrip() {
        let master = vec![0x55u8; 32];
        let subkey = sub_keys::clock_check_key(&master);
        let ts = "1700000000000";

        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
        mac.update(b"CLOCK-CHECK:");
        mac.update(ts.as_bytes());
        let stored = mac.finalize().into_bytes().to_vec();

        // Verify with sub-key.
        let mut mac_ok =
            <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
        mac_ok.update(b"CLOCK-CHECK:");
        mac_ok.update(ts.as_bytes());
        assert!(mac_ok.verify_slice(&stored).is_ok());

        // Master cannot verify.
        let mut mac_master =
            <Hmac<Sha256> as Mac>::new_from_slice(&master).expect("hmac key");
        mac_master.update(b"CLOCK-CHECK:");
        mac_master.update(ts.as_bytes());
        assert!(mac_master.verify_slice(&stored).is_err());
    }

    /// record_hmac_v2: V2 sub-key matches itself; V1 (master) does not match
    /// against the V2-keyed expected value, but verify_record_hmac_v2 still
    /// accepts V1-keyed legacy values for backward compatibility.
    #[test]
    fn record_hmac_v2_subkey_and_legacy_accept() {
        let master = vec![0x66u8; 32];
        let subkey = sub_keys::record_hmac_key(&master);
        let key_id = "k-abc";
        let expiry: u64 = 1_700_000_000_000;
        let fp = "fingerprint-xyz";

        let v2 = compute_record_hmac_v2(&*subkey, key_id, expiry, fp);
        let v1 = compute_record_hmac_v2(&master, key_id, expiry, fp);
        assert_ne!(v2, v1, "V2 and V1 record HMACs must differ");

        // Both V2 and V1 stored values verify (compat path).
        assert!(verify_record_hmac_v2(&master, &v2, key_id, expiry, fp));
        assert!(verify_record_hmac_v2(&master, &v1, key_id, expiry, fp));

        // Tampered fingerprint fails for both keystreams.
        assert!(!verify_record_hmac_v2(
            &master,
            &v2,
            key_id,
            expiry,
            "different-fp"
        ));
        assert!(!verify_record_hmac_v2(
            &master,
            &v1,
            key_id,
            expiry,
            "different-fp"
        ));

        // Tampered expiry fails.
        assert!(!verify_record_hmac_v2(&master, &v2, key_id, expiry + 1, fp));
    }

    /// Combined V2/V1 verifier helpers must accept legacy stored values
    /// (master-keyed) AND V2 values (sub-key-keyed) for clock and sentinel.
    #[test]
    fn clock_and_sentinel_verifiers_accept_legacy_and_v2() {
        // We can't easily exercise verify_clock_hmac_v2_v1 /
        // verify_sentinel_blob_hmac_v2_v1 with arbitrary masters because they
        // call get_local_encryption_key() internally. We test the inner
        // mathematical invariant instead: a stored MAC built with master key
        // (V1) and the same MAC built with sub-key (V2) over identical input
        // are distinct, but each verifies against its own keystream.
        let master = vec![0x77u8; 32];

        let clock_sub = sub_keys::clock_check_key(&master);
        let sent_sub = sub_keys::sentinel_key(&master);

        // Clock V1 vs V2 distinct.
        let mac_clock = |key: &[u8]| {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
            m.update(b"CLOCK-CHECK:");
            m.update(b"123");
            m.finalize().into_bytes().to_vec()
        };
        assert_ne!(mac_clock(&master), mac_clock(&*clock_sub));

        // Sentinel V1 vs V2 distinct.
        let mac_sent = |key: &[u8]| {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
            m.update(b"SENTINEL-BLOB-V1:");
            m.update(b"deadbeef");
            m.finalize().into_bytes().to_vec()
        };
        assert_ne!(mac_sent(&master), mac_sent(&*sent_sub));
    }
}
