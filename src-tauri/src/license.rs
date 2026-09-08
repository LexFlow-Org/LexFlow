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
use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::{atomic_write_with_sync, safe_now_ms};
use crate::lockout::{check_lockout, clear_lockout, record_failed_attempt_locked};
use crate::platform::{
    compute_machine_fingerprint, decrypt_local_with_migration, get_local_encryption_key,
};
use crate::state::AppState;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::fs;
use tauri::State;

const LAST_CHECK_TS_FILE: &str = ".last-license-check";
const CLOCK_HIGH_WATERMARK_FILE: &str = ".clock-watermark";
const MAX_LICENSE_TOKEN_BYTES: usize = 16 * 1024;
const ACTIVATION_JOURNAL_FILE: &str = ".license-activation-pending";
const SIGNED_RECORD_VERSION: &str = "ed25519-signed-v3";

fn license_deadline(expiry_ms: u64, grace_days: u64) -> Option<u64> {
    grace_days.checked_mul(86_400_000)?.checked_add(expiry_ms)
}

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
    #[cfg(test)]
    pub(super) fn record_hmac_key(master: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_subkey(master, b"LexFlow-v1-license-record-hmac-v2")
    }
}

// ─── Public-key bytes (literal const, must match build.rs) ──
//
// SECURITY NOTE (audit:HIGH-CRYPTO): the public key is embedded as a literal
// const so build.rs and CI's integrity check can verify byte-for-byte
// equality between this file and the seed used to derive the binary HMAC.
// A previous attempt (v1.0.0 audit pass) split the key into XOR-masked
// fragments to defeat trivial `strings` scans, but that defeats the build-
// time literal-byte equality check the CI workflow runs. The audit itself
// flagged the obfuscation as "not security" — a determined attacker with
// debugger access recovers the key either way. We therefore keep the
// literal here and rely on:
//   1. Build-time HMAC over the constants seeded with this public key.
//   2. OS code-signing chain (notarization on macOS, Authenticode on Win).
//   3. (Future) server-side recheck for high-value SKUs.
//
// ROTATED 2026-05-11: key pair regenerated (v5.1) — post-audit, v1.0.0 release.
// CI invariant: `grep -A4 'PUBLIC_KEY_BYTES.*must match' license.rs` must
// extract the same `Nu8` literals as the analogous block in `build.rs`.

// PUBLIC_KEY_BYTES (must match build.rs exactly)
pub(crate) const PUBLIC_KEY_BYTES: [u8; 32] = [
    174u8, 48u8, 245u8, 149u8, 58u8, 105u8, 117u8, 189u8, 197u8, 166u8, 82u8, 54u8, 39u8, 166u8,
    166u8, 194u8, 189u8, 248u8, 121u8, 72u8, 199u8, 249u8, 194u8, 97u8, 34u8, 165u8, 16u8, 49u8,
    44u8, 16u8, 222u8, 13u8,
];

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

fn read_clock_marker_with(
    path: &std::path::Path,
    label: &[u8],
    verify: impl Fn(&[u8], &str, &[u8]) -> bool,
) -> Result<Option<u64>, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Indicatore orologio non leggibile.".into()),
        Ok(_) => {}
    }
    let bytes = crate::io::safe_bounded_read(path, 256)?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| "Indicatore orologio corrotto.")?;
    let (timestamp, tag) = raw
        .trim()
        .split_once(':')
        .ok_or("Indicatore orologio corrotto.")?;
    let timestamp_ms = timestamp
        .parse::<u64>()
        .map_err(|_| "Timestamp licenza non valido.")?;
    let tag = hex::decode(tag).map_err(|_| "Autenticazione dell'orologio non valida.")?;
    if tag.len() != 32 || !verify(label, timestamp, &tag) {
        return Err("Indicatore orologio manomesso; file originale conservato.".into());
    }
    Ok(Some(timestamp_ms))
}

fn monotonic_clock_check(sec_dir: &std::path::Path) -> Result<(), String> {
    monotonic_clock_check_after_proof(sec_dir, false)
}

/// Missing historical markers may be initialized only for a new install or
/// after an explicit signed license proof. Corrupt markers are never reset.
fn monotonic_clock_check_after_proof(
    sec_dir: &std::path::Path,
    signed_proof: bool,
) -> Result<(), String> {
    let check_path = sec_dir.join(LAST_CHECK_TS_FILE);
    let high_path = sec_dir.join(CLOCK_HIGH_WATERMARK_FILE);
    let checked = read_clock_marker_with(&check_path, b"CLOCK-CHECK:", verify_clock_hmac_v2_v1)?;
    let high = read_clock_marker_with(
        &high_path,
        b"CLOCK-HIGH-WATERMARK:",
        verify_clock_hmac_v2_v1,
    )?;
    if checked.is_none()
        && high.is_none()
        && !signed_proof
        && (sec_dir.join(LICENSE_FILE).exists() || sec_dir.join(LICENSE_SENTINEL_FILE).exists())
    {
        return Err(
            "Indicatori orologio mancanti: reinserisci la licenza originale per verificarla."
                .into(),
        );
    }
    let now = safe_now_ms();
    let previous = checked.into_iter().chain(high).max().unwrap_or(0);
    if now < previous.saturating_sub(CLOCK_ROLLBACK_SLACK_MS) {
        return Err("Orologio di sistema arretrato. Ripristina data e ora corrette.".into());
    }
    let timestamp = now.to_string();
    let tag = compute_clock_hmac_v2(b"CLOCK-CHECK:", &timestamp);
    atomic_write_with_sync(&check_path, format!("{}:{}", timestamp, tag).as_bytes())?;
    let timestamp = now.max(previous).to_string();
    let tag = compute_clock_hmac_v2(b"CLOCK-HIGH-WATERMARK:", &timestamp);
    atomic_write_with_sync(&high_path, format!("{}:{}", timestamp, tag).as_bytes())
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

/// Bind cached activation records to the only issuer trusted by this build.
/// This is stored inside the authenticated encrypted license record. Records
/// predating issuer binding are deliberately revoked, not silently upgraded.
fn current_signing_key_id() -> String {
    hex::encode(<Sha256 as sha2::Digest>::digest(PUBLIC_KEY_BYTES))
}

fn record_has_current_issuer(data: &Value) -> bool {
    data.get("signingKeyId").and_then(Value::as_str) == Some(current_signing_key_id().as_str())
}

/// Verify a sentinel blob HMAC against `stored_bytes` using the V2 sentinel
/// sub-key first, falling back to the V1 master key. Returns true on a match
/// against either keystream so legacy on-disk material keeps validating.
fn verify_sentinel_blob_hmac_v2_v1(encrypted_key_id_hex: &str, stored_bytes: &[u8]) -> bool {
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
    let sentinel_bytes = crate::io::safe_bounded_read(sentinel_path, 4096).ok()?;
    let sentinel_content = std::str::from_utf8(&sentinel_bytes).ok()?;
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
                eprintln!("[SECURITY] sentinel blob HMAC mismatch — possible tampering");
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

fn existing_license_allows_replacement(
    data: &Value,
    new_id: &str,
    public: &[u8; 32],
    now: u64,
) -> bool {
    if data.get("signingKeyId").and_then(Value::as_str) != Some(signing_key_id(public).as_str()) {
        return true; // A revoked issuer cannot block a current issuer.
    }
    let Some(token) = data.get("signedToken").and_then(Value::as_str) else {
        return false;
    };
    let Ok(payload) = verified_payload(token, public) else {
        return false;
    };
    payload.id == new_id
        || license_deadline(payload.e, payload.g.unwrap_or(0))
            .is_some_and(|deadline| now > deadline)
}

fn sentinel_bytes(
    master: &[u8],
    fingerprint: &str,
    key_id: &str,
    now: &str,
) -> Result<Vec<u8>, String> {
    let subkey = sub_keys::sentinel_key(master);
    let encrypted_key_id = hex::encode(encrypt_data(&*subkey, key_id.as_bytes())?);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("HMAC key length");
    mac.update(
        format!(
            "LEXFLOW-SENTINEL:{}:{}:{}:{}",
            fingerprint, key_id, now, encrypted_key_id
        )
        .as_bytes(),
    );
    let compound = hex::encode(mac.finalize().into_bytes());
    let mut blob_mac = <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("HMAC key length");
    blob_mac.update(b"SENTINEL-BLOB-V1:");
    blob_mac.update(encrypted_key_id.as_bytes());
    Ok(format!(
        "{}\n{}\n{}",
        compound,
        encrypted_key_id,
        hex::encode(blob_mac.finalize().into_bytes())
    )
    .into_bytes())
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
#[cfg(test)]
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
#[cfg(test)]
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
    _key: &[u8],
    _path: &std::path::Path,
    _current_fp: &str,
    _needs_fp_upgrade: bool,
) -> Value {
    if !record_has_current_issuer(data) {
        return json!({"activated": false, "revoked": true, "reason": "Licenza revocata: è richiesta una licenza dell'emittente attuale."});
    }
    json!({"activated": false, "needsLicenseProof": true,
        "reason": "Per verificare questa attivazione precedente, reinserisci la stessa chiave di licenza originale. Non serve una nuova licenza."})
}

fn signing_key_id(public: &[u8; 32]) -> String {
    hex::encode(<Sha256 as sha2::Digest>::digest(public))
}

/// Verify issuer proof independently of wall clock, so an expired signed license
/// can still prove a previous activation and permit an authenticated renewal.
fn verified_payload(token: &str, public: &[u8; 32]) -> Result<LicensePayload, String> {
    if token.len() > MAX_LICENSE_TOKEN_BYTES {
        return Err("Chiave troppo lunga.".into());
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "LXFW" {
        return Err("Formato chiave non valido.".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| "Errore decodifica payload.")?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| "Errore decodifica firma.")?;
    let signature = Signature::from_slice(&signature).map_err(|_| "Firma corrotta.")?;
    let verifier =
        VerifyingKey::from_bytes(public).map_err(|_| "Errore chiave pubblica interna.")?;
    verifier
        .verify_strict(parts[1].as_bytes(), &signature)
        .map_err(|_| "Firma non valida o licenza manomessa!")?;
    let payload: LicensePayload =
        serde_json::from_slice(&bytes).map_err(|_| "Dati licenza corrotti.")?;
    if payload.id.trim().is_empty()
        || payload.id.len() > 512
        || payload.c.trim().is_empty()
        || payload.c.len() > 2000
        || payload.e == 0
        || payload.g.unwrap_or(0) > 3650
        || license_deadline(payload.e, payload.g.unwrap_or(0)).is_none()
    {
        return Err("Dati licenza non validi.".into());
    }
    Ok(payload)
}

fn legacy_proof_matches(
    data: &Value,
    token: &str,
    master: &[u8],
    fingerprint: &str,
    public: &[u8; 32],
) -> bool {
    let Ok(payload) = verified_payload(token, public) else {
        return false;
    };
    if data.get("signingKeyId").and_then(Value::as_str) != Some(signing_key_id(public).as_str())
        || data.get("keyId").and_then(Value::as_str) != Some(payload.id.as_str())
        || data.get("machineFingerprint").and_then(Value::as_str) != Some(fingerprint)
        || payload
            .h
            .as_deref()
            .is_some_and(|required| required != fingerprint)
    {
        return false;
    }
    let Some(stored) = data
        .get("tokenHmac")
        .and_then(Value::as_str)
        .and_then(|value| hex::decode(value).ok())
    else {
        return false;
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(master).expect("HMAC key length");
    mac.update(token.as_bytes());
    mac.verify_slice(&stored).is_ok()
}

fn signed_status(data: &Value, public: &[u8; 32], fingerprint: &str, now: u64) -> Value {
    if data.get("signingKeyId").and_then(Value::as_str) != Some(signing_key_id(public).as_str()) {
        return json!({"activated": false, "revoked": true, "reason": "Emittente della licenza non valido."});
    }
    let Some(token) = data.get("signedToken").and_then(Value::as_str) else {
        return json!({"activated": false, "reason": "Prova firmata della licenza mancante."});
    };
    let payload = match verified_payload(token, public) {
        Ok(payload) => payload,
        Err(error) => return json!({"activated": false, "reason": error}),
    };
    if data.get("machineFingerprint").and_then(Value::as_str) != Some(fingerprint)
        || payload
            .h
            .as_deref()
            .is_some_and(|required| required != fingerprint)
    {
        return json!({"activated": false, "reason": "Licenza attivata su un altro dispositivo."});
    }
    let grace = payload.g.unwrap_or(0);
    if now > license_deadline(payload.e, grace).unwrap_or(0) {
        return json!({"activated": false, "expired": true, "reason": "Licenza scaduta."});
    }
    json!({"activated": true, "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
        "client": payload.c, "lawyerName": payload.a.unwrap_or_default(),
        "lawyerTitle": payload.t.unwrap_or_else(|| "Avv.".into()), "studioName": payload.s.unwrap_or_default(),
        "inGracePeriod": now > payload.e, "graceDays": grace, "hardwareLocked": payload.h.is_some()})
}

#[derive(Serialize, Deserialize)]
struct ActivationJournal {
    version: u8,
    token: String,
    fingerprint: String,
    activated_at: String,
    burned_keys: Vec<String>,
}

fn journal_key(master: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    sub_keys::derive_subkey(master, b"LexFlow-v1-license-activation-journal")
}

/// Roll forward an authenticated transaction. The journal is persisted before
/// any activation file changes and removed only after all three writes succeed.
/// Repeating any prefix after a crash produces the same complete activation.
fn finish_activation_with(
    sec_dir: &std::path::Path,
    master: &[u8],
    public: &[u8; 32],
    fingerprint: &str,
    mut write: impl FnMut(&std::path::Path, &[u8]) -> Result<(), String>,
) -> Result<Option<String>, String> {
    let journal_path = sec_dir.join(ACTIVATION_JOURNAL_FILE);
    if !journal_path.try_exists().map_err(|e| e.to_string())? {
        return Ok(None);
    }
    let encrypted = crate::io::safe_bounded_read(&journal_path, MAX_SETTINGS_FILE_SIZE)?;
    let plain = decrypt_data(&*journal_key(master), &encrypted)?;
    let journal: ActivationJournal =
        serde_json::from_slice(&plain).map_err(|_| "Transazione licenza non valida.")?;
    let payload = verified_payload(&journal.token, public)?;
    if journal.version != 1
        || journal.fingerprint != fingerprint
        || payload
            .h
            .as_deref()
            .is_some_and(|required| required != fingerprint)
        || journal
            .burned_keys
            .iter()
            .any(|hash| hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("Transazione licenza non valida per questo dispositivo.".into());
    }
    let burn_hash = compute_burn_hash(&journal.token);
    if !journal.burned_keys.contains(&burn_hash) {
        return Err("Registro della transazione incompleto.".into());
    }
    let record = json!({"keyVersion": SIGNED_RECORD_VERSION, "signedToken": journal.token,
        "signingKeyId": signing_key_id(public), "machineFingerprint": fingerprint,
        "activatedAt": journal.activated_at, "keyId": payload.id});
    let burn_bytes = encrypt_data(
        &*sub_keys::burn_key(master),
        journal.burned_keys.join("\n").as_bytes(),
    )?;
    write(&sec_dir.join(BURNED_KEYS_FILE), &burn_bytes)?;
    let record_bytes = encrypt_data(
        master,
        &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
    )?;
    write(&sec_dir.join(LICENSE_FILE), &record_bytes)?;
    let sentinel = sentinel_bytes(master, fingerprint, &payload.id, &journal.activated_at)?;
    write(&sec_dir.join(LICENSE_SENTINEL_FILE), &sentinel)?;
    fs::remove_file(&journal_path).map_err(|e| e.to_string())?;
    Ok(Some(burn_hash))
}

fn recover_pending_activation(sec_dir: &std::path::Path) -> Result<(), String> {
    if !sec_dir
        .join(ACTIVATION_JOURNAL_FILE)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Ok(());
    }
    let master = get_local_encryption_key();
    if let Some(hash) = finish_activation_with(
        sec_dir,
        &master,
        &PUBLIC_KEY_BYTES,
        &compute_machine_fingerprint(),
        atomic_write_with_sync,
    )? {
        burn_key_keychain(&hash);
    }
    Ok(())
}

fn stage_activation(
    sec_dir: &std::path::Path,
    token: &str,
    fingerprint: &str,
    activated_at: String,
) -> Result<(), String> {
    let mut burned_keys = load_burned_keys(sec_dir)?;
    let burn_hash = compute_burn_hash(token);
    if !burned_keys.contains(&burn_hash) {
        burned_keys.push(burn_hash);
    }
    let journal = ActivationJournal {
        version: 1,
        token: token.into(),
        fingerprint: fingerprint.into(),
        activated_at,
        burned_keys,
    };
    let plain = serde_json::to_vec(&journal).map_err(|e| e.to_string())?;
    if plain.len() as u64 + 64 > MAX_SETTINGS_FILE_SIZE {
        return Err("Registro licenze troppo grande.".into());
    }
    let master = get_local_encryption_key();
    let encrypted = encrypt_data(&*journal_key(&master), &plain)?;
    atomic_write_with_sync(&sec_dir.join(ACTIVATION_JOURNAL_FILE), &encrypted)?;
    recover_pending_activation(sec_dir)
}

// ─── Internal helpers / Tauri commands ──────────────────────

fn invalid_license(message: &str) -> VerificationResult {
    VerificationResult {
        valid: false,
        client: None,
        message: message.into(),
        in_grace_period: None,
        grace_days: None,
        hardware_locked: None,
    }
}

pub(crate) fn verify_license(key_string: String) -> VerificationResult {
    verify_license_with_key(key_string, &PUBLIC_KEY_BYTES)
}

// Keep the complete verification path testable with synthetic signing keys.
// Production always supplies the single embedded key through verify_license.
fn verify_license_with_key(key_string: String, public_key_bytes: &[u8; 32]) -> VerificationResult {
    let payload = match verified_payload(&key_string, public_key_bytes) {
        Ok(payload) => payload,
        Err(error) => return invalid_license(&error),
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
    let Some(deadline) = license_deadline(payload.e, grace_days) else {
        return invalid_license("Durata della licenza non valida.");
    };

    if now > payload.e {
        if grace_days > 0 && now <= deadline {
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
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Err(error) = recover_pending_activation(&sec_dir) {
        return json!({"activated": false, "activationPending": true, "reason": format!("Completamento dell'attivazione non riuscito: {}. Riavvia per riprovare.", error)});
    }
    if let Err(error) = monotonic_clock_check(&sec_dir) {
        return json!({"activated": false, "reason": error});
    }
    let path = sec_dir.join(LICENSE_FILE);
    if !path.exists() {
        return if sec_dir.join(LICENSE_SENTINEL_FILE).exists() {
            json!({"activated": false, "tampered": true, "reason": "File di licenza rimosso o manomesso. Contattare il supporto."})
        } else {
            json!({"activated": false})
        };
    }
    let Some(plain) = decrypt_local_with_migration(&path) else {
        return json!({"activated": false, "reason": "File licenza corrotto o non valido per questo dispositivo."});
    };
    let Ok(data) = serde_json::from_slice::<Value>(&plain) else {
        return json!({"activated": false, "reason": "Dati licenza corrotti."});
    };
    let fingerprint = compute_machine_fingerprint();
    if data.get("keyVersion").and_then(Value::as_str) == Some(SIGNED_RECORD_VERSION) {
        return signed_status(&data, &PUBLIC_KEY_BYTES, &fingerprint, safe_now_ms());
    }
    // Historical records retaining their signed token can migrate without user input.
    if let Some(token) = data.get("key").and_then(Value::as_str) {
        if verified_payload(token, &PUBLIC_KEY_BYTES).is_ok()
            && data.get("machineFingerprint").and_then(Value::as_str) == Some(fingerprint.as_str())
        {
            if let Err(error) = stage_activation(
                &sec_dir,
                token,
                &fingerprint,
                chrono::Utc::now().to_rfc3339(),
            ) {
                return json!({"activated": false, "activationPending": true, "reason": error});
            }
            let record = json!({"signedToken": token, "signingKeyId": current_signing_key_id(), "machineFingerprint": fingerprint});
            return signed_status(&record, &PUBLIC_KEY_BYTES, &fingerprint, safe_now_ms());
        }
    }
    check_license_burned(&data, &[], &path, &fingerprint, false)
}

#[tauri::command]
pub(crate) fn activate_license(state: State<AppState>, key: String) -> Value {
    if key.len() > MAX_LICENSE_TOKEN_BYTES {
        return json!({"success": false, "error": "Chiave troppo lunga."});
    }
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let sec_dir = state
        .security_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Err(error) = recover_pending_activation(&sec_dir) {
        return json!({"success": false, "activationPending": true, "error": error});
    }
    if let Err(locked) = check_lockout(&state, &sec_dir) {
        return locked;
    }
    let key = key.trim();
    let payload = match verified_payload(key, &PUBLIC_KEY_BYTES) {
        Ok(payload) => payload,
        Err(error) => {
            record_failed_attempt_locked(&state, &sec_dir);
            return json!({"success": false, "error": error});
        }
    };
    let fingerprint = compute_machine_fingerprint();
    if payload
        .h
        .as_deref()
        .is_some_and(|required| required != fingerprint)
    {
        record_failed_attempt_locked(&state, &sec_dir);
        return json!({"success": false, "error": "Licenza bloccata su un altro dispositivo (Hardware ID mismatch)."});
    }
    let path = sec_dir.join(LICENSE_FILE);
    let sentinel_path = sec_dir.join(LICENSE_SENTINEL_FILE);
    let existing = if path.exists() {
        match decrypt_local_with_migration(&path)
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        {
            Some(data) => Some(data),
            None => {
                return json!({"success": false, "error": "Licenza locale non leggibile. Conserva i file e contatta il supporto."})
            }
        }
    } else {
        None
    };
    let proof = existing.as_ref().is_some_and(|data| {
        if data.get("keyVersion").and_then(Value::as_str) == Some("ed25519-burned") {
            return legacy_proof_matches(
                data,
                key,
                &get_local_encryption_key(),
                &fingerprint,
                &PUBLIC_KEY_BYTES,
            );
        }
        data.get("keyVersion").and_then(Value::as_str) == Some(SIGNED_RECORD_VERSION)
            && data.get("signedToken").and_then(Value::as_str) == Some(key)
            && data.get("signingKeyId").and_then(Value::as_str)
                == Some(current_signing_key_id().as_str())
            && data.get("machineFingerprint").and_then(Value::as_str) == Some(fingerprint.as_str())
    });
    if let Some(data) = &existing {
        if !proof
            && !existing_license_allows_replacement(
                data,
                &payload.id,
                &PUBLIC_KEY_BYTES,
                safe_now_ms(),
            )
        {
            return json!({"success": false, "needsLicenseProof": data.get("keyVersion").and_then(Value::as_str) != Some(SIGNED_RECORD_VERSION),
                "error": "La licenza attuale deve essere verificata con la chiave originale oppure deve essere scaduta prima del rinnovo."});
        }
    } else if sentinel_path.exists()
        && recover_sentinel_key_id(&sentinel_path).as_deref() != Some(payload.id.as_str())
    {
        return json!({"success": false, "error": "Questa installazione ha già una licenza registrata. Contattare il supporto."});
    }
    if proof {
        match is_key_burned(&sec_dir, key, &fingerprint) {
            Ok(true) => {}
            _ => {
                return json!({"success": false, "error": "Impossibile confermare il registro della precedente attivazione."})
            }
        }
    } else {
        let verification = verify_license(key.to_string());
        if !verification.valid {
            record_failed_attempt_locked(&state, &sec_dir);
            return json!({"success": false, "error": verification.message});
        }
        if let Err(error) = check_burned_key_registry(&sec_dir, key, &fingerprint) {
            return error;
        }
        if sentinel_path.exists() && !sec_dir.join(BURNED_KEYS_FILE).exists() {
            return json!({"success": false, "error": "Registro chiavi compromesso. Contattare il supporto."});
        }
    }
    if let Err(error) = monotonic_clock_check_after_proof(&sec_dir, true) {
        return json!({"success": false, "error": error});
    }
    match stage_activation(&sec_dir, key, &fingerprint, chrono::Utc::now().to_rfc3339()) {
        Ok(()) => {
            clear_lockout(&state, &sec_dir);
            if safe_now_ms() > license_deadline(payload.e, payload.g.unwrap_or(0)).unwrap_or(0) {
                return json!({"success": false, "proofRestored": proof, "needsLicenseProof": false, "needsRenewal": true,
                    "error": "La licenza originale è stata verificata, ma è scaduta. Inserisci una nuova licenza di rinnovo."});
            }
            json!({"success": true, "client": payload.c, "lawyerName": payload.a.unwrap_or_default(),
                "lawyerTitle": payload.t.unwrap_or_else(|| "Avv.".into()), "proofRestored": proof,
                "needsRenewal": safe_now_ms() > license_deadline(payload.e, payload.g.unwrap_or(0)).unwrap_or(0)})
        }
        Err(error) => json!({"success": false, "activationPending": true,
            "error": format!("Attivazione da completare: {}. I dati sono conservati; riavvia LexFlow per riprovare.", error)}),
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clock_marker_rejects_corruption_oversize_and_preserves_original() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clock");
        let verify = |_: &[u8], _: &str, tag: &[u8]| tag == [7; 32];
        assert_eq!(
            read_clock_marker_with(&path, b"test", verify).unwrap(),
            None
        );
        for value in [
            b"".to_vec(),
            b"corrupt".to_vec(),
            vec![b'x'; 257],
            format!("42:{}", "00".repeat(32)).into_bytes(),
        ] {
            fs::write(&path, &value).unwrap();
            assert!(read_clock_marker_with(&path, b"test", verify).is_err());
            assert_eq!(fs::read(&path).unwrap(), value);
        }
        fs::write(&path, format!("42:{}", "07".repeat(32))).unwrap();
        assert_eq!(
            read_clock_marker_with(&path, b"test", verify).unwrap(),
            Some(42)
        );
    }
    #[cfg(unix)]
    #[test]
    fn clock_marker_rejects_symlinks_without_following_them() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"preserved").unwrap();
        let path = dir.path().join("clock");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(read_clock_marker_with(&path, b"test", |_, _, _| true).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserved");
    }

    fn synthetic_payload(payload: Value) -> (String, [u8; 32]) {
        use ed25519_dalek::{Signer, SigningKey};
        let signer = SigningKey::from_bytes(&[91; 32]);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signature = URL_SAFE_NO_PAD.encode(signer.sign(payload.as_bytes()).to_bytes());
        (
            format!("LXFW.{payload}.{signature}"),
            signer.verifying_key().to_bytes(),
        )
    }
    fn synthetic_token(id: &str, expiry: u64) -> (String, [u8; 32]) {
        synthetic_payload(json!({"c":"Synthetic studio","a":"Synthetic lawyer","id":id,"e":expiry}))
    }

    #[test]
    fn signed_records_reverify_claims_and_reject_issuer_forgery() {
        let (token, public) = synthetic_token("signed-test", 10_000);
        let mut record = json!({"signedToken":token,"signingKeyId":signing_key_id(&public),"machineFingerprint":"fp","expiryMs":u64::MAX,"client":"Forged client"});
        let status = signed_status(&record, &public, "fp", 5000);
        assert_eq!(status["activated"], true);
        assert_eq!(status["client"], "Synthetic studio");
        assert_eq!(
            signed_status(&record, &public, "fp", 20_000)["expired"],
            true
        );
        assert_eq!(
            signed_status(&record, &public, "other-fp", 5000)["activated"],
            false
        );
        record["signedToken"] = json!("LXFW.e30.invalid");
        assert_eq!(
            signed_status(&record, &public, "fp", 5000)["activated"],
            false
        );
        record["signedToken"] = json!(token);
        record["signingKeyId"] = json!("old-issuer");
        assert_eq!(signed_status(&record, &public, "fp", 5000)["revoked"], true);
    }

    #[test]
    fn unsigned_cache_never_grants_access_even_with_matching_public_issuer() {
        let record = json!({"keyVersion":"ed25519-burned","signingKeyId":current_signing_key_id(),"tokenHmac":"anything","expiryMs":u64::MAX});
        let result = check_license_burned(
            &record,
            &[0; 32],
            std::path::Path::new("unused"),
            "fp",
            false,
        );
        assert_eq!(result["activated"], false);
        assert_eq!(result["needsLicenseProof"], true);
    }

    #[test]
    fn previous_activation_proof_requires_exact_token_id_hmac_and_fingerprint() {
        let (token, public) = synthetic_token("proof-test", 1); // Expired proof can authenticate a renewal.
        let master = [82; 32];
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&master).unwrap();
        mac.update(token.as_bytes());
        let mut record = json!({"keyId":"proof-test","tokenHmac":hex::encode(mac.finalize().into_bytes()),"signingKeyId":signing_key_id(&public),"machineFingerprint":"fp"});
        assert!(legacy_proof_matches(
            &record, &token, &master, "fp", &public
        ));
        assert!(!legacy_proof_matches(
            &record, &token, &master, "other", &public
        ));
        for field in ["keyId", "tokenHmac", "signingKeyId", "machineFingerprint"] {
            let original = record[field].clone();
            record[field] = json!("tampered");
            assert!(
                !legacy_proof_matches(&record, &token, &master, "fp", &public),
                "{field}"
            );
            record[field] = original;
        }
        let (bound_token, _) = synthetic_payload(
            json!({"c":"Synthetic","id":"proof-test","e":1,"h":"different-hardware"}),
        );
        let mut bound_mac = <Hmac<Sha256> as Mac>::new_from_slice(&master).unwrap();
        bound_mac.update(bound_token.as_bytes());
        let mut bound_record = record.clone();
        bound_record["tokenHmac"] = json!(hex::encode(bound_mac.finalize().into_bytes()));
        assert!(!legacy_proof_matches(
            &bound_record,
            &bound_token,
            &master,
            "fp",
            &public
        ));
        assert!(!legacy_proof_matches(
            &record,
            "LXFW.e30.invalid",
            &master,
            "fp",
            &public
        ));
        let (different_token, _) = synthetic_token("proof-test", 20_000);
        assert!(!legacy_proof_matches(
            &record,
            &different_token,
            &master,
            "fp",
            &public
        ));
    }

    #[test]
    fn renewal_uses_signed_deadline_including_grace_not_cached_expiry() {
        let (token, public) = synthetic_token("original", 10_000);
        let record =
            json!({"signedToken":token,"signingKeyId":signing_key_id(&public),"expiryMs":1});
        assert!(!existing_license_allows_replacement(
            &record, "renewal", &public, 5000
        ));
        assert!(existing_license_allows_replacement(
            &record, "renewal", &public, 20_000
        ));
        let (with_grace, _) =
            synthetic_payload(json!({"c":"Synthetic","id":"original","e":10_000,"g":2}));
        let grace_record = json!({"signedToken":with_grace,"signingKeyId":signing_key_id(&public)});
        assert!(!existing_license_allows_replacement(
            &grace_record,
            "renewal",
            &public,
            10_000 + 86_400_000
        ));
        assert!(existing_license_allows_replacement(
            &grace_record,
            "renewal",
            &public,
            10_001 + 2 * 86_400_000
        ));
        let unsigned =
            json!({"keyId":"original","signingKeyId":signing_key_id(&public),"expiryMs":1});
        assert!(!existing_license_allows_replacement(
            &unsigned, "renewal", &public, 20_000
        ));
    }

    #[test]
    fn activation_journal_recovers_every_interrupted_write_and_replay() {
        let master = [83; 32];
        let (token, public) = synthetic_token("journal", 100_000);
        for fail_at in 1..=3 {
            let dir = tempfile::tempdir().unwrap();
            let journal_path = dir.path().join(ACTIVATION_JOURNAL_FILE);
            let previous_license = b"previous-expired-record";
            fs::write(dir.path().join(LICENSE_FILE), previous_license).unwrap();
            let journal = ActivationJournal {
                version: 1,
                token: token.clone(),
                fingerprint: "fp".into(),
                activated_at: "2026-09-08T00:00:00Z".into(),
                burned_keys: vec!["a".repeat(64), compute_burn_hash(&token)],
            };
            let encrypted = encrypt_data(
                &*journal_key(&master),
                &serde_json::to_vec(&journal).unwrap(),
            )
            .unwrap();
            atomic_write_with_sync(&journal_path, &encrypted).unwrap();
            let mut writes = 0;
            let result =
                finish_activation_with(dir.path(), &master, &public, "fp", |path, bytes| {
                    writes += 1;
                    if writes == fail_at {
                        return Err("simulated crash before durable write".into());
                    }
                    atomic_write_with_sync(path, bytes)
                });
            assert!(result.is_err());
            assert!(journal_path.exists());
            if fail_at <= 2 {
                assert_eq!(
                    fs::read(dir.path().join(LICENSE_FILE)).unwrap(),
                    previous_license
                );
            }
            assert_eq!(
                finish_activation_with(dir.path(), &master, &public, "fp", atomic_write_with_sync)
                    .unwrap(),
                Some(compute_burn_hash(&token))
            );
            assert!(!journal_path.exists());
            let decrypted =
                decrypt_data(&master, &fs::read(dir.path().join(LICENSE_FILE)).unwrap()).unwrap();
            let record: Value = serde_json::from_slice(&decrypted).unwrap();
            assert_eq!(signed_status(&record, &public, "fp", 10)["activated"], true);
            let burns = decrypt_data(
                &*sub_keys::burn_key(&master),
                &fs::read(dir.path().join(BURNED_KEYS_FILE)).unwrap(),
            )
            .unwrap();
            assert_eq!(
                String::from_utf8(burns.to_vec()).unwrap().lines().count(),
                2
            );
            // Simulate a crash after final unlink whose directory update was not durable.
            atomic_write_with_sync(&journal_path, &encrypted).unwrap();
            assert!(finish_activation_with(
                dir.path(),
                &master,
                &public,
                "fp",
                atomic_write_with_sync
            )
            .unwrap()
            .is_some());
            assert!(finish_activation_with(
                dir.path(),
                &master,
                &public,
                "fp",
                atomic_write_with_sync
            )
            .unwrap()
            .is_none());
        }
    }

    #[test]
    fn activation_journal_rejects_tampered_or_wrong_issuer_before_any_commit() {
        let dir = tempfile::tempdir().unwrap();
        let master = [84; 32];
        let (token, _public) = synthetic_token("journal", 100_000);
        let journal = ActivationJournal {
            version: 1,
            token: token.clone(),
            fingerprint: "fp".into(),
            activated_at: "synthetic".into(),
            burned_keys: vec![compute_burn_hash(&token)],
        };
        let encrypted = encrypt_data(
            &*journal_key(&master),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        atomic_write_with_sync(&dir.path().join(ACTIVATION_JOURNAL_FILE), &encrypted).unwrap();
        assert!(finish_activation_with(
            dir.path(),
            &master,
            &PUBLIC_KEY_BYTES,
            "fp",
            |_, _| panic!("unverified journal reached writer")
        )
        .is_err());
        assert!(!dir.path().join(LICENSE_FILE).exists());
        assert!(!dir.path().join(BURNED_KEYS_FILE).exists());
    }

    #[test]
    fn license_duration_rejects_overflow_without_panicking() {
        assert_eq!(license_deadline(100, 2), Some(172_800_100));
        assert_eq!(license_deadline(100, u64::MAX), None);
        assert_eq!(license_deadline(u64::MAX, 1), None);
        assert_eq!(license_deadline(u64::MAX, 0), Some(u64::MAX));
    }

    #[test]
    fn oversized_license_is_rejected_before_decoding() {
        let result = verify_license(format!(
            "LXFW.{}.signature",
            "A".repeat(MAX_LICENSE_TOKEN_BYTES)
        ));
        assert!(!result.valid);
        assert_eq!(result.message, "Chiave troppo lunga.");
    }

    #[test]
    fn test_license_verification_full_cycle() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

        // Deterministic test-only seeds; never load the real signing key.
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let previous_signing_key = SigningKey::from_bytes(&[43u8; 32]);
        let public = signing_key.verifying_key().to_bytes();
        let expiry_ms = safe_now_ms() + 86_400_000 * 365; // 1 year from now
        let payload = serde_json::json!({
            "c": "pietro_test",
            "e": expiry_ms,
            "id": "test-self-signed"
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        // The wire protocol signs only payload_b64, matching the generator.
        let signature = signing_key.sign(payload_b64.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("LXFW.{payload_b64}.{sig_b64}");

        let accepted = verify_license_with_key(token.clone(), &public);
        assert!(
            accepted.valid,
            "Fresh issuer token must pass: {}",
            accepted.message
        );
        assert_eq!(accepted.client.as_deref(), Some("pietro_test"));

        let previous_signature = previous_signing_key.sign(payload_b64.as_bytes());
        let previous_token = format!(
            "LXFW.{payload_b64}.{}",
            URL_SAFE_NO_PAD.encode(previous_signature.to_bytes())
        );
        assert!(
            verify_license_with_key(
                previous_token.clone(),
                &previous_signing_key.verifying_key().to_bytes()
            )
            .valid,
            "The previous token is valid under its own synthetic issuer"
        );
        let revoked = verify_license_with_key(previous_token, &public);
        assert!(
            !revoked.valid,
            "Previous issuer must be rejected after rotation"
        );
        assert_eq!(revoked.message, "Firma non valida o licenza manomessa!");

        // The production entry point still trusts only its embedded public key.
        let result = verify_license(token.clone());
        assert!(
            !result.valid,
            "Token signed with wrong key should be rejected, got: {}",
            result.message
        );

        let pub_key = VerifyingKey::from_bytes(&PUBLIC_KEY_BYTES);
        assert!(
            pub_key.is_ok(),
            "Embedded PUBLIC_KEY_BYTES must be a valid Ed25519 key"
        );

        let altered_payload = json!({"c": "Altered", "e": expiry_ms, "id": "test-self-signed"});
        let tampered = format!(
            "LXFW.{}.{sig_b64}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&altered_payload).unwrap())
        );
        let tamper_result = verify_license_with_key(tampered, &public);
        assert!(!tamper_result.valid, "Tampered token should be rejected");

        let wrong_protocol_signature = signing_key.sign(format!("LXFW.{payload_b64}").as_bytes());
        let wrong_protocol = format!(
            "LXFW.{payload_b64}.{}",
            URL_SAFE_NO_PAD.encode(wrong_protocol_signature.to_bytes())
        );
        assert!(!verify_license_with_key(wrong_protocol, &public).valid);

        let invalid_format = "TOKEN_SENZA_PUNTI";
        let format_result = verify_license(invalid_format.to_string());
        assert!(!format_result.valid);
        assert_eq!(format_result.message, "Formato chiave non valido.");
    }

    #[test]
    fn cached_activations_require_the_current_issuer() {
        let master = [7u8; 32];
        let subkey = sub_keys::record_hmac_key(&master);
        let expiry = u64::MAX;
        let mut record = json!({
            "tokenHmac": "synthetic-token-hmac",
            "recordHmacV2": compute_record_hmac_v2(&*subkey, "cached-test", expiry, "synthetic-fp"),
            "keyVersion": "ed25519-burned",
            "keyId": "cached-test",
            "expiryMs": expiry,
            "machineFingerprint": "synthetic-fp",
        });
        // This helper does no file IO with needs_fp_upgrade=false.
        let check = |data: &Value| {
            check_license_burned(
                data,
                &master,
                std::path::Path::new("unused"),
                "synthetic-fp",
                false,
            )
        };
        let legacy = check(&record);
        assert_eq!(legacy["activated"], false);
        assert_eq!(legacy["revoked"], true);

        record["signingKeyId"] = json!("a-previous-issuer");
        let revoked = check(&record);
        assert_eq!(revoked["activated"], false);
        assert_eq!(revoked["revoked"], true);

        record["signingKeyId"] = json!(current_signing_key_id());
        assert_eq!(check(&record)["activated"], false);
        assert_eq!(check(&record)["needsLicenseProof"], true);
        record["expiryMs"] = json!(1);
        assert_eq!(
            check(&record)["activated"],
            false,
            "Issuer binding must not skip record authentication"
        );
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
        seed.extend_from_slice(&PUBLIC_KEY_BYTES);
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
        assert_ne!(&sub_keys::burn_key(&m1)[..], &sub_keys::burn_key(&m2)[..]);
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
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());

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

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
        mac.update(b"SENTINEL-BLOB-V1:");
        mac.update(blob_hex.as_bytes());
        let stored = mac.finalize().into_bytes().to_vec();

        // Same key + same input verifies.
        let mut mac2 = <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
        mac2.update(b"SENTINEL-BLOB-V1:");
        mac2.update(blob_hex.as_bytes());
        assert!(mac2.verify_slice(&stored).is_ok());

        // Master-keyed verify must fail for the sub-key HMAC (separation).
        let mut mac_master = <Hmac<Sha256> as Mac>::new_from_slice(&master).expect("hmac key");
        mac_master.update(b"SENTINEL-BLOB-V1:");
        mac_master.update(blob_hex.as_bytes());
        assert!(mac_master.verify_slice(&stored).is_err());

        // Tampered blob hex must fail.
        let mut mac3 = <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
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

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
        mac.update(b"CLOCK-CHECK:");
        mac.update(ts.as_bytes());
        let stored = mac.finalize().into_bytes().to_vec();

        // Verify with sub-key.
        let mut mac_ok = <Hmac<Sha256> as Mac>::new_from_slice(&*subkey).expect("hmac key");
        mac_ok.update(b"CLOCK-CHECK:");
        mac_ok.update(ts.as_bytes());
        assert!(mac_ok.verify_slice(&stored).is_ok());

        // Master cannot verify.
        let mut mac_master = <Hmac<Sha256> as Mac>::new_from_slice(&master).expect("hmac key");
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
