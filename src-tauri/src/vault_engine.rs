// ═══════════════════════════════════════════════════════════
//  VAULT V4 — Envelope encryption, per-record crypto, rotation
// ═══════════════════════════════════════════════════════════
//
//  Format: VAULT_MAGIC_V4 + JSON { version:4, kdf, wrapped_dek, ... }
//  KEK = Argon2id(password, salt, adaptive params)
//  DEK = random 256-bit, wrapped with AES-256-GCM-SIV(KEK)
//  Each record: AES-256-GCM-SIV(DEK, record_data) — nonce-misuse resistant
//  Index: AES-256-GCM-SIV(DEK, [{id, field, title, tags, updated_at}...])
//
//  SECURITY: AES-GCM-SIV is nonce-misuse resistant. If a nonce is accidentally
//  reused, only indistinguishability of identical plaintexts is lost — confidentiality
//  of all data is preserved. With standard AES-GCM, nonce reuse is catastrophic.

use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

// ─── Constants ──────────────────────────────────────────────

pub(crate) const CURRENT_VAULT_VERSION: u32 = 7;
pub(crate) const VAULT_MAGIC: &[u8] = b"LEXFLOW_V7";
/// Legacy V4 magic — kept only for reading old vaults (auto-migrated on save).
pub(crate) const VAULT_MAGIC_V4: &[u8] = b"LEXFLOW_V4";
const AES_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
pub(crate) const MAX_RECORD_VERSIONS: usize = 5;

// ─── Types ──────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultData {
    pub version: u32,
    pub kdf: KdfParams,
    pub wrapped_dek: String,
    pub dek_iv: String,
    pub dek_alg: String,
    pub header_mac: String,
    /// HMAC computation version — determines which fields are included in the MAC.
    /// Missing (None) = legacy v1 (included rotation). Current = 2 (excludes rotation).
    /// The app READS all versions but always WRITES the latest.
    #[serde(default)]
    pub mac_version: Option<u32>,
    pub rotation: RotationMeta,
    /// Recovery key: second DEK wrapper (optional, set via generate_recovery_key)
    #[serde(default)]
    pub wrapped_dek_recovery: Option<String>,
    #[serde(default)]
    pub recovery_iv: Option<String>,
    #[serde(default)]
    pub recovery_salt: Option<String>,
    pub index: EncryptedBlock,
    pub records: BTreeMap<String, RecordEntry>,
}

// Custom Debug that redacts wrapped_dek and header_mac (security-sensitive fields)
impl std::fmt::Debug for VaultData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultData")
            .field("version", &self.version)
            .field("kdf", &self.kdf)
            .field("wrapped_dek", &"[REDACTED]")
            .field("dek_iv", &"[REDACTED]")
            .field("dek_alg", &self.dek_alg)
            .field("header_mac", &"[REDACTED]")
            .field("rotation", &self.rotation)
            .field("records_count", &self.records.len())
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KdfParams {
    pub alg: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String, // base64, 32 bytes
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RotationMeta {
    pub created: String,    // ISO8601
    pub interval_days: u32, // default 90
    pub writes: u64,        // incremented on each write
    pub max_writes: u64,    // default 10000
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedBlock {
    pub iv: String,   // base64, 12 bytes
    pub tag: String,  // base64, 16 bytes (GCM tag)
    pub data: String, // base64, ciphertext (without tag, tag is separate)
    #[serde(default)] // backward compat: false if missing
    pub compressed: bool, // PERF: zstd-compressed before encryption
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecordVersion {
    pub v: u32,
    pub ts: String, // ISO8601
    pub iv: String,
    pub tag: String,
    pub data: String,
    #[serde(default)] // backward compat: false if missing
    pub compressed: bool,
    /// V7: serialization format. "json" (legacy/default) or "msgpack"
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecordEntry {
    pub versions: Vec<RecordVersion>,
    pub current: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IndexEntry {
    pub id: String,
    pub field: String,      // "practices", "agenda", etc.
    pub title: String,      // searchable summary
    pub tags: Vec<String>,  // category, status, etc.
    pub updated_at: String, // ISO8601
    /// V5 PERF: summary fields for lazy list rendering.
    /// Contains type-specific metadata (client, status, type, court, etc.)
    /// so the frontend renders complete lists WITHOUT decrypting each record.
    #[serde(default)]
    pub summary: Option<serde_json::Value>,
}

// FIX-12 (BE-T2): custom Debug that redacts title/tags/summary
// (PII-bearing fields). Mirrors the redaction pattern used for VaultData.
impl std::fmt::Debug for IndexEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexEntry")
            .field("id", &self.id)
            .field("field", &self.field)
            .field("title", &"[REDACTED]")
            .field("tags", &"[REDACTED]")
            .field("updated_at", &self.updated_at)
            .field("summary", &"[REDACTED]")
            .finish()
    }
}

/// V6 split-vault encrypted index payload.
///
/// Adds a per-record SHA-256 manifest so an attacker with FS access cannot
/// silently delete / rename / swap individual `record_<id>.enc` files
/// undetected (BE-5-HIGH-2 / audit:HIGH F2).
///
/// `manifest_version`:
///   * `0` (sentinel) → legacy vault written before manifest support;
///     read path skips integrity check (logs a warning) and the next
///     write upgrades the vault by populating the manifest.
///   * `1` (current)  → manifest is authoritative; mismatch = hard error.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct V6Index {
    #[serde(default)]
    pub entries: Vec<IndexEntry>,
    /// Map: record_id → hex(SHA-256(record_<id>.enc bytes on disk)).
    /// Empty when `manifest_version == 0` (legacy).
    #[serde(default)]
    pub record_manifest: BTreeMap<String, String>,
    /// Manifest schema version. `0` = legacy (no manifest). Current = 1.
    #[serde(default)]
    pub manifest_version: u32,
}

/// Current `V6Index.manifest_version` written by this code.
pub(crate) const CURRENT_MANIFEST_VERSION: u32 = 1;

// ═══════════════════════════════════════════════════════════
//  FASE 2: KEK Derivation + Auto-benchmark
// ═══════════════════════════════════════════════════════════

/// Benchmark Argon2 to find params yielding ~250-400ms on this device.
/// Called during vault creation and password change.
pub fn benchmark_argon2_params() -> KdfParams {
    // In debug builds, skip expensive benchmark and use safe defaults.
    // Debug-mode Argon2 is 10-20x slower than release.
    #[cfg(debug_assertions)]
    {
        return KdfParams {
            alg: "argon2id".to_string(),
            m: 16384,
            t: 3,
            p: 1,
            salt: String::new(),
        };
    }

    #[cfg(not(debug_assertions))]
    {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1);
        let max_p = (cores as f32 * 0.75).floor().clamp(1.0, 4.0) as u32;

        // Android: cap memory at 32MB to avoid OOM
        let max_m: u32 = if cfg!(target_os = "android") {
            32768
        } else {
            262144 // 256MB absolute ceiling
        };

        let target_ms: u128 = 300;
        let candidates_m: &[u32] = if cfg!(target_os = "android") {
            &[16384, 24576, 32768]
        } else {
            &[16384, 32768, 65536, 131072]
        };

        let mut best: Option<(KdfParams, i128)> = None;
        let test_salt = [0u8; 32];

        // Strategy: single probe per (m,p) combo — if within target, accept immediately.
        // Only do 3-run median for the first good match to confirm stability.
        'outer: for &m in candidates_m {
            if m > max_m {
                break;
            }
            for p in 1..=max_p {
                // Quick single probe first
                let start = std::time::Instant::now();
                let _ = derive_kek_raw("x", &test_salt, m, 3, p);
                let probe_ms = start.elapsed().as_millis();

                // Skip if way too slow (> 2x target) — higher m/p will be worse
                if probe_ms > target_ms * 2 {
                    break; // skip remaining p values for this m
                }

                // If within range, confirm with 2 more runs (median of 3)
                if (200..=800).contains(&probe_ms) {
                    let mut durations = vec![probe_ms];
                    for _ in 0..2 {
                        let start = std::time::Instant::now();
                        let _ = derive_kek_raw("x", &test_salt, m, 3, p);
                        durations.push(start.elapsed().as_millis());
                    }
                    durations.sort();
                    let median = durations[1];
                    let distance = (median as i128 - target_ms as i128).abs();

                    if best.is_none() || distance < best.as_ref().unwrap().1 {
                        best = Some((
                            KdfParams {
                                alg: "argon2id".to_string(),
                                m,
                                t: 3,
                                p,
                                salt: String::new(),
                            },
                            distance,
                        ));
                        // If very close to target (within 50ms), stop searching
                        if distance < 50 {
                            break 'outer;
                        }
                    }
                }
            }
        }

        // Fallback: safe minimum params
        best.map(|(params, _)| params).unwrap_or(KdfParams {
            alg: "argon2id".to_string(),
            m: 16384,
            t: 3,
            p: 1,
            salt: String::new(),
        })
    } // end #[cfg(not(debug_assertions))]
}

/// Derive KEK from password + KdfParams (reads params from vault header).
/// SECURITY: validates minimum KDF params to prevent downgrade attacks.
pub fn derive_kek(password: &str, params: &KdfParams) -> Result<Zeroizing<Vec<u8>>, String> {
    // SECURITY: reject trivially weak params that an attacker could inject
    if params.m < 8192 {
        return Err(format!("KDF m_cost too low ({}), minimum 8192", params.m));
    }
    if params.t < 2 || params.t > 100 {
        return Err(format!("KDF t_cost invalid ({}), must be 2-100", params.t));
    }
    if params.m > 524288 {
        // 512MB ceiling — prevents memory bomb
        return Err(format!(
            "KDF m_cost too high ({}), maximum 524288",
            params.m
        ));
    }
    if params.p < 1 || params.p > 16 {
        return Err(format!("KDF p_cost invalid ({}), must be 1-16", params.p));
    }
    let salt = B64
        .decode(&params.salt)
        .map_err(|e| format!("Invalid KDF salt: {}", e))?;
    if salt.len() < 16 {
        return Err(format!(
            "KDF salt too short ({} bytes), minimum 16",
            salt.len()
        ));
    }
    derive_kek_raw(password, &salt, params.m, params.t, params.p)
}

/// Raw KEK derivation with explicit params.
fn derive_kek_raw(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut key = Zeroizing::new(vec![0u8; AES_KEY_LEN]);
    let params = Params::new(m_cost, t_cost, p_cost, Some(AES_KEY_LEN))
        .map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let pwd_bytes = Zeroizing::new(password.as_bytes().to_vec());
    argon2
        .hash_password_into(&pwd_bytes, salt, &mut key)
        .map_err(|e| format!("Argon2 hash error: {}", e))?;
    Ok(key)
}

// ═══════════════════════════════════════════════════════════
//  FASE 3: DEK + Envelope Encryption + Header HMAC
// ═══════════════════════════════════════════════════════════

/// Generate a random 256-bit DEK.
pub(crate) fn generate_dek() -> Zeroizing<Vec<u8>> {
    let mut dek = Zeroizing::new(vec![0u8; AES_KEY_LEN]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut dek);
    dek
}

/// Wrap DEK with KEK using AES-256-GCM. Returns (wrapped_dek_base64, iv_base64).
pub(crate) fn wrap_dek(kek: &[u8], dek: &[u8]) -> Result<(String, String), String> {
    if kek.len() != 32 {
        return Err("Invalid KEK length: expected 32 bytes".into());
    }
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(kek));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: dek,
                aad: b"LEXFLOW-DEK-WRAP",
            },
        )
        .map_err(|_| "DEK wrap encryption failed")?;
    Ok((B64.encode(&ciphertext), B64.encode(nonce_bytes)))
}

/// Unwrap DEK from wrapped_dek using KEK.
pub(crate) fn unwrap_dek(
    kek: &[u8],
    wrapped_dek_b64: &str,
    iv_b64: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let wrapped = B64
        .decode(wrapped_dek_b64)
        .map_err(|e| format!("Invalid wrapped DEK: {}", e))?;
    let iv = B64
        .decode(iv_b64)
        .map_err(|e| format!("Invalid DEK IV: {}", e))?;
    if iv.len() != NONCE_LEN {
        return Err("DEK IV length mismatch".into());
    }
    if kek.len() != 32 {
        return Err("Invalid KEK length: expected 32 bytes".into());
    }
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(kek));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &wrapped,
                aad: b"LEXFLOW-DEK-WRAP",
            },
        )
        .map_err(|_| "Password non corretta o database danneggiato.")?;
    Ok(Zeroizing::new(plaintext))
}

/// Current HMAC version — always used for new writes.
pub(crate) const CURRENT_MAC_VERSION: u32 = 2;

/// Compute canonical bytes for a given MAC version.
/// v1 (legacy): included rotation in canonical header
/// v2 (current): excludes rotation (writes changes on every save, KEK unavailable)
fn canonical_header_bytes(vault: &VaultData, mac_ver: u32) -> Vec<u8> {
    let canonical = if mac_ver <= 1 {
        // Legacy v1: included rotation
        serde_json::json!({
            "dek_alg": vault.dek_alg,
            "dek_iv": vault.dek_iv,
            "kdf": vault.kdf,
            "rotation": vault.rotation,
            "version": vault.version,
            "wrapped_dek": vault.wrapped_dek,
        })
    } else {
        // v2+: rotation excluded (changes on every save)
        serde_json::json!({
            "dek_alg": vault.dek_alg,
            "dek_iv": vault.dek_iv,
            "kdf": vault.kdf,
            "version": vault.version,
            "wrapped_dek": vault.wrapped_dek,
        })
    };
    serde_json::to_vec(&canonical).expect("canonical header serialization cannot fail")
}

/// Compute HMAC-SHA256(KEK, canonical_header) for tamper detection.
/// Always uses CURRENT_MAC_VERSION for new writes.
pub(crate) fn compute_header_mac(kek: &[u8], vault: &VaultData) -> String {
    let canonical_bytes = canonical_header_bytes(vault, CURRENT_MAC_VERSION);
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(kek).expect("HMAC can take key of any size");
    mac.update(&canonical_bytes);
    B64.encode(mac.finalize().into_bytes())
}

/// Verify header HMAC — tries the vault's declared mac_version first,
/// then falls back to ALL known versions. This ensures vaults created by
/// ANY past version of the app can always be opened.
/// Returns Ok(needs_migration) where true = HMAC was verified with a legacy
/// version and the vault should be re-saved with CURRENT_MAC_VERSION.
pub fn verify_header_mac(kek: &[u8], vault: &VaultData) -> Result<bool, String> {
    let stored_bytes = B64
        .decode(&vault.header_mac)
        .map_err(|_| "Il database non è verificabile. Potrebbe essere stato modificato o è di una versione incompatibile.")?;

    // Try the declared version first (fast path)
    let declared_ver = vault.mac_version.unwrap_or(1); // missing = legacy v1
    {
        let canonical_bytes = canonical_header_bytes(vault, declared_ver);
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(kek).expect("HMAC can take key of any size");
        mac.update(&canonical_bytes);
        if mac.verify_slice(&stored_bytes).is_ok() {
            // MAC valid — check if migration needed
            return Ok(declared_ver != CURRENT_MAC_VERSION);
        }
    }

    // Fast path failed — try ALL known versions as fallback.
    // This handles the case where mac_version field is wrong/missing.
    // FIX-6 (BE-5-MED): iterate up to CURRENT_MAC_VERSION instead of hard-coding [1, 2].
    for ver in 1..=CURRENT_MAC_VERSION {
        if ver == declared_ver {
            continue; // already tried
        }
        let canonical_bytes = canonical_header_bytes(vault, ver);
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(kek).expect("HMAC can take key of any size");
        mac.update(&canonical_bytes);
        if mac.verify_slice(&stored_bytes).is_ok() {
            eprintln!(
                "[SECURITY] Header MAC verified with fallback version {} (declared: {}). Will migrate.",
                ver, declared_ver
            );
            return Ok(true); // needs migration
        }
    }

    Err("Il database non è verificabile. Potrebbe essere stato modificato o è di una versione incompatibile.".to_string())
}

// ═══════════════════════════════════════════════════════════
//  FASE 4: Per-Record Encryption + Index
// ═══════════════════════════════════════════════════════════

/// Encrypt a single record/block with DEK.
/// PERF: compresses with zstd level 3 before encryption (~60-80% size reduction on legal text).
pub(crate) fn encrypt_record(dek: &[u8], plaintext: &[u8]) -> Result<EncryptedBlock, String> {
    if dek.len() != 32 {
        return Err("Invalid DEK length: expected 32 bytes".into());
    }
    // PERF: compress before encrypt (safe — no compression oracle in LexFlow)
    let to_encrypt =
        zstd::encode_all(plaintext, 3).map_err(|e| format!("Compression failed: {}", e))?;

    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(dek));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let ciphertext_with_tag = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &to_encrypt,
                aad: b"LEXFLOW-RECORD",
            },
        )
        .map_err(|_| "Record encryption failed")?;
    // AES-GCM appends 16-byte tag to ciphertext
    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_start];
    let tag = &ciphertext_with_tag[tag_start..];
    Ok(EncryptedBlock {
        iv: B64.encode(nonce_bytes),
        tag: B64.encode(tag),
        data: B64.encode(ciphertext),
        compressed: true,
    })
}

/// Decrypt a single record/block with DEK.
///
/// Returns `Zeroizing<Vec<u8>>` so plaintext is wiped on drop. Callers that
/// need to persist the bytes beyond the local scope should clone via
/// `.to_vec()` (which loses zeroization) or keep the wrapper alive.
pub(crate) fn decrypt_record(
    dek: &[u8],
    block: &EncryptedBlock,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if dek.len() != 32 {
        return Err("Invalid DEK length: expected 32 bytes".into());
    }
    // FIX-5 (BE-5-MED): hard cap on ciphertext length (100 MiB) to prevent
    // pathological allocation / DoS via a tampered EncryptedBlock.
    const MAX_CT_LEN: usize = 100 * 1024 * 1024;
    if block.data.len() > MAX_CT_LEN {
        return Err("ciphertext too large".to_string());
    }
    let iv = B64.decode(&block.iv).map_err(|_| "Invalid record IV")?;
    let tag = B64.decode(&block.tag).map_err(|_| "Invalid record tag")?;
    let data = B64.decode(&block.data).map_err(|_| "Invalid record data")?;
    if data.len() > MAX_CT_LEN {
        return Err("ciphertext too large".to_string());
    }
    if iv.len() != NONCE_LEN {
        return Err("Record IV length mismatch".into());
    }
    if tag.len() != 16 {
        return Err(format!(
            "Record tag length invalid ({} bytes, expected 16)",
            tag.len()
        ));
    }
    // Reconstruct ciphertext+tag for AES-GCM
    let mut ct_with_tag = data;
    ct_with_tag.extend_from_slice(&tag);
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(dek));
    let decrypted = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: ct_with_tag.as_slice(),
                    aad: b"LEXFLOW-RECORD",
                },
            )
            .map_err(|_| {
                "Impossibile leggere questo fascicolo. Il dato potrebbe essere danneggiato."
                    .to_string()
            })?,
    );

    // PERF: decompress if compressed flag is set
    if block.compressed {
        // LOW FIX: cap decompression output at 100MB to prevent zip-bomb OOM
        // (data is AES-GCM-SIV authenticated, so attacker needs DEK — defense-in-depth)
        let mut decoder = zstd::Decoder::new(decrypted.as_slice())
            .map_err(|e| format!("Decompression init failed: {}", e))?;
        let mut output = Zeroizing::new(Vec::new());
        use std::io::Read;
        decoder
            .by_ref()
            .take(100 * 1024 * 1024) // 100MB cap
            .read_to_end(&mut output)
            .map_err(|e| format!("Decompression failed: {}", e))?;
        Ok(output)
    } else {
        Ok(decrypted)
    }
}

/// Encrypt the index with DEK.
pub(crate) fn encrypt_index(dek: &[u8], entries: &[IndexEntry]) -> Result<EncryptedBlock, String> {
    let plaintext = serde_json::to_vec(entries).map_err(|e| format!("Index serialize: {}", e))?;
    encrypt_record(dek, &plaintext)
}

/// Decrypt the index. Returns an empty Vec if the block is empty (new/migrated vault).
///
/// The returned plaintext may be a bare `Vec<IndexEntry>` (legacy V4/V5 shape
/// or pre-BE-5-HIGH-2 V6) or a `V6Index { entries, record_manifest, … }`
/// wrapper. We try the wrapper first and fall back to the bare list, so all
/// in-memory `vault.index` blocks (which are written via `encrypt_index` —
/// always bare entries) deserialize correctly.
pub(crate) fn decrypt_index(dek: &[u8], block: &EncryptedBlock) -> Result<Vec<IndexEntry>, String> {
    if block.iv.is_empty() {
        return Ok(Vec::new());
    }
    let plaintext = decrypt_record(dek, block)?;
    // Tolerant deserialization: V6Index OR Vec<IndexEntry>.
    if let Ok(v6) = serde_json::from_slice::<V6Index>(&plaintext) {
        return Ok(v6.entries);
    }
    serde_json::from_slice(&plaintext).map_err(|e| format!("Index deserialize: {}", e))
}

// ═══════════════════════════════════════════════════════════
//  FASE 5: Record Versioning + Key Rotation
// ═══════════════════════════════════════════════════════════

/// Append a new version to a record entry, capping at MAX_RECORD_VERSIONS.
pub(crate) fn append_record_version(
    entry: &mut RecordEntry,
    dek: &[u8],
    plaintext: &[u8],
) -> Result<(), String> {
    let block = encrypt_record(dek, plaintext)?;
    let new_v = entry.current.checked_add(1).unwrap_or(entry.current); // saturate instead of wrap
    let version = RecordVersion {
        v: new_v,
        ts: chrono::Utc::now().to_rfc3339(),
        iv: block.iv,
        tag: block.tag,
        data: block.data,
        compressed: block.compressed,
        format: Some("msgpack".to_string()),
    };
    entry.versions.push(version);
    entry.current = new_v;
    // Cap at MAX_RECORD_VERSIONS — drop oldest
    if entry.versions.len() > MAX_RECORD_VERSIONS {
        let excess = entry.versions.len() - MAX_RECORD_VERSIONS;
        entry.versions.drain(0..excess);
    }
    Ok(())
}

/// Get the current version's decrypted data.
///
/// Returns `Zeroizing<Vec<u8>>` so plaintext is wiped on drop. See
/// `decrypt_record` for ownership notes.
pub(crate) fn read_current_version(
    entry: &RecordEntry,
    dek: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let version = entry
        .versions
        .iter()
        .find(|v| v.v == entry.current)
        .ok_or("Current version not found in record")?;
    let block = EncryptedBlock {
        iv: version.iv.clone(),
        tag: version.tag.clone(),
        data: version.data.clone(),
        compressed: version.compressed,
    };
    decrypt_record(dek, &block)
}

/// Check if key rotation is needed (>interval_days or >max_writes).
pub(crate) fn needs_rotation(rotation: &RotationMeta) -> bool {
    if rotation.writes >= rotation.max_writes {
        return true;
    }
    if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&rotation.created) {
        let age_days = (chrono::Utc::now() - created.with_timezone(&chrono::Utc))
            .num_days()
            .unsigned_abs();
        if age_days >= rotation.interval_days as u64 {
            return true;
        }
    }
    false
}

/// Perform key rotation: generate new DEK, re-encrypt all records + index.
/// Called when needs_rotation() returns true (>90 days or >10k writes).
/// Triggered automatically at unlock in vault.rs.
pub(crate) fn rotate_dek(vault: &mut VaultData, kek: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    // Unwrap old DEK
    let old_dek = unwrap_dek(kek, &vault.wrapped_dek, &vault.dek_iv)?;

    // Generate new DEK
    let new_dek = generate_dek();

    // Re-encrypt all records with new DEK
    for (_id, entry) in vault.records.iter_mut() {
        for version in entry.versions.iter_mut() {
            let block = EncryptedBlock {
                iv: version.iv.clone(),
                tag: version.tag.clone(),
                data: version.data.clone(),
                compressed: version.compressed,
            };
            // `decrypt_record` already returns `Zeroizing<Vec<u8>>` (BE-5-L-5).
            let plaintext = decrypt_record(&old_dek, &block)?;
            let new_block = encrypt_record(&new_dek, &plaintext)?;
            version.iv = new_block.iv;
            version.tag = new_block.tag;
            version.data = new_block.data;
            version.compressed = new_block.compressed;
        }
    }

    // Re-encrypt index (entries contain titles/tags — lower sensitivity than record content)
    let index_entries = decrypt_index(&old_dek, &vault.index)?;
    vault.index = encrypt_index(&new_dek, &index_entries)?;
    drop(index_entries); // explicit drop to minimize plaintext lifetime

    // Wrap new DEK with KEK
    let (wrapped, iv) = wrap_dek(kek, &new_dek)?;
    vault.wrapped_dek = wrapped;
    vault.dek_iv = iv;

    // Update rotation metadata
    vault.rotation = RotationMeta {
        created: chrono::Utc::now().to_rfc3339(),
        interval_days: vault.rotation.interval_days,
        writes: 0,
        max_writes: vault.rotation.max_writes,
    };

    // Recompute header MAC
    vault.header_mac = compute_header_mac(kek, vault);

    Ok(new_dek)
}

// ═══════════════════════════════════════════════════════════
//  High-level Vault I/O
// ═══════════════════════════════════════════════════════════

/// Serialize VaultData to bytes for disk storage.
pub fn serialize_vault(vault: &VaultData) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(vault).map_err(|e| format!("Vault serialize: {}", e))?;
    let mut out = VAULT_MAGIC.to_vec();
    out.extend_from_slice(&json);
    Ok(out)
}

/// Deserialize VaultData from bytes read from disk.
pub fn deserialize_vault(data: &[u8]) -> Result<VaultData, String> {
    // FIX-5 (BE-5-MED): hard cap on raw vault input (500 MiB) to avoid pathological
    // allocations during JSON parsing on tampered/oversized files.
    const MAX_VAULT_LEN: usize = 500 * 1024 * 1024;
    if data.len() > MAX_VAULT_LEN {
        return Err("vault file too large".into());
    }
    // Accept both current and legacy V4 magic
    let magic_len = if data.starts_with(VAULT_MAGIC) {
        VAULT_MAGIC.len()
    } else if data.starts_with(VAULT_MAGIC_V4) {
        VAULT_MAGIC_V4.len()
    } else {
        return Err("Not a valid vault file".into());
    };
    let json_bytes = &data[magic_len..];
    serde_json::from_slice(json_bytes).map_err(|e| format!("Vault deserialize: {}", e))
}

/// Create a brand new v4 vault from password. Returns (vault, dek).
pub fn create_vault(password: &str) -> Result<(VaultData, Zeroizing<Vec<u8>>), String> {
    // Benchmark and generate KDF params
    let mut kdf = benchmark_argon2_params();
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    kdf.salt = B64.encode(salt);

    // Derive KEK
    let kek = derive_kek(password, &kdf)?;

    // Generate DEK
    let dek = generate_dek();

    // Wrap DEK
    let (wrapped_dek, dek_iv) = wrap_dek(&kek, &dek)?;

    // Create empty index
    let empty_index: Vec<IndexEntry> = vec![];
    let index = encrypt_index(&dek, &empty_index)?;

    // Build vault
    let mut vault = VaultData {
        version: CURRENT_VAULT_VERSION,
        kdf,
        wrapped_dek,
        dek_iv,
        dek_alg: "aes-256-gcm-siv".to_string(),
        header_mac: String::new(),
        mac_version: Some(CURRENT_MAC_VERSION),
        wrapped_dek_recovery: None,
        recovery_iv: None,
        recovery_salt: None,
        rotation: RotationMeta {
            created: chrono::Utc::now().to_rfc3339(),
            interval_days: 90,
            writes: 0,
            max_writes: 10000,
        },
        index,
        records: BTreeMap::new(),
    };

    // Compute header MAC
    vault.header_mac = compute_header_mac(&kek, &vault);

    Ok((vault, dek))
}

/// Open an existing v4 vault: derive KEK, verify header MAC, unwrap DEK.
/// Anti-rollback: verify write counter against stored maximum.
pub fn open_vault(password: &str, data: &[u8]) -> Result<(VaultData, Zeroizing<Vec<u8>>), String> {
    let mut vault = deserialize_vault(data)?;

    if vault.version != CURRENT_VAULT_VERSION && vault.version != 4 {
        return Err(format!("Unsupported vault version: {}", vault.version));
    }

    // Derive KEK from password + stored params
    let kek = derive_kek(password, &vault.kdf)?;

    // Verify header MAC (constant-time) — supports all past MAC versions
    let needs_mac_migration = verify_header_mac(&kek, &vault)?;

    // Unwrap DEK
    let dek = unwrap_dek(&kek, &vault.wrapped_dek, &vault.dek_iv)?;

    // If MAC was verified with a legacy version, re-compute with current version
    if needs_mac_migration {
        vault.header_mac = compute_header_mac(&kek, &vault);
        vault.mac_version = Some(CURRENT_MAC_VERSION);
        eprintln!(
            "[SECURITY] Vault header MAC migrated to version {}",
            CURRENT_MAC_VERSION
        );
        // Caller (vault.rs) will persist the updated vault on next write
    }

    Ok((vault, dek))
}

// ═══════════════════════════════════════════════════════════
//  FASE 6: Migration v2 → v4
// ═══════════════════════════════════════════════════════════

/// Detect vault format by examining the first bytes.
pub(crate) fn detect_vault_version(data: &[u8]) -> u32 {
    if data.starts_with(VAULT_MAGIC) {
        return CURRENT_VAULT_VERSION;
    }
    if data.starts_with(VAULT_MAGIC_V4) {
        return 4;
    }
    if data.starts_with(crate::constants::VAULT_MAGIC) {
        return 2;
    }
    0 // unknown
}

// v2 migration removed — v2 vaults no longer supported

// ─── Record metadata helpers (used by migration + vault write) ───

/// Extract a human-readable title from a record (pub for vault.rs).
pub(crate) fn extract_record_title_pub(item: &serde_json::Value, field: &str) -> String {
    extract_record_title(item, field)
}

/// Extract tags from a record (pub for vault.rs).
pub(crate) fn extract_record_tags_pub(item: &serde_json::Value, field: &str) -> Vec<String> {
    extract_record_tags(item, field)
}

/// V5 PERF: Extract summary fields for lazy list rendering.
/// Returns a JSON object with type-specific metadata so the frontend
/// can render complete lists WITHOUT decrypting each record.
// TODO(audit:BE-5-L-6): consider truncating PII fields (e.g. show only first
// 3 chars + "***") for `email`, `phone`, `fiscal_code` to limit in-memory
// exposure of summaries. Currently full values are copied into a non-zeroizable
// serde_json::Value.
pub(crate) fn extract_record_summary(
    item: &serde_json::Value,
    field: &str,
) -> Option<serde_json::Value> {
    let s = |key: &str| {
        item.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    match field {
        "practices" => Some(serde_json::json!({
            "client": s("client"),
            "counterparty": s("counterparty"),
            "object": s("object"),
            "court": s("court"),
            "type": s("type"),
            "status": s("status"),
            "code": s("code"),
            "createdAt": s("createdAt"),
        })),
        "contacts" => Some(serde_json::json!({
            "name": s("name"),
            "role": s("role"),
            "email": s("email"),
            "phone": s("phone"),
            "type": s("type"),
        })),
        "agenda" => Some(serde_json::json!({
            "title": s("title"),
            "date": s("date"),
            "time": s("time"),
            "type": s("type"),
            "completed": item.get("completed").and_then(|v| v.as_bool()).unwrap_or(false),
        })),
        "timeLogs" => Some(serde_json::json!({
            "description": s("description"),
            "date": s("date"),
            "minutes": item.get("minutes").and_then(|v| v.as_u64()).unwrap_or(0),
            "practiceId": s("practiceId"),
        })),
        "invoices" => Some(serde_json::json!({
            "number": s("number"),
            "client": s("client"),
            "status": s("status"),
            "total": item.get("total").and_then(|v| v.as_f64()).unwrap_or(0.0),
        })),
        _ => None,
    }
}

fn extract_record_title(item: &serde_json::Value, field: &str) -> String {
    match field {
        "practices" => {
            let client = item.get("client").and_then(|v| v.as_str()).unwrap_or("");
            let object = item.get("object").and_then(|v| v.as_str()).unwrap_or("");
            if object.is_empty() {
                client.to_string()
            } else {
                format!("{} — {}", client, object)
            }
        }
        "agenda" => item
            .get("title")
            .or_else(|| item.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or("(agenda)")
            .to_string(),
        "contacts" => item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(contatto)")
            .to_string(),
        "timeLogs" => {
            let date = item.get("date").and_then(|v| v.as_str()).unwrap_or("");
            let desc = item
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!("{} {}", date, desc)
        }
        "invoices" => {
            let num = item.get("number").and_then(|v| v.as_str()).unwrap_or("");
            let client = item
                .get("clientName")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!("#{} {}", num, client)
        }
        _ => "(record)".to_string(),
    }
}

fn extract_record_tags(item: &serde_json::Value, field: &str) -> Vec<String> {
    let mut tags = vec![field.to_string()];
    if field == "practices" {
        if let Some(status) = item.get("status").and_then(|v| v.as_str()) {
            tags.push(format!("status:{}", status));
        }
        if let Some(ptype) = item.get("type").and_then(|v| v.as_str()) {
            tags.push(format!("type:{}", ptype));
        }
    }
    tags
}

// ═══════════════════════════════════════════════════════════
//  Recovery Key
// ═══════════════════════════════════════════════════════════

/// Generate a human-readable recovery key and wrap the DEK with it.
/// Returns the display string (e.g., "KBQW-E3TF-MZXG-K3DP") to show to user ONCE.
pub(crate) fn generate_recovery_key(vault: &mut VaultData, dek: &[u8]) -> Result<String, String> {
    // Generate 16 random bytes for recovery key
    let mut recovery_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut recovery_bytes);

    // Format as base32 groups: XXXX-XXXX-XXXX-XXXX
    // FIX-7 (BE-T2 #6): wrap intermediate base32-encoded form in Zeroizing.
    // `display` is returned to the caller — schema-changing the return type to
    // Zeroizing<String> would break callers (vault.rs), so at least the local
    // `encoded` is zeroized on drop.
    // TODO(audit:BE-T2-#6): change return type to Zeroizing<String> end-to-end.
    let encoded = Zeroizing::new(base32_encode(&recovery_bytes));
    let display = encoded
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or("????"))
        .collect::<Vec<_>>()
        .join("-");

    // Derive recovery KEK from recovery bytes
    let mut recovery_salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut recovery_salt);

    // FIX-10: wrap hex-encoded recovery key in Zeroizing for proper zeroization on drop
    let mut recovery_hex = Zeroizing::new(hex::encode(recovery_bytes));
    // FIX A2: zeroize recovery_bytes and recovery_hex after use
    recovery_bytes.zeroize();

    // OWASP 2024 stronger profile (was 16384, now 65536)
    // TODO(audit:BE-5-HIGH-1): persist recovery_kdf params in VaultData schema for adaptive recovery
    let recovery_kek = derive_kek_raw(&recovery_hex, &recovery_salt, 65536, 3, 1)?;
    // Zeroize hex string after KEK derivation (no longer needed)
    recovery_hex.zeroize();

    // Wrap DEK with recovery KEK
    let (wrapped, iv) = wrap_dek(&recovery_kek, dek)?;

    vault.wrapped_dek_recovery = Some(wrapped);
    vault.recovery_iv = Some(iv);
    vault.recovery_salt = Some(B64.encode(recovery_salt));

    Ok(display)
}

/// Attempt to unlock vault using recovery key.
pub(crate) fn open_vault_with_recovery(
    recovery_display: &str,
    data: &[u8],
) -> Result<(VaultData, Zeroizing<Vec<u8>>), String> {
    let vault = deserialize_vault(data)?;
    if vault.version != CURRENT_VAULT_VERSION && vault.version != 4 {
        return Err("Unsupported vault version".into());
    }

    let wrapped = vault
        .wrapped_dek_recovery
        .as_ref()
        .ok_or("No recovery key configured for this vault")?;
    let iv = vault.recovery_iv.as_ref().ok_or("Missing recovery IV")?;
    let salt_b64 = vault
        .recovery_salt
        .as_ref()
        .ok_or("Missing recovery salt")?;

    // Decode recovery key from display format
    let clean: String = recovery_display
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .collect();
    let recovery_bytes =
        Zeroizing::new(base32_decode(&clean).ok_or("Invalid recovery key format")?);

    let recovery_salt = B64.decode(salt_b64).map_err(|_| "Invalid recovery salt")?;

    // FIX-10: wrap hex-encoded recovery key in Zeroizing for proper zeroization on drop
    let mut recovery_hex = Zeroizing::new(hex::encode(&*recovery_bytes));
    // OWASP 2024 stronger profile (was 16384, now 65536)
    // TODO(audit:BE-5-HIGH-1): persist recovery_kdf params in VaultData schema for adaptive recovery
    let recovery_kek = derive_kek_raw(&recovery_hex, &recovery_salt, 65536, 3, 1)?;
    recovery_hex.zeroize();

    let dek = unwrap_dek(&recovery_kek, wrapped, iv)?;

    // SECURITY FIX: verify vault integrity via DEK.
    // We can't verify header_mac (computed with password KEK, which we don't have).
    // Instead, try decrypting the index — if it succeeds, the DEK is valid and the
    // vault data is intact. AES-GCM-SIV authentication guarantees integrity.
    // TODO(audit:BE-5-MED-6): add header_mac_recovery field (HMAC keyed by recovery_KEK)
    // to VaultData schema, persist during generate_recovery_key, and verify here for
    // explicit header tamper detection on the recovery path.
    let _ = decrypt_index(&dek, &vault.index).map_err(|_| {
        "Recovery failed: vault data integrity check failed. The vault may be corrupted."
    })?;

    Ok((vault, dek))
}

/// Simple base32 encode (RFC 4648, no padding)
pub(crate) fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        buffer <<= 5 - bits;
        result.push(ALPHABET[(buffer & 0x1F) as usize] as char);
    }
    result
}

/// Simple base32 decode (RFC 4648)
pub(crate) fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;
    for c in s.to_uppercase().chars() {
        let val = ALPHABET.iter().position(|&b| b == c as u8)? as u64;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }
    Some(result)
}

// ═══════════════════════════════════════════════════════════
//  V6: SPLIT-FILE VAULT LAYOUT
// ═══════════════════════════════════════════════════════════

use crate::constants::{VAULT_DIR, VAULT_HEADER_FILE, VAULT_INDEX_FILE, VAULT_RECORDS_DIR};

/// V6 header: everything except index and records (serialized as JSON).
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultHeader {
    pub version: u32,
    pub kdf: KdfParams,
    pub wrapped_dek: String,
    pub dek_iv: String,
    pub dek_alg: String,
    pub header_mac: String,
    #[serde(default)]
    pub mac_version: Option<u32>,
    pub rotation: RotationMeta,
    #[serde(default)]
    pub wrapped_dek_recovery: Option<String>,
    #[serde(default)]
    pub recovery_iv: Option<String>,
    #[serde(default)]
    pub recovery_salt: Option<String>,
    /// V6 format marker
    #[serde(default)]
    pub split_format: Option<u32>,
}

// FIX-12 (BE-T2): custom Debug that redacts secret fields.
impl std::fmt::Debug for VaultHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultHeader")
            .field("version", &self.version)
            .field("kdf", &self.kdf)
            .field("wrapped_dek", &"[REDACTED]")
            .field("dek_iv", &"[REDACTED]")
            .field("dek_alg", &self.dek_alg)
            .field("header_mac", &"[REDACTED]")
            .field("mac_version", &self.mac_version)
            .field("rotation", &self.rotation)
            .field("wrapped_dek_recovery", &"[REDACTED]")
            .field("recovery_iv", &"[REDACTED]")
            .field("recovery_salt", &"[REDACTED]")
            .field("split_format", &self.split_format)
            .finish()
    }
}

impl VaultHeader {
    /// Convert from monolithic VaultData (drop index/records)
    pub fn from_vault(v: &VaultData) -> Self {
        Self {
            version: v.version,
            kdf: v.kdf.clone(),
            wrapped_dek: v.wrapped_dek.clone(),
            dek_iv: v.dek_iv.clone(),
            dek_alg: v.dek_alg.clone(),
            header_mac: v.header_mac.clone(),
            mac_version: v.mac_version,
            rotation: v.rotation.clone(),
            wrapped_dek_recovery: v.wrapped_dek_recovery.clone(),
            recovery_iv: v.recovery_iv.clone(),
            recovery_salt: v.recovery_salt.clone(),
            split_format: Some(6),
        }
    }

    /// Convert back to VaultData by attaching index + records
    pub fn into_vault(
        self,
        index: EncryptedBlock,
        records: BTreeMap<String, RecordEntry>,
    ) -> VaultData {
        VaultData {
            version: self.version,
            kdf: self.kdf,
            wrapped_dek: self.wrapped_dek,
            dek_iv: self.dek_iv,
            dek_alg: self.dek_alg,
            header_mac: self.header_mac,
            mac_version: self.mac_version,
            rotation: self.rotation,
            wrapped_dek_recovery: self.wrapped_dek_recovery,
            recovery_iv: self.recovery_iv,
            recovery_salt: self.recovery_salt,
            index,
            records,
        }
    }
}

/// Check if vault uses V6 split format (directory exists)
pub fn is_split_vault(data_dir: &std::path::Path) -> bool {
    data_dir.join(VAULT_DIR).join(VAULT_HEADER_FILE).exists()
}

/// Write vault in V6 split format with per-record SHA-256 manifest.
///
/// File-level integrity (BE-5-HIGH-2 / audit:HIGH F2): every record file
/// receives a SHA-256 entry in the manifest stored inside the encrypted index.
/// On read, `read_split_vault` recomputes the hash for each manifested file
/// and refuses to load on mismatch — preventing silent tamper / rollback /
/// deletion of individual `record_<id>.enc` files that would otherwise go
/// undetected because the V6 layout has no file-level MAC.
pub fn write_split_vault(
    data_dir: &std::path::Path,
    vault: &VaultData,
    dek: &[u8],
) -> Result<(), String> {
    use sha2::Digest;

    let vault_dir = data_dir.join(VAULT_DIR);
    let records_dir = vault_dir.join(VAULT_RECORDS_DIR);
    std::fs::create_dir_all(&records_dir)
        .map_err(|_| "Impossibile creare la cartella del database.".to_string())?;

    // 1. Write header
    let header = VaultHeader::from_vault(vault);
    let header_bytes = serde_json::to_vec(&header)
        .map_err(|_| "Errore nella serializzazione dell'header.".to_string())?;
    let header_enc = crate::crypto::encrypt_data(dek, &header_bytes)?;
    crate::io::atomic_write_with_sync(&vault_dir.join(VAULT_HEADER_FILE), &header_enc)?;

    // 2. Write each record as a separate file FIRST, building the manifest as
    //    we go — the manifest must reflect the bytes that actually landed on
    //    disk (so we hash post-encryption ciphertext).
    let mut manifest: BTreeMap<String, String> = BTreeMap::new();
    for (id, entry) in &vault.records {
        let rec_bytes = serde_json::to_vec(entry)
            .map_err(|_| "Errore nella serializzazione del record.".to_string())?;
        let rec_enc = crate::crypto::encrypt_data(dek, &rec_bytes)?;
        let safe_id = id.replace(['/', '\\', '.'], "_");
        crate::io::atomic_write_with_sync(&records_dir.join(format!("{}.enc", safe_id)), &rec_enc)?;
        // SHA-256 over the on-disk ciphertext bytes — this is what read_split_vault
        // will hash to verify integrity.
        let digest = sha2::Sha256::digest(&rec_enc);
        manifest.insert(id.clone(), hex::encode(digest));
    }

    // 3. Decrypt existing entries from the in-memory index block (so we can
    //    rebuild the V6 wrapper around them with the freshly computed manifest).
    //    This is cheap: the index is small and DEK-encrypted with the same key.
    let entries = decrypt_index(dek, &vault.index)?;
    let v6_index = V6Index {
        entries,
        record_manifest: manifest,
        manifest_version: CURRENT_MANIFEST_VERSION,
    };
    let index_bytes = serde_json::to_vec(&v6_index)
        .map_err(|_| "Errore nella serializzazione dell'indice.".to_string())?;
    let index_enc = crate::crypto::encrypt_data(dek, &index_bytes)?;
    crate::io::atomic_write_with_sync(&vault_dir.join(VAULT_INDEX_FILE), &index_enc)?;

    // 4. Remove records that no longer exist
    if let Ok(entries) = std::fs::read_dir(&records_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".enc") {
                if !vault.records.contains_key(id) {
                    let _ = crate::security::secure_delete_file(&entry.path());
                }
            }
        }
    }

    Ok(())
}

/// Read vault from V6 split format with per-record SHA-256 manifest verification.
///
/// Integrity check (BE-5-HIGH-2 / audit:HIGH F2): for every record_id listed
/// in the manifest, recompute SHA-256 of the on-disk file bytes and compare.
/// Mismatch / missing → hard error. Records on disk that are NOT in the
/// manifest are treated as orphans (warning only, skipped).
///
/// Backward-compat: vaults written before manifest support set
/// `manifest_version == 0`; in that case the integrity check is skipped (with
/// a warning eprintln) and the next save migrates the vault by populating the
/// manifest.
pub fn read_split_vault(data_dir: &std::path::Path, dek: &[u8]) -> Result<VaultData, String> {
    use sha2::Digest;

    let vault_dir = data_dir.join(VAULT_DIR);

    // 1. Read + decrypt header
    let header_enc =
        crate::io::safe_bounded_read(&vault_dir.join(VAULT_HEADER_FILE), 10 * 1024 * 1024)?;
    let header_bytes = crate::crypto::decrypt_data(dek, &header_enc)?;
    let header: VaultHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| "Impossibile leggere l'header del database.".to_string())?;

    // 2. Read + decrypt index (now wrapped in V6Index with optional manifest)
    let index_path = vault_dir.join(VAULT_INDEX_FILE);
    let records_dir_check = vault_dir.join(VAULT_RECORDS_DIR);
    let (index, v6_index) = if index_path.exists() {
        let index_enc = crate::io::safe_bounded_read(&index_path, 100 * 1024 * 1024)?;
        let index_bytes = crate::crypto::decrypt_data(dek, &index_enc)?;
        // Try V6Index first (has manifest); fall back to legacy bare EncryptedBlock
        // for vaults written before this change.
        if let Ok(v6) = serde_json::from_slice::<V6Index>(&index_bytes) {
            // V6 wrapped form — re-encrypt the entries-only block for the
            // returned VaultData (it does not carry the manifest).
            let entries_block = encrypt_index(dek, &v6.entries)?;
            (entries_block, v6)
        } else if let Ok(legacy_block) = serde_json::from_slice::<EncryptedBlock>(&index_bytes) {
            // Legacy: index file historically stored a serialized EncryptedBlock
            // (an earlier-still iteration). Treat as no manifest.
            eprintln!(
                "[SECURITY] V6 index in legacy bare-EncryptedBlock format — manifest integrity check SKIPPED. Will upgrade on next save."
            );
            (
                legacy_block,
                V6Index {
                    entries: Vec::new(),
                    record_manifest: BTreeMap::new(),
                    manifest_version: 0,
                },
            )
        } else {
            return Err("Impossibile leggere l'indice del database.".to_string());
        }
    } else {
        // FIX-4 (BE-5-MED): if records exist on disk but the index file is missing,
        // this is NOT a fresh vault — refuse to load to avoid masking tampering or
        // accidental deletion as "empty vault".
        let has_records = records_dir_check
            .read_dir()
            .map(|mut it| {
                it.any(|entry| {
                    entry
                        .ok()
                        .and_then(|e| {
                            e.file_name()
                                .to_string_lossy()
                                .ends_with(".enc")
                                .then_some(())
                        })
                        .is_some()
                })
            })
            .unwrap_or(false);
        if has_records {
            return Err("vault index missing but records found — possible tampering".to_string());
        }
        // INTENTIONAL: For new vaults or vaults migrated from monolithic format,
        // the index file may not exist yet. An empty EncryptedBlock signals
        // "no index on disk" — callers MUST check `iv.is_empty()` before
        // attempting decryption (decrypt_index would fail on empty IV/data).
        (
            EncryptedBlock {
                iv: String::new(),
                tag: String::new(),
                data: String::new(),
                compressed: false,
            },
            V6Index::default(),
        )
    };

    // 3. Read each record file. When the manifest is authoritative (manifest_version
    //    >= 1), verify SHA-256 of every manifested file before decrypting it. Files
    //    not in the manifest are loaded best-effort but logged as orphans.
    let manifest_active = v6_index.manifest_version >= CURRENT_MANIFEST_VERSION
        && !v6_index.record_manifest.is_empty();
    if v6_index.manifest_version == 0 {
        eprintln!(
            "[SECURITY] V6 split-vault has no record manifest (manifest_version=0). Integrity check SKIPPED — manifest will be populated on next save."
        );
    }

    let mut records = BTreeMap::new();
    let mut corrupted_record_ids: Vec<String> = Vec::new();
    let records_dir = vault_dir.join(VAULT_RECORDS_DIR);
    let mut on_disk_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    if records_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&records_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(id) = name.strip_suffix(".enc") {
                    on_disk_ids.insert(id.to_string());
                    let rec_enc = crate::io::safe_bounded_read(&entry.path(), 50 * 1024 * 1024)?;

                    // BE-5-HIGH-2: when the manifest is authoritative, verify the
                    // file's SHA-256 against the expected digest BEFORE decrypting.
                    // Mismatch = hard error (refuses to load the entire vault).
                    if manifest_active {
                        match v6_index.record_manifest.get(id) {
                            Some(expected_hex) => {
                                let actual = sha2::Sha256::digest(&rec_enc);
                                let actual_hex = hex::encode(actual);
                                if !constant_time_hex_eq(expected_hex, &actual_hex) {
                                    return Err(format!(
                                        "record file {} integrity check failed",
                                        id
                                    ));
                                }
                            }
                            None => {
                                // Orphan: file on disk not referenced by manifest.
                                // Log a warning and skip (do NOT load — could be
                                // attacker-planted file).
                                eprintln!(
                                    "[SECURITY] ORPHAN_RECORD id={} (not in manifest, skipping)",
                                    id
                                );
                                continue;
                            }
                        }
                    }

                    match crate::crypto::decrypt_data(dek, &rec_enc) {
                        Ok(rec_bytes) => {
                            if let Ok(entry_data) =
                                serde_json::from_slice::<RecordEntry>(&rec_bytes)
                            {
                                records.insert(id.to_string(), entry_data);
                            } else {
                                // L12: Track corrupted record IDs for structured reporting
                                eprintln!(
                                    "[SECURITY] CORRUPTED_RECORD id={} reason=invalid_structure file={}",
                                    id, name
                                );
                                corrupted_record_ids.push(id.to_string());
                            }
                        }
                        Err(_) => {
                            // L12: Track corrupted record IDs for structured reporting
                            eprintln!(
                                "[SECURITY] CORRUPTED_RECORD id={} reason=decryption_failed file={}",
                                id, name
                            );
                            corrupted_record_ids.push(id.to_string());
                        }
                    }
                }
            }
        }
    }
    if !corrupted_record_ids.is_empty() {
        eprintln!(
            "[SECURITY] VAULT_LOAD_SUMMARY: {} corrupted records skipped: [{}]",
            corrupted_record_ids.len(),
            corrupted_record_ids.join(", ")
        );
    }

    // BE-5-HIGH-2: when the manifest is authoritative, every manifested ID
    // must be present on disk. Missing file → hard error (rollback / deletion
    // attack).
    if manifest_active {
        for id in v6_index.record_manifest.keys() {
            if !on_disk_ids.contains(id) {
                return Err(format!("record file {} missing (manifest expected it)", id));
            }
        }
    }

    Ok(header.into_vault(index, records))
}

/// Constant-time hex comparison to avoid timing oracles when checking
/// SHA-256 manifest entries. Returns false if lengths differ.
fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..ab.len() {
        diff |= ab[i] ^ bb[i];
    }
    diff == 0
}

/// Migrate monolithic vault.lex to V6 split format
pub fn migrate_to_split(
    data_dir: &std::path::Path,
    vault: &VaultData,
    dek: &[u8],
) -> Result<(), String> {
    eprintln!("[MIGRATION] Migrating vault from monolithic to V6 split format...");

    // Write split format
    write_split_vault(data_dir, vault, dek)?;

    // Rename old monolithic file as backup (don't delete — keep for 30 days)
    let old_path = data_dir.join(crate::constants::VAULT_FILE);
    if old_path.exists() {
        let backup = data_dir.join("vault.lex.v4-backup");
        let _ = std::fs::rename(&old_path, &backup);
        eprintln!("[MIGRATION] Old vault.lex backed up as vault.lex.v4-backup");
    }

    eprintln!(
        "[MIGRATION] V6 split migration complete. {} records.",
        vault.records.len()
    );
    Ok(())
}

/// Write a single record file (V6 incremental save)
#[allow(dead_code)]
pub fn write_single_record(
    data_dir: &std::path::Path,
    record_id: &str,
    entry: &RecordEntry,
    dek: &[u8],
) -> Result<(), String> {
    let records_dir = data_dir.join(VAULT_DIR).join(VAULT_RECORDS_DIR);
    std::fs::create_dir_all(&records_dir)
        .map_err(|_| "Impossibile creare la cartella records.".to_string())?;
    let rec_bytes =
        serde_json::to_vec(entry).map_err(|_| "Errore serializzazione record.".to_string())?;
    let rec_enc = crate::crypto::encrypt_data(dek, &rec_bytes)?;
    let safe_id = record_id.replace(['/', '\\', '.'], "_");
    crate::io::atomic_write_with_sync(&records_dir.join(format!("{}.enc", safe_id)), &rec_enc)
}

/// Write index file only (V6 incremental)
#[allow(dead_code)]
pub fn write_split_index(
    data_dir: &std::path::Path,
    index: &EncryptedBlock,
    dek: &[u8],
) -> Result<(), String> {
    let vault_dir = data_dir.join(VAULT_DIR);
    let index_bytes =
        serde_json::to_vec(index).map_err(|_| "Errore serializzazione indice.".to_string())?;
    let index_enc = crate::crypto::encrypt_data(dek, &index_bytes)?;
    crate::io::atomic_write_with_sync(&vault_dir.join(VAULT_INDEX_FILE), &index_enc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dek() -> Zeroizing<Vec<u8>> {
        let mut dek = Zeroizing::new(vec![0u8; AES_KEY_LEN]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut dek);
        dek
    }

    /// BE-5-L-5: `decrypt_record` must return Zeroizing<Vec<u8>> so plaintext
    /// is wiped on drop. This test only checks the type contract via .as_slice().
    #[test]
    fn test_decrypt_record_returns_zeroizing() {
        let dek = fresh_dek();
        let plaintext = b"sensitive legal data";
        let block = encrypt_record(&dek, plaintext).unwrap();
        let decrypted: Zeroizing<Vec<u8>> = decrypt_record(&dek, &block).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    /// BE-5-L-5: `read_current_version` must also return Zeroizing.
    #[test]
    fn test_read_current_version_returns_zeroizing() {
        let dek = fresh_dek();
        let mut entry = RecordEntry {
            versions: Vec::new(),
            current: 0,
        };
        append_record_version(&mut entry, &dek, b"v1 payload").unwrap();
        let pt: Zeroizing<Vec<u8>> = read_current_version(&entry, &dek).unwrap();
        assert_eq!(pt.as_slice(), b"v1 payload");
    }

    /// BE-5-HIGH-2: V6Index round-trips with `deny_unknown_fields` so it does
    /// NOT accidentally swallow a legacy bare `EncryptedBlock` JSON.
    #[test]
    fn test_v6_index_rejects_legacy_encrypted_block() {
        let legacy_eb_json =
            br#"{"iv":"AAA","tag":"BBB","data":"CCC","compressed":false}"#.to_vec();
        let parsed: Result<V6Index, _> = serde_json::from_slice(&legacy_eb_json);
        assert!(
            parsed.is_err(),
            "V6Index must NOT deserialize from a legacy EncryptedBlock JSON (would mask legacy detection)"
        );
    }

    /// BE-5-HIGH-2: a fresh V6Index round-trips through serde with manifest preserved.
    #[test]
    fn test_v6_index_roundtrip_with_manifest() {
        let mut manifest = BTreeMap::new();
        manifest.insert("rec1".to_string(), "deadbeef".to_string());
        let v6 = V6Index {
            entries: Vec::new(),
            record_manifest: manifest.clone(),
            manifest_version: CURRENT_MANIFEST_VERSION,
        };
        let bytes = serde_json::to_vec(&v6).unwrap();
        let parsed: V6Index = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.manifest_version, CURRENT_MANIFEST_VERSION);
        assert_eq!(
            parsed.record_manifest.get("rec1").map(|s| s.as_str()),
            Some("deadbeef")
        );
    }

    /// BE-5-HIGH-2: legacy V6 vaults (manifest_version == 0) deserialize via
    /// `serde(default)` and skip integrity checks transparently.
    #[test]
    fn test_v6_index_legacy_zero_version() {
        // Simulate a fresh V6Index with no manifest fields written.
        let bytes = b"{\"entries\":[]}".to_vec();
        let parsed: V6Index = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.manifest_version, 0);
        assert!(parsed.record_manifest.is_empty());
    }

    #[test]
    fn test_constant_time_hex_eq() {
        assert!(constant_time_hex_eq("abc123", "abc123"));
        assert!(!constant_time_hex_eq("abc123", "abc124"));
        assert!(!constant_time_hex_eq("abc", "abcd"));
        assert!(constant_time_hex_eq("", ""));
    }
}
