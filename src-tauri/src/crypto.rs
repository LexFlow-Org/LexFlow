// ═══════════════════════════════════════════════════════════
//  CORE CRYPTO ENGINE — AES-256-GCM-SIV + Argon2id
// ═══════════════════════════════════════════════════════════
//
// MIGRATION NOTE (BE-T2 #9): this module historically used plain AES-256-GCM
// with 96-bit random nonces (birthday-bound at ~2^32 messages per key). The
// V4 envelope (vault_engine.rs) already uses AES-GCM-SIV directly; the V6
// split-vault file path (header.enc / index.json.enc / record_<id>.enc) goes
// through `encrypt_data` / `decrypt_data` here and was therefore inconsistent
// with the documented threat model.
//
// Fix: `encrypt_data` now produces AES-GCM-SIV ciphertexts marked with a
// 1-byte version tag (`0x02`) prepended to the encrypted block. `decrypt_data`
// is backward-compatible: existing V6 vaults written before this change have
// no version tag and are decrypted with legacy AES-256-GCM. On the next write
// they are re-encrypted with AES-GCM-SIV. This migration is fully implicit;
// no schema change is required.

use crate::constants::*;
// `aead` traits (`Aead`, `KeyInit`) are re-exported by both `aes-gcm` and
// `aes-gcm-siv` from the same upstream `aead` crate, so a single import is
// sufficient to call `.encrypt()` / `.decrypt()` / `::new()` on either cipher.
use aes_gcm::Aes256Gcm;
use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Format version tag for AES-GCM-SIV ciphertext blocks (post-migration).
/// Legacy AES-GCM blocks have no tag (detected by absence on read).
const ENC_VERSION_GCM_SIV: u8 = 0x02;

pub(crate) fn derive_secure_key(password: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if salt.len() < SALT_LEN {
        return Err(format!(
            "Salt must be at least {} bytes (got {})",
            SALT_LEN,
            salt.len()
        ));
    }
    let mut key = Zeroizing::new(vec![0u8; AES_KEY_LEN]);
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

/// Encrypt a buffer with AES-256-GCM-SIV (nonce-misuse resistant).
///
/// Layout:
///   VAULT_MAGIC || NONCE(12) || ENC_VERSION_GCM_SIV(1) || CIPHERTEXT+TAG
///
/// The single-byte version tag (`0x02`) marks blocks produced by this
/// (current) code path. Older V6 vaults written before the AES-GCM-SIV
/// migration have no tag; `decrypt_data` recognizes both.
pub(crate) fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Invalid key length: expected 32 bytes".into());
    }
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad: VAULT_MAGIC,
    };
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| "Encryption error")?;
    let mut out = Vec::with_capacity(VAULT_MAGIC.len() + NONCE_LEN + 1 + ciphertext.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.push(ENC_VERSION_GCM_SIV);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a buffer produced by `encrypt_data`.
///
/// Auto-detects the format:
///   - If the byte at offset MAGIC+NONCE is `ENC_VERSION_GCM_SIV` (`0x02`),
///     decrypt the remainder with AES-256-GCM-SIV.
///   - Otherwise, treat the entire post-magic+nonce slice as legacy
///     AES-256-GCM ciphertext (V6 vaults written before the migration).
///
/// Returns `Zeroizing<Vec<u8>>` so plaintext is wiped on drop.
pub(crate) fn decrypt_data(key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    const DECRYPT_ERR: &str = "decryption failed";
    // minimal length: MAGIC + NONCE + 16-byte tag (legacy GCM, no version byte)
    if data.len() < VAULT_MAGIC.len() + NONCE_LEN + 16 {
        #[cfg(debug_assertions)]
        eprintln!("decrypt_data: data too short");
        return Err(DECRYPT_ERR.to_string());
    }
    if !data.starts_with(VAULT_MAGIC) {
        #[cfg(debug_assertions)]
        eprintln!("decrypt_data: magic bytes mismatch");
        return Err(DECRYPT_ERR.to_string());
    }
    if key.len() != 32 {
        #[cfg(debug_assertions)]
        eprintln!("decrypt_data: invalid key length");
        return Err(DECRYPT_ERR.to_string());
    }
    let nonce_slice = &data[VAULT_MAGIC.len()..VAULT_MAGIC.len() + NONCE_LEN];
    let after_nonce = &data[VAULT_MAGIC.len() + NONCE_LEN..];

    // Detect format: AES-GCM-SIV blocks have a leading 0x02 version byte.
    // Legacy AES-GCM blocks start directly with ciphertext|tag bytes — there
    // is a 1/256 chance the legacy first byte happens to equal 0x02; if that
    // happens, the AES-GCM-SIV branch will fail authentication and we fall
    // through to the legacy AES-GCM path. This double-decrypt fallback only
    // runs on the (rare) ambiguous case.
    let try_gcm_siv = !after_nonce.is_empty() && after_nonce[0] == ENC_VERSION_GCM_SIV;
    let plaintext = if try_gcm_siv {
        let ciphertext = &after_nonce[1..];
        if ciphertext.len() >= 16 {
            let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
            match cipher.decrypt(
                Nonce::from_slice(nonce_slice),
                Payload {
                    msg: ciphertext,
                    aad: VAULT_MAGIC,
                },
            ) {
                Ok(pt) => pt,
                Err(_) => {
                    // Fall through to legacy AES-GCM (handles 1/256 byte collision)
                    decrypt_legacy_aes_gcm(key, nonce_slice, after_nonce)?
                }
            }
        } else {
            decrypt_legacy_aes_gcm(key, nonce_slice, after_nonce)?
        }
    } else {
        decrypt_legacy_aes_gcm(key, nonce_slice, after_nonce)?
    };

    Ok(Zeroizing::new(plaintext))
}

/// Legacy AES-256-GCM decrypt path (V6 vaults written before AES-GCM-SIV
/// migration). Returns the same uniform error string as `decrypt_data` to
/// avoid format-oracle leakage.
fn decrypt_legacy_aes_gcm(
    key: &[u8],
    nonce_slice: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, String> {
    const DECRYPT_ERR: &str = "decryption failed";
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce_slice),
            Payload {
                msg: ciphertext_with_tag,
                aad: VAULT_MAGIC,
            },
        )
        .map_err(|_| {
            #[cfg(debug_assertions)]
            eprintln!("decrypt_data: legacy AES-GCM authentication failed");
            DECRYPT_ERR.to_string()
        })
}

pub(crate) fn verify_hash_matches(key: &[u8], stored: &[u8]) -> bool {
    let mut hmac = match <Hmac<Sha256> as Mac>::new_from_slice(key) {
        Ok(h) => h,
        Err(_) => return false,
    };
    hmac.update(b"LEX_VERIFY_DOMAIN_V2");
    hmac.verify_slice(stored).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = vec![0x42u8; 32];
        let plaintext = b"Dati sensibili del fascicolo Rossi vs Bianchi";
        let encrypted = encrypt_data(&key, plaintext).unwrap();
        let decrypted = decrypt_data(&key, &encrypted).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let key = vec![0x42u8; 32];
        let encrypted = encrypt_data(&key, b"").unwrap();
        let decrypted = decrypt_data(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let key = vec![0x42u8; 32];
        let plaintext = vec![0xABu8; 1_000_000]; // 1MB
        let encrypted = encrypt_data(&key, &plaintext).unwrap();
        let decrypted = decrypt_data(&key, &encrypted).unwrap();
        assert_eq!(&*decrypted, &plaintext);
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = vec![0x42u8; 32];
        let short = vec![0u8; 10];
        assert!(decrypt_data(&key, &short).is_err());
    }

    #[test]
    fn test_decrypt_wrong_magic() {
        let key = vec![0x42u8; 32];
        let mut data = vec![0u8; VAULT_MAGIC.len() + NONCE_LEN + 32];
        data[0..5].copy_from_slice(b"WRONG");
        // FIX-5: error message is uniform ("decryption failed") to avoid oracle leaks
        assert_eq!(
            decrypt_data(&key, &data).unwrap_err(),
            "decryption failed"
        );
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = vec![0x42u8; 32];
        let key2 = vec![0x43u8; 32];
        let encrypted = encrypt_data(&key1, b"secret").unwrap();
        assert!(decrypt_data(&key2, &encrypted).is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = vec![0x42u8; 32];
        let mut encrypted = encrypt_data(&key, b"secret data").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt_data(&key, &encrypted).is_err());
    }

    #[test]
    fn test_decrypt_tampered_nonce() {
        let key = vec![0x42u8; 32];
        let mut encrypted = encrypt_data(&key, b"secret data").unwrap();
        encrypted[VAULT_MAGIC.len()] ^= 0x01;
        assert!(decrypt_data(&key, &encrypted).is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = vec![0x42u8; 32];
        let mut nonces = HashSet::new();
        for _ in 0..500 {
            let enc = encrypt_data(&key, b"same data").unwrap();
            let nonce = enc[VAULT_MAGIC.len()..VAULT_MAGIC.len() + NONCE_LEN].to_vec();
            nonces.insert(nonce);
        }
        assert_eq!(nonces.len(), 500, "All 500 nonces must be unique");
    }

    #[test]
    fn test_same_plaintext_different_ciphertext() {
        let key = vec![0x42u8; 32];
        let enc1 = encrypt_data(&key, b"same").unwrap();
        let enc2 = encrypt_data(&key, b"same").unwrap();
        assert_ne!(
            enc1, enc2,
            "Encryptions of same plaintext must differ (random nonce)"
        );
    }

    #[test]
    fn test_encrypted_starts_with_magic() {
        let key = vec![0x42u8; 32];
        let encrypted = encrypt_data(&key, b"hello").unwrap();
        assert!(encrypted.starts_with(VAULT_MAGIC));
    }

    #[test]
    fn test_encrypted_has_version_byte() {
        // BE-T2 #9: new format must mark itself with the version byte 0x02
        let key = vec![0x42u8; 32];
        let encrypted = encrypt_data(&key, b"hello").unwrap();
        assert_eq!(
            encrypted[VAULT_MAGIC.len() + NONCE_LEN],
            ENC_VERSION_GCM_SIV,
            "new ciphertext must carry the AES-GCM-SIV version byte"
        );
    }

    /// Build a legacy AES-256-GCM ciphertext block (no version byte) the way
    /// pre-migration `encrypt_data` did, to verify backward-compat decryption.
    fn legacy_aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: VAULT_MAGIC,
                },
            )
            .expect("legacy encrypt");
        let mut out = VAULT_MAGIC.to_vec();
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn test_decrypt_legacy_aes_gcm_format() {
        // BE-T2 #9: existing V6 vaults must still decrypt after the migration.
        let key = vec![0x42u8; 32];
        let plaintext = b"Pre-migration vault payload";
        let encrypted = legacy_aes_gcm_encrypt(&key, plaintext);
        // No version byte must be present at MAGIC+NONCE in legacy data.
        // (Note: in rare cases the first ciphertext byte could collide with
        // 0x02; that is unavoidable without a true format flag in the legacy
        // format. The collision rate is 1/256 per block — acceptable for the
        // existing-data read path. New writes always use the tagged format.)
        let decrypted = decrypt_data(&key, &encrypted).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_new_aes_gcm_siv_format() {
        // Round-trip via current `encrypt_data` (AES-GCM-SIV with 0x02 tag).
        let key = vec![0x42u8; 32];
        let plaintext = b"Post-migration payload";
        let encrypted = encrypt_data(&key, plaintext).unwrap();
        let decrypted = decrypt_data(&key, &encrypted).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_derive_secure_key_deterministic() {
        let salt = [0x01u8; 16];
        let k1 = derive_secure_key("password", &salt).unwrap();
        let k2 = derive_secure_key("password", &salt).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn test_derive_secure_key_different_passwords() {
        let salt = [0x01u8; 16];
        let k1 = derive_secure_key("password1", &salt).unwrap();
        let k2 = derive_secure_key("password2", &salt).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_derive_secure_key_different_salts() {
        let s1 = [0x01u8; 16];
        let s2 = [0x02u8; 16];
        let k1 = derive_secure_key("password", &s1).unwrap();
        let k2 = derive_secure_key("password", &s2).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_derive_secure_key_length() {
        let salt = [0x01u8; 16];
        let key = derive_secure_key("pass", &salt).unwrap();
        assert_eq!(key.len(), AES_KEY_LEN);
    }

    #[test]
    fn test_verify_hash_matches_correct() {
        let key = vec![0x42u8; 32];
        let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        hmac.update(b"LEX_VERIFY_DOMAIN_V2");
        let hash = hmac.finalize().into_bytes().to_vec();
        assert!(verify_hash_matches(&key, &hash));
    }

    #[test]
    fn test_verify_hash_matches_wrong_key() {
        let key1 = vec![0x42u8; 32];
        let key2 = vec![0x43u8; 32];
        let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&key1).unwrap();
        hmac.update(b"LEX_VERIFY_DOMAIN_V2");
        let hash = hmac.finalize().into_bytes().to_vec();
        assert!(!verify_hash_matches(&key2, &hash));
    }

    #[test]
    fn test_verify_hash_matches_tampered_hash() {
        let key = vec![0x42u8; 32];
        let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        hmac.update(b"LEX_VERIFY_DOMAIN_V2");
        let mut hash = hmac.finalize().into_bytes().to_vec();
        hash[0] ^= 0xFF;
        assert!(!verify_hash_matches(&key, &hash));
    }

    #[test]
    fn test_verify_hash_matches_empty() {
        let key = vec![0x42u8; 32];
        assert!(!verify_hash_matches(&key, &[]));
    }
}
