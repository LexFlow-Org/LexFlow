// ═══════════════════════════════════════════════════════════
//  CORE CRYPTO ENGINE — AES-256-GCM + Argon2id
// ═══════════════════════════════════════════════════════════

use crate::constants::*;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub(crate) fn derive_secure_key(password: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
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

pub(crate) fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
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

pub(crate) fn decrypt_data(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < VAULT_MAGIC.len() + NONCE_LEN + 16 {
        return Err("Corrupted".into());
    }
    if !data.starts_with(VAULT_MAGIC) {
        return Err("Invalid file format: magic bytes mismatch".into());
    }
    let nonce = Nonce::from_slice(&data[VAULT_MAGIC.len()..VAULT_MAGIC.len() + NONCE_LEN]);
    let ciphertext = &data[VAULT_MAGIC.len() + NONCE_LEN..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let payload = Payload {
        msg: ciphertext,
        aad: VAULT_MAGIC,
    };
    if let Ok(dec) = cipher.decrypt(nonce, payload) {
        LEGACY_AAD_CLEAN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Ok(dec);
    }

    let clean_count = LEGACY_AAD_CLEAN_COUNTER.load(std::sync::atomic::Ordering::Relaxed);
    if clean_count >= LEGACY_AAD_SUNSET_THRESHOLD
        && !LEGACY_AAD_EVER_USED.load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err("Auth failed (legacy fallback disabled — all files should be migrated)".into());
    }

    let legacy_payload = Payload {
        msg: ciphertext,
        aad: b"",
    };
    cipher
        .decrypt(nonce, legacy_payload)
        .map_err(|_| "Auth failed".into())
        .inspect(|_dec| {
            LEGACY_AAD_CLEAN_COUNTER.store(0, std::sync::atomic::Ordering::Relaxed);
            LEGACY_AAD_EVER_USED.store(true, std::sync::atomic::Ordering::Relaxed);
            eprintln!(
                "SECURITY WARNING: File decifrato con fallback legacy (senza AAD). \
                RE-CIFRATURA AUTOMATICA in corso. Questo fallback sarà rimosso in v4.0.0."
            );
        })
}

pub(crate) fn verify_hash_matches(key: &[u8], stored: &[u8]) -> bool {
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    hmac.update(b"LEX_VERIFY_DOMAIN_V2");
    hmac.verify_slice(stored).is_ok()
}

pub(crate) fn make_verify_tag(vault_key: &[u8]) -> Vec<u8> {
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(vault_key).unwrap();
    hmac.update(b"LEX_VERIFY_DOMAIN_V2");
    hmac.finalize().into_bytes().to_vec()
}
