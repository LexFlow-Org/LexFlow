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
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
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
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| "Auth failed".into())
}

pub(crate) fn verify_hash_matches(key: &[u8], stored: &[u8]) -> bool {
    let mut hmac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
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
        assert_eq!(&decrypted, plaintext);
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
        assert_eq!(decrypted, plaintext);
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
        assert!(decrypt_data(&key, &data).unwrap_err().contains("magic"));
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
        assert_ne!(enc1, enc2, "Encryptions of same plaintext must differ (random nonce)");
    }

    #[test]
    fn test_encrypted_starts_with_magic() {
        let key = vec![0x42u8; 32];
        let encrypted = encrypt_data(&key, b"hello").unwrap();
        assert!(encrypted.starts_with(VAULT_MAGIC));
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
