fn main() {
    // Compute integrity HMAC at build time — guarantees match regardless of
    // optimization level, target triple, or platform.
    // This duplicates the exact same computation as setup.rs::verify_binary_integrity()
    // but runs at compile time so the expected value is always correct.
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    let mut seed = Vec::with_capacity(256);
    seed.extend_from_slice(b"LEXFLOW-INTEGRITY-V2:");
    seed.extend_from_slice(b"LEXFLOW_V2_SECURE"); // VAULT_MAGIC
    seed.extend_from_slice(&(32u64).to_le_bytes()); // AES_KEY_LEN
    seed.extend_from_slice(&(12u64).to_le_bytes()); // NONCE_LEN
    seed.extend_from_slice(&(65536u32).to_le_bytes()); // ARGON2_M_COST (OWASP stronger profile)
    seed.extend_from_slice(&(3u32).to_le_bytes()); // ARGON2_T_COST
    seed.extend_from_slice(&(1u32).to_le_bytes()); // ARGON2_P_COST
                                                   // PUBLIC_KEY_BYTES (must match license.rs exactly)
                                                   // ROTATED 2026-05-11: v5.1 — synced with license.rs
    seed.extend_from_slice(&[
        90u8, 7u8, 33u8, 6u8, 155u8, 146u8, 238u8, 227u8, 219u8, 64u8, 209u8, 178u8, 21u8, 69u8,
        177u8, 90u8, 181u8, 127u8, 231u8, 233u8, 144u8, 1u8, 54u8, 91u8, 94u8, 113u8, 188u8, 244u8,
        168u8, 34u8, 31u8, 14u8,
    ]);
    seed.extend_from_slice(&(10u32).to_le_bytes()); // DEK_WIPE_THRESHOLD

    let hmac_key = Sha256::digest(&seed);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).unwrap();
    mac.update(&seed);
    let result = mac.finalize().into_bytes();
    let hex_str = result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    println!("cargo:rustc-env=LEXFLOW_INTEGRITY_HMAC={}", hex_str);

    tauri_build::build();
}
