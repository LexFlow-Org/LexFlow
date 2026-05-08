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
    seed.extend_from_slice(&(16384u32).to_le_bytes()); // ARGON2_M_COST
    seed.extend_from_slice(&(3u32).to_le_bytes()); // ARGON2_T_COST
    seed.extend_from_slice(&(1u32).to_le_bytes()); // ARGON2_P_COST
                                                   // PUBLIC_KEY_BYTES (must match license.rs exactly)
    // ROTATED 2026-04-11: v5.0 — synced with license.rs
    seed.extend_from_slice(&[
        68u8, 17u8, 204u8, 75u8, 33u8, 178u8, 142u8, 35u8, 80u8, 225u8, 11u8, 121u8, 146u8, 211u8,
        252u8, 220u8, 179u8, 206u8, 88u8, 129u8, 82u8, 148u8, 38u8, 103u8, 113u8, 3u8, 106u8, 4u8,
        9u8, 239u8, 47u8, 150u8,
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
