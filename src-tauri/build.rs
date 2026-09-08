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
                                                   // ROTATED 2026-09-06: v1.0.1 — previous issuer revoked
    seed.extend_from_slice(&[
        174u8, 48u8, 245u8, 149u8, 58u8, 105u8, 117u8, 189u8, 197u8, 166u8, 82u8, 54u8, 39u8,
        166u8, 166u8, 194u8, 189u8, 248u8, 121u8, 72u8, 199u8, 249u8, 194u8, 97u8, 34u8, 165u8,
        16u8, 49u8, 44u8, 16u8, 222u8, 13u8,
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

    // Android 15+ can run with 16 KiB memory pages. NDK r27 defaults to 4 KiB.
    // Apply alignment to the final shared library without changing desktop flags.
    // https://developer.android.com/guide/practices/page-sizes
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-arg=-Wl,-z,max-page-size=16384");
        println!("cargo:rustc-link-arg=-Wl,-z,common-page-size=16384");
    }

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        build_macos_biometry();
    }

    tauri_build::build();
}

/// Compile only while building macOS, on the developer's machine/CI. The user
/// receives linked framework calls and does not need Swift, Xcode or CLT.
fn build_macos_biometry() {
    use std::path::PathBuf;
    use std::process::Command;
    let architecture = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        other => panic!("Unsupported macOS architecture: {other:?}"),
    };
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let object = output.join("macos_biometry.o");
    let archive = output.join("liblexflow_biometry.a");
    println!("cargo:rerun-if-changed=src/macos_biometry.m");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    let sdk = Command::new("/usr/bin/xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .expect("macOS SDK lookup failed");
    assert!(sdk.status.success(), "macOS SDK unavailable");
    let sdk = String::from_utf8(sdk.stdout).expect("SDK path must be UTF-8");
    let status = Command::new("/usr/bin/xcrun")
        .args([
            "--sdk",
            "macosx",
            "clang",
            "-arch",
            architecture,
            "-isysroot",
            sdk.trim(),
            "-mmacosx-version-min=11.0",
            "-fobjc-arc",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
            "src/macos_biometry.m",
            "-o",
        ])
        .arg(&object)
        .status()
        .expect("macOS biometric bridge compiler failed");
    assert!(
        status.success(),
        "macOS biometric bridge compilation failed"
    );
    let status = Command::new("/usr/bin/xcrun")
        .args(["--sdk", "macosx", "ar", "crs"])
        .arg(&archive)
        .arg(&object)
        .status()
        .expect("macOS bridge archiver failed");
    assert!(status.success(), "macOS biometric bridge archive failed");
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=lexflow_biometry");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    println!("cargo:rustc-link-lib=framework=Security");
}
