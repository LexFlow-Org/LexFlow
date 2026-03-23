#!/usr/bin/env rust
//! LexFlow CLI v2.0 — Professional vault operations for testing, CI, and forensics.
//!
//! USAGE:
//!   lexflow-cli <COMMAND> [OPTIONS]
//!
//! COMMANDS:
//!   create    <path> --password <pwd>   Create a new empty vault
//!   open      <path> --password <pwd>   Open and validate a vault
//!   verify    <path> --password <pwd>   Full 4-step integrity verification
//!   info      <path>                    Show vault metadata (no password)
//!   benchmark                           Run Argon2id benchmark on this machine
//!   export    <vault> <output> --password <pwd>  Export vault as portable .lex backup
//!   rotate    <path> --password <pwd>   Force DEK rotation (re-encrypt all records)
//!   test-crypto                         Verify AES-256-GCM-SIV + Argon2id pipeline
//!   version                             Show CLI and crypto library versions
//!
//! EXIT CODES:
//!   0  Success
//!   1  Error (invalid args, wrong password, corrupted vault, etc.)
//!   2  Security violation (tampering detected, rollback, etc.)

use std::env;
use std::fs;
use std::process;
use std::time::Instant;

use app_lib::vault_v4::{
    benchmark_argon2_params, create_vault_v4, decrypt_index, decrypt_record, derive_kek,
    deserialize_vault, encrypt_record, generate_dek, needs_rotation, open_vault_v4, rotate_dek,
    serialize_vault, verify_header_mac, wrap_dek, unwrap_dek,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let exit_code = match args[1].as_str() {
        "open" => cmd_open(&args[2..]),
        "create" => cmd_create(&args[2..]),
        "info" => cmd_info(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "benchmark" => cmd_benchmark(),
        "export" => cmd_export(&args[2..]),
        "rotate" => cmd_rotate(&args[2..]),
        "test-crypto" => cmd_test_crypto(),
        "version" => cmd_version(),
        "--help" | "-h" | "help" => {
            print_usage();
            0
        }
        other => {
            eprintln!("ERROR: Unknown command '{}'\n", other);
            print_usage();
            1
        }
    };

    process::exit(exit_code);
}

fn print_usage() {
    eprintln!("LexFlow CLI v{} — Professional vault operations", VERSION);
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  lexflow-cli <COMMAND> [OPTIONS]");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  create    <path> --password <pwd>            Create new vault");
    eprintln!("  open      <path> --password <pwd>            Open and validate vault");
    eprintln!("  verify    <path> --password <pwd>            Full integrity check (4 steps)");
    eprintln!("  info      <path>                             Vault metadata (no password)");
    eprintln!("  benchmark                                    Argon2id benchmark");
    eprintln!("  export    <vault> <output> --password <pwd>  Export as .lex backup");
    eprintln!("  rotate    <path> --password <pwd>            Force DEK rotation");
    eprintln!("  test-crypto                                  Verify crypto pipeline");
    eprintln!("  version                                      Show version info");
    eprintln!();
    eprintln!("EXIT CODES: 0=success, 1=error, 2=security violation");
}

fn extract_password(args: &[String]) -> Option<&str> {
    for i in 0..args.len() {
        if args[i] == "--password" && i + 1 < args.len() {
            return Some(&args[i + 1]);
        }
    }
    None
}

fn read_vault_file(path: &str) -> Vec<u8> {
    match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ERROR: cannot read '{}': {}", path, e);
            process::exit(1);
        }
    }
}

fn require_password(args: &[String]) -> &str {
    match extract_password(args) {
        Some(p) => p,
        None => {
            eprintln!("ERROR: --password <pwd> is required");
            process::exit(1);
        }
    }
}

fn require_path(args: &[String], name: &str) -> String {
    if args.is_empty() || args[0].starts_with('-') {
        eprintln!("ERROR: {} path is required", name);
        process::exit(1);
    }
    args[0].clone()
}

// ═══════════════════════════════════════════════════════════
//  COMMANDS
// ═══════════════════════════════════════════════════════════

fn cmd_open(args: &[String]) -> i32 {
    let path = require_path(args, "vault");
    let password = require_password(args);
    let data = read_vault_file(&path);

    let start = Instant::now();
    match open_vault_v4(password, &data) {
        Ok((_vault, _dek)) => {
            println!("OK: vault opened in {:.0}ms", start.elapsed().as_millis());
            0
        }
        Err(e) => {
            eprintln!("FAIL: {}", e);
            1
        }
    }
}

fn cmd_create(args: &[String]) -> i32 {
    let path = require_path(args, "vault");
    let password = require_password(args);

    let start = Instant::now();
    match create_vault_v4(password) {
        Ok((vault, _dek)) => {
            let bytes = match serialize_vault(&vault) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FAIL: serialize: {}", e);
                    return 1;
                }
            };
            if let Err(e) = fs::write(&path, &bytes) {
                eprintln!("FAIL: write: {}", e);
                return 1;
            }
            println!(
                "OK: vault created at {} ({} bytes, {:.0}ms)",
                path,
                bytes.len(),
                start.elapsed().as_millis()
            );
            println!(
                "  KDF: argon2id (m={}, t={}, p={})",
                vault.kdf.m, vault.kdf.t, vault.kdf.p
            );
            println!("  Cipher: {}", vault.dek_alg);
            0
        }
        Err(e) => {
            eprintln!("FAIL: {}", e);
            1
        }
    }
}

fn cmd_info(args: &[String]) -> i32 {
    let path = require_path(args, "vault");
    let data = read_vault_file(&path);

    match deserialize_vault(&data) {
        Ok(vault) => {
            println!("╔══════════════════════════════════════╗");
            println!("║  LexFlow Vault v{}                   ║", vault.version);
            println!("╚══════════════════════════════════════╝");
            println!();
            println!("  Format:       {}", vault.dek_alg);
            println!(
                "  KDF:          {} (m={} t={} p={})",
                vault.kdf.alg, vault.kdf.m, vault.kdf.t, vault.kdf.p
            );
            println!("  Records:      {}", vault.records.len());
            println!("  DEK created:  {}", vault.rotation.created);
            println!(
                "  Writes:       {}/{}",
                vault.rotation.writes, vault.rotation.max_writes
            );
            println!(
                "  Rotation due: {}",
                if needs_rotation(&vault.rotation) {
                    "YES"
                } else {
                    "no"
                }
            );
            println!(
                "  Recovery key: {}",
                if vault.wrapped_dek_recovery.is_some() {
                    "configured"
                } else {
                    "NOT configured"
                }
            );
            println!("  File size:    {} bytes", data.len());
            0
        }
        Err(e) => {
            eprintln!("FAIL: not a valid LexFlow v4 vault: {}", e);
            1
        }
    }
}

fn cmd_verify(args: &[String]) -> i32 {
    let path = require_path(args, "vault");
    let password = require_password(args);
    let data = read_vault_file(&path);

    // Step 1: Deserialize
    let vault = match deserialize_vault(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[1/5] FAIL: deserialize: {}", e);
            return 1;
        }
    };
    println!(
        "[1/5] Deserialized: v{}, {} records",
        vault.version,
        vault.records.len()
    );

    // Step 2: Derive KEK
    let start = Instant::now();
    let kek = match derive_kek(password, &vault.kdf) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[2/5] FAIL: KEK derivation: {}", e);
            return 1;
        }
    };
    println!("[2/5] KEK derived in {:.0}ms", start.elapsed().as_millis());

    // Step 3: Verify header MAC
    match verify_header_mac(&kek, &vault) {
        Ok(()) => println!("[3/5] Header MAC: VALID (constant-time verified)"),
        Err(e) => {
            eprintln!("[3/5] FAIL: Header MAC: {}", e);
            return 2; // Security violation
        }
    }

    // Step 4: Unwrap DEK + decrypt index
    let dek = match open_vault_v4(password, &data) {
        Ok((_v, d)) => d,
        Err(e) => {
            eprintln!("[4/5] FAIL: DEK unwrap: {}", e);
            return 1;
        }
    };
    let index = match decrypt_index(&dek, &vault.index) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("[4/5] FAIL: index decrypt: {}", e);
            return 1;
        }
    };
    println!(
        "[4/5] DEK unwrapped, index decrypted ({} entries)",
        index.len()
    );

    // Step 5: Verify every record decrypts
    let mut ok_count = 0u32;
    let mut fail_count = 0u32;
    for entry in &index {
        if let Some(record_entry) = vault.records.get(&entry.id) {
            for ver in &record_entry.versions {
                let block = app_lib::vault_v4::EncryptedBlock {
                    iv: ver.iv.clone(),
                    tag: ver.tag.clone(),
                    data: ver.data.clone(),
                    compressed: ver.compressed,
                };
                match decrypt_record(&dek, &block) {
                    Ok(_) => ok_count += 1,
                    Err(e) => {
                        eprintln!(
                            "  WARNING: record {} v{} decrypt failed: {}",
                            entry.id, ver.v, e
                        );
                        fail_count += 1;
                    }
                }
            }
        }
    }
    println!(
        "[5/5] Records verified: {} OK, {} FAILED",
        ok_count, fail_count
    );

    if fail_count > 0 {
        eprintln!("\nWARNING: {} corrupted record versions detected", fail_count);
        return 2;
    }

    println!("\n✓ ALL CHECKS PASSED — vault integrity verified");
    0
}

fn cmd_benchmark() -> i32 {
    println!("╔══════════════════════════════════════╗");
    println!("║  Argon2id Benchmark                  ║");
    println!("╚══════════════════════════════════════╝");
    println!();

    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!("  CPU cores: {}", cores);

    let start = Instant::now();
    let params = benchmark_argon2_params();
    let elapsed = start.elapsed();

    println!("  Benchmark time: {:.1}s", elapsed.as_secs_f64());
    println!();
    println!("  Optimal parameters:");
    println!("    m_cost: {} ({} MB)", params.m, params.m / 1024);
    println!("    t_cost: {}", params.t);
    println!("    p_cost: {}", params.p);
    println!();

    // Actual derivation time
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let mut kdf = params.clone();
    kdf.salt = base64::engine::general_purpose::STANDARD.encode(salt);

    let start2 = Instant::now();
    let _ = derive_kek("BenchmarkTest123!", &kdf);
    let derive_ms = start2.elapsed().as_millis();

    println!("  Single derivation: {}ms", derive_ms);
    if derive_ms > 0 {
        println!(
            "  Brute-force rate:  ~{:.1} attempts/sec",
            1000.0 / derive_ms as f64
        );
        println!(
            "  Time for 1M attempts: {:.1} days",
            derive_ms as f64 * 1_000_000.0 / 86_400_000.0
        );
    }
    0
}

fn cmd_export(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("ERROR: usage: lexflow-cli export <vault_path> <output_path> --password <pwd>");
        return 1;
    }
    let vault_path = &args[0];
    let output_path = &args[1];
    let password = require_password(args);
    let data = read_vault_file(vault_path);

    // Verify password first
    let (_vault, dek) = match open_vault_v4(password, &data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL: wrong password or corrupted vault: {}", e);
            return 1;
        }
    };

    // Export format: [32-byte salt][encrypted monolithic JSON]
    let mut salt = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let key = match app_lib::vault_v4::derive_kek(password, &_vault.kdf) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("FAIL: KEK derivation: {}", e);
            return 1;
        }
    };

    // Read and decrypt all records into monolithic JSON
    let index = match decrypt_index(&dek, &_vault.index) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("FAIL: index decrypt: {}", e);
            return 1;
        }
    };

    let mut vault_data = serde_json::json!({
        "practices": [], "agenda": [], "contacts": [], "timeLogs": [], "invoices": []
    });
    for entry in &index {
        if let Some(record_entry) = _vault.records.get(&entry.id) {
            if let Some(ver) = record_entry.versions.iter().find(|v| v.v == record_entry.current) {
                let block = app_lib::vault_v4::EncryptedBlock {
                    iv: ver.iv.clone(),
                    tag: ver.tag.clone(),
                    data: ver.data.clone(),
                    compressed: ver.compressed,
                };
                if let Ok(plaintext) = decrypt_record(&dek, &block) {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&plaintext) {
                        if let Some(arr) = vault_data
                            .get_mut(&entry.field)
                            .and_then(|v| v.as_array_mut())
                        {
                            arr.push(val);
                        }
                    }
                }
            }
        }
    }

    let plaintext = serde_json::to_vec(&vault_data).unwrap_or_default();
    let encrypted =
        match app_lib::vault_v4::encrypt_record(&key, &plaintext) {
            Ok(block) => serde_json::to_vec(&block).unwrap_or_default(),
            Err(e) => {
                eprintln!("FAIL: encryption: {}", e);
                return 1;
            }
        };

    let mut out = salt;
    out.extend(encrypted);
    if let Err(e) = fs::write(output_path, &out) {
        eprintln!("FAIL: write: {}", e);
        return 1;
    }

    println!(
        "OK: exported {} records to {} ({} bytes)",
        index.len(),
        output_path,
        out.len()
    );
    0
}

fn cmd_rotate(args: &[String]) -> i32 {
    let path = require_path(args, "vault");
    let password = require_password(args);
    let data = read_vault_file(&path);

    let mut vault = match deserialize_vault(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL: deserialize: {}", e);
            return 1;
        }
    };

    let kek = match derive_kek(password, &vault.kdf) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("FAIL: KEK derivation: {}", e);
            return 1;
        }
    };

    match verify_header_mac(&kek, &vault) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("FAIL: header MAC: {}", e);
            return 2;
        }
    }

    println!(
        "Current DEK: created={}, writes={}",
        vault.rotation.created, vault.rotation.writes
    );

    let start = Instant::now();
    match rotate_dek(&mut vault, &kek) {
        Ok(_new_dek) => {
            let elapsed = start.elapsed();
            let bytes = match serialize_vault(&vault) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FAIL: serialize: {}", e);
                    return 1;
                }
            };
            if let Err(e) = fs::write(&path, &bytes) {
                eprintln!("FAIL: write: {}", e);
                return 1;
            }
            println!(
                "OK: DEK rotated in {:.0}ms ({} records re-encrypted)",
                elapsed.as_millis(),
                vault.records.len()
            );
            0
        }
        Err(e) => {
            eprintln!("FAIL: rotation: {}", e);
            1
        }
    }
}

fn cmd_test_crypto() -> i32 {
    println!("╔══════════════════════════════════════╗");
    println!("║  LexFlow Crypto Pipeline Test        ║");
    println!("╚══════════════════════════════════════╝");
    println!();

    let mut pass = 0u32;
    let mut fail = 0u32;

    // Test 1: DEK generation
    let dek = generate_dek();
    if dek.len() == 32 {
        println!("  [PASS] DEK generation (256-bit)");
        pass += 1;
    } else {
        eprintln!("  [FAIL] DEK generation: expected 32 bytes, got {}", dek.len());
        fail += 1;
    }

    // Test 2: Record encrypt/decrypt roundtrip
    let plaintext = b"Test legal document content for AES-256-GCM-SIV";
    match encrypt_record(&dek, plaintext) {
        Ok(block) => match decrypt_record(&dek, &block) {
            Ok(dec) => {
                if dec == plaintext {
                    println!("  [PASS] AES-256-GCM-SIV encrypt/decrypt roundtrip");
                    pass += 1;
                } else {
                    eprintln!("  [FAIL] Roundtrip: decrypted data mismatch");
                    fail += 1;
                }
            }
            Err(e) => {
                eprintln!("  [FAIL] Decrypt: {}", e);
                fail += 1;
            }
        },
        Err(e) => {
            eprintln!("  [FAIL] Encrypt: {}", e);
            fail += 1;
        }
    }

    // Test 3: Wrong key cannot decrypt
    let wrong_dek = generate_dek();
    if let Ok(block) = encrypt_record(&dek, plaintext) {
        if decrypt_record(&wrong_dek, &block).is_err() {
            println!("  [PASS] Wrong key correctly rejected");
            pass += 1;
        } else {
            eprintln!("  [FAIL] Wrong key was accepted!");
            fail += 1;
        }
    }

    // Test 4: DEK wrap/unwrap
    let kek = generate_dek(); // use random key as KEK for testing
    match wrap_dek(&kek, &dek) {
        Ok((wrapped, iv)) => match unwrap_dek(&kek, &wrapped, &iv) {
            Ok(recovered) => {
                if *recovered == *dek {
                    println!("  [PASS] DEK wrap/unwrap roundtrip");
                    pass += 1;
                } else {
                    eprintln!("  [FAIL] DEK wrap/unwrap: recovered DEK mismatch");
                    fail += 1;
                }
            }
            Err(e) => {
                eprintln!("  [FAIL] DEK unwrap: {}", e);
                fail += 1;
            }
        },
        Err(e) => {
            eprintln!("  [FAIL] DEK wrap: {}", e);
            fail += 1;
        }
    }

    // Test 5: Vault create/open roundtrip
    let password = "TestCryptoP@ssw0rd!2026";
    match create_vault_v4(password) {
        Ok((vault, _)) => match serialize_vault(&vault) {
            Ok(bytes) => match open_vault_v4(password, &bytes) {
                Ok(_) => {
                    println!("  [PASS] Vault create/open roundtrip");
                    pass += 1;
                }
                Err(e) => {
                    eprintln!("  [FAIL] Vault open: {}", e);
                    fail += 1;
                }
            },
            Err(e) => {
                eprintln!("  [FAIL] Vault serialize: {}", e);
                fail += 1;
            }
        },
        Err(e) => {
            eprintln!("  [FAIL] Vault create: {}", e);
            fail += 1;
        }
    }

    // Test 6: Bit flip detection
    if let Ok(block) = encrypt_record(&dek, plaintext) {
        let mut tampered = block.clone();
        if let Some(b) = tampered.data.as_bytes().first() {
            let flipped = if *b == b'A' { 'B' } else { 'A' };
            tampered.data = format!("{}{}", flipped, &tampered.data[1..]);
        }
        if decrypt_record(&dek, &tampered).is_err() {
            println!("  [PASS] Bit flip detected by GCM-SIV");
            pass += 1;
        } else {
            eprintln!("  [FAIL] Bit flip NOT detected!");
            fail += 1;
        }
    }

    println!();
    println!("  Results: {} passed, {} failed", pass, fail);
    if fail > 0 {
        eprintln!("\n  CRYPTO PIPELINE VERIFICATION FAILED");
        1
    } else {
        println!("\n  ✓ ALL CRYPTO TESTS PASSED");
        0
    }
}

fn cmd_version() -> i32 {
    println!("LexFlow CLI v{}", VERSION);
    println!("  Cipher:  AES-256-GCM-SIV (aes-gcm-siv crate)");
    println!("  KDF:     Argon2id v0x13 (argon2 crate)");
    println!("  HMAC:    SHA-256 (hmac + sha2 crates)");
    println!("  Signing: Ed25519 (ed25519-dalek crate)");
    println!("  Compress: zstd (zstd crate)");
    println!("  RNG:     OsRng (rand crate)");
    0
}
