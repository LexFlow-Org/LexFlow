#!/usr/bin/env rust
//! LexFlow CLI — vault operations for testing and CI security scripts.
//!
//! Usage:
//!   lexflow-cli open <vault_path> --password <pwd>   Open and validate a vault
//!   lexflow-cli create <vault_path> --password <pwd> Create a new empty vault
//!   lexflow-cli info <vault_path>                    Show vault metadata (no password needed)
//!   lexflow-cli verify <vault_path> --password <pwd> Open, verify HMAC, list records
//!   lexflow-cli benchmark                            Run Argon2 benchmark on this machine

use std::env;
use std::fs;

use std::process;
use std::time::Instant;

// Import vault_v4 functions directly (they don't depend on Tauri)
use app_lib::vault_v4::{
    benchmark_argon2_params, create_vault_v4, derive_kek, deserialize_vault, open_vault_v4,
    serialize_vault, verify_header_mac,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "open" => cmd_open(&args[2..]),
        "create" => cmd_create(&args[2..]),
        "info" => cmd_info(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "benchmark" => cmd_benchmark(),
        "--help" | "-h" | "help" => {
            print_usage();
            process::exit(0);
        }
        other => {
            eprintln!("Unknown command: {}", other);
            print_usage();
            process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("LexFlow CLI — vault operations for testing and CI");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  lexflow-cli open <vault_path> --password <pwd>");
    eprintln!("  lexflow-cli create <vault_path> --password <pwd>");
    eprintln!("  lexflow-cli info <vault_path>");
    eprintln!("  lexflow-cli verify <vault_path> --password <pwd>");
    eprintln!("  lexflow-cli benchmark");
}

fn extract_password(args: &[String]) -> Option<&str> {
    for i in 0..args.len() {
        if args[i] == "--password" && i + 1 < args.len() {
            return Some(&args[i + 1]);
        }
    }
    None
}

fn cmd_open(args: &[String]) {
    if args.is_empty() {
        eprintln!("Error: vault path required");
        process::exit(1);
    }
    let path = &args[0];
    let password = match extract_password(args) {
        Some(p) => p,
        None => {
            eprintln!("Error: --password required");
            process::exit(1);
        }
    };

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: cannot read file: {}", e);
            process::exit(1);
        }
    };

    let start = Instant::now();
    match open_vault_v4(password, &data) {
        Ok((_vault, _dek)) => {
            let elapsed = start.elapsed();
            println!(
                "OK: vault opened successfully in {:.0}ms",
                elapsed.as_millis()
            );
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_create(args: &[String]) {
    if args.is_empty() {
        eprintln!("Error: vault path required");
        process::exit(1);
    }
    let path = &args[0];
    let password = match extract_password(args) {
        Some(p) => p,
        None => {
            eprintln!("Error: --password required");
            process::exit(1);
        }
    };

    let start = Instant::now();
    match create_vault_v4(password) {
        Ok((vault, _dek)) => {
            let bytes = serialize_vault(&vault).expect("serialize failed");
            fs::write(path, &bytes).expect("write failed");
            let elapsed = start.elapsed();
            println!(
                "OK: vault created at {} ({} bytes, {:.0}ms)",
                path,
                bytes.len(),
                elapsed.as_millis()
            );
            println!(
                "  KDF: m={}, t={}, p={}",
                vault.kdf.m, vault.kdf.t, vault.kdf.p
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_info(args: &[String]) {
    if args.is_empty() {
        eprintln!("Error: vault path required");
        process::exit(1);
    }
    let path = &args[0];

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: cannot read file: {}", e);
            process::exit(1);
        }
    };

    match deserialize_vault(&data) {
        Ok(vault) => {
            println!("Vault v{}", vault.version);
            println!(
                "  KDF: {} (m={}, t={}, p={})",
                vault.kdf.alg, vault.kdf.m, vault.kdf.t, vault.kdf.p
            );
            println!("  Cipher: {}", vault.dek_alg);
            println!("  Records: {}", vault.records.len());
            println!(
                "  Rotation: created={}, writes={}/{}",
                vault.rotation.created, vault.rotation.writes, vault.rotation.max_writes
            );
            println!(
                "  Has recovery key: {}",
                vault.wrapped_dek_recovery.is_some()
            );
            println!("  File size: {} bytes", data.len());
        }
        Err(e) => {
            eprintln!("Error: not a valid LexFlow v4 vault: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_verify(args: &[String]) {
    if args.is_empty() {
        eprintln!("Error: vault path required");
        process::exit(1);
    }
    let path = &args[0];
    let password = match extract_password(args) {
        Some(p) => p,
        None => {
            eprintln!("Error: --password required");
            process::exit(1);
        }
    };

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: cannot read file: {}", e);
            process::exit(1);
        }
    };

    // Step 1: deserialize
    let vault = match deserialize_vault(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL: deserialize: {}", e);
            process::exit(1);
        }
    };
    println!(
        "[1/4] Deserialized: v{}, {} records",
        vault.version,
        vault.records.len()
    );

    // Step 2: derive KEK
    let start = Instant::now();
    let kek = match derive_kek(password, &vault.kdf) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("FAIL: KEK derivation: {}", e);
            process::exit(1);
        }
    };
    println!("[2/4] KEK derived in {:.0}ms", start.elapsed().as_millis());

    // Step 3: verify header MAC
    match verify_header_mac(&kek, &vault) {
        Ok(()) => println!("[3/4] Header MAC: VALID"),
        Err(e) => {
            eprintln!("FAIL: Header MAC: {}", e);
            process::exit(1);
        }
    }

    // Step 4: open vault (unwrap DEK + decrypt index)
    match open_vault_v4(password, &data) {
        Ok((_v, _dek)) => println!("[4/4] Vault opened: all records accessible"),
        Err(e) => {
            eprintln!("FAIL: open: {}", e);
            process::exit(1);
        }
    }

    println!("\nALL CHECKS PASSED");
}

fn cmd_benchmark() {
    println!("Running Argon2id benchmark on this machine...");
    println!();

    let start = Instant::now();
    let params = benchmark_argon2_params();
    let elapsed = start.elapsed();

    println!("Optimal parameters found in {:.1}s:", elapsed.as_secs_f64());
    println!("  m_cost: {} ({} MB)", params.m, params.m / 1024);
    println!("  t_cost: {}", params.t);
    println!("  p_cost: {}", params.p);

    // Test actual derivation time with chosen params
    let test_password = "BenchmarkTest123!";
    let start2 = Instant::now();
    let _ = derive_kek(test_password, &params);
    let derive_time = start2.elapsed();
    println!("  Derivation time: {:.0}ms", derive_time.as_millis());
    println!(
        "  Brute-force rate: ~{:.1} attempts/sec",
        1000.0 / derive_time.as_millis() as f64
    );
    println!(
        "  Time for 1M attempts: {:.1} days",
        derive_time.as_secs_f64() * 1_000_000.0 / 86400.0
    );
}
