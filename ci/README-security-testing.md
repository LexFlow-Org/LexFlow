# Security Testing Guide

## Automated Tests (run in CI and locally)

### 1. Unit Tests (110 tests)
```bash
cargo test --lib vault_v4_tests -- --test-threads=1
```

### 2. Python Attack Suite (144 attacks)
```bash
python3 ci/attack_vault_format.py
```

### 3. Binary Leak Check
```bash
cargo build --release
bash ci/check_binary_leaks.sh
```

## Advanced Tests (CI job with nightly toolchain)

### MIRI (undefined behavior in unsafe code)
```bash
# Incompatible with Tauri runtime — extract crypto core to separate crate for MIRI
rustup component add miri --toolchain nightly
cargo +nightly miri test --lib vault_v4_tests
```

### AddressSanitizer
```bash
RUSTFLAGS="-Zsanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu
```

### LeakSanitizer
```bash
RUSTFLAGS="-Zsanitizer=leak" cargo +nightly test --target x86_64-unknown-linux-gnu
```

**Note**: MIRI and sanitizers are incompatible with the full Tauri runtime due to FFI/syscall
dependencies. For maximum coverage, extract the vault_v4 crypto engine into a standalone crate
and run MIRI/ASan on that crate independently.

## Manual Pre-Release

### Frida (runtime hooking)
```bash
pip install frida-tools
frida -f ./target/release/lexflow --no-pause -l ci/frida_hook_lexflow.js
```

### Binary Analysis
```bash
strings target/release/lexflow | grep -i "password\|secret\|key"
nm target/release/lexflow | grep -i "decrypt\|encrypt"
```
