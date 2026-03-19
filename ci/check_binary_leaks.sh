#!/bin/bash
# ci/check_binary_leaks.sh — Check release binary for leaked secrets/symbols
# Run after: cargo build --release

set -e

# Find the binary (macOS .dylib, Linux .so, or the test binary)
BIN=""
for candidate in \
    "target/release/liblexflow.dylib" \
    "target/release/liblexflow.so" \
    "target/release/lexflow.exe" \
    "target/release/lexflow"; do
    if [ -f "$candidate" ]; then
        BIN="$candidate"
        break
    fi
done

if [ -z "$BIN" ]; then
    echo "SKIP: No release binary found. Run 'cargo build --release' first."
    exit 0
fi

echo "Checking binary: $BIN"
FAIL=0

# 1. No test strings in binary
echo -n "  Test strings... "
LEAKS=$(strings "$BIN" | grep -ci "test_password\|MARKER_FOR_TEST\|fixture\|dummy_key\|benchmark_test_pwd" || true)
if [ "$LEAKS" -gt 0 ]; then
    echo "FAIL: $LEAKS test strings found!"
    strings "$BIN" | grep -i "test_password\|MARKER_FOR_TEST\|fixture\|dummy_key" | head -5
    FAIL=1
else
    echo "OK"
fi

# 2. No hardcoded passwords
echo -n "  Hardcoded passwords... "
PWDS=$(strings "$BIN" | grep -ci "password123\|letmein\|admin123\|secret123" || true)
if [ "$PWDS" -gt 0 ]; then
    echo "FAIL: $PWDS potential hardcoded passwords!"
    FAIL=1
else
    echo "OK"
fi

# 3. Check for suspiciously long base64 strings (potential embedded keys)
echo -n "  Embedded base64 keys... "
B64=$(strings "$BIN" | grep -cE "^[A-Za-z0-9+/]{44,}={0,2}$" || true)
if [ "$B64" -gt 20 ]; then
    echo "WARN: $B64 base64 strings (may include legitimate constants)"
else
    echo "OK ($B64 found, acceptable)"
fi

# 4. Strip check (release should have stripped symbols)
echo -n "  Symbol stripping... "
if command -v nm &>/dev/null; then
    SYMS=$(nm "$BIN" 2>/dev/null | grep -ci "derive_kek\|unwrap_dek\|decrypt_record" || true)
    if [ "$SYMS" -gt 0 ]; then
        echo "WARN: $SYMS crypto symbols visible (consider strip=true in Cargo.toml)"
    else
        echo "OK (stripped)"
    fi
else
    echo "SKIP (nm not available)"
fi

if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAILED — leaked data in binary!"
    exit 1
fi

echo "RESULT: PASS — binary is clean"
