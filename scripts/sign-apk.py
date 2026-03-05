#!/usr/bin/env python3
"""Sign APK with zipalign + apksigner (v1-v4 schemes)."""
import os
import subprocess
import sys
import glob

# Find build-tools
android_home = os.environ.get("ANDROID_HOME", "")
bt_dirs = sorted(glob.glob(os.path.join(android_home, "build-tools", "*")))
if not bt_dirs:
    print("::error::No Android build-tools found")
    sys.exit(1)
bt = bt_dirs[-1]
zipalign = os.path.join(bt, "zipalign")
apksigner = os.path.join(bt, "apksigner")

# Find release APK
apk = None
for pattern in ["*universal-release.apk", "*release.apk"]:
    matches = glob.glob(f"src-tauri/gen/android/**/{pattern}", recursive=True)
    matches = [m for m in matches if "unsigned" not in m]
    if matches:
        apk = matches[0]
        break

if not apk:
    print("::error::No release APK found")
    sys.exit(1)
print(f"Source: {apk}")

# Zipalign
aligned = "/tmp/lexflow-aligned.apk"
subprocess.run([zipalign, "-f", "-p", "4", apk, aligned], check=True)
subprocess.run([zipalign, "-c", "-p", "4", aligned], check=True)

# Determine version from GITHUB_REF_NAME
tag = os.environ.get("GITHUB_REF_NAME", "v1.0.0")
version = tag.lstrip("v") if tag.startswith("v") else "1.0.0"
final_apk = f"/tmp/LexFlow-v{version}-universal.apk"

# Sign
subprocess.run([
    apksigner, "sign",
    "--ks", "src-tauri/gen/android/app/release.keystore",
    "--ks-pass", "env:ANDROID_STORE_PASSWORD",
    "--ks-key-alias", os.environ.get("ANDROID_KEY_ALIAS", ""),
    "--key-pass", "env:ANDROID_KEY_PASSWORD",
    "--v1-signing-enabled", "true",
    "--v2-signing-enabled", "true",
    "--v3-signing-enabled", "true",
    "--v4-signing-enabled", "true",
    "--out", final_apk,
    aligned,
], check=True)

# Verify
result = subprocess.run(
    [apksigner, "verify", "--verbose", final_apk],
    capture_output=True, text=True,
)
print(result.stdout)
if "Verifies" not in result.stdout:
    print("::error::APK verification failed")
    sys.exit(1)
print("APK signed and verified")

# Write to GITHUB_ENV
gh_env = os.environ.get("GITHUB_ENV", "")
if gh_env:
    with open(gh_env, "a") as f:
        f.write(f"APK_FINAL={final_apk}\n")

# AAB
aab_matches = glob.glob("src-tauri/gen/android/**/*release.aab", recursive=True)
if aab_matches:
    import shutil
    aab_final = f"/tmp/LexFlow-v{version}-universal.aab"
    shutil.copy2(aab_matches[0], aab_final)
    if gh_env:
        with open(gh_env, "a") as f:
            f.write(f"AAB_FINAL={aab_final}\n")
    print(f"AAB copied: {aab_final}")
