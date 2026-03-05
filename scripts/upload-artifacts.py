#!/usr/bin/env python3
"""Upload APK + AAB artifacts to GitHub Release."""
import os
import subprocess
import sys
import time

if len(sys.argv) < 2:
    print("Usage: upload-artifacts.py <tag>")
    sys.exit(1)

tag = sys.argv[1]

# Wait for release (created by macOS job)
for i in range(1, 31):
    result = subprocess.run(
        ["gh", "release", "view", tag],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        break
    print(f"  Waiting for release... ({i}/30)")
    time.sleep(15)

apk_final = os.environ.get("APK_FINAL", "")
aab_final = os.environ.get("AAB_FINAL", "")

if apk_final and os.path.isfile(apk_final):
    subprocess.run(["gh", "release", "upload", tag, apk_final, "--clobber"], check=True)
    # Also upload with generic name
    import shutil
    generic = "/tmp/app-universal-release.apk"
    shutil.copy2(apk_final, generic)
    subprocess.run(["gh", "release", "upload", tag, generic, "--clobber"], check=True)
    print("APK uploaded")

if aab_final and os.path.isfile(aab_final):
    subprocess.run(["gh", "release", "upload", tag, aab_final, "--clobber"], check=True)
    import shutil
    generic = "/tmp/app-universal-release.aab"
    shutil.copy2(aab_final, generic)
    subprocess.run(["gh", "release", "upload", tag, generic, "--clobber"], check=True)
    print("AAB uploaded")
