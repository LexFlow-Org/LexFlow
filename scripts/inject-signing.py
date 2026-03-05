#!/usr/bin/env python3
"""Inject release signing config into Android build.gradle.kts."""
import pathlib
import sys

gradle_path = pathlib.Path("src-tauri/gen/android/app/build.gradle.kts")
ks_path = pathlib.Path("src-tauri/gen/android/app/release.keystore")

if not ks_path.exists() or not gradle_path.exists():
    print("Keystore or Gradle file not found, skipping signing injection")
    sys.exit(0)

content = gradle_path.read_text()

signing_config = """
    signingConfigs {
        create("release") {
            storeFile = file("release.keystore")
            storePassword = System.getenv("ANDROID_STORE_PASSWORD") ?: ""
            keyAlias = System.getenv("ANDROID_KEY_ALIAS") ?: ""
            keyPassword = System.getenv("ANDROID_KEY_PASSWORD") ?: ""
        }
    }

"""

content = content.replace("buildTypes {", signing_config + "    buildTypes {", 1)
content = content.replace(
    'getByName("release") {',
    'getByName("release") {\n                signingConfig = signingConfigs.getByName("release")',
    1,
)
gradle_path.write_text(content)
print("Gradle signing configured")
