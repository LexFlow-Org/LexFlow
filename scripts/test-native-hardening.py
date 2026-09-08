#!/usr/bin/env python3
"""Regression tests for native release hardening, using isolated fixtures only."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import xml.etree.ElementTree as ET

SPEC = importlib.util.spec_from_file_location("harden_android", Path(__file__).with_name("harden-android.py"))
HARDEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARDEN)
MAC_SPEC = importlib.util.spec_from_file_location("verify_macos", Path(__file__).with_name("verify-macos-sidecars.py"))
MAC = importlib.util.module_from_spec(MAC_SPEC)
MAC_SPEC.loader.exec_module(MAC)

MANIFEST = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
<application android:usesCleartextTraffic="${usesCleartextTraffic}">
<activity android:name=".MainActivity" android:exported="true"/>
<provider android:name="androidx.core.content.FileProvider" android:exported="false"/>
</application></manifest>'''
# Matches the native template embedded in @tauri-apps/cli 2.10.1.
ACTIVITY = '''package com.pietrolongo.lexflow
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }
}
'''


class NativeHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lexflow-native-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        self.main = self.project / "app/src/main"
        self.main.mkdir(parents=True)
        (self.main / "AndroidManifest.xml").write_text(MANIFEST)
        (self.main / "MainActivity.kt").write_text(ACTIVITY)

    def test_offline_release_preserves_native_components_and_debug(self):
        HARDEN.harden(self.project)
        main = ET.parse(self.main / "AndroidManifest.xml").getroot()
        self.assertIsNotNone(main.find("application/provider"))
        self.assertEqual(main.find("uses-permission").get(HARDEN.A + "name"), "android.permission.POST_NOTIFICATIONS")
        release = ET.parse(self.project / "app/src/release/AndroidManifest.xml").getroot()
        self.assertEqual(len(release.findall("uses-permission")), 2)
        self.assertTrue(all(x.get(HARDEN.T + "node") == "remove" for x in release.findall("uses-permission")))
        self.assertEqual(release.find("application").get(HARDEN.A + "allowBackup"), "false")
        self.assertEqual(release.find("application").get(HARDEN.A + "debuggable"), "false")
        self.assertEqual(release.find("application").get(HARDEN.T + "ignore"), "HardcodedDebugMode")
        debug = ET.parse(self.project / "app/src/debug/AndroidManifest.xml").getroot()
        self.assertIsNone(debug.find("application").get(HARDEN.A + "debuggable"))
        self.assertEqual(debug.find("uses-permission").get(HARDEN.A + "name"), "android.permission.INTERNET")
        self.assertEqual(debug.find("application").get(HARDEN.A + "usesCleartextTraffic"), "true")

    def test_all_storage_domains_excluded_from_cloud_and_transfer(self):
        HARDEN.harden(self.project)
        modern = ET.parse(self.main / "res/xml/lexflow_data_extraction_rules.xml").getroot()
        for mode in ("cloud-backup", "device-transfer"):
            self.assertEqual({x.get("domain") for x in modern.find(mode)}, set(HARDEN.DOMAINS))
            self.assertTrue(all(x.get("path") == "." for x in modern.find(mode)))

    def test_idempotent_hardening_does_not_duplicate_secure_flag(self):
        HARDEN.harden(self.project)
        before = {p.relative_to(self.project): p.read_bytes() for p in self.project.rglob("*") if p.is_file()}
        HARDEN.harden(self.project)
        after = {p.relative_to(self.project): p.read_bytes() for p in self.project.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual((self.main / "MainActivity.kt").read_text().count(HARDEN.SECURE_LINE), 1)
        self.assertEqual((self.main / "MainActivity.kt").read_text().count(HARDEN.RELEASE_DEBUG_LINE), 1)

    def test_activity_already_hardened_for_screenshots_gains_release_debug_guard(self):
        previous = ACTIVITY.replace("super.onCreate(savedInstanceState)",
                                    "super.onCreate(savedInstanceState)\n    " + HARDEN.SECURE_LINE)
        patched = HARDEN.patch_activity(previous)
        self.assertEqual(patched.count(HARDEN.SECURE_LINE), 1)
        self.assertEqual(patched.count(HARDEN.RELEASE_DEBUG_LINE), 1)
        self.assertEqual(HARDEN.patch_activity(patched), patched)

    def test_existing_unknown_debug_policy_is_not_silently_overwritten(self):
        modified = ACTIVITY.replace("super.onCreate(savedInstanceState)",
                                    "super.onCreate(savedInstanceState)\n    android.webkit.WebView.setWebContentsDebuggingEnabled(true)")
        with self.assertRaises(ValueError):
            HARDEN.patch_activity(modified)

    def test_unrecognized_activity_fails_before_writing_manifest(self):
        (self.main / "MainActivity.kt").write_text("class MainActivity : OtherActivity() {}")
        with self.assertRaises(ValueError):
            HARDEN.harden(self.project)
        self.assertEqual((self.main / "AndroidManifest.xml").read_text(), MANIFEST)

    def test_apk_verifier_rejects_network_or_backup_enabled(self):
        manifest = "A: android:allowBackup(0x01010280)=(type 0x12)0x0\nA: android:usesCleartextTraffic(0x010104ec)=(type 0x12)0x0\nA: android:debuggable(0x0101000f)=(type 0x12)0x0\nA: android:fullBackupContent(0x010104eb)=@0x7f110000\nA: android:dataExtractionRules(0x0101063e)=@0x7f110001"
        HARDEN.verify_manifest_dump("permission: POST_NOTIFICATIONS", manifest)
        with self.assertRaises(ValueError):
            HARDEN.verify_manifest_dump("uses-permission: android.permission.INTERNET", manifest)
        with self.assertRaises(ValueError):
            HARDEN.verify_manifest_dump("", manifest.replace("0x0\n", "0xffffffff\n", 1))
        with self.assertRaises(ValueError):
            HARDEN.verify_manifest_dump("", manifest.replace("android:debuggable(0x0101000f)=(type 0x12)0x0", "android:debuggable(0x0101000f)=(type 0x12)0xffffffff"))
        with self.assertRaises(ValueError):
            HARDEN.verify_manifest_dump("", "")

    def test_native_library_requires_16k_load_segment_alignment(self):
        data = bytearray(120)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
        struct.pack_into("<I", data, 64, 1)
        struct.pack_into("<Q", data, 64 + 48, 16384)
        HARDEN.verify_elf_page_alignment(data)
        struct.pack_into("<Q", data, 64 + 48, 4096)
        with self.assertRaises(ValueError):
            HARDEN.verify_elf_page_alignment(data)
        struct.pack_into("<Q", data, 64 + 48, 16384)
        struct.pack_into("<Q", data, 64 + 16, 4096)
        with self.assertRaises(ValueError):
            HARDEN.verify_elf_page_alignment(data)

    def test_native_library_rejects_truncated_or_malformed_headers(self):
        for data in (b"", b"not an ELF" * 20, b"\x7fELF\x02\x01" + b"\0" * 114):
            with self.assertRaises(ValueError):
                HARDEN.verify_elf_page_alignment(data)

    def test_macos_rejects_homebrew_and_unbundled_relative_libraries(self):
        output = '''qpdf (architecture arm64):
    /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)
    /System/Library/Frameworks/Security.framework/Versions/A/Security (compatibility version 1.0.0, current version 1.0.0)
    /opt/homebrew/lib/libqpdf.30.dylib (compatibility version 30.0.0, current version 30.0.0)
    @rpath/libcrypto.dylib (compatibility version 3.0.0, current version 3.0.0)
'''
        self.assertEqual(MAC.external_dependencies(output), ["/opt/homebrew/lib/libqpdf.30.dylib", "@rpath/libcrypto.dylib"])


if __name__ == "__main__":
    unittest.main()
