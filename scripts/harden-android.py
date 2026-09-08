#!/usr/bin/env python3
"""Apply and verify LexFlow's offline policy after `tauri android init`.

The generated native project is ignored by Git, so these changes must be applied
on every fresh initialization. Debug keeps access to the local Vite dev server.
Release removes INTERNET even when a dependency requests it during manifest merge.
"""

import argparse
from pathlib import Path
import re
import struct
import subprocess
import zipfile
import xml.etree.ElementTree as ET

ANDROID = "http://schemas.android.com/apk/res/android"
TOOLS = "http://schemas.android.com/tools"
ET.register_namespace("android", ANDROID)
ET.register_namespace("tools", TOOLS)
A = "{" + ANDROID + "}"
T = "{" + TOOLS + "}"
NETWORK_PERMISSIONS = ("android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE")
DOMAINS = ("root", "file", "database", "sharedpref", "external", "device_root", "device_file", "device_database", "device_sharedpref")
SECURE_LINE = "window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)"
RELEASE_DEBUG_LINE = "if (!BuildConfig.DEBUG) android.webkit.WebView.setWebContentsDebuggingEnabled(false)"


def xml_write(path, root):
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.indent(root, space="    ")
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def patch_activity(source):
    if source.count(SECURE_LINE) == 1 and source.count(RELEASE_DEBUG_LINE) == 1:
        return source
    if source.count("FLAG_SECURE") != source.count(SECURE_LINE) or source.count(SECURE_LINE) > 1 or not re.search(r"class\s+MainActivity\s*:\s*TauriActivity\(\)", source):
        raise ValueError("Unsupported MainActivity: review the native screenshot protection manually")
    if source.count("setWebContentsDebuggingEnabled") != source.count(RELEASE_DEBUG_LINE) or source.count(RELEASE_DEBUG_LINE) > 1:
        raise ValueError("Unsupported MainActivity: review the native WebView debugging policy manually")
    pattern = r"(?m)^(\s*)super\.onCreate\(savedInstanceState\)\s*$"
    if len(re.findall(pattern, source)) != 1:
        raise ValueError("Unsupported MainActivity.onCreate: no unambiguous insertion point")
    missing = [line for line in (SECURE_LINE, RELEASE_DEBUG_LINE) if line not in source]
    return re.sub(pattern, lambda m: m.group(0) + "".join("\n" + m.group(1) + line for line in missing), source)


def harden(project):
    src = project / "app/src"
    manifest_path = src / "main/AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    app = root.find("application")
    if app is None:
        raise ValueError("Generated manifest has no application")
    activities = list((src / "main").rglob("MainActivity.kt"))
    if len(activities) != 1:
        raise ValueError("Expected exactly one generated MainActivity.kt")
    # Validate the Kotlin template before writing any generated file.
    activity = patch_activity(activities[0].read_text())

    for permission in list(root):
        if permission.tag.startswith("uses-permission") and permission.get(A + "name") in NETWORK_PERMISSIONS:
            root.remove(permission)
    app.set(A + "allowBackup", "false")
    app.set(A + "fullBackupContent", "@xml/lexflow_backup_rules")
    app.set(A + "dataExtractionRules", "@xml/lexflow_data_extraction_rules")
    app.set(A + "usesCleartextTraffic", "false")

    # A release overlay has higher priority than main and dependency manifests.
    release_path = src / "release/AndroidManifest.xml"
    release = ET.parse(release_path).getroot() if release_path.exists() else ET.Element("manifest")
    for child in list(release):
        if child.tag.startswith("uses-permission") and child.get(A + "name") in NETWORK_PERMISSIONS:
            release.remove(child)
    permission_index = 0
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for name in NETWORK_PERMISSIONS:
            release.insert(permission_index, ET.Element(tag, {A + "name": name, T + "node": "remove"}))
            permission_index += 1
    release_app = release.find("application")
    if release_app is None:
        release_app = ET.SubElement(release, "application")
    for name in ("allowBackup", "usesCleartextTraffic", "fullBackupContent", "dataExtractionRules"):
        release_app.set(A + name, app.get(A + name))
    release_app.set(A + "debuggable", "false")
    # Deliberate false in the release-only overlay; debug builds use another overlay.
    # Suppress this single manifest warning, keeping the other Android lint checks.
    ignored = set(filter(None, release_app.get(T + "ignore", "").split(",")))
    ignored.add("HardcodedDebugMode")
    release_app.set(T + "ignore", ",".join(sorted(ignored)))
    replace = set(filter(None, release_app.get(T + "replace", "").split(",")))
    replace.update("android:" + name for name in ("allowBackup", "usesCleartextTraffic", "fullBackupContent", "dataExtractionRules", "debuggable"))
    release_app.set(T + "replace", ",".join(sorted(replace)))

    debug_path = src / "debug/AndroidManifest.xml"
    debug = ET.parse(debug_path).getroot() if debug_path.exists() else ET.Element("manifest")
    if not any(p.get(A + "name") == NETWORK_PERMISSIONS[0] for p in debug.findall("uses-permission")):
        ET.SubElement(debug, "uses-permission", {A + "name": NETWORK_PERMISSIONS[0]})
    debug_app = debug.find("application")
    if debug_app is None:
        debug_app = ET.SubElement(debug, "application")
    debug_app.set(A + "usesCleartextTraffic", "true")
    debug_replace = set(filter(None, debug_app.get(T + "replace", "").split(",")))
    debug_replace.add("android:usesCleartextTraffic")
    debug_app.set(T + "replace", ",".join(sorted(debug_replace)))

    legacy = ET.Element("full-backup-content")
    for domain in DOMAINS:
        ET.SubElement(legacy, "exclude", {"domain": domain, "path": "."})
    modern = ET.Element("data-extraction-rules")
    for transport in ("cloud-backup", "device-transfer"):
        section = ET.SubElement(modern, transport)
        for domain in DOMAINS:
            ET.SubElement(section, "exclude", {"domain": domain, "path": "."})

    xml_write(manifest_path, root)
    xml_write(release_path, release)
    xml_write(debug_path, debug)
    xml_write(src / "main/res/xml/lexflow_backup_rules.xml", legacy)
    xml_write(src / "main/res/xml/lexflow_data_extraction_rules.xml", modern)
    activities[0].write_text(activity)


def verify_manifest_dump(permissions, manifest):
    for permission in NETWORK_PERMISSIONS:
        if permission in permissions:
            raise ValueError(f"Release APK unexpectedly grants {permission}")
    for attribute in ("allowBackup", "usesCleartextTraffic", "debuggable"):
        matches = re.findall(r"android:" + attribute + r"\([^)]*\)=\(type 0x12\)(0x[0-9a-fA-F]+)", manifest)
        if len(matches) != 1 or int(matches[0], 16) != 0:
            raise ValueError(f"Release APK must set android:{attribute}=false")
    for attribute in ("fullBackupContent", "dataExtractionRules"):
        if not re.search(r"android:" + attribute + r"\([^)]*\)=@0x[0-9a-fA-F]+", manifest):
            raise ValueError(f"Release APK is missing android:{attribute} exclusion rules")


def verify_elf_page_alignment(data, name="native library"):
    """Validate load-segment alignment for Android's 16 KiB ARM64/x86_64 loader."""
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"{name}: expected a little-endian ELF64 library")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize < 56 or phnum == 0 or phnum > 1024 or phoff + phentsize * phnum > len(data):
        raise ValueError(f"{name}: invalid ELF program headers")
    loads = 0
    for index in range(phnum):
        offset = phoff + index * phentsize
        if struct.unpack_from("<I", data, offset)[0] != 1:
            continue
        loads += 1
        file_offset, address = struct.unpack_from("<QQ", data, offset + 8)
        alignment = struct.unpack_from("<Q", data, offset + 48)[0]
        if alignment < 16384 or alignment & (alignment - 1) or file_offset % 16384 != address % 16384:
            raise ValueError(f"{name}: load segment is not compatible with 16 KiB pages")
    if not loads:
        raise ValueError(f"{name}: no ELF load segment")


def verify_apk_native_alignment(apk):
    with zipfile.ZipFile(apk) as archive:
        libraries = [entry for entry in archive.infolist()
                     if entry.filename.startswith(("lib/arm64-v8a/", "lib/x86_64/")) and entry.filename.endswith(".so")]
        for entry in libraries:
            if entry.file_size > 256 * 1024 * 1024:
                raise ValueError(f"{entry.filename}: native library exceeds verification size limit")
            verify_elf_page_alignment(archive.read(entry), entry.filename)
    return len(libraries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path("src-tauri/gen/android"))
    parser.add_argument("--verify-apk", type=Path)
    parser.add_argument("--aapt", default="aapt")
    args = parser.parse_args()
    if args.verify_apk:
        permissions = subprocess.check_output([args.aapt, "dump", "permissions", str(args.verify_apk)], text=True)
        manifest = subprocess.check_output([args.aapt, "dump", "xmltree", str(args.verify_apk), "AndroidManifest.xml"], text=True)
        verify_manifest_dump(permissions, manifest)
        libraries = verify_apk_native_alignment(args.verify_apk)
        print(f"16 KiB alignment verified for {libraries} native 64-bit libraries.")
        print("Release APK verified: no Internet permission, cleartext and debugging disabled, backup disabled with exclusion rules.")
    else:
        harden(args.project)
        print("Android hardened: release offline, debugging disabled, backups excluded, FLAG_SECURE applied; debug Vite allowed.")


if __name__ == "__main__":
    main()
