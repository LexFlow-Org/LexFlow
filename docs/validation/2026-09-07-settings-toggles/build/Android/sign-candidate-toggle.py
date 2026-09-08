from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import zipfile

PROJECT = Path.cwd()
ROOT = Path('/private/tmp/lexflow-validation-2026-09-07/android')
SOURCE = PROJECT / 'src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk'
OUTPUT = ROOT / 'candidate-toggle'
OUTPUT.mkdir(exist_ok=True)
FINAL = OUTPUT / 'LexFlow-1.0.1-Android-arm64.apk'
TOOLS = ROOT / 'sdk/build-tools/36.0.0'
ENV = dict(os.environ, **json.loads((ROOT / 'build-environment.json').read_text()))
KEY_FOLDER = Path('/Users/pielongo/Library/Application Support/LexFlow Build Keys/android-2026-09-06-eb4cb2f3')
CERTIFICATE = 'bab0ab7ef4395793afb278b688233d177c4545c4c49748a0a10409447544eaf5'

def run(arguments):
    result = subprocess.run([str(arg) for arg in arguments], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=ENV, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout

assert not FINAL.exists(), 'Refusing to overwrite an existing candidate'
badging = run([TOOLS / 'aapt', 'dump', 'badging', SOURCE])
assert "versionName='1.0.1'" in badging and "versionCode='253'" in badging
assert "sdkVersion:'24'" in badging and "targetSdkVersion:'36'" in badging
assert "native-code: 'arm64-v8a'" in badging
hardener = ['python3', PROJECT / 'scripts/harden-android.py', '--verify-apk']
run([*hardener, SOURCE, '--aapt', TOOLS / 'aapt'])
aligned = ROOT / 'candidate-toggle-aligned.apk'
assert not aligned.exists()
run([TOOLS / 'zipalign', '-P', '16', '4', SOURCE, aligned])
run([TOOLS / 'apksigner', 'sign', '--ks', KEY_FOLDER / 'release.p12', '--ks-key-alias',
     'lexflow-android-release', '--ks-pass', 'file:' + str(KEY_FOLDER / 'store-password.txt'),
     '--v4-signing-enabled', 'false', '--out', FINAL, aligned])
signature = run([TOOLS / 'apksigner', 'verify', '--verbose', '--print-certs', FINAL])
fingerprint = re.search(r'Signer #1 certificate SHA-256 digest: ([a-f0-9]+)', signature).group(1)
assert fingerprint == CERTIFICATE
zipalign = run([TOOLS / 'zipalign', '-c', '-P', '16', '-v', '4', FINAL])
hardening = run([*hardener, FINAL, '--aapt', TOOLS / 'aapt'])
with zipfile.ZipFile(FINAL) as archive:
    names = archive.namelist()
    assert sorted(n for n in names if n.startswith('lib/') and n.endswith('.so')) == ['lib/arm64-v8a/libapp_lib.so'], 'Unexpected native library duplicate'
    for license_file in (PROJECT / 'src-tauri/licenses').rglob('*'):
        if license_file.is_file():
            assert 'assets/licenses/' + license_file.relative_to(PROJECT / 'src-tauri/licenses').as_posix() in names
    assert not any(name.endswith(('.pem', '.p12', '.jks', '.keystore')) for name in names)
    native = archive.read('lib/arm64-v8a/libapp_lib.so')
    assert bytes.fromhex('ae30f5953a6975bdc5a6523627a6a6c2bdf87948c7f9c26122a510312c10de0d') in native
before = json.loads((ROOT / 'toggle-source-before.json').read_text())
after = json.loads((ROOT / 'toggle-source-after.json').read_text())
assert before == after, 'Source changed during candidate build'
checksum = hashlib.sha256(FINAL.read_bytes()).hexdigest()
metadata = {
    'apk': FINAL.name, 'app_version': '1.0.1', 'android_version_code': 253,
    'apk_bytes': FINAL.stat().st_size, 'apk_sha256': checksum, 'certificate_sha256': fingerprint,
    'min_sdk': 24, 'target_sdk': 36, 'native_libraries': ['arm64-v8a/libapp_lib.so'],
    'minimum_webview_chromium_version': 111, 'elf_page_alignment': 16384, 'zip_page_alignment': 16384,
    'signature_verified': True, 'offline_manifest_verified': True, 'debuggable_manifest_false': True,
    'all_licenses_included': True, 'new_license_public_key_found_in_apk': True,
    'physical_device_tested': False, 'candidate_runtime_tested': False,
    'source_fingerprint_sha256': before['source_fingerprint_sha256'],
    'source_changes': ['settings toggle geometry', 'biometric availability diagnostic command'],
    'android_professional_runtime_validated': False,
    'prior_252_crash_and_rendering_limitations_remain_unresolved': True,
    'runtime_limitations': ['APK253 not executed in an emulator or physical device', 'Previous APK252 reproduced Wry0.54.4 startup Timeout panic during SwiftShader boot with SystemUI ANR', 'Previous APK252 auto GPU display showed white bands; rendering issue attribution unresolved', 'Android vault CRUD and SAF backup/restore not completed', 'Physical device and16KB kernel execution not tested'],
}
(OUTPUT / 'source-fingerprint.json').write_text(json.dumps(before, indent=2) + '\n')
(OUTPUT / 'INSTALLAZIONE.md').write_text((ROOT / 'candidate-toggle-installation.md').read_text())
(OUTPUT / 'verifica-pacchetto.json').write_text(json.dumps(metadata, indent=2) + '\n')
(OUTPUT / 'SHA256SUMS.txt').write_text(checksum + '  ' + FINAL.name + '\n')
(OUTPUT / 'CERTIFICATO-FIRMA.txt').write_text('Certificato APK SHA256: ' + fingerprint + '\nStesso certificato della precedente versione 1.0.1, codici251e252.\n')
for name, text in [('signature', signature), ('zipalign', zipalign), ('hardening', hardening)]:
    (ROOT / ('candidate-toggle-' + name + '-verification.txt')).write_text(text)
print('Candidate signed and verified:', FINAL)
print('SHA256:', checksum)
print('Bytes:', metadata['apk_bytes'])
print(hardening)
