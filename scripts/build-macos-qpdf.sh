#!/bin/sh
# Build pinned, standalone qpdf CPU slices for Tauri. Public sources only.
# qpdf 12.4.1 published 2026-08-27; libjpeg-turbo 3.2.0 published 2026-06-30.
# Source SHA256 values verified against official release metadata on 2026-09-06.
set -eu

usage() {
  cat <<'HELP'
Usage: scripts/build-macos-qpdf.sh [--work-dir DIRECTORY] [--jobs 1..64]

Requires macOS, Xcode Command Line Tools, CMake, Python 3.12+, and curl.
Downloads pinned public sources, builds static qpdf/libjpeg for ARM64 and Intel,
checks architecture/dependencies and a synthetic encryption round trip, then
replaces only the three qpdf macOS sidecars and their distribution licenses.

--work-dir chooses a parent for a NEW temporary build directory. Logs, original
binaries, and PROVENANCE.json stay there. No application data or keys are read.
Environment: LEXFLOW_CMAKE may select a CMake executable; LEXFLOW_BUILD_ROOT may
set the default scratch parent. Default parallelism is 4. Target: macOS 11.0+.
HELP
}

TASK_PARENT=${LEXFLOW_BUILD_ROOT:-${TMPDIR:-/tmp}}
TASK_JOBS=4
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --work-dir) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; TASK_PARENT=$2; shift 2 ;;
    --jobs) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; TASK_JOBS=$2; shift 2 ;;
    *) usage >&2; exit 2 ;;
  esac
done
case "$TASK_JOBS" in ''|*[!0-9]*|0) echo 'Jobs must be between 1 and 64.' >&2; exit 2 ;; esac
[ "$TASK_JOBS" -le 64 ] || { echo 'Jobs must be between 1 and 64.' >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || { echo 'This script requires macOS.' >&2; exit 1; }
TASK_SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TASK_REPO=$(cd "$TASK_SCRIPT_DIR/.." && pwd)
TASK_CMAKE=${LEXFLOW_CMAKE:-$(command -v cmake || true)}
if [ -z "$TASK_CMAKE" ]; then
  for TASK_CANDIDATE in /opt/homebrew/bin/cmake /usr/local/bin/cmake; do
    if [ -x "$TASK_CANDIDATE" ]; then TASK_CMAKE=$TASK_CANDIDATE; break; fi
  done
fi
[ -n "$TASK_CMAKE" ] || { echo 'CMake is required (set LEXFLOW_CMAKE if needed).' >&2; exit 1; }
for TASK_TOOL in python3 curl xcrun; do command -v "$TASK_TOOL" >/dev/null || exit 1; done
python3 -c 'import sys; assert sys.version_info >= (3,12), "Python 3.12+ is required"'
TASK_SDK=$(xcrun --sdk macosx --show-sdk-path)
umask 077
mkdir -p "$TASK_PARENT"
TASK_ROOT=$(mktemp -d "${TASK_PARENT%/}/lexflow-qpdf-build.XXXXXX")
echo "Build workspace: $TASK_ROOT"
trap 'echo "Build files retained at: $TASK_ROOT"' EXIT

TASK_QPDF_VERSION=12.4.1
TASK_JPEG_VERSION=3.2.0
TASK_QPDF_SHA=f045aa277be2356ff53a89a8622945958291177d2483afc20ede7c8a8cd3873c
TASK_JPEG_SHA=6f30092cef9fb839779646608f4ee14ae3cbac989c47fa05e841b0841f09878e
TASK_QPDF_URL="https://github.com/qpdf/qpdf/releases/download/v${TASK_QPDF_VERSION}/qpdf-${TASK_QPDF_VERSION}.tar.gz"
TASK_JPEG_URL="https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/${TASK_JPEG_VERSION}/libjpeg-turbo-${TASK_JPEG_VERSION}.tar.gz"
fetch() {
  curl --fail --location --show-error --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --connect-timeout 20 --max-time 180 --retry 3 "$1" -o "$2"
}
fetch "$TASK_QPDF_URL" "$TASK_ROOT/qpdf.tar.gz"
fetch "$TASK_JPEG_URL" "$TASK_ROOT/jpeg.tar.gz"
python3 - "$TASK_ROOT" "$TASK_QPDF_SHA" "$TASK_JPEG_SHA" <<'PY'
from pathlib import Path
import hashlib, sys, tarfile
root = Path(sys.argv[1])
for name, expected in zip(("qpdf.tar.gz", "jpeg.tar.gz"), sys.argv[2:]):
    archive = root / name
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"SHA256 mismatch: {name}; refusing to extract or build")
    with tarfile.open(archive) as source:
        source.extractall(root, filter="data")
PY
mkdir -p "$TASK_ROOT/jpeg-universal/include" "$TASK_ROOT/jpeg-universal/lib" "$TASK_ROOT/empty-pkgconfig"
for TASK_ARCH in arm64 x86_64; do
  "$TASK_CMAKE" -S "$TASK_ROOT/libjpeg-turbo-$TASK_JPEG_VERSION" -B "$TASK_ROOT/jpeg-$TASK_ARCH" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_SYSROOT="$TASK_SDK" \
    -DCMAKE_OSX_ARCHITECTURES="$TASK_ARCH" -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
    -DENABLE_SHARED=OFF -DENABLE_STATIC=ON -DWITH_SIMD=OFF -DWITH_TURBOJPEG=OFF \
    > "$TASK_ROOT/configure-jpeg-$TASK_ARCH.log" 2>&1
  "$TASK_CMAKE" --build "$TASK_ROOT/jpeg-$TASK_ARCH" --target jpeg-static --parallel "$TASK_JOBS" \
    > "$TASK_ROOT/build-jpeg-$TASK_ARCH.log" 2>&1
done
for TASK_HEADER in jpeglib.h jmorecfg.h jerror.h; do
  cp "$TASK_ROOT/libjpeg-turbo-$TASK_JPEG_VERSION/src/$TASK_HEADER" "$TASK_ROOT/jpeg-universal/include/"
done
cp "$TASK_ROOT/jpeg-arm64/jconfig.h" "$TASK_ROOT/jpeg-universal/include/"
xcrun lipo -create "$TASK_ROOT/jpeg-arm64/libjpeg.a" "$TASK_ROOT/jpeg-x86_64/libjpeg.a" -output "$TASK_ROOT/jpeg-universal/lib/libjpeg.a"
PKG_CONFIG_PATH= PKG_CONFIG_LIBDIR="$TASK_ROOT/empty-pkgconfig" "$TASK_CMAKE" \
  -S "$TASK_ROOT/qpdf-$TASK_QPDF_VERSION" -B "$TASK_ROOT/qpdf-build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_SYSROOT="$TASK_SDK" \
  '-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64' -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_DOC=OFF \
  -DUSE_IMPLICIT_CRYPTO=OFF -DREQUIRE_CRYPTO_NATIVE=ON -DREQUIRE_CRYPTO_OPENSSL=OFF -DREQUIRE_CRYPTO_GNUTLS=OFF \
  -DUSE_INSECURE_RANDOM=OFF -DSKIP_OS_SECURE_RANDOM=OFF \
  -DZLIB_H_PATH="$TASK_SDK/usr/include" -DZLIB_LIB_PATH="$TASK_SDK/usr/lib/libz.tbd" \
  -DLIBJPEG_H_PATH="$TASK_ROOT/jpeg-universal/include" -DLIBJPEG_LIB_PATH="$TASK_ROOT/jpeg-universal/lib/libjpeg.a" \
  > "$TASK_ROOT/configure-qpdf.log" 2>&1
"$TASK_CMAKE" --build "$TASK_ROOT/qpdf-build" --target qpdf --parallel "$TASK_JOBS" > "$TASK_ROOT/build-qpdf.log" 2>&1

python3 - "$TASK_ROOT" "$TASK_REPO" "$TASK_QPDF_VERSION" "$TASK_JPEG_VERSION" "$TASK_QPDF_URL" "$TASK_JPEG_URL" "$TASK_SDK" <<'PY'
from pathlib import Path
import hashlib, importlib.util, json, os, shutil, subprocess, sys
root, repo = map(Path, sys.argv[1:3])
qpdf_version, jpeg_version, qpdf_url, jpeg_url, sdk = sys.argv[3:]
binary = root / "qpdf-build/qpdf/qpdf"
staged = root / "verified-binaries"
staged.mkdir()
spec = importlib.util.spec_from_file_location("verifier", repo / "scripts/verify-macos-sidecars.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
targets = {"aarch64": ["arm64"], "x86_64": ["x86_64"], "universal": ["arm64", "x86_64"]}
for target, architectures in targets.items():
    output = staged / f"qpdf-{target}-apple-darwin"
    if len(architectures) == 1:
        subprocess.run(["xcrun", "lipo", str(binary), "-thin", architectures[0], "-output", str(output)], check=True)
    else:
        shutil.copy2(binary, output)
    output.chmod(0o755)
    verifier.verify(output, architectures)
    load_commands = subprocess.check_output(["otool", "-arch", "all", "-l", str(output)], text=True)
    if load_commands.count("minos 11.0") != len(architectures):
        raise SystemExit("Unexpected macOS deployment target")
# The upstream minimal.pdf is a synthetic test fixture from the verified source.
source = root / f"qpdf-{qpdf_version}/qpdf/qtest/qpdf/minimal.pdf"
args_file = root / "encryption.args"
args_file.write_text("--encrypt\n--user-password=\n--owner-password=synthetic-build-check\n--bits=256\n--extract=n\n--print=none\n--modify=none\n--\n")
password = root / "password.txt"
password.write_text("synthetic-build-check")
def run(arguments, expected=0):
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True, text=True)
    if result.returncode != expected:
        raise SystemExit(f"Synthetic qpdf check failed: {result.stderr}")
    return result.stdout.strip()
version = run(["--version"])
if f"version {qpdf_version}" not in version or run(["--show-crypto"]) != "native":
    raise SystemExit("Unexpected qpdf version or crypto provider")
encrypted, decrypted = root / "encrypted.pdf", root / "decrypted.pdf"
run(["--check", source])
run([source, "@" + str(args_file), encrypted])
run(["--is-encrypted", encrypted])
run(["--password-file=" + str(password), "--decrypt", encrypted, decrypted])
run(["--is-encrypted", decrypted], 2)
run(["--check", decrypted])
if run(["--show-npages", source]) != run(["--show-npages", decrypted]):
    raise SystemExit("Synthetic encryption round trip changed page count")
provenance = {
    "qpdf_version": qpdf_version, "jpeg_version": jpeg_version,
    "sources": [{"url": url, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()}
                for url, name in ((qpdf_url, "qpdf.tar.gz"), (jpeg_url, "jpeg.tar.gz"))],
    "deployment_target": "11.0", "architectures": ["arm64", "x86_64"],
    "sdk": sdk, "compiler": subprocess.check_output(["xcrun", "clang", "--version"], text=True),
    "configuration": "static libqpdf/libjpeg; native crypto; OS secure random; JPEG SIMD disabled; only Apple system dylibs",
    "validation": "all slices verified; native-host synthetic AES-256 encryption/decryption passed",
    "binaries": {path.name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
                 for path in staged.iterdir()},
}
(root / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
# Replace only verified outputs; preserve previous sidecars in the scratch area.
destination = repo / "src-tauri/binaries"
destination.mkdir(parents=True, exist_ok=True)
backup = root / "original-sidecars"
backup.mkdir()
for source in staged.iterdir():
    output = destination / source.name
    if output.exists() or output.is_symlink():
        shutil.copy2(output, backup / output.name, follow_symlinks=False)
    temporary = destination / (source.name + ".verified.tmp")
    shutil.copy2(source, temporary)
    os.replace(temporary, output)
licenses = repo / "src-tauri/licenses/qpdf"
licenses.mkdir(parents=True, exist_ok=True)
for source, name in [(root / f"qpdf-{qpdf_version}/LICENSE.txt", "qpdf-LICENSE.txt"),
                     (root / f"qpdf-{qpdf_version}/NOTICE.md", "qpdf-NOTICE.md"),
                     (root / f"libjpeg-turbo-{jpeg_version}/LICENSE.md", "libjpeg-turbo-LICENSE.md"),
                     (root / f"libjpeg-turbo-{jpeg_version}/README.ijg", "libjpeg-turbo-README.ijg")]:
    shutil.copy2(source, licenses / name)
print("Three qpdf macOS sidecars verified and installed; provenance:", root / "PROVENANCE.json")
PY
