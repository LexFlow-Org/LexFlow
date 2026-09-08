#!/bin/sh
# Pinned official Typst release; no latest URLs or unverified binary reuse.
set -eu
usage() {
  cat <<'HELP'
Usage: scripts/fetch-macos-typst.sh [--work-dir DIRECTORY]

Requires macOS, Xcode Command Line Tools, Python 3.12+, and curl.
Downloads official Typst 0.15.1 ARM64/Intel releases, verifies pinned SHA256,
creates and checks the universal executable, and replaces only three Typst
sidecars plus their distribution licenses. Previous binaries and provenance
remain in a new temporary directory under --work-dir (default system temp).
Environment: LEXFLOW_BUILD_ROOT selects the default scratch parent.
HELP
}
TASK_PARENT=${LEXFLOW_BUILD_ROOT:-${TMPDIR:-/tmp}}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --work-dir) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; TASK_PARENT=$2; shift 2 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[ "$(uname -s)" = Darwin ] || { echo 'This script requires macOS.' >&2; exit 1; }
for TASK_TOOL in python3 curl xcrun; do command -v "$TASK_TOOL" >/dev/null || exit 1; done
python3 -c 'import sys; assert sys.version_info >= (3,12), "Python 3.12+ is required"'
TASK_SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TASK_REPO=$(cd "$TASK_SCRIPT_DIR/.." && pwd)
umask 077
mkdir -p "$TASK_PARENT"
TASK_ROOT=$(mktemp -d "${TASK_PARENT%/}/lexflow-typst-fetch.XXXXXX")
echo "Download workspace: $TASK_ROOT"
trap 'echo "Download files retained at: $TASK_ROOT"' EXIT
TASK_VERSION=0.15.1
for TASK_ARCH in aarch64 x86_64; do
  TASK_ASSET="typst-${TASK_ARCH}-apple-darwin.tar.xz"
  curl --fail --location --show-error --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --connect-timeout 20 --max-time 180 --retry 3 \
    "https://github.com/typst/typst/releases/download/v${TASK_VERSION}/${TASK_ASSET}" -o "$TASK_ROOT/$TASK_ASSET"
done
python3 - "$TASK_ROOT" "$TASK_REPO" "$TASK_VERSION" <<'PY'
from pathlib import Path
import hashlib, importlib.util, json, os, shutil, subprocess, sys, tarfile
root, repo = map(Path, sys.argv[1:3])
version = sys.argv[3]
# Official release asset digests verified on 2026-09-06.
digests = {
    "aarch64": "48f62ed034aa3a7978309579ac6ca00045e2ef0da73114e8af27cfd8e74dc05a",
    "x86_64": "7f9fdd9584866245de9a79e0add8f9236fae6f40a8a45e2c4771ccc14db4e0fa",
}
staged = root / "verified-binaries"
staged.mkdir()
for arch, expected in digests.items():
    archive = root / f"typst-{arch}-apple-darwin.tar.xz"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"SHA256 mismatch: {archive.name}; refusing to extract or execute")
    with tarfile.open(archive) as source:
        source.extractall(root, filter="data")
    executable = root / f"typst-{arch}-apple-darwin/typst"
    shutil.copy2(executable, staged / f"typst-{arch}-apple-darwin")
    (staged / f"typst-{arch}-apple-darwin").chmod(0o755)
universal = staged / "typst-universal-apple-darwin"
subprocess.run(["xcrun", "lipo", "-create", str(staged / "typst-aarch64-apple-darwin"),
                str(staged / "typst-x86_64-apple-darwin"), "-output", str(universal)], check=True)
universal.chmod(0o755)
spec = importlib.util.spec_from_file_location("verifier", repo / "scripts/verify-macos-sidecars.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
for target, arches in {"aarch64": ["arm64"], "x86_64": ["x86_64"], "universal": ["arm64", "x86_64"]}.items():
    verifier.verify(staged / f"typst-{target}-apple-darwin", arches)
actual_version = subprocess.check_output([str(universal), "--version"], text=True).strip()
if not actual_version.startswith(f"typst {version} "):
    raise SystemExit(f"Unexpected version: {actual_version}")
provenance = {
    "version": version,
    "sources": [{"url": f"https://github.com/typst/typst/releases/download/v{version}/typst-{arch}-apple-darwin.tar.xz",
                 "sha256": digest} for arch, digest in digests.items()],
    "validation": "all CPU slices and dynamic dependencies verified; native-host --version passed",
    "binaries": {path.name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
                 for path in staged.iterdir()},
}
(root / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
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
licenses = repo / "src-tauri/licenses"
licenses.mkdir(parents=True, exist_ok=True)
for name in ("LICENSE", "NOTICE"):
    arm = root / f"typst-aarch64-apple-darwin/{name}"
    intel = root / f"typst-x86_64-apple-darwin/{name}"
    shutil.copy2(arm, licenses / f"typst-{name}.txt")
    if arm.read_bytes() != intel.read_bytes():
        shutil.copy2(intel, licenses / f"typst-x86_64-{name}.txt")
print("Three Typst macOS sidecars verified and installed; provenance:", root / "PROVENANCE.json")
PY
