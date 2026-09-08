#!/bin/sh
set -eu
windows_build_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# Tauri intentionally clears these variables before spawning makensis. Reapply
# the explicit scratch paths here so the unmodified Homebrew tool is relocatable.
export NSISDIR="$windows_build_root/nsis/makensis/3.12/share/nsis"
export NSISCONFDIR="$NSISDIR"
exec "$windows_build_root/nsis/makensis/3.12/bin/makensis" "$@"
