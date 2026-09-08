#!/bin/sh
set -eu
windows_build_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PATH="$windows_build_root/wrappers:$windows_build_root/llvm/LLVM-22.1.8-macOS-ARM64/bin:$windows_build_root/cargo-xwin/cargo_xwin-0.23.1.data/scripts:$windows_build_root/nsis/makensis/3.12/bin:$PATH"
export NSISDIR="$windows_build_root/nsis/makensis/3.12/share/nsis"
export XWIN_CACHE_DIR="$windows_build_root/xwin"
export XWIN_ARCH=x86_64
export CARGO_TARGET_DIR="$windows_build_root/target"
export CARGO_HOME="$windows_build_root/cargo-home"
export CARGO_BUILD_JOBS=2
cd "$windows_build_root/project"
node node_modules/@tauri-apps/cli/tauri.js build --runner cargo-xwin --target x86_64-pc-windows-msvc --config src-tauri/tauri.windows.conf.json --config "$windows_build_root/cross-build-config.json" --ci --no-sign -- --locked
