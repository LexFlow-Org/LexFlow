#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════
# LexFlow — Setup Typst Sidecar & Fonts
# Run this after cloning the repo to download the required binaries
# ══════════════════════════════════════════════════════════════════════════
set -euo pipefail

TYPST_VERSION="v0.13.1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TAURI_DIR="$SCRIPT_DIR/../src-tauri"
BIN_DIR="$TAURI_DIR/binaries"
FONT_DIR="$TAURI_DIR/fonts"

echo "🖋️  LexFlow Typst Setup"
echo "========================"

# ── Create directories ──
mkdir -p "$BIN_DIR" "$FONT_DIR"

# ── Detect current platform ──
ARCH=$(uname -m)
OS=$(uname -s)

download_typst() {
  local target="$1"
  local ext="${2:-}"
  local url="https://github.com/typst/typst/releases/download/${TYPST_VERSION}/typst-${target}.tar.xz"
  local outname="typst-${target}${ext}"

  if [ -f "$BIN_DIR/$outname" ]; then
    echo "  ✓ $outname already exists"
    return
  fi

  echo "  ⬇ Downloading $outname..."
  curl -L -o "$BIN_DIR/typst-${target}.tar.xz" "$url"
  cd "$BIN_DIR"
  tar -xf "typst-${target}.tar.xz"
  mv "typst-${target}/typst" "$outname"
  rm -rf "typst-${target}" "typst-${target}.tar.xz"
  chmod +x "$outname"
  echo "  ✓ $outname ready"
  cd "$SCRIPT_DIR"
}

echo ""
echo "📦 Downloading Typst ${TYPST_VERSION} binaries..."

# Always download for current platform
if [ "$OS" = "Darwin" ]; then
  if [ "$ARCH" = "arm64" ]; then
    download_typst "aarch64-apple-darwin"
  else
    download_typst "x86_64-apple-darwin"
  fi
elif [ "$OS" = "Linux" ]; then
  download_typst "x86_64-unknown-linux-musl"
fi

# Optional: download for cross-compilation targets
if [ "${CROSS_COMPILE:-}" = "1" ]; then
  echo ""
  echo "📦 Cross-compile mode: downloading all targets..."
  download_typst "aarch64-apple-darwin"
  download_typst "x86_64-apple-darwin"
  download_typst "x86_64-pc-windows-msvc" ".exe"
fi

# ── Download Fonts ──
echo ""
echo "🔤 Setting up fonts..."

# Libertinus Serif
if [ ! -f "$FONT_DIR/LibertinusSerif-Regular.otf" ]; then
  echo "  ⬇ Downloading Libertinus Serif..."
  curl -L -o "$FONT_DIR/libertinus.zip" \
    "https://github.com/alerque/libertinus/releases/download/v7.051/Libertinus-7.051.zip"
  cd "$FONT_DIR"
  unzip -q -o libertinus.zip
  cp Libertinus-7.051/static/OTF/LibertinusSerif-Regular.otf .
  cp Libertinus-7.051/static/OTF/LibertinusSerif-Bold.otf .
  cp Libertinus-7.051/static/OTF/LibertinusSerif-Italic.otf .
  cp Libertinus-7.051/static/OTF/LibertinusSerif-BoldItalic.otf .
  rm -rf Libertinus-7.051 libertinus.zip
  echo "  ✓ Libertinus Serif installed"
  cd "$SCRIPT_DIR"
else
  echo "  ✓ Libertinus Serif already exists"
fi

# Cinzel
if [ ! -f "$FONT_DIR/Cinzel-Regular.ttf" ]; then
  echo "  ⬇ Downloading Cinzel..."
  curl -L -o "$FONT_DIR/Cinzel-Regular.ttf" \
    "https://github.com/google/fonts/raw/main/ofl/cinzel/Cinzel%5Bwght%5D.ttf"
  echo "  ✓ Cinzel installed"
else
  echo "  ✓ Cinzel already exists"
fi

echo ""
echo "✅ Typst setup complete!"
echo ""
echo "Files:"
ls -lh "$BIN_DIR"/typst-* 2>/dev/null || echo "  (no binaries)"
echo ""
ls -lh "$FONT_DIR"/*.otf "$FONT_DIR"/*.ttf 2>/dev/null || echo "  (no fonts)"
echo ""
echo "You can now build LexFlow with: cd src-tauri && cargo build"
