#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  GENERATE-ICONS — Script Universale per Generare Tutte le Icone
  
  Sorgente: assets/icon-master.png (1024x1024)
  Output:   src-tauri/icons/* (tutte le piattaforme)
  
  Requisiti: pip3 install Pillow
  Uso:       python3 scripts/generate-icons.py
═══════════════════════════════════════════════════════════════
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("❌ Pillow non installato. Esegui: pip3 install Pillow")
    sys.exit(1)


# ── Paths ────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
MASTER_ICON = ROOT / "assets" / "icon-master.png"
ICONS_DIR = ROOT / "src-tauri" / "icons"


def ensure_dirs():
    """Crea le cartelle di output."""
    ICONS_DIR.mkdir(parents=True, exist_ok=True)
    (ICONS_DIR / "android").mkdir(exist_ok=True)
    for dpi in ["mipmap-mdpi", "mipmap-hdpi", "mipmap-xhdpi", "mipmap-xxhdpi", "mipmap-xxxhdpi"]:
        (ICONS_DIR / "android" / dpi).mkdir(parents=True, exist_ok=True)
    (ICONS_DIR / "ios").mkdir(exist_ok=True)


def resize(img: Image.Image, size: int) -> Image.Image:
    """Resize con antialiasing di alta qualità."""
    return img.resize((size, size), Image.LANCZOS)


def make_rounded(img: Image.Image, size: int, radius_ratio: float = 0.22) -> Image.Image:
    """Crea un'icona con bordi arrotondati stile macOS."""
    img = resize(img, size)
    radius = int(size * radius_ratio)
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle([(0, 0), (size - 1, size - 1)], radius=radius, fill=255)
    result = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    result.paste(img, (0, 0), mask)
    return result


def generate_standard_icons(master: Image.Image):
    """Genera le icone standard per Tauri (macOS/Linux/Windows)."""
    print("📐 Generando icone standard...")
    
    # App icon principale
    resize(master, 1024).save(ICONS_DIR / "icon.png")
    
    # Dimensioni standard Tauri
    sizes = {
        "32x32.png": 32,
        "64x64.png": 64,
        "128x128.png": 128,
        "128x128@2x.png": 256,
    }
    for name, size in sizes.items():
        resize(master, size).save(ICONS_DIR / name)
        print(f"  ✅ {name} ({size}x{size})")


def generate_tray_icon(master: Image.Image):
    """Genera l'icona tray 44x44 con bordi arrotondati."""
    print("🔔 Generando icona tray (44x44 rounded)...")
    rounded = make_rounded(master, 44, radius_ratio=0.22)
    rounded.save(ICONS_DIR / "tray-icon.png")
    print("  ✅ tray-icon.png (44x44)")


def generate_windows_icons(master: Image.Image):
    """Genera le icone Windows Store + .ico."""
    print("🪟 Generando icone Windows...")
    
    # Windows Store tiles
    win_sizes = {
        "Square30x30Logo.png": 30,
        "Square44x44Logo.png": 44,
        "Square71x71Logo.png": 71,
        "Square89x89Logo.png": 89,
        "Square107x107Logo.png": 107,
        "Square142x142Logo.png": 142,
        "Square150x150Logo.png": 150,
        "Square284x284Logo.png": 284,
        "Square310x310Logo.png": 310,
        "StoreLogo.png": 50,
    }
    for name, size in win_sizes.items():
        resize(master, size).save(ICONS_DIR / name)
        print(f"  ✅ {name} ({size}x{size})")
    
    # .ico (multi-size)
    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    ico_images = [resize(master, s) for s in ico_sizes]
    ico_images[0].save(
        ICONS_DIR / "icon.ico",
        format="ICO",
        sizes=[(s, s) for s in ico_sizes],
        append_images=ico_images[1:]
    )
    print("  ✅ icon.ico (multi-size)")


def generate_macos_icns(master: Image.Image):
    """Genera icon.icns per macOS usando iconutil."""
    print("🍎 Generando icon.icns per macOS...")
    
    iconset_dir = ICONS_DIR / "icon.iconset"
    iconset_dir.mkdir(exist_ok=True)
    
    icns_sizes = {
        "icon_16x16.png": 16,
        "icon_16x16@2x.png": 32,
        "icon_32x32.png": 32,
        "icon_32x32@2x.png": 64,
        "icon_128x128.png": 128,
        "icon_128x128@2x.png": 256,
        "icon_256x256.png": 256,
        "icon_256x256@2x.png": 512,
        "icon_512x512.png": 512,
        "icon_512x512@2x.png": 1024,
    }
    for name, size in icns_sizes.items():
        resize(master, size).save(iconset_dir / name)
    
    # Converti con iconutil (solo macOS)
    if sys.platform == "darwin":
        try:
            subprocess.run(
                ["iconutil", "-c", "icns", str(iconset_dir), "-o", str(ICONS_DIR / "icon.icns")],
                check=True, capture_output=True
            )
            print("  ✅ icon.icns")
        except subprocess.CalledProcessError as e:
            print(f"  ⚠️  iconutil fallito: {e.stderr.decode()}")
    else:
        print("  ⚠️  iconutil disponibile solo su macOS, .icns non generato")
    
    # Pulizia iconset temporanea
    shutil.rmtree(iconset_dir, ignore_errors=True)


def generate_android_icons(master: Image.Image):
    """Genera le icone Android (adaptive icons)."""
    print("🤖 Generando icone Android...")
    
    android_sizes = {
        "mipmap-mdpi": 48,
        "mipmap-hdpi": 72,
        "mipmap-xhdpi": 96,
        "mipmap-xxhdpi": 144,
        "mipmap-xxxhdpi": 192,
    }
    for dpi, size in android_sizes.items():
        # Foreground (icona intera)
        resize(master, size).save(ICONS_DIR / "android" / dpi / "ic_launcher_foreground.png")
        # Round (con bordi arrotondati)
        make_rounded(master, size).save(ICONS_DIR / "android" / dpi / "ic_launcher_round.png")
        print(f"  ✅ android/{dpi}/ ({size}x{size})")


def generate_ios_icons(master: Image.Image):
    """Genera le icone iOS (AppIcon set)."""
    print("📱 Generando icone iOS...")
    
    ios_sizes = {
        "AppIcon-20x20@1x.png": 20,
        "AppIcon-20x20@2x.png": 40,
        "AppIcon-20x20@2x-1.png": 40,
        "AppIcon-20x20@3x.png": 60,
        "AppIcon-29x29@1x.png": 29,
        "AppIcon-29x29@2x.png": 58,
        "AppIcon-29x29@2x-1.png": 58,
        "AppIcon-29x29@3x.png": 87,
        "AppIcon-40x40@1x.png": 40,
        "AppIcon-40x40@2x.png": 80,
        "AppIcon-40x40@2x-1.png": 80,
        "AppIcon-40x40@3x.png": 120,
        "AppIcon-60x60@2x.png": 120,
        "AppIcon-60x60@3x.png": 180,
        "AppIcon-76x76@1x.png": 76,
        "AppIcon-76x76@2x.png": 152,
        "AppIcon-83.5x83.5@2x.png": 167,
        "AppIcon-512@2x.png": 1024,
    }
    for name, size in ios_sizes.items():
        resize(master, size).save(ICONS_DIR / "ios" / name)
    print(f"  ✅ {len(ios_sizes)} icone iOS generate")


def main():
    print("═" * 60)
    print("  GENERATE-ICONS — Generazione Completa da icon-master.png")
    print("═" * 60)
    print()
    
    if not MASTER_ICON.exists():
        print(f"❌ File sorgente non trovato: {MASTER_ICON}")
        print("   Crea un'icona 1024x1024 PNG in: assets/icon-master.png")
        sys.exit(1)
    
    master = Image.open(MASTER_ICON).convert("RGBA")
    w, h = master.size
    print(f"📎 Sorgente: {MASTER_ICON} ({w}x{h})")
    if w < 1024 or h < 1024:
        print("⚠️  Attenzione: la sorgente è più piccola di 1024x1024, la qualità potrebbe soffrire")
    print()
    
    ensure_dirs()
    
    generate_standard_icons(master)
    print()
    generate_tray_icon(master)
    print()
    generate_macos_icns(master)
    print()
    generate_windows_icons(master)
    print()
    generate_android_icons(master)
    print()
    generate_ios_icons(master)
    
    print()
    print("═" * 60)
    print("  ✅ TUTTE LE ICONE GENERATE CON SUCCESSO")
    print(f"  📁 Output: {ICONS_DIR}")
    print("═" * 60)


if __name__ == "__main__":
    main()
