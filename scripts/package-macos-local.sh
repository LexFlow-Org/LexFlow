#!/bin/sh
# Package an already-built LexFlow.app locally; never builds or launches it.
set -eu
TASK_SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TASK_REPO=$(cd "$TASK_SCRIPT_DIR/.." && pwd)
exec python3 - "$TASK_REPO" "$@" <<'PY'
from pathlib import Path
import argparse
import hashlib
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile


def reject_existing_output(path):
    # exists() alone misses dangling symbolic links.
    if path.exists() or path.is_symlink():
        raise ValueError("La destinazione esiste già. Scegli un nuovo nome DMG.")


def publish_new_image(source, destination):
    """Copy a verified image, then atomically publish without replacing a name."""
    reject_existing_output(destination)
    staged = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".lexflow-dmg-", suffix=".tmp",
                                         dir=destination.parent, delete=False) as output:
            staged = Path(output.name)
            with source.open("rb") as input_file:
                shutil.copyfileobj(input_file, output, length=1024 * 1024)
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            os.fsync(output.fileno())
        # Same-filesystem hard link is atomic and fails if destination appeared
        # during the copy, including a symlink. Never fall back to overwrite.
        os.link(staged, destination, follow_symlinks=False)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def normalize_bundle_permissions(app):
    """Change permissions only inside our generated temporary app copy."""
    app.chmod(0o755)
    for path in app.rglob("*"):
        if path.is_symlink():
            # Preserve legitimate internal bundle links; reject links outside
            # the copy before signing or operating on their possible targets.
            if not path.resolve(strict=True).is_relative_to(app):
                raise ValueError("Il bundle contiene un collegamento esterno non consentito.")
            continue
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            path.chmod(0o644)
        else:
            raise ValueError("Il bundle contiene un elemento non regolare.")
    for path in (app / "Contents/MacOS").iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("Contents/MacOS deve contenere eseguibili regolari.")
        path.chmod(0o755)


def binary_architectures(binary):
    if binary.is_symlink() or not binary.is_file():
        raise ValueError(f"Eseguibile richiesto assente o non regolare: {binary.name}")
    result = subprocess.run(["/usr/bin/lipo", "-archs", str(binary)],
                            check=True, capture_output=True, text=True)
    return set(result.stdout.split())


def thin_binary(binary, architecture):
    present = binary_architectures(binary)
    if architecture not in present:
        raise ValueError(f"{binary.name} non contiene l'architettura {architecture}.")
    if present != {architecture}:
        temporary = binary.with_name(binary.name + ".thin")
        subprocess.run(["/usr/bin/lipo", str(binary), "-thin", architecture,
                        "-output", str(temporary)], check=True)
        temporary.chmod(0o755)
        temporary.replace(binary)
    if binary_architectures(binary) != {architecture}:
        raise ValueError(f"Architettura finale non valida per {binary.name}.")


def main():
    repo = Path(sys.argv[1])
    parser = argparse.ArgumentParser(
        prog="scripts/package-macos-local.sh",
        description="Crea un DMG locale con firma ad hoc da una LexFlow.app già compilata.",
        epilog="Richiede macOS, Python 3.11+ e strumenti Xcode. Lavora in /private/tmp, senza modificare "
               "l'app sorgente. Non compila, non avvia l'app e non usa certificati Developer ID.")
    parser.add_argument("--app", required=True, type=Path, help="Percorso della .app già generata")
    parser.add_argument("--output", required=True, type=Path, help="Nuovo file .dmg (mai sovrascritto)")
    parser.add_argument("--arch", required=True, choices=("arm64", "x86_64"),
                        help="Architettura del pacchetto: Apple Silicon o Intel")
    args = parser.parse_args(sys.argv[2:])
    if sys.version_info < (3, 11):
        parser.error("Python 3.11 o successivo è richiesto.")
    output = args.output.expanduser().absolute()
    if output.suffix.lower() != ".dmg":
        parser.error("--output deve terminare con .dmg")
    # Check output before app inspection or calling any packaging utility.
    try:
        reject_existing_output(output)
        parent = output.parent.resolve(strict=True)
        if not parent.is_dir():
            raise ValueError("La directory di destinazione non è valida.")
        output = parent / output.name
        reject_existing_output(output)
        source_app = args.app.expanduser().resolve(strict=True)
        if not source_app.is_dir() or source_app.suffix != ".app":
            raise ValueError("--app deve indicare un bundle .app esistente.")
        info = plistlib.loads((source_app / "Contents/Info.plist").read_bytes())
        if info.get("CFBundleIdentifier") != "com.pietrolongo.lexflow":
            raise ValueError("Il bundle sorgente non è LexFlow.")
        executable = info.get("CFBundleExecutable", "")
        if not executable or Path(executable).name != executable or executable in (".", ".."):
            raise ValueError("Nome eseguibile principale non valido nel bundle.")
        entitlements = repo / "src-tauri/entitlements.mac.plist"
        if not entitlements.is_file():
            raise ValueError("Entitlements macOS del progetto mancanti.")
        if sys.platform != "darwin":
            raise ValueError("Il packaging locale richiede macOS.")
        utilities = ["/usr/bin/ditto", "/usr/bin/xattr", "/usr/bin/codesign", "/usr/bin/hdiutil",
                     "/usr/bin/lipo"]
        if any(not os.access(path, os.X_OK) for path in utilities):
            raise ValueError("Mancano gli strumenti di packaging macOS.")
        native_names = ("qpdf", "typst", executable)
        for name in native_names:
            if args.arch not in binary_architectures(source_app / "Contents/MacOS" / name):
                raise ValueError(f"Il bundle sorgente non contiene {args.arch} in {name}.")
        with tempfile.TemporaryDirectory(prefix="lexflow-macos-package-", suffix=".noindex",
                                         dir="/private/tmp") as scratch:
            work = Path(scratch)
            volume = work / "volume"
            volume.mkdir(mode=0o755)
            (volume / ".metadata_never_index").touch(mode=0o644)
            app = volume / "LexFlow.app"
            subprocess.run(["/usr/bin/ditto", "--norsrc", "--noextattr", "--noacl",
                            str(source_app), str(app)], check=True)
            normalize_bundle_permissions(app)
            subprocess.run(["/usr/bin/xattr", "-cr", str(app)], check=True)
            native = [app / "Contents/MacOS" / name for name in native_names]
            for binary in native:
                thin_binary(binary, args.arch)
            signing = ["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime",
                       "--entitlements", str(entitlements)]
            for binary in native:
                subprocess.run([*signing, str(binary)], check=True)
            subprocess.run([*signing, str(app)], check=True)
            subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2",
                            str(app)], check=True)
            for binary in native:
                if binary_architectures(binary) != {args.arch}:
                    raise ValueError(f"Architettura dopo la firma non valida per {binary.name}.")
            (volume / "Applications").symlink_to("/Applications", target_is_directory=True)
            readme = volume / "LEGGIMI.txt"
            readme.write_text(
                "LexFlow — pacchetto locale per macOS\n\n"
                + ("Versione per Mac con chip Apple Silicon (arm64).\n\n" if args.arch == "arm64"
                   else "Versione per Mac con processore Intel (x86_64).\n\n") +
                "Richiede macOS 11 o successivo e Safari/WebKit 16.4 o successivo.\n"
                "Aggiorna i componenti di sistema prima dell'uso offline.\n"
                "Trascina LexFlow.app nella cartella Applications (Applicazioni).\n"
                "Questo pacchetto usa una firma locale ad hoc e non è notarizzato da Apple.\n"
                "Se macOS ne blocca l'apertura, verifica la provenienza del pacchetto e usa\n"
                "l'autorizzazione per questa app in Impostazioni di Sistema > Privacy e sicurezza.\n"
                "Per l'attivazione serve il codice licenza fornito separatamente.\n\n"
                "Prima di aggiornare un archivio esistente, conserva una copia completa\n"
                "con l'app chiusa: il formato V8 non è leggibile dalle versioni precedenti.\n"
                "Il vault è locale e cifrato; allegati ed export restano file separati.\n"
                "Per mantenerli locali scegli cartelle fuori da iCloud/OneDrive.\n"
                "Il collaudo completo dell'app e della rete sui dispositivi di destinazione\n"
                "resta da completare; questa build non certifica l'isolamento dalla rete.\n",
                encoding="utf-8")
            readme.chmod(0o644)
            image = work / "LexFlow.dmg"
            subprocess.run(["/usr/bin/hdiutil", "create", "-volname", "LexFlow", "-srcfolder",
                            str(volume), "-format", "UDZO", "-fs", "HFS+", str(image)], check=True)
            subprocess.run(["/usr/bin/hdiutil", "verify", str(image)], check=True)
            publish_new_image(image, output)
        with output.open("rb") as complete:
            digest = hashlib.file_digest(complete, "sha256").hexdigest()
        print(f"DMG creato: {output}\nSHA256: {digest}")
    except (OSError, ValueError, plistlib.InvalidFileException, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Packaging interrotto: {error}\nL'app sorgente non è stata modificata.\n")


if __name__ == "__main__":
    main()
PY
