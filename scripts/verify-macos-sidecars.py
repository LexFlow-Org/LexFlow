#!/usr/bin/env python3
"""Fail a release if its sidecars need Homebrew or have the wrong CPU slices."""
import argparse
from pathlib import Path
import subprocess


def external_dependencies(otool_output):
    dependencies = []
    for line in otool_output.splitlines():
        if " (compatibility version " not in line:
            continue
        library = line.strip().split(" (compatibility version ", 1)[0]
        if not library.startswith(("/usr/lib/", "/System/Library/")):
            dependencies.append(library)
    return dependencies


def verify(binary, architectures):
    if not binary.is_file():
        raise ValueError(f"Missing sidecar: {binary}")
    subprocess.run(["lipo", str(binary), "-verify_arch", *architectures], check=True, capture_output=True, text=True)
    output = subprocess.check_output(["otool", "-arch", "all", "-L", str(binary)], text=True)
    external = external_dependencies(output)
    if external:
        raise ValueError(f"{binary.name} is not standalone; unbundled libraries: {', '.join(sorted(set(external)))}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("src-tauri/binaries"))
    args = parser.parse_args()
    try:
        for tool in ("typst", "qpdf"):
            for target, architectures in (("aarch64", ["arm64"]), ("x86_64", ["x86_64"]), ("universal", ["arm64", "x86_64"])):
                verify(args.directory / f"{tool}-{target}-apple-darwin", architectures)
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Sidecar release verification failed: {error}\nProvide standalone sidecars for both macOS architectures; renaming a Homebrew binary does not make it portable.\n")
    print("macOS sidecars verified: correct CPU slices, no unbundled dynamic libraries.")


if __name__ == "__main__":
    main()
