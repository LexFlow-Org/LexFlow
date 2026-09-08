#!/bin/sh
# Run from any working directory, without downloads or automatic .env reads.
set -eu
umask 077
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3 non trovato. Installa Python 3 e la libreria cryptography.' >&2
    exit 1
fi
if [ "$#" -eq 0 ]; then
    set -- generate
fi
exec python3 "$script_dir/generate_license_v2.py" "$@"
