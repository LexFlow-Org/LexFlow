#!/bin/sh
set -eu
TASK_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
printf 'macOS richiede la password amministratore per misurare il traffico di LexFlow.\nLa password resta nel Terminale e non viene salvata o inviata in chat.\n'
sudo /usr/bin/python3 "$TASK_SCRIPT_DIR/capture-macos-validation.py"
printf '\nPremi Invio per chiudere. '
IFS= read -r TASK_DISMISS
