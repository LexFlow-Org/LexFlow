#!/bin/sh
# macOS Finder launcher. The key stays in the owner's local Application Support.
set -u
umask 077
TASK_PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
TASK_ARGUMENT_COUNT=$#
if [ "$#" -eq 0 ]; then
    set -- generate --local-key
fi

"$TASK_PROJECT_DIR/scripts/generate-license.sh" "$@"
TASK_EXIT_STATUS=$?

# Keep a double-clicked Terminal window readable after success or an error.
if [ "$TASK_ARGUMENT_COUNT" -eq 0 ] && [ -t 0 ]; then
    printf '\nPremi Invio per terminare... '
    IFS= read -r TASK_DISMISS || true
fi
exit "$TASK_EXIT_STATUS"
