#!/usr/bin/env python3
"""Park and restore the local LexFlow profile for synthetic native release tests.

No existing user data is deleted or copied to the project/cloud folder. Originals
remain in an owner-only local holding directory until an explicit restore.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

LIBRARY = Path.home() / 'Library'
HOLDING = LIBRARY / 'Application Support' / 'LexFlow Validation Sessions'
SCRATCH = Path('/private/tmp/lexflow-validation-2026-09-07/macos')
MARKER = '.lexflow-qa-session'
IDS = ('com.pietrolongo.lexflow', 'com.technojaw.lexflow')


def paths():
    for bundle in IDS:
        for section, suffix in (
            ('Application Support', ''), ('WebKit', ''), ('HTTPStorages', ''),
            ('HTTPStorages', '.binarycookies'), ('Caches', ''), ('Logs', ''),
            ('Preferences', '.plist'), ('Saved Application State', '.savedState'),
        ):
            yield LIBRARY / section / (bundle + suffix)


def save(path, value):
    temporary = path.with_suffix('.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def require_closed():
    result = subprocess.run(['/usr/bin/pgrep', '-x', 'lexflow'], capture_output=True)
    if result.returncode != 1:
        raise SystemExit('LexFlow must be closed; process enumeration must be available.')


def stage():
    require_closed()
    HOLDING.mkdir(mode=0o700, parents=True, exist_ok=True)
    if HOLDING.is_symlink() or HOLDING.stat().st_uid != os.getuid():
        raise SystemExit('Unsafe holding directory.')
    os.chmod(HOLDING, 0o700)
    if any(HOLDING.glob('*/session.json')):
        raise SystemExit('A previous session exists. Restore/check it before starting another.')
    session = HOLDING / time.strftime('%Y%m%d-%H%M%S')
    session.mkdir(mode=0o700)
    ledger = session / 'session.json'
    entries = []
    for index, source in enumerate(paths()):
        if source.is_symlink():
            raise SystemExit('Refusing a symlink profile path: ' + str(source))
        entries.append({'source': str(source), 'original': str(session / ('original-' + str(index))),
                        'existed': source.exists()})
    state = {'session': str(session), 'phase': 'parking', 'entries': entries}
    save(ledger, state)
    # The ledger precedes every rename, so an interrupted stage is recoverable.
    for entry in entries:
        if entry['existed']:
            os.rename(entry['source'], entry['original'])
    fresh = LIBRARY / 'Application Support' / IDS[0]
    fresh.mkdir(mode=0o700)
    (fresh / MARKER).write_text(str(session))
    state['phase'] = 'testing'
    save(ledger, state)
    SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
    save(SCRATCH / 'profile-session.json', {'ledger': str(ledger)})
    print(json.dumps({'phase': state['phase'], 'ledger': str(ledger),
                      'original_locations_preserved': sum(e['existed'] for e in entries)}))


def restore():
    require_closed()
    ledgers = list(HOLDING.glob('*/session.json'))
    if len(ledgers) != 1:
        raise SystemExit('Expected exactly one active profile session.')
    ledger = ledgers[0]
    state = json.loads(ledger.read_text())
    if state['session'] != str(ledger.parent):
        raise SystemExit('Invalid session ledger.')
    if [e['source'] for e in state['entries']] != [str(p) for p in paths()]:
        raise SystemExit('Invalid source paths in ledger.')
    marker = LIBRARY / 'Application Support' / IDS[0] / MARKER
    if state['phase'] == 'testing' and (not marker.is_file() or marker.read_text() != state['session']):
        raise SystemExit('Synthetic profile marker missing; no automatic replacement allowed.')
    state['phase'] = 'restoring'
    save(ledger, state)
    for index, entry in enumerate(state['entries']):
        source = Path(entry['source'])
        original = ledger.parent / ('original-' + str(index))
        if str(original) != entry['original']:
            raise SystemExit('Invalid original path in ledger.')
        synthetic = ledger.parent / ('synthetic-' + str(index))
        if original.exists() or (not entry['existed'] and source.exists()):
            if source.exists():
                if source.is_symlink() or synthetic.exists():
                    raise SystemExit('Unexpected profile state; keeping all data for recovery.')
                os.rename(source, synthetic)
            if original.exists():
                os.rename(original, source)
    state['phase'] = 'restored'
    save(ledger.parent / 'restored.json', state)
    ledger.unlink()
    print(json.dumps({'phase': 'restored', 'synthetic_artifacts': str(ledger.parent),
                      'user_data_deleted': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stage', 'restore'))
    args = parser.parse_args()
    (stage if args.action == 'stage' else restore)()
