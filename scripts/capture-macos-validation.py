#!/usr/bin/env python3
"""Capture only LexFlow/probe traffic; requires the user's macOS administrator authentication."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

BASE = Path('/private/tmp/lexflow-validation-2026-09-07/macos')
FILTER = 'proc=lexflow or eproc=lexflow or proc=qpdf or eproc=qpdf or proc=typst or eproc=typst or proc=lexflow-probe or eproc=lexflow-probe'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=900)
    args = parser.parse_args()
    if not 5 <= args.seconds <= 1800:
        parser.error('Durata consentita: da 5 a 1800 secondi.')
    if os.geteuid() != 0:
        parser.error('macOS richiede privilegi amministrativi: avviare con sudo, senza comunicare la password in chat.')
    uid = int(os.environ.get('SUDO_UID', '-1'))
    if uid < 1 or not BASE.is_dir() or BASE.is_symlink() or BASE.stat().st_uid != uid:
        parser.error('La cartella di collaudo deve essere già predisposta e appartenere all’utente che esegue sudo.')
    stamp = time.strftime('%Y%m%d-%H%M%S')
    capture = BASE / ('network-' + stamp + '.pcapng')
    log = BASE / ('network-' + stamp + '.log')
    stop = BASE / 'stop-capture'
    stop.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(capture, flags, 0o600); os.fchown(fd, uid, -1)
    logfd = os.open(log, flags, 0o600); os.fchown(logfd, uid, -1)
    begin = time.time()
    with os.fdopen(fd, 'wb') as output, os.fdopen(logfd, 'wb') as errors:
        child = subprocess.Popen(['/usr/sbin/tcpdump', '-B', '16384', '-i', 'pktap,all', '-Q', FILTER,
            '-n', '-s', '128', '-U', '-w', '-'], stdout=output, stderr=errors)
        print('Cattura limitata a LexFlow avviata. Lascia aperta questa finestra; termina automaticamente.', flush=True)
        try:
            while child.poll() is None and time.time() - begin < args.seconds and not stop.exists():
                time.sleep(0.25)
        except KeyboardInterrupt:
            pass
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
            child.wait(timeout=10)
    capture_log = log.read_text(errors='replace')
    actual_snaplen = re.search(r'snapshot length (\d+) bytes', capture_log)
    kernel_drops = re.search(r'(\d+) packets dropped by kernel', capture_log)
    result = {'capture': str(capture), 'log': str(log), 'filter': FILTER,
              'duration_seconds': round(time.time() - begin, 3), 'exit_code': child.returncode,
              'requested_snapshot_bytes': 128,
              'actual_snapshot_bytes': int(actual_snaplen.group(1)) if actual_snaplen else None,
              'kernel_dropped_packets': int(kernel_drops.group(1)) if kernel_drops else None,
              'capture_buffer_kib': 16384, 'full_device_traffic_captured': False}
    summary = BASE / ('network-' + stamp + '.json')
    fd = os.open(summary, flags, 0o600); os.fchown(fd, uid, -1)
    with os.fdopen(fd, 'w') as out:
        json.dump(result, out, indent=2); out.write('\n')
    print('Cattura terminata: ' + str(summary))
    return child.returncode

if __name__ == '__main__':
    raise SystemExit(main())
