#!/usr/bin/env python3
"""Sample RSS and CPU for the native LexFlow process (excludes WebKit helpers)."""
import argparse
import json
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--seconds', type=int, default=300)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
if not 1 <= args.seconds <= 1800:
    parser.error('duration must be between 1 and 1800 seconds')
start = time.monotonic()
with args.output.open('x') as output:
    while time.monotonic() - start < args.seconds:
        processes = subprocess.run(['/usr/bin/pgrep', '-x', 'lexflow'], capture_output=True, text=True)
        for pid in processes.stdout.split():
            value = subprocess.run(['/bin/ps', '-p', pid, '-o', 'rss=,pcpu='], capture_output=True, text=True)
            fields = value.stdout.split()
            if len(fields) == 2:
                output.write(json.dumps({'unix_seconds': time.time(), 'pid': int(pid),
                    'rss_bytes': int(fields[0]) * 1024, 'cpu_percent': float(fields[1]),
                    'scope': 'native_process_only'}) + '\n')
                output.flush()
        time.sleep(0.5)
