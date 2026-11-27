"""On-demand evidence of relay activity from existing sockets and log tails."""
from collections import Counter
import os
from pathlib import Path
import re
import subprocess

from manager import FIRST, LAST


LOG_BUDGET = 512 * 1024
TAIL_LIMIT = 32 * 1024
RECORD = re.compile(
    rb'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) port=(\d+) error=\d+ in=(\d+) out=(\d+) duration=\d+'
)


def connected_ports(ports):
    try:
        result = subprocess.run(
            ['ss', '-Hnt', 'state', 'established', f'( sport >= :{FIRST} and sport <= :{LAST} )'],
            capture_output=True, text=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    counts = Counter()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            port = fields[-2].rsplit(':', 1)[-1]
            if port.isascii() and port.isdecimal() and int(port) in ports:
                counts[int(port)] += 1
    return counts


def last_forwarded(path, port, limit):
    try:
        with path.open('rb') as log:
            size = os.fstat(log.fileno()).st_size
            offset = max(0, size - limit)
            log.seek(offset)
            data = log.read(limit)
    except OSError:
        return None
    if offset:
        data = data.partition(b'\n')[2]
    # A record being written concurrently is not a complete observation.
    records = data.split(b'\n')[:-1]
    for line in reversed(records):
        match = RECORD.fullmatch(line.rstrip(b'\r'))
        if match and int(match[2]) == port and (int(match[3]) or int(match[4])):
            return match[1].decode('ascii')
    return None


def snapshot(rows, log_dir):
    ports = {row['port'] for row in rows}
    if not ports:
        return {}
    limit = min(TAIL_LIMIT, LOG_BUDGET // len(ports))
    counts = connected_ports(ports)
    return {port: {'connections': None if counts is None else counts[port],
                   'recent': last_forwarded(Path(log_dir) / f'relay-{port}.log', port, limit)}
            for port in ports}
