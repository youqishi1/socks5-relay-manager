"""Render service units for the installed interpreter and systemd version."""
from pathlib import Path
import sys


def render(text, python, version):
    text = text.replace('/usr/bin/python3', python)
    if version >= 240:
        return text
    lines = []
    for line in text.splitlines():
        key = line.partition('=')[0]
        if key in {'ProtectKernelTunables', 'ProtectKernelModules', 'ProtectControlGroups',
                   'RestrictSUIDSGID', 'LockPersonality', 'StartLimitIntervalSec', 'StartLimitBurst'}:
            continue
        if line == '[Service]':
            lines.extend([line, 'StartLimitInterval=60', 'StartLimitBurst=5'])
        elif key == 'ProtectSystem':
            lines.append('ProtectSystem=full')
        elif key == 'ReadWritePaths':
            lines.extend(['ReadWriteDirectories=/var/log/socks5-relay-manager',
                          'ReadOnlyDirectories=/opt/socks5-relay-manager /etc/socks5-relay-manager'])
        elif key == 'StandardError':
            # manager.py opens a private append log before starting either core.
            lines.append('StandardError=null')
        else:
            lines.append(line)
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    source, destination, python, version = sys.argv[1:]
    if not Path(python).is_absolute() or not python.replace('/', '').replace('-', '').replace('.', '').replace('_', '').isalnum():
        raise SystemExit('错误：Python 路径无效。')
    Path(destination).mkdir(mode=0o700, exist_ok=True)
    for name in ('socks-relay@.service', 'socks-access@.service'):
        Path(destination, name).write_text(render(Path(source, name).read_text(), python, int(version)))
