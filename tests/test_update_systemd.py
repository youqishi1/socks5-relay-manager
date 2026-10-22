"""Actual published downgrade and cached upgrade with live independent relays."""
import contextlib
import copy
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys

if os.geteuid() != 0 or os.environ.get('RELAY_DISPOSABLE_HOST') != 'YES':
    raise SystemExit('只允许在明确标记的可丢弃 root 测试主机运行。')

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'scripts'))
from manager import Manager, Error
import access
import diagnostics
import updates
sys.path.insert(0, str(root / 'tests'))
from test_relay import serve, Target, Upstream, PASSWORD

os.umask(0o077)
app = Path('/opt/socks5-relay-manager')
archive = root / '.tools' / ('socks5-relay-manager-v' + (root / 'VERSION').read_text().strip() + '-install.tar.gz')
assert archive.is_file()
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
cache = app / 'cache/downloads'
cache.mkdir(parents=True, exist_ok=True)
shutil.copyfile(archive, cache / digest)
selected = dict(tag='v' + (root / 'VERSION').read_text().strip(), sha256=digest, size=archive.stat().st_size,
                url='https://github.com/' + updates.REPO + '/releases/download/v' + (root / 'VERSION').read_text().strip() + '/' + archive.name)
target, upstream = serve(Target), serve(Upstream)
target.hits = []
upstream.user, upstream.password = 'updater-fixture', PASSWORD
upstream.requests, upstream.exit_source = [], '127.0.0.2'
manager = Manager(ip_url='http://exit.invalid:' + str(target.server_address[1]))
assert not manager.rows(), 'disposable host must start without user profiles'
try:
    with manager.lock():
        row = dict(port=manager.allocate(), upstream_host='127.0.0.1', upstream_port=upstream.server_address[1],
                   upstream_user=upstream.user, upstream_password=PASSWORD, client_user='updater-client',
                   client_password=PASSWORD, sources=['127.0.0.1'], bind='127.0.0.1', enabled=True)
        row['access'] = access.generate([], row['port'])
        manager.apply({row['port']: row})
    original = copy.deepcopy(manager.rows())
    assert manager.verify(row)[0] == '127.0.0.2'
    before_pid = subprocess.check_output(['systemctl', 'show', 'socks-access@' + str(row['port']) + '.service', '-p', 'MainPID'])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        diagnostics.run(manager, [row], Error)
    assert 'SS 回环连接：通过' in output.getvalue(), output.getvalue()
    assert 'TUIC 回环连接：通过' in output.getvalue(), output.getvalue()
    assert PASSWORD not in output.getvalue()
    assert manager.rows() == original
    assert subprocess.check_output(['systemctl', 'show', 'socks-access@' + str(row['port']) + '.service', '-p', 'MainPID']) == before_pid
    print('PASS: real SS/TUIC diagnostic connections preserve all credentials and server PID', flush=True)
    old = updates.release(updates.metadata('/releases/tags/v1.3.3'))
    assert old
    updates.install(manager, old, app)
    assert (app / 'current/VERSION').read_text().strip() == '1.3.3'
    assert manager.rows() == original
    assert manager.verify(row)[0] == '127.0.0.2'
    print('PASS: actual published v1.3.3 downgrade preserves authenticated live relay and private Python', flush=True)
    updates.install(manager, selected, app)
    assert (app / 'current/VERSION').read_text().strip() == selected['tag'][1:]
    assert manager.rows() == original
    assert manager.verify(row)[0] == '127.0.0.2'
    assert len(list((manager.root / 'backups').glob('*.json'))) >= 2
    print('PASS: verified cached upgrade restores new menu with credentials and private runtime intact', flush=True)
finally:
    with manager.lock():
        manager.apply({r['port']: None for r in manager.rows()})
    for server in (target, upstream):
        server.shutdown()
        server.server_close()
