"""Actual installer, systemd startup, repeat install, rollback and persistence."""
import copy
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).parent))
from test_relay import m, serve, Target, Upstream, PASSWORD
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import access

if os.geteuid() != 0 or os.environ.get('RELAY_DISPOSABLE_HOST') != 'YES':
    raise SystemExit('只允许在明确标记的可丢弃 root 测试主机运行。')
os.umask(0o077)
target, upstream, second = serve(Target), serve(Upstream), serve(Upstream)
target.hits = []
upstream.user, upstream.password = 'systemd-test', PASSWORD
upstream.requests, upstream.exit_source = [], '127.0.0.2'
second.user, second.password = 'systemd-other', PASSWORD
second.requests, second.exit_source = [], '127.0.0.3'
manager = m.Manager(ip_url='http://exit.invalid:' + str(target.server_address[1]))
rows = []
try:
    shortcut = Path('/usr/local/bin/sb1')
    assert shortcut.is_symlink() and os.readlink(shortcut) == '/usr/local/bin/socks-menu'
    menu = subprocess.run(['sb1'], input='0\n', text=True, capture_output=True, check=True)
    assert '查看全部连接信息和账密' in menu.stdout
    print('PASS: sb1 opens the actual Chinese management menu', flush=True)
    with manager.lock():
        for i in range(3):
            row = dict(port=manager.allocate(), upstream_host='127.0.0.1', upstream_port=upstream.server_address[1],
                       upstream_user=upstream.user, upstream_password=PASSWORD, client_user='systemd' + str(i),
                       client_password=PASSWORD, sources=['127.0.0.1'], bind='0.0.0.0', enabled=True)
            if i == 1:
                row['bind'] = '127.0.0.1'
                row['access'] = access.generate(rows, row['port'])
            manager.apply({row['port']: row})
            rows.append(row)
    print('PASS: real systemd startup and relay exit verification', flush=True)
    for row in rows:
        subprocess.run(['systemctl', 'is-enabled', '--quiet', manager.backend.unit(row['port'])], check=True)
        assert manager.verify(row)[0] == '127.0.0.2'
    dual = rows[1]
    dual_unit = 'socks-access@' + str(dual['port']) + '.service'
    subprocess.run(['systemctl', 'is-enabled', '--quiet', dual_unit], check=True)
    assert manager.backend.owns_listener(dual['access']['port'], unit=dual_unit, both=True)
    print('PASS: actual encrypted TCP + TUIC service, boot enablement, TCP/UDP listener ownership', flush=True)
    original = manager.pointers()
    subprocess.run(['bash', 'install.sh', '--local'], check=True)
    assert shortcut.is_symlink() and os.readlink(shortcut) == '/usr/local/bin/socks-menu'
    assert manager.pointers() == original
    for row in rows:
        assert manager.verify(row)[0] == '127.0.0.2'
    print('PASS: repeated installation preserves credentials and active revisions', flush=True)
    survivor_unit = manager.backend.unit(rows[1]['port'])
    survivor_pid = subprocess.check_output(['systemctl', 'show', survivor_unit, '--property=MainPID'])
    front_pid = subprocess.check_output(['systemctl', 'show', dual_unit, '--property=MainPID'])
    with manager.lock():
        manager.apply({rows[0]['port']: None})
    assert subprocess.check_output(['systemctl', 'show', survivor_unit, '--property=MainPID']) == survivor_pid
    assert subprocess.check_output(['systemctl', 'show', dual_unit, '--property=MainPID']) == front_pid
    print('PASS: single deletion preserves other service PID', flush=True)
    with manager.lock():
        bad = copy.deepcopy(rows[1])
        bad['upstream_password'] = 'incorrect'
        try:
            manager.apply({bad['port']: bad})
            raise AssertionError('bad upstream unexpectedly accepted')
        except m.Error:
            pass
    assert manager.verify(rows[1])[0] == '127.0.0.2'
    print('PASS: actual systemd transaction rollback', flush=True)
    subprocess.run(['systemctl', 'kill', '--signal=SIGKILL', survivor_unit], check=True)
    import time
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            assert manager.verify(rows[1])[0] == '127.0.0.2'
            break
        except (m.Error, AssertionError):
            time.sleep(0.5)
    else:
        raise AssertionError('systemd did not restart crashed process')
    print('PASS: systemd automatic crash restart', flush=True)
    assert manager.backend.owns_listener(dual['access']['port'], unit=dual_unit, both=True)
    subprocess.run(['systemctl', 'kill', '--signal=SIGKILL', dual_unit], check=True)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if manager.backend.owns_listener(dual['access']['port'], unit=dual_unit, both=True):
            break
        time.sleep(.5)
    else:
        raise AssertionError('dual service did not restart')
    print('PASS: dual service survives inner core restart and recovers from its own crash', flush=True)
    from entrance_profiles import configure
    from diagnostics import local_entrance
    with manager.lock():
        reduced = configure(manager, manager.row(dual['port']), '1')
    assert manager.backend.owns_listener(dual['access']['port'], unit=dual_unit, udp_only=True)
    assert not manager.backend.owns_listener(dual['access']['port'], unit=dual_unit)
    assert local_entrance(manager, reduced, 'tuic')[0] == '127.0.0.2'
    with manager.lock():
        configure(manager, reduced, '3')
    assert manager.backend.owns_listener(dual['access']['port'], unit=dual_unit, both=True)
    print('PASS: actual systemd UDP-only transition, TUIC query and SS listener restoration', flush=True)
    for row in manager.rows():
        manager.backend.apply(row['port'], None)
    # New management process and state load, then systemd restart. This is not a VPS reboot.
    manager = m.Manager(ip_url=manager.ip_url)
    for row in manager.rows():
        manager.backend.apply(row['port'], row)
        assert manager.verify(row)[0] == '127.0.0.2'
    for path in manager.root.rglob('*'):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600), path
    for path in manager.log.glob('*.log'):
        assert path.stat().st_mode & 0o777 == 0o600, path
        assert PASSWORD not in path.read_text(errors='replace'), path
    print('PASS: process restart persistence, boot enablement, credentials/log permissions', flush=True)
    old_release = os.readlink('/opt/socks5-relay-manager/current')
    original_pointers = manager.pointers()
    source_unit = Path('systemd/socks-relay@.service')
    source_text = source_unit.read_text()
    try:
        source_unit.write_text(source_text.replace('ExecStart=/usr/bin/python3', 'ExecStart=/nonexistent-test-python'))
        result = subprocess.run(['bash', 'install.sh', '--local'])
        assert result.returncode != 0, 'broken update should fail'
    finally:
        source_unit.write_text(source_text)
    assert os.readlink('/opt/socks5-relay-manager/current') == old_release
    assert manager.pointers() == original_pointers
    for row in manager.rows():
        assert manager.verify(row)[0] == '127.0.0.2'
    print('PASS: installer/update failure restores old release, unit, binary and running relays', flush=True)

    from shared_access import UNIT
    other = dict(manager.row(dual['port']), port=manager.allocate(), upstream_user=second.user,
                 upstream_port=second.server_address[1], client_user='systemd-other')
    other['access'] = access.generate(manager.rows(), other['port'])
    with manager.lock():
        manager.apply({other['port']: other})
    ports = (dual['port'], other['port'])
    saved_links = access.configs([manager.row(port) for port in ports], '203.0.113.1')
    selection = ','.join(map(str, ports))
    switched = subprocess.run(['sb1'], input='26\n' + selection + '\n1\n8\n0\n',
                              text=True, capture_output=True, check=True)
    assert '已切换 2 个入口' in switched.stdout and switched.stdout.count('共享入口 运行中') == 2
    assert subprocess.run(['systemctl', 'is-enabled', '--quiet', UNIT]).returncode == 0
    for port in ports:
        assert not manager.backend.call('is-active', '--quiet', f'socks-access@{port}.service', required=False)

    def check_shared():
        for port, exit_ip in zip(ports, ('127.0.0.2', '127.0.0.3')):
            row = manager.row(port)
            assert manager.backend.owns_listener(row['access']['port'], unit=UNIT, both=True)
            for protocol in ('tcp', 'tuic'):
                assert local_entrance(manager, row, protocol)[0] == exit_ip

    check_shared()
    assert access.configs([manager.row(port) for port in ports], '203.0.113.1') == saved_links
    print('PASS: menu switches two endpoints to one sing-box with distinct authenticated upstreams and identical exports', flush=True)
    subprocess.run(['bash', 'install.sh', '--local'], check=True)
    check_shared()
    print('PASS: repeated installation preserves shared listeners and both working exits', flush=True)

    with manager.lock():
        bad = dict(manager.row(other['port']), upstream_password='incorrect')
        try:
            manager.apply({bad['port']: bad})
        except m.Error as exc:
            assert '已自动回滚' in str(exc)
        else:
            raise AssertionError('bad shared upstream unexpectedly accepted')
    check_shared()
    print('PASS: a failed shared node edit restores both listeners and routes', flush=True)
    switched = subprocess.run(['sb1'], input=f'26\n{dual["port"]}\n2\n0\n',
                              text=True, capture_output=True, check=True)
    assert '已切换 1 个入口' in switched.stdout
    assert manager.backend.owns_listener(dual['access']['port'], unit=dual_unit, both=True)
    assert manager.backend.owns_listener(other['access']['port'], unit=UNIT, both=True)
    assert local_entrance(manager, manager.row(dual['port']), 'tuic')[0] == '127.0.0.2'
    assert local_entrance(manager, manager.row(other['port']), 'tcp')[0] == '127.0.0.3'
    with manager.lock():
        manager.apply({other['port']: None})
    assert not manager.backend.call('is-active', '--quiet', UNIT, required=False)
    assert not manager.backend.call('is-enabled', '--quiet', UNIT, required=False)
    assert not (manager.root / 'shared-access.json').exists()
    assert manager.backend.owns_listener(dual['access']['port'], unit=dual_unit, both=True)
    print('PASS: shared and independent modes coexist; deleting the last shared endpoint stops the shared service', flush=True)
finally:
    with manager.lock():
        manager.apply({r['port']: None for r in manager.rows()})
    for server in (target, upstream, second):
        server.shutdown()
        server.server_close()
