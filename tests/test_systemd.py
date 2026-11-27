"""Actual installer, systemd startup, repeat install, rollback and persistence."""
import copy
import contextlib
import http.client
import io
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch
from urllib.parse import quote

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
    from web_admin import PASSWORD_FILE, PORT, password_digest
    settings = manager.root / PASSWORD_FILE
    salt = b'disposable-fixture'
    m.write_json(settings, {'salt': salt.hex(), 'digest': password_digest('install-fixture-password', salt).hex()})
    web = subprocess.Popen(['sb1', 'web'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 5
        while not m.listening(PORT, '127.0.0.1'):
            assert web.poll() is None and time.monotonic() < deadline, 'installed web listener did not start'
            time.sleep(.05)
        for path, status in (('/', 303), ('/style.css', 200), ('/app.js', 200), ('/icon.png', 200)):
            connection = http.client.HTTPConnection('127.0.0.1', PORT, timeout=5)
            try:
                connection.request('GET', path)
                response = connection.getresponse()
                assert response.status == status, path
                response.read()
            finally:
                connection.close()
    finally:
        m.stop_process(web)
        settings.unlink()
    assert not m.listening(PORT, '127.0.0.1')
    print('PASS: installed sb1 web starts on demand, ships UI assets and stops without a service', flush=True)
    import certificates
    import domain_web
    from test_certificates import CertificateTests
    from test_domain_web import LocalHTTPS
    CertificateTests.setUpClass()
    fixture = CertificateTests()
    cert_settings = dict(domain=fixture.domain, email='', webroot='', challenge=certificates.DNS01)
    settings_file = manager.root / certificates.SETTING
    cert, key = certificates.material_paths(m.APP, fixture.domain)
    public_port = m.free_port()
    try:
        m.atomic(cert, fixture.cert)
        m.atomic(key, fixture.key)
        m.write_json(settings_file, cert_settings)
        m.write_json(settings, {'salt': salt.hex(), 'digest': password_digest('install-fixture-password', salt).hex()})
        with patch.dict(os.environ, {'SSL_CERT_FILE': str(cert)}), manager.lock():
            domain_web.install(manager, public_port, cert_settings)
        assert manager.backend.call('is-active', '--quiet', domain_web.SOCKET, required=False)
        assert not manager.backend.call('is-active', '--quiet', domain_web.SERVICE, required=False)
        conn = LocalHTTPS(fixture.domain, public_port, context=fixture.context(), timeout=8)
        try:
            conn.request('GET', '/')
            response = conn.getresponse()
            assert response.status == 303 and response.getheader('Location') == '/login?next=/'
            response.read()
        finally:
            conn.close()
        assert manager.backend.call('is-active', '--quiet', domain_web.SERVICE, required=False)
    finally:
        with manager.lock():
            domain_web.disable(manager)
        for path in (settings, settings_file, cert, key):
            path.unlink(missing_ok=True)
        CertificateTests.tearDownClass()
    assert not m.listening(public_port, '127.0.0.1')
    print('PASS: installed domain HTTPS activates on request and disables cleanly', flush=True)
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
    other_port = manager.allocate()
    line = 'socks5://' + quote(second.user, safe='') + ':' + quote(second.password, safe='') + '@127.0.0.1:' + str(second.server_address[1])
    display = io.StringIO()
    independent_pid = subprocess.check_output(['systemctl', 'show', dual_unit, '--property=MainPID'])
    with patch.object(m, 'public_address', return_value='203.0.113.1'), contextlib.redirect_stdout(display):
        with patch('builtins.input', side_effect=['1', '0', '0']), patch.object(m.getpass, 'getpass') as paste:
            m.menu(manager)
            paste.assert_not_called()
        assert str(other_port) not in manager.pointers()
        with patch('builtins.input', side_effect=['1', 'invalid', '', '19', str(dual['port']), '0']), \
             patch.object(m.getpass, 'getpass', return_value=line) as paste:
            m.menu(manager)
            paste.assert_called_once()
    other = manager.row(other_port)
    assert other['shared'] is True
    assert '请输入 1、2 或 0' in display.getvalue() and '运行方式：共享' in display.getvalue()
    assert '此节点已启用加密入口' in display.getvalue()
    assert subprocess.check_output(['systemctl', 'show', dual_unit, '--property=MainPID']) == independent_pid
    assert manager.backend.owns_listener(other['access']['port'], unit=UNIT, both=True)
    print('PASS: menu 1 cancels before requesting credentials, retries invalid mode, and defaults to shared; menu 19 preserves an active core', flush=True)
    ports = (dual['port'], other['port'])
    saved_links = access.configs([manager.row(port) for port in ports], '203.0.113.1')
    selection = ','.join(map(str, ports))
    switched = subprocess.run(['sb1'], input='26\n' + selection + '\n1\n8\n0\n',
                              text=True, capture_output=True, check=True)
    assert '已切换 1 个入口' in switched.stdout and switched.stdout.count('共享入口 运行中') == 2
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
        for _ in range(6):
            manager.backend.apply(dual['port'], manager.row(dual['port']))
            manager.backend.stop_shared()
            manager.backend.start_shared([(other['access']['port'], False)])
    assert local_entrance(manager, manager.row(dual['port']), 'tcp')[0] == '127.0.0.2'
    assert local_entrance(manager, manager.row(other['port']), 'tuic')[0] == '127.0.0.3'
    print('PASS: consecutive validated relay and entrance starts do not trip the systemd crash-loop limit', flush=True)
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
