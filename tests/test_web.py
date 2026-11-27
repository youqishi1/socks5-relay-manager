"""Loopback HTTP, session boundaries, persisted admin password and relay forms."""
import contextlib
import copy
import http.client
import json
import subprocess
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import manager
import test_certificates
import web_admin
import web_activity
import web_views

PASSWORD = 'local-fixture-password-42'
UPSTREAM = 'new-proxy.example:1080:fixture-account:fixture-proxy-secret'


class Fixture:
    def __init__(self, root, row):
        self.root = root
        self.log = root / 'logs'
        self.log.mkdir()
        self.access_binary = root / 'sing-box'
        self.access_binary.touch()
        row = dict(row, upstream_host='initial-proxy.example', upstream_port=1080,
                   upstream_user='initial-account', upstream_password='initial-fixture-secret',
                   bind='127.0.0.1', sources=['127.0.0.1'])
        self.data = {row['port']: row}
        self.notes = {}
        self.writes = self.probes = 0
        self.outcomes = {row['port']: {'ip': '8.8.8.8', 'country': '美国', 'checked': 1}}
        self.failed_ports = set()
        self.busy = False
        manager.write_json(root / 'public-address.json', {'address': '203.0.113.1'})
        self.write_password(PASSWORD)

    def write_password(self, password):
        salt = b'test-only-salt!!'
        manager.write_json(self.root / web_admin.PASSWORD_FILE,
                           {'salt': salt.hex(), 'digest': web_admin.password_digest(password, salt).hex()})

    @contextlib.contextmanager
    def lock(self, wait=True, read_only=False):
        if self.busy:
            assert wait is False
            raise manager.OperationBusy('正在更新中转，请稍后重试。')
        yield

    def rows(self, with_note=False):
        return [self.row(port, with_note) for port in self.data]

    def row(self, port, with_note=False):
        row = copy.deepcopy(self.data[port])
        if with_note and self.notes.get(port):
            row['note'] = self.notes[port]
        return row

    def set_note(self, port, note):
        self.notes[port] = note.strip()
        return self.row(port, with_note=True)

    def pointers(self):
        return {str(port): {} for port in self.data}

    def allocate(self):
        return next(port for port in range(20001, 20010) if port not in self.data)

    def apply(self, changes):
        for port, row in changes.items():
            self.data[port] = manager.validate(copy.deepcopy(row))
        self.writes += 1

    def exit_location(self, row, refresh=False, cached_only=False, cooldown=0):
        assert refresh or cached_only
        port = row['port']
        if refresh:
            assert cooldown == web_admin.EXIT_COOLDOWN
            self.probes += 1
            self.outcomes[port] = ({'ip': '', 'country': '', 'checked': 1} if port in self.failed_ports
                                   else {'ip': '9.9.9.9', 'country': '美国', 'checked': 1})
        return self.outcomes.get(port, {'ip': '', 'country': '', 'checked': 0})


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_certificates.CertificateTests.setUpClass()
        cls.fixture = test_certificates.CertificateTests()

    @classmethod
    def tearDownClass(cls):
        test_certificates.CertificateTests.tearDownClass()

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        row = self.fixture.row()
        row['access'].update(server_name='tuic.example.test', certificate_trust='system')
        self.instance = Fixture(Path(folder.name), row)
        self.server = web_admin.AdminServer(self.instance, port=0)
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_port
        self.origin = f'http://127.0.0.1:{self.port}'
        self.cookie = ''

    def call(self, path, form=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=6)
        request_headers = {'Cookie': self.cookie} if self.cookie else {}
        if form is not None:
            request_headers.update({'Origin': self.origin, 'Content-Type': 'application/x-www-form-urlencoded'})
        request_headers.update(headers or {})
        try:
            connection.request('GET' if form is None else 'POST', path,
                               urlencode(form) if form is not None else None, request_headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def login(self):
        status, headers, _ = self.call('/login', {'password': PASSWORD, 'next': '/nodes/20001/qr'})
        self.assertEqual(status, 303)
        self.assertEqual(headers['Location'], '/nodes/20001/qr')
        self.assertIn('HttpOnly; SameSite=Strict', headers['Set-Cookie'])
        self.cookie = headers['Set-Cookie'].split(';', 1)[0]

    def test_qr_link_and_password_rotation_keep_credentials_private(self):
        status, headers, body = self.call('/nodes/20001/qr')
        self.assertEqual((status, headers['Location']), (303, '/login?next=/nodes/20001/qr'))
        self.assertNotIn(b'tuic://', body)
        self.assertEqual(self.call('/nodes/20001/qr.png')[0], 303)
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        self.login()
        page = self.call('/nodes/20001/qr')[2].decode()
        self.assertIn('美国-8.8.8.8-20001-TUIC', page)
        status, headers, body = self.call('/nodes/20001/qr.png')
        self.assertEqual((status, headers['Content-Type'], headers['Cache-Control']), (200, 'image/png', 'no-store'))
        self.assertTrue(body.startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertIn('tuic://', self.call('/nodes/20001')[2].decode())
        self.assertEqual(self.instance.probes, 0)
        self.instance.write_password('another-fixture-password')
        self.assertEqual(self.call('/nodes/20001/qr.png')[0], 303)

    def test_login_throttled_and_request_source_verified(self):
        self.assertEqual(self.call('/', headers={'Host': 'foreign.example'})[0], 403)
        for i in range(web_admin.ATTEMPTS):
            status, _, _ = self.call('/login', {'password': 'wrong-password'})
            self.assertEqual(status, 429 if i + 1 == web_admin.ATTEMPTS else 401)
        status, headers, _ = self.call('/login', {'password': PASSWORD})
        self.assertEqual(status, 429)
        self.assertGreater(int(headers['Retry-After']), 0)

    def test_edit_add_detect_and_reject_untrusted_writes(self):
        self.login()
        status, _, body = self.call('/')
        self.assertEqual(status, 200)
        self.assertIn('8.8.8.8', body.decode())
        self.assertNotIn(UPSTREAM.encode(), body)
        form = {'csrf': self.server.csrf, 'upstream': UPSTREAM, 'mode': 'independent'}
        self.assertEqual(self.call('/add', {}, {'Origin': 'https://foreign.example'})[0], 403)
        self.assertEqual(self.call('/add', dict(form, csrf='invalid'))[0], 403)
        self.assertEqual(self.instance.writes, 0)
        before = self.instance.row(20001)
        self.assertEqual(self.call('/nodes/20001/edit', form)[0], 303)
        changed = self.instance.row(20001)
        self.assertEqual(changed['upstream_host'], 'new-proxy.example')
        self.assertEqual(changed['access'], before['access'])
        self.assertEqual(self.call('/nodes/20001/edit', dict(form, upstream='invalid'))[0], 400)
        self.assertEqual(self.instance.row(20001), changed)
        with patch.object(web_admin, 'add_access', side_effect=lambda _, row, shared: row.update(
                access=dict(before['access'], port=30002), shared=shared)):
            self.assertEqual(self.call('/add', dict(form, mode='shared'))[0], 303)
        self.assertEqual(len(self.instance.rows()), 2)
        self.assertTrue(self.instance.row(20002)['shared'])
        self.assertEqual(self.call('/nodes/20001/detect', {'csrf': self.server.csrf})[0], 303)
        self.assertEqual(self.instance.probes, 1)
        self.assertEqual(self.call('/logout', {'csrf': self.server.csrf})[0], 303)
        self.assertEqual(self.call('/nodes/20001/qr.png')[0], 303)

    def test_home_copies_node_links_and_uses_cache_only_for_assets(self):
        status, headers, _ = self.call('/style.css?v=' + web_views.VERSION)
        self.assertEqual(status, 200)
        self.assertIn('immutable', headers['Cache-Control'])
        self.login()
        status, headers, body = self.call('/')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        html = body.decode()
        self.assertIn('data-share="ss://', html)
        self.assertIn('data-share="tuic://', html)
        self.assertIn('复制当前列表链接', html)
        self.assertNotIn('initial-fixture-secret', html)
        self.instance.data[20002] = dict(self.instance.row(20001), port=20002, access=None)
        self.instance.data[20001]['access'].pop('server_name')
        self.instance.data[20001]['access'].pop('certificate_trust')
        _, headers, body = self.call('/')
        html = body.decode()
        self.assertIn("connect-src 'self'", headers['Content-Security-Policy'])
        self.assertIn('data-share="v2rayn://tuic/', html)
        self.assertNotIn('data-share="tuic://', html)
        self.assertEqual(self.instance.probes, 0)
        self.instance.busy = True
        self.assertEqual(self.call('/')[0], 409)
        self.assertEqual(self.call('/nodes/20001')[0], 409)
        self.assertEqual(self.call('/add')[0], 200)
        self.assertEqual(self.call('/add', {'csrf': self.server.csrf, 'upstream': UPSTREAM, 'mode': 'shared'})[0], 409)

    def test_home_detects_one_at_a_time_and_refreshes_links(self):
        accept = {'Accept': 'application/json'}
        self.assertEqual(self.call('/nodes/20001/detect', {'csrf': 'invalid'}, accept)[0], 401)
        self.login()
        row = self.instance.row(20001)
        self.instance.data[20002] = dict(row, port=20002, access=dict(row['access'], port=30002))
        self.instance.notes[20002] = '办公'
        html = self.call('/')[2].decode()
        self.assertIn('id="detect-missing"', html)
        self.assertIn('data-detect="/nodes/20002/detect"', html)
        self.assertIn('出口未检测', html)
        self.assertEqual(self.instance.probes, 0)
        form = {'csrf': self.server.csrf}
        status, headers, body = self.call('/nodes/20002/detect', form, accept)
        self.assertEqual(status, 200)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        result = json.loads(body)
        self.assertTrue(result['ok'])
        self.assertEqual(result['text'], '美国 · 9.9.9.9')
        self.assertIn('9.9.9.9-20002-TUIC', result['links']['tuic'])
        self.assertIn('%E5%8A%9E%E5%85%AC-', result['links']['tuic'])
        self.instance.failed_ports.add(20001)
        result = json.loads(self.call('/nodes/20001/detect', form, accept)[2])
        self.assertFalse(result['ok'])
        self.assertEqual(result['text'], '检测失败')
        self.assertIn('检测失败', self.call('/')[2].decode())
        self.assertEqual(self.instance.probes, 2)

    def test_home_renames_without_probing_or_changing_the_node(self):
        self.login()
        form = {'csrf': self.server.csrf, 'note': ' 办公 <A> '}
        target = '/nodes/20001/note'
        accept = {'Accept': 'application/json'}
        self.assertEqual(self.call(target, dict(form, csrf='bad'), accept)[0], 403)
        original = self.instance.row(20001)
        status, _, body = self.call(target, form, accept)
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result['note'], '办公 <A>')
        self.assertIn('%3CA%3E-', result['links']['tuic'])
        self.assertIn('8.8.8.8-20001-TUIC', result['links']['tuic'])
        self.assertIn('办公 &lt;A&gt;', self.call('/')[2].decode())
        self.assertIn('办公 &lt;A&gt;-美国-', self.call('/nodes/20001/qr')[2].decode())
        self.assertEqual(self.call(target, dict(form, note=''), accept)[0], 200)
        self.assertNotIn('办公', self.call('/')[2].decode())
        self.assertEqual(self.instance.row(20001), original)
        self.assertEqual((self.instance.probes, self.instance.writes), (0, 0))

    def test_note_is_persisted_without_replacing_the_service_revision(self):
        root = self.instance.root / 'manager'
        backend = Mock()
        instance = manager.Manager(root, root / 'logs', backend=backend)
        row = dict(self.instance.row(20001), enabled=False)
        port = row['port']
        pointer = {'revision': 'a' * 32}
        manager.write_json(instance.revision(port, pointer) / 'relay.json', row)
        instance.set_pointer(port, pointer)
        with self.assertRaises(manager.Error):
            instance.set_note(port, '甲' * 33)
        instance.set_note(port, '巴西办公')
        self.assertEqual(instance.pointers()[str(port)]['revision'], pointer['revision'])
        self.assertEqual(instance.row(port), row)
        backend.apply.assert_not_called()
        instance.apply({port: row}, verify=False)
        self.assertEqual(instance.row(port, with_note=True)['note'], '巴西办公')
        instance.set_note(port, '')
        self.assertNotIn('note', instance.row(port, with_note=True))

    def test_usage_reads_existing_sockets_and_log_only_when_requested(self):
        self.login()
        second = dict(self.instance.row(20001), port=20002, access=None)
        self.instance.data[20002] = second
        log = self.instance.log / 'relay-20001.log'
        log.write_bytes(
            b'2026-11-27 12:01:00 port=20001 error=00000 in=300 out=20 duration=1\n'
            b'2026-11-27 12:02:00 port=20001 error=00000 in=0 out=0 duration=1\n'
            b'2026-11-27 12:03:00 port=20001 error=00000 in=4 out=6 duration=300'
        )
        socket_output = '0 0 127.0.0.1:20001 127.0.0.1:48100\n0 0 [::1]:20001 [::1]:48101\n'
        result = subprocess.CompletedProcess([], 0, stdout=socket_output, stderr='')
        with patch.object(web_activity.subprocess, 'run', return_value=result) as command:
            self.assertNotIn('当前未见连接', self.call('/')[2].decode())
            command.assert_not_called()
            status, _, body = self.call('/?activity=1')
            self.assertEqual(status, 200)
            self.assertIn('有连接（2）', body.decode())
            self.assertIn('当前未见连接', body.decode())
            self.assertIn('2026-11-27 12:01:00', body.decode())
            self.assertNotIn('2026-11-27 12:03:00', body.decode())
            command.assert_called_once()
        self.assertEqual(self.instance.probes, 0)
        self.assertIsNone(web_activity.last_forwarded(log, 20001, 10))
        with patch.object(web_activity.subprocess, 'run', side_effect=OSError()):
            unavailable = web_activity.snapshot(self.instance.rows(), self.instance.log)
        self.assertIsNone(unavailable[20001]['connections'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
