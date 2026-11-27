"""Loopback HTTP, session boundaries, persisted admin password and relay forms."""
import contextlib
import copy
import http.client
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import manager
import test_certificates
import web_admin

PASSWORD = 'local-fixture-password-42'
UPSTREAM = 'new-proxy.example:1080:fixture-account:fixture-proxy-secret'


class Fixture:
    def __init__(self, root, row):
        self.root = root
        self.access_binary = root / 'sing-box'
        self.access_binary.touch()
        row = dict(row, upstream_host='initial-proxy.example', upstream_port=1080,
                   upstream_user='initial-account', upstream_password='initial-fixture-secret',
                   bind='127.0.0.1', sources=['127.0.0.1'])
        self.data = {row['port']: row}
        self.writes = self.probes = 0
        manager.write_json(root / 'public-address.json', {'address': '203.0.113.1'})
        self.write_password(PASSWORD)

    def write_password(self, password):
        salt = b'test-only-salt!!'
        manager.write_json(self.root / web_admin.PASSWORD_FILE,
                           {'salt': salt.hex(), 'digest': web_admin.password_digest(password, salt).hex()})

    lock = staticmethod(contextlib.nullcontext)

    def rows(self):
        return [copy.deepcopy(row) for row in self.data.values()]

    def row(self, port):
        return copy.deepcopy(self.data[port])

    def pointers(self):
        return {str(port): {} for port in self.data}

    def allocate(self):
        return next(port for port in range(20001, 20010) if port not in self.data)

    def apply(self, changes):
        for port, row in changes.items():
            self.data[port] = manager.validate(copy.deepcopy(row))
        self.writes += 1

    def exit_locations(self, rows, refresh=False, cached_only=False):
        assert refresh or cached_only
        self.probes += int(refresh)
        return {row['port']: ('8.8.8.8', '美国') for row in rows}


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
        self.assertEqual(self.call('/add', form, {'Origin': 'https://foreign.example'})[0], 403)
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
