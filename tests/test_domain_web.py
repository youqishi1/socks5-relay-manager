"""Domain routing, HTTPS cookies, TLS hostname verification and login limits."""
import http.client
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from domain_web import DomainServer, tls_context
from test_web import Fixture, PASSWORD, test_certificates
from web_admin import ATTEMPTS


class LocalHTTPS(http.client.HTTPSConnection):
    """Connect to the fixture IP while retaining normal host and TLS checks."""
    def connect(self):
        connection = socket.create_connection(('127.0.0.1', self.port), self.timeout)
        self.sock = self._context.wrap_socket(connection, server_hostname=self.host)


class DomainTests(unittest.TestCase):
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
        instance = Fixture(Path(folder.name), self.fixture.row())
        server_socket = socket.socket()
        server_socket.bind(('127.0.0.1', 0))
        server_socket.listen(6)
        self.port = server_socket.getsockname()[1]
        self.host = self.fixture.domain
        settings = {'domain': self.host, 'port': self.port}
        tls = tls_context(self.fixture.root / 'cert.pem', self.fixture.root / 'key.pem')
        self.server = DomainServer(instance, server_socket, settings, tls)
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        self.addCleanup(self.server.shutdown)

    def call(self, path, form=None, headers=None):
        request_headers = dict(headers or {})
        if form is not None:
            request_headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
            request_headers.setdefault('Origin', f'https://{self.host}:{self.port}')
        connection = LocalHTTPS(self.host, self.port, context=self.fixture.context(), timeout=5)
        try:
            connection.request('GET' if form is None else 'POST', path,
                               urlencode(form) if form is not None else None, request_headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_https_login_direct_links_and_cookie(self):
        self.assertEqual(self.call('/', headers={'Sec-Fetch-Site': 'cross-site'})[0], 303)
        self.assertEqual(self.call('/', headers={'Host': 'wrong.example'})[0], 403)
        self.assertEqual(self.call('/login', {'password': PASSWORD}, {'Origin': 'http://localhost'})[0], 403)
        status, headers, _ = self.call('/login', {'password': PASSWORD, 'next': '/nodes/20001'})
        self.assertEqual(status, 303)
        self.assertIn('HttpOnly; SameSite=Strict; Secure', headers['Set-Cookie'])
        cookie = headers['Set-Cookie'].split(';')[0]
        self.assertEqual(self.call('/nodes/20001', headers={'Cookie': cookie})[0], 200)
        self.assertEqual(self.call('/nodes/20001')[0], 303)

    def test_failed_login_limits_are_independent_by_address(self):
        self.assertEqual(self.server.login('192.0.2.10', 'wrong'), ('', 0))
        token, wait = self.server.login('192.0.2.20', PASSWORD)
        self.assertEqual(token, '')
        self.assertGreater(wait, 0)
        for _ in range(ATTEMPTS - 1):
            self.server.next_login = 0
            self.server.login('192.0.2.10', 'wrong')
        self.server.next_login = 0
        self.assertGreater(self.server.login('192.0.2.10', PASSWORD)[1], 1)
        self.assertTrue(self.server.login('192.0.2.20', PASSWORD)[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
