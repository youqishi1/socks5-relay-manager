"""Integration tests use REAL 3proxy and authenticated, forwarding SOCKS5 servers."""
import copy
import importlib.util
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('manager', Path(__file__).resolve().parents[1] / 'scripts' / 'manager.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
BINARY = Path(os.environ.get('THREEPROXY_BINARY', '/opt/socks5-relay-manager/3proxy')).resolve()
PASSWORD = 'a $b!"c" #d:e\\f 中文'


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Target(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        request = b''
        while b'\r\n\r\n' not in request and len(request) < 10000:
            part = self.request.recv(1024)
            if not part:
                return
            request += part
        self.server.hits.append(self.client_address[0])
        body = self.client_address[0].encode()
        self.request.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


class Upstream(socketserver.BaseRequestHandler):
    def handle(self):
        downstream = self.request
        downstream.settimeout(6)
        try:
            version, count = m.recv(downstream, 2)
            methods = m.recv(downstream, count)
            if version != 5 or 2 not in methods:
                downstream.sendall(b'\x05\xff')
                return
            downstream.sendall(b'\x05\x02')
            version, count = m.recv(downstream, 2)
            user = m.recv(downstream, count).decode()
            password = m.recv(downstream, m.recv(downstream, 1)[0]).decode()
            success = version == 1 and user == self.server.user and password == self.server.password
            downstream.sendall(b'\x01' + (b'\x00' if success else b'\x01'))
            if not success:
                return
            version, command, _, kind = m.recv(downstream, 4)
            if kind == 3:
                address = m.recv(downstream, m.recv(downstream, 1)[0]).decode()
            elif kind == 1:
                address = socket.inet_ntoa(m.recv(downstream, 4))
            elif kind == 4:
                address = socket.inet_ntop(socket.AF_INET6, m.recv(downstream, 16))
            else:
                return
            port = int.from_bytes(m.recv(downstream, 2), 'big')
            self.server.requests.append((address, port))
            if command != 1 or address == 'bad.invalid':
                downstream.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            if address == 'exit.invalid':
                address = '127.0.0.1'
            with socket.socket() as upstream:
                upstream.settimeout(5)
                upstream.bind((self.server.exit_source, 0))
                upstream.connect((address, port))
                downstream.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                while True:
                    readable, _, _ = select.select([downstream, upstream], [], [], 5)
                    if not readable:
                        return
                    for source in readable:
                        data = source.recv(16384)
                        if not data:
                            return
                        (upstream if source is downstream else downstream).sendall(data)
        except (OSError, m.Error, UnicodeError):
            return


def serve(handler):
    server = Server(('127.0.0.1', 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Processes:
    """Mimics per-port service lifecycle, always runs real binary/config files."""
    def __init__(self):
        self.processes = {}
        self.manager = None
        self.fail_once = False

    def apply(self, port, row):
        if port in self.processes:
            m.stop_process(self.processes.pop(port))
        if self.fail_once:
            self.fail_once = False
            raise m.Error('注入的服务启动故障')
        if row and row['enabled']:
            pointer = m.read_json(self.manager.pointer_path(port))
            config = self.manager.revision(port, pointer) / '3proxy.cfg'
            process = subprocess.Popen([str(BINARY), str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.processes[port] = process
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise m.Error('真实 3proxy 进程启动失败')
                if m.listening(port, row['bind']):
                    return
                time.sleep(0.05)
            raise m.Error('真实 3proxy 监听超时')

    def active(self, port):
        return port in self.processes and self.processes[port].poll() is None

    def close(self):
        for process in self.processes.values():
            m.stop_process(process)
        self.processes.clear()


class RelayTests(unittest.TestCase):
    def setUp(self):
        os.umask(0o077)
        self.folder = tempfile.TemporaryDirectory(prefix='relay-test-')
        self.target = serve(Target)
        self.target.hits = []
        self.upstreams = []
        self.backends = []
        self.backend = Processes()
        self.backends.append(self.backend)
        self.manager = m.Manager(Path(self.folder.name) / 'state', Path(self.folder.name) / 'logs', BINARY,
                                 self.backend, 'http://exit.invalid:' + str(self.target.server_address[1]))
        self.backend.manager = self.manager

    def tearDown(self):
        for backend in self.backends:
            backend.close()
        for server in [self.target] + self.upstreams:
            server.shutdown()
            server.server_close()
        self.folder.cleanup()

    def upstream(self, index=2):
        server = serve(Upstream)
        server.user, server.password = 'provider $" :\\ 中文', PASSWORD
        server.requests = []
        server.exit_source = '127.0.0.' + str(index)
        self.upstreams.append(server)
        return server

    def row(self, upstream=None):
        upstream = upstream or self.upstream()
        return dict(port=self.manager.allocate(), upstream_host='127.0.0.1', upstream_port=upstream.server_address[1],
                    upstream_user=upstream.user, upstream_password=upstream.password, client_user='client01',
                    client_password=PASSWORD, sources=['127.0.0.1'], bind='0.0.0.0', enabled=True)

    def add(self, upstream=None):
        row = self.row(upstream)
        self.manager.apply({row['port']: row})
        return self.manager.row(row['port'])

    def test_01_real_relay_special_credentials_remote_dns(self):
        row = self.add()
        ip, _ = self.manager.verify(row)
        self.assertEqual(ip, '127.0.0.2')
        self.assertTrue(any(address == 'exit.invalid' for address, _ in self.upstreams[0].requests))
        self.assertNotIn('127.0.0.1', self.target.hits)
        log = (self.manager.log / ('relay-' + str(row['port']) + '.log')).read_text(errors='replace')
        self.assertNotIn(PASSWORD, log)
        self.assertNotIn(row['upstream_user'], log)

    def test_02_three_and_ten_ports_are_independent(self):
        rows = []
        for i in range(10):
            rows.append(self.add(self.upstream(i + 2)))
            if i in (0, 2, 9):
                self.assertEqual(len(self.manager.rows()), i + 1)
        for i, row in enumerate(rows):
            self.assertEqual(self.manager.verify(row)[0], '127.0.0.' + str(i + 2))
        survivor = self.backend.processes[rows[1]['port']]
        self.manager.apply({rows[0]['port']: None})
        self.assertIs(self.backend.processes[rows[1]['port']], survivor)
        self.assertIsNone(survivor.poll())
        self.assertEqual(self.manager.allocate(), rows[0]['port'])
        changed = copy.deepcopy(rows[2])
        changed['upstream_port'] = self.upstreams[8].server_address[1]
        self.manager.apply({changed['port']: changed})
        self.assertEqual(self.manager.verify(self.manager.row(changed['port']))[0], '127.0.0.10')
        self.assertIs(self.backend.processes[rows[1]['port']], survivor)

    def test_03_bad_upstream_auth_rolls_back(self):
        row = self.add()
        old = self.manager.pointers()
        changed = copy.deepcopy(row)
        changed['upstream_password'] = 'incorrect'
        self.target.hits.clear()
        with self.assertRaises(m.Error):
            self.manager.apply({row['port']: changed})
        self.assertEqual(self.manager.pointers(), old)
        self.assertEqual(self.target.hits, [])
        self.assertEqual(self.manager.verify(row)[0], '127.0.0.2')

    def test_04_upstream_offline_never_goes_direct_or_other_upstream(self):
        broken = self.add()
        good = self.add(self.upstream(3))
        # Remove the actual upstream listener, then test an IP destination that
        # would be reachable directly from 3proxy if it fell back to direct.
        server = self.upstreams[0]
        server.shutdown()
        server.server_close()
        self.upstreams.remove(server)
        self.target.hits.clear()
        direct_url = 'http://127.0.0.1:' + str(self.target.server_address[1])
        with self.assertRaises(m.Error):
            m.health('127.0.0.1', broken['port'], broken['client_user'], broken['client_password'], direct_url)
        self.assertEqual(self.target.hits, [])
        self.assertEqual(self.manager.verify(good)[0], '127.0.0.3')

    def test_05_dns_failure_is_closed(self):
        row = self.add()
        self.target.hits.clear()
        with self.assertRaises(m.Error):
            m.health('127.0.0.1', row['port'], row['client_user'], row['client_password'],
                     'http://bad.invalid:' + str(self.target.server_address[1]))
        self.assertEqual(self.target.hits, [])
        old = self.manager.pointers()
        with patch.object(m.socket, 'getaddrinfo', side_effect=socket.gaierror()):
            changed = copy.deepcopy(row)
            changed['upstream_host'] = 'absent.invalid'
            with self.assertRaises(m.Error):
                self.manager.apply({row['port']: changed})
        self.assertEqual(self.manager.pointers(), old)

    def test_06_anonymous_wrong_password_bind_udp_are_denied(self):
        row = self.add()
        with socket.create_connection(('127.0.0.1', row['port'])) as sock:
            sock.sendall(b'\x05\x01\x00')
            self.assertEqual(m.recv(sock, 2), b'\x05\xff')
        with self.assertRaises(m.Error):
            # 3proxy defers credential validation until the CONNECT request.
            # An RFC1929 handshake response alone does not prove authentication.
            m.health('127.0.0.1', row['port'], row['client_user'], 'wrong', self.manager.ip_url)
        for command in (2, 3):
            with socket.create_connection(('127.0.0.1', row['port'])) as sock:
                sock.settimeout(5)
                sock.sendall(b'\x05\x01\x02')
                self.assertEqual(m.recv(sock, 2), b'\x05\x02')
                u, p = row['client_user'].encode(), row['client_password'].encode()
                sock.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
                self.assertEqual(m.recv(sock, 2), b'\x01\x00')
                sock.sendall(bytes([5, command, 0, 1]) + b'\x7f\x00\x00\x01\x00\x50')
                try:
                    self.assertNotEqual(m.recv(sock, 2)[1], 0)
                except (m.Error, ConnectionResetError):
                    # 3proxy may reject an unsupported operation by closing.
                    pass

    def test_07_occupied_ports_and_service_rollback(self):
        port = self.manager.allocate()
        with socket.socket() as occupied:
            occupied.bind(('0.0.0.0', port))
            occupied.listen()
            self.assertNotEqual(self.manager.allocate(), port)
        row = self.add()
        old = self.manager.pointers()
        self.backend.fail_once = True
        with self.assertRaises(m.Error):
            self.manager.apply({row['port']: row})
        self.assertEqual(self.manager.pointers(), old)
        self.assertEqual(self.manager.verify(row)[0], '127.0.0.2')

    def test_08_config_failure_does_not_touch_running_port(self):
        row = self.add()
        old = self.manager.pointers()
        process = self.backend.processes[row['port']]
        with patch.object(m, 'render', return_value='this-is-invalid\n'):
            with self.assertRaises(m.Error):
                self.manager.apply({row['port']: row})
        self.assertEqual(self.manager.pointers(), old)
        self.assertIs(self.backend.processes[row['port']], process)

    def test_09_restart_persistence_backup_restore(self):
        row = self.add()
        backup = self.manager.backup()
        pointer = self.manager.pointers()
        self.backend.close()
        self.backend = Processes()
        self.backends.append(self.backend)
        self.manager = m.Manager(self.manager.root, self.manager.log, BINARY, self.backend, self.manager.ip_url)
        self.backend.manager = self.manager
        for current in self.manager.rows():
            self.backend.apply(current['port'], current)
        self.assertEqual(self.manager.pointers(), pointer)
        self.assertEqual(self.manager.verify(row)[0], '127.0.0.2')
        self.manager.apply({row['port']: None})
        self.manager.restore(backup)
        self.assertEqual(self.manager.verify(self.manager.rows()[0])[0], '127.0.0.2')

    def test_10_crash_journal_recovery(self):
        row = self.add()
        old = self.manager.pointers()
        m.write_json(self.manager.root / 'pending.json', {'ports': [str(row['port'])], 'old': old})
        self.manager.set_pointer(row['port'], None)
        self.backend.apply(row['port'], None)
        self.manager.recover()
        self.assertEqual(self.manager.pointers(), old)
        self.assertEqual(self.manager.verify(row)[0], '127.0.0.2')

    def test_11_disabled_invalid_upstream_has_no_listener(self):
        row = self.row()
        row['upstream_host'] = 'absent.invalid'
        row['enabled'] = False
        self.manager.apply({row['port']: row})
        self.assertFalse(self.backend.active(row['port']))
        self.assertFalse(m.listening(row['port']))

    def test_12_injection_rejected_and_sensitive_permissions(self):
        row = self.add()
        for key, value in [('upstream_host', '127.0.0.1\nallow *'), ('client_user', '*'),
                           ('upstream_password', 'abc\nsystem evil'), ('sources', ['127.0.0.1;evil']),
                           ('upstream_host', '0.0.0.0'), ('upstream_user', '*')]:
            changed = copy.deepcopy(row)
            changed[key] = value
            with self.assertRaises(m.Error):
                m.validate(changed)
        if os.name == 'posix':
            for path in self.manager.root.rglob('*'):
                self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600, str(path))
            for path in self.manager.log.rglob('*'):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600, str(path))

    def test_13_proxy_env_cannot_bypass_local_relay(self):
        row = self.add()
        with patch.dict(os.environ, {'NO_PROXY': '*', 'ALL_PROXY': 'http://invalid.invalid:9', 'http_proxy': 'http://invalid.invalid:9'}):
            self.assertEqual(self.manager.verify(row)[0], '127.0.0.2')

    def test_14_multi_port_restore_failure_rolls_back_all(self):
        first = self.add()
        second = self.add(self.upstream(3))
        old = self.manager.pointers()
        changed1, changed2 = copy.deepcopy(first), copy.deepcopy(second)
        changed1['client_password'] = 'new-password'
        changed2['upstream_password'] = 'incorrect'
        with self.assertRaises(m.Error):
            self.manager.apply({first['port']: changed1, second['port']: changed2})
        self.assertEqual(self.manager.pointers(), old)
        self.assertEqual(self.manager.verify(first)[0], '127.0.0.2')
        self.assertEqual(self.manager.verify(second)[0], '127.0.0.3')

    def test_15_source_acl_blocks_non_loopback_client(self):
        row = self.add()
        with socket.socket() as sock:
            sock.settimeout(5)
            sock.bind(('127.0.0.4', 0))
            sock.connect(('127.0.0.1', row['port']))
            sock.sendall(b'\x05\x01\x02')
            self.assertEqual(m.recv(sock, 2), b'\x05\x02')
            u, p = row['client_user'].encode(), row['client_password'].encode()
            sock.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
            self.assertEqual(m.recv(sock, 2), b'\x01\x00')
            name = b'exit.invalid'
            sock.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + self.target.server_address[1].to_bytes(2, 'big'))
            self.assertNotEqual(m.recv(sock, 2)[1], 0)

    def test_16_bad_upstream_username_is_rejected(self):
        row = self.row()
        row['upstream_user'] = 'wrong-user'
        self.target.hits.clear()
        with self.assertRaises(m.Error):
            self.manager.apply({row['port']: row})
        self.assertEqual(self.manager.pointers(), {})
        self.assertEqual(self.target.hits, [])


if __name__ == '__main__':
    if not BINARY.is_file():
        raise SystemExit('请设置 THREEPROXY_BINARY 指向真实 3proxy 二进制。')
    unittest.main(verbosity=2)
