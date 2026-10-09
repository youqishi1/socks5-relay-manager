"""Real encrypted TCP/TUIC, pinned TLS, isolated upstreams and single-line input."""
import copy
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import access as a
import test_relay as relay
import test_clients
m = relay.m


class InputTests(unittest.TestCase):
    def test_complete_line_url_and_ipv6(self):
        for value, address, password in [
                ('203.0.113.1:1080:user:p:a:ss', '203.0.113.1', 'p:a:ss'),
                ('[2001:db8::1]:1080:user:中文:pass', '2001:db8::1', '中文:pass'),
                ('socks5://user:p%3Aa%40ss@203.0.113.1:1080', '203.0.113.1', 'p:a@ss')]:
            row = m.parse_upstream(value)
            self.assertEqual(row['upstream_host'], address)
            self.assertEqual(row['upstream_password'], password)

    def test_invalid_line_never_echoes_secrets(self):
        for value in ['host:99999:user:VERY_SECRET', 'host:1080:user:VERY_SECRET\nBAD',
                      'socks5://user:VERY_SECRET@host:1080?bad=1', 'host:1080:*:VERY_SECRET',
                      'socks5://user:VERY_SECRET\n@host:1080']:
            with self.assertRaises(m.Error) as caught:
                m.parse_upstream(value)
            self.assertNotIn('VERY_SECRET', str(caught.exception))

    def test_one_input_auto_credentials_and_loopback(self):
        manager = unittest.mock.Mock()
        manager.allocate.return_value = 20001
        with patch.object(m.getpass, 'getpass', return_value='203.0.113.1:1080:user:pass') as prompt, \
             patch.object(m, 'resolve', return_value='203.0.113.1'), \
             patch.object(m, 'health', return_value=('203.0.113.2', 1000)):
            row = m.pasted_row(manager)
        self.assertEqual(prompt.call_count, 1)
        self.assertEqual(row['bind'], '127.0.0.1')
        self.assertEqual(row['sources'], ['127.0.0.1'])
        self.assertGreaterEqual(len(row['client_password']), 32)


class DualProcesses(relay.Processes):
    def __init__(self):
        super().__init__()
        self.fronts = {}

    def apply(self, port, row):
        if port in self.fronts:
            m.stop_process(self.fronts.pop(port))
        super().apply(port, row)
        if row and row['enabled'] and row.get('access'):
            directory = self.manager.revision(port, m.read_json(self.manager.pointer_path(port)))
            process = subprocess.Popen([str(self.manager.access_binary), 'run', '-c', str(directory / 'access.json')],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.fronts[port] = process
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise m.Error('双模式真实进程未能启动')
                if m.listening(row['access']['port'], '127.0.0.1'):
                    return
                time.sleep(.05)
            raise m.Error('双模式监听超时')

    def close(self):
        for process in self.fronts.values():
            m.stop_process(process)
        self.fronts.clear()
        super().close()


class DualChains(unittest.TestCase):
    launch = test_clients.TuicChains.launch
    close = test_clients.TuicChains.close

    def setUp(self):
        self.singbox, self.mihomo = os.environ.get('SINGBOX_BINARY'), os.environ.get('MIHOMO_BINARY')
        if not self.singbox or not self.mihomo:
            self.skipTest('Real sing-box and Mihomo binaries required')
        self.fixture = relay.RelayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = Path(self.fixture.folder.name)
        self.processes, self.logs = [], []
        self.addCleanup(self.close)
        self.manager = self.fixture.manager
        self.backend = DualProcesses()
        self.backend.manager = self.manager
        self.fixture.backends.append(self.backend)
        self.manager.backend = self.backend
        self.manager.access_binary = Path(self.singbox)
        self.rows = []
        for index in (2, 3):
            row = self.fixture.row(self.fixture.upstream(index))
            row['bind'] = '127.0.0.1'
            row['client_user'] = 'client' + str(index)
            row['client_password'] = 'isolated-local-password-' + str(index)
            row['access'] = a.generate(self.rows, row['port'])
            self.manager.apply({row['port']: row})
            self.rows.append(row)

    def client(self, kind, mode, bad_pin=False, bad_password=False):
        configs = a.configs(self.rows, '203.0.113.1')
        name = 'clash-dual.yaml' if kind == 'mihomo' else 'v2rayn-' + mode + '.json'
        config = json.loads(configs[name])
        ports = []
        inbounds, field = ('listeners', 'port') if kind == 'mihomo' else ('inbounds', 'listen_port')
        for inbound in config[inbounds]:
            inbound[field] = m.free_port()
            ports.append(inbound[field])
        nodes = config['proxies'] if kind == 'mihomo' else config['outbounds']
        for node in nodes:
            node['server'] = '127.0.0.1'
            if bad_pin and node['type'] == 'tuic':
                if kind == 'mihomo':
                    node['fingerprint'] = '0' * 64
                else:
                    node['tls']['certificate'] = self.rows[1]['access']['certificate'].splitlines()
            if bad_password:
                node['password'] = ('A' * 43 + '=') if node['type'] in ('ss', 'shadowsocks') else 'wrong-test-password'
        if kind == 'mihomo':
            for group in config['proxy-groups'][:-1]:
                if mode == 'tcp':
                    group['proxies'].reverse()
        process = self.launch(kind, config, kind + '-' + mode)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and not all(m.listening(port, '127.0.0.1') for port in ports):
            self.assertIsNone(process.poll())
            time.sleep(.05)
        return ports

    def chain(self, kind, mode):
        ports = self.client(kind, mode)
        for index, (row, port) in enumerate(zip(self.rows, ports), 2):
            self.assertEqual(m.health('127.0.0.1', port, row['client_user'], row['client_password'], self.manager.ip_url)[0], '127.0.0.' + str(index))
        survivor = self.backend.fronts[self.rows[1]['port']].pid
        self.manager.apply({self.rows[0]['port']: None})
        self.assertEqual(self.backend.fronts[self.rows[1]['port']].pid, survivor)
        before = len(self.fixture.target.hits)
        with self.assertRaises(m.Error):
            m.health('127.0.0.1', ports[0], self.rows[0]['client_user'], self.rows[0]['client_password'], self.manager.ip_url)
        self.assertEqual(len(self.fixture.target.hits), before)
        self.assertEqual(m.health('127.0.0.1', ports[1], self.rows[1]['client_user'], self.rows[1]['client_password'], self.manager.ip_url)[0], '127.0.0.3')

    def test_mihomo_tcp(self): self.chain('mihomo', 'tcp')
    def test_mihomo_tuic(self): self.chain('mihomo', 'tuic')
    def test_singbox_tcp(self): self.chain('sing', 'tcp')
    def test_singbox_tuic(self): self.chain('sing', 'tuic')

    def test_export_validation_and_secret_boundaries(self):
        configs = a.configs(self.rows, '203.0.113.1')
        for data in configs.values():
            self.assertNotIn(self.rows[0]['upstream_password'], data)
            self.assertNotIn(self.rows[0]['upstream_user'], data)
            self.assertNotIn('PRIVATE KEY', data)
            self.assertNotIn('DIRECT', data)
        for address in ['127.0.0.1', '0.0.0.0', '::1', '224.0.0.1', 'invalid..domain', 'evil/command']:
            with self.assertRaises(a.AccessError): a.configs(self.rows, address)
        for field, value in [('ss_password', 'wrong'), ('uuid', None), ('private_key', None), ('fingerprint', '0' * 64)]:
            front = copy.deepcopy(self.rows[0]['access'])
            front[field] = value
            with self.assertRaises(a.AccessError): a.validate(front)

    def test_menu_default_single_paste_and_credential_view(self):
        from urllib.parse import quote
        upstream = self.fixture.upstream(4)
        port = self.manager.allocate()
        line = 'socks5://' + quote(upstream.user, safe='') + ':' + quote(upstream.password, safe='') + '@127.0.0.1:' + str(upstream.server_address[1])
        answers = iter(['1', '16', str(port), '0'])
        output = io.StringIO()
        with patch.object(self.manager, 'lock', side_effect=contextlib.nullcontext), \
             patch.object(m.getpass, 'getpass', return_value=line) as paste, \
             patch.object(m, 'public_address', return_value='203.0.113.1'), \
             patch('builtins.input', side_effect=lambda _: next(answers)), contextlib.redirect_stdout(output):
            m.menu(self.manager)
        self.assertEqual(paste.call_count, 1)
        row = self.manager.row(port)
        self.assertEqual(self.manager.verify(row)[0], '127.0.0.4')
        self.assertEqual(row['bind'], '127.0.0.1')
        self.assertIn(row['access']['tuic_password'], output.getvalue())
        self.assertIn('ss://', output.getvalue())
        files = list((self.manager.root / 'exports' / 'dual').glob('*'))
        self.assertEqual(len(files), 6)
        for path in files:
            self.assertNotIn(upstream.password, path.read_text(encoding='utf-8'))
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_v2rayn_internal_link_preserves_tls_and_runs_real_core(self):
        line = a.configs(self.rows, '203.0.113.1')['v2rayN-一键导入.txt'].splitlines()[1]
        encoded = line.split('/')[-1]
        profile = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        self.assertEqual(profile['ConfigVersion'], 4)
        self.assertEqual(profile['ConfigType'], 8)
        self.assertEqual(profile['CoreType'], 24)
        self.assertEqual(profile['AllowInsecure'], 'false')
        self.assertNotIn('PRIVATE KEY', profile['Cert'])
        # Fields consumed by v2rayN's official TUIC/TLS sing-box builder.
        port = m.free_port()
        config = {'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': port,
                                'users': [{'username': 'test', 'password': 'test'}]}],
                  'outbounds': [{'type': 'tuic', 'server': '127.0.0.1', 'server_port': profile['Port'],
                                 'uuid': profile['Username'], 'password': profile['Password'],
                                 'congestion_control': profile['ProtoExtraObj']['CongestionControl'],
                                 'tls': {'enabled': True, 'server_name': profile['Sni'], 'alpn': [profile['Alpn']],
                                         'insecure': False, 'certificate': profile['Cert'].splitlines()}}]}
        process = self.launch('sing', config, 'v2rayn-link-core')
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and not m.listening(port, '127.0.0.1'):
            self.assertIsNone(process.poll())
            time.sleep(.05)
        self.assertEqual(m.health('127.0.0.1', port, 'test', 'test', self.manager.ip_url)[0], '127.0.0.2')

    def test_wrong_tls_pin_rejected_by_both_clients(self):
        for kind in ('mihomo', 'sing'):
            ports = self.client(kind, 'tuic', bad_pin=True)
            before = len(self.fixture.target.hits)
            with self.assertRaises(m.Error):
                m.health('127.0.0.1', ports[0], self.rows[0]['client_user'], self.rows[0]['client_password'], self.manager.ip_url)
            self.assertEqual(len(self.fixture.target.hits), before)

    def test_wrong_transport_credentials_rejected(self):
        for mode in ('tcp', 'tuic'):
            ports = self.client('sing', mode, bad_password=True)
            before = len(self.fixture.target.hits)
            with self.assertRaises(m.Error):
                m.health('127.0.0.1', ports[0], self.rows[0]['client_user'], self.rows[0]['client_password'], self.manager.ip_url)
            self.assertEqual(len(self.fixture.target.hits), before)

    def test_upstream_failure_rolls_back_dual_services(self):
        old = self.manager.pointers()
        bad = copy.deepcopy(self.rows[0])
        bad['upstream_password'] = 'incorrect'
        with self.assertRaises(m.Error): self.manager.apply({bad['port']: bad})
        self.assertEqual(self.manager.pointers(), old)
        self.assertEqual(self.manager.verify(self.rows[0])[0], '127.0.0.2')
        ports = self.client('sing', 'tcp')
        self.assertEqual(m.health('127.0.0.1', ports[0], self.rows[0]['client_user'], self.rows[0]['client_password'], self.manager.ip_url)[0], '127.0.0.2')


if __name__ == '__main__':
    unittest.main(verbosity=2)
