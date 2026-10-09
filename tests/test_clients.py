"""Exporter security tests and real TUIC -> 3proxy -> authenticated SOCKS chains."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import client_config as c
import test_relay as relay
m = relay.m

LINK = 'tuic://00000000-0000-4000-8000-000000000001:secret%3A%40%22%E4%B8%AD%E6%96%87@203.0.113.1:10443?sni=tuic.example.org&alpn=h3&congestion_control=bbr'


def example_row(port=20001):
    return dict(port=port, client_user='client01', client_password='local $" :\\ 中文',
                enabled=True, bind='127.0.0.1', sources=['127.0.0.1'],
                upstream_user='provider-private', upstream_password='provider-secret')


class ExportTests(unittest.TestCase):
    def test_standard_link_and_url_escaped_password(self):
        node = c.parse_tuic(LINK)
        self.assertEqual(node['password'], 'secret:@"中文')
        self.assertEqual(node['cc'], 'bbr')
        self.assertEqual(node['alpn'], ['h3'])
        self.assertFalse(node['insecure'])

    def test_reject_malformed_unknown_and_control_fields(self):
        for link in [LINK.replace('tuic://', 'https://'), LINK.replace(':10443', ':99999'),
                     LINK.replace('00000000-0000-4000-8000-000000000001', 'invalid'),
                     LINK + '&evil=1', LINK + '&sni=other.example', LINK.replace('secret%3A', 'secret%0A'),
                     LINK.replace('203.0.113.1', '127.0.0.1'), LINK + '&allow_insecure=maybe',
                     LINK + '&congestion-controller=cubic']:
            with self.subTest(link=link), self.assertRaises(c.ConfigError):
                c.parse_tuic(link)

    def test_certificate_check_cannot_be_silently_disabled(self):
        node = c.parse_tuic(LINK + '&allow_insecure=1')
        with self.assertRaises(c.ConfigError):
            c.export_configs([example_row()], node)
        clash = json.loads(c.export_configs([example_row()], node, allow_insecure=True)['clash-verge.yaml'])
        self.assertTrue(clash['proxies'][0]['skip-cert-verify'])

    def test_per_port_routes_and_no_provider_credentials_or_direct_fallback(self):
        rows = [example_row(20002), example_row(20001)]
        rows.append({**example_row(20003), 'enabled': False})
        configs = c.export_configs(rows, c.parse_tuic(LINK))
        for value in configs.values():
            self.assertNotIn('provider-private', value)
            self.assertNotIn('provider-secret', value)
            self.assertNotIn('DIRECT', value)
            self.assertNotIn('fallback', value)
        clash = json.loads(configs['clash-verge.yaml'])
        self.assertEqual([item['port'] for item in clash['listeners']], [20001, 20002])
        for listener, proxy in zip(clash['listeners'], clash['proxies'][1:]):
            self.assertEqual(listener['listen'], '127.0.0.1')
            self.assertEqual(listener['proxy'], proxy['name'])
            self.assertEqual(proxy['server'], '127.0.0.1')
            self.assertFalse(listener['udp'])
            self.assertEqual(proxy['dialer-proxy'], clash['proxies'][0]['name'])
        sing = json.loads(configs['v2rayn-sing-box.json'])
        self.assertEqual(len(sing['route']['rules']), 2)
        self.assertEqual(sing['route']['final'], '固定出口-20001')
        self.assertFalse(sing['outbounds'][0]['tls']['insecure'])

    def test_empty_or_nonlocal_bind_rejected(self):
        for rows in [[], [{**example_row(), 'enabled': False}], [{**example_row(), 'bind': '10.0.0.1'}]]:
            with self.assertRaises(c.ConfigError):
                c.export_configs(rows, c.parse_tuic(LINK))

    def test_loopback_add_does_not_ask_to_expose_public_ports(self):
        with patch.object(m, 'host', side_effect=lambda value: value), \
             patch.object(m, 'ask', side_effect=['203.0.113.2', '1080', 'provider']), \
             patch.object(m.getpass, 'getpass', return_value='provider-password'), \
             patch.object(m, 'confirm', side_effect=[False, True]), \
             patch.object(m, 'resolve', return_value='203.0.113.2'), \
             patch.object(m, 'health', return_value=('203.0.113.3', 10)):
            manager = unittest.mock.Mock()
            manager.allocate.return_value = 20001
            row = m.new_row(manager, local_tuic=True)
        self.assertEqual(row['bind'], '127.0.0.1')
        self.assertEqual(row['sources'], ['127.0.0.1'])

    def test_private_export_files_and_no_service_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            manager = unittest.mock.Mock()
            manager.root = Path(folder)
            manager.rows.return_value = [example_row()]
            with patch.object(m.getpass, 'getpass', return_value=LINK):
                m.export_tuic(manager)
            files = list((Path(folder) / 'exports').glob('*/*'))
            self.assertEqual(len(files), 3)
            for path in files:
                self.assertNotIn('provider-secret', path.read_text(encoding='utf-8'))
                if os.name == 'posix':
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            manager.backend.assert_not_called()


class TuicChains(unittest.TestCase):
    def setUp(self):
        self.singbox = os.environ.get('SINGBOX_BINARY')
        self.mihomo = os.environ.get('MIHOMO_BINARY')
        self.openssl = os.environ.get('OPENSSL_BINARY') or shutil.which('openssl')
        if not self.singbox or not self.mihomo or not self.openssl:
            self.skipTest('Set SINGBOX_BINARY, MIHOMO_BINARY and provide OpenSSL for real TUIC tests')
        self.fixture = relay.RelayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = Path(self.fixture.folder.name)
        self.processes = []
        self.logs = []
        self.addCleanup(self.close)
        cert, key = self.root / 'test-cert.pem', self.root / 'test-key.pem'
        subprocess.run([self.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.cert = cert.read_text()
        self.fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert)).hexdigest()
        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            self.tuic_port = sock.getsockname()[1]
        self.node = c.parse_tuic(LINK)
        self.node.update(server='127.0.0.1', port=self.tuic_port, sni='localhost', cc='cubic')
        self.server_config = {'log': {'level': 'error'}, 'inbounds': [
            {'type': 'tuic', 'listen': '127.0.0.1', 'listen_port': self.tuic_port,
             'users': [{'uuid': self.node['uuid'], 'password': self.node['password']}],
             'tls': {'enabled': True, 'certificate_path': str(cert), 'key_path': str(key), 'alpn': ['h3']}}],
             'outbounds': [{'type': 'direct', 'tag': 'test-server-direct'}]}
        self.rows = []
        for index in (2, 3):
            row = self.fixture.row(self.fixture.upstream(index))
            row['bind'] = '127.0.0.1'
            row['client_user'] = 'client' + str(index)
            self.fixture.manager.apply({row['port']: row})
            self.rows.append(row)

    def close(self):
        for process in self.processes:
            m.stop_process(process)
        for stream in self.logs:
            stream.close()

    def launch(self, kind, config, name):
        path = self.root / (name + '.json')
        path.write_text(json.dumps(config, ensure_ascii=False), encoding='utf-8')
        if kind == 'sing':
            args = [self.singbox, 'run', '-c', str(path)]
            check = [self.singbox, 'check', '-c', str(path)]
        else:
            args = [self.mihomo, '-d', str(self.root / name), '-f', str(path)]
            check = [self.mihomo, '-t', '-d', str(self.root / name), '-f', str(path)]
        result = subprocess.run(check, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        stream = open(self.root / (name + '.log'), 'wb')
        self.logs.append(stream)
        process = subprocess.Popen(args, stdout=stream, stderr=stream)
        self.processes.append(process)
        return process

    def run_chain(self, kind):
        configs = c.export_configs(self.rows, self.node)
        name = 'clash-verge.yaml' if kind == 'mihomo' else 'v2rayn-sing-box.json'
        config = json.loads(configs[name])
        inbound_key, port_key = ('listeners', 'port') if kind == 'mihomo' else ('inbounds', 'listen_port')
        local_ports = []
        for inbound in config[inbound_key]:
            port = m.free_port()
            local_ports.append(port)
            inbound[port_key] = port  # Client and server are separate machines in production.
        server = self.launch('sing', self.server_config, 'tuic-server')
        time.sleep(0.3)
        # Test CA trust/pinning stays confined to fixtures, never the OS trust store.
        if kind == 'mihomo':
            config['proxies'][0]['fingerprint'] = self.fingerprint
        else:
            config['outbounds'][0]['tls']['certificate'] = self.cert.splitlines()
        client = self.launch(kind, config, kind + '-client')
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and not all(m.listening(port, '127.0.0.1') for port in local_ports):
            self.assertIsNone(client.poll())
            time.sleep(0.1)
        for index, (port, row) in enumerate(zip(local_ports, self.rows), 2):
            ip, _ = m.health('127.0.0.1', port, row['client_user'], row['client_password'], self.fixture.manager.ip_url)
            self.assertEqual(ip, '127.0.0.' + str(index))
        # Killing only TUIC must prevent the exported SOCKS nodes from dialing directly.
        m.stop_process(server)
        before = len(self.fixture.target.hits)
        with self.assertRaises(m.Error):
            m.health('127.0.0.1', local_ports[0], self.rows[0]['client_user'], self.rows[0]['client_password'], self.fixture.manager.ip_url)
        self.assertEqual(len(self.fixture.target.hits), before)

    def test_mihomo_real_tuic_per_port_identity_and_failure_closed(self):
        self.run_chain('mihomo')

    def test_singbox_real_tuic_per_port_identity_and_failure_closed(self):
        self.run_chain('sing')

    def test_untrusted_certificate_rejected_by_both_clients(self):
        self.launch('sing', self.server_config, 'untrusted-tuic-server')
        configs = c.export_configs(self.rows, self.node)
        for kind, name, inbound_key, port_key in (
                ('mihomo', 'clash-verge.yaml', 'listeners', 'port'),
                ('sing', 'v2rayn-sing-box.json', 'inbounds', 'listen_port')):
            config = json.loads(configs[name])
            for inbound in config[inbound_key]:
                inbound[port_key] = m.free_port()
            port = config[inbound_key][0][port_key]
            client = self.launch(kind, config, 'untrusted-' + kind)
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline and not m.listening(port, '127.0.0.1'):
                self.assertIsNone(client.poll())
                time.sleep(0.1)
            before = len(self.fixture.target.hits)
            with self.assertRaises(m.Error):
                m.health('127.0.0.1', port, self.rows[0]['client_user'], self.rows[0]['client_password'], self.fixture.manager.ip_url)
            self.assertEqual(len(self.fixture.target.hits), before)
            m.stop_process(client)


if __name__ == '__main__':
    unittest.main(verbosity=2)
