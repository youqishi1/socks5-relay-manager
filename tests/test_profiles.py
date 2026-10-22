"""Real UDP-only entrances, authenticated fixed exits and certificate verification."""
import asyncio
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import access
import entrance_profiles as profiles
import test_access
import test_clients
import test_relay

m = test_relay.m


class Policy(unittest.TestCase):
    def test_profile_validation_requires_public_ca_and_strong_hy2_password(self):
        for front in ({'profile': []}, {'profile': 'unknown'},
                      {'profile': 'hysteria2-only', 'hy2_password': 'x' * 43},
                      {'profile': 'hysteria2-only', 'certificate_trust': 'system', 'hy2_password': 'short'}):
            with self.assertRaises(access.AccessError):
                profiles.validate_profile(front)

    def test_refused_self_signed_change_does_not_restart_or_write(self):
        manager = Mock()
        row = dict(port=20001, access={'certificate_trust': 'self-signed'})
        with self.assertRaises(access.AccessError):
            profiles.configure(manager, row, '2')
        manager.apply.assert_not_called()
        self.assertNotIn('hy2_password', row['access'])


class Entrances(unittest.TestCase):
    launch = test_clients.TuicChains.launch
    close = test_clients.TuicChains.close

    def setUp(self):
        self.singbox, self.mihomo = os.environ.get('SINGBOX_BINARY'), os.environ.get('MIHOMO_BINARY')
        if not self.singbox or not self.mihomo:
            self.skipTest('Real sing-box and Mihomo binaries required')
        self.fixture = test_relay.RelayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = Path(self.fixture.folder.name)
        self.processes, self.logs = [], []
        self.addCleanup(self.close)
        self.manager = self.fixture.manager
        self.backend = test_access.DualProcesses()
        self.backend.manager = self.manager
        self.fixture.backends.append(self.backend)
        self.manager.backend = self.backend
        self.manager.access_binary = Path(self.singbox)
        self.row = self.fixture.row()
        self.row['bind'] = '127.0.0.1'
        self.row['client_password'] = 'local-only-fixture-client-password'
        self.row['access'] = access.generate([], self.row['port'])
        self.manager.apply({self.row['port']: self.row})

    def choose(self, choice):
        if choice == '2':
            # A local test root replaces the public CA, without disabling TLS.
            self.row['access'].update(server_name=access.SNI, certificate_trust='system')
        self.row = profiles.configure(self.manager, self.row, choice)
        return self.row

    def client(self, kind, mode, bad_password=False, bad_certificate=False):
        files = access.configs([self.row], '203.0.113.1')
        config = json.loads(files['clash-dual.yaml' if kind == 'mihomo' else 'v2rayn-' + mode + '.json'])
        port = m.free_port()
        inbound = config['listeners' if kind == 'mihomo' else 'inbounds'][0]
        inbound['port' if kind == 'mihomo' else 'listen_port'] = port
        node = config['proxies' if kind == 'mihomo' else 'outbounds'][0]
        node['server'] = '127.0.0.1'
        if bad_password:
            node['password'] = 'wrong-fixture-password'
        if kind == 'sing' and mode == 'hysteria2':
            node['tls']['certificate'] = self.row['access']['certificate'].splitlines()
            if bad_certificate:
                node['tls']['server_name'] = 'wrong.example.org'
        if kind == 'mihomo' and bad_certificate:
            node['sni'] = 'wrong.example.org'
        if kind == 'mihomo' and mode == 'hysteria2' and os.name == 'nt':
            # Go/Windows ignores SSL_CERT_FILE. Pin only this fixture's cert;
            # Mihomo still verifies the certificate name and expiry. Linux CI
            # exercises the unchanged system-CA export with SSL_CERT_FILE.
            node['fingerprint'] = self.row['access']['fingerprint']
        cert = self.root / 'trusted-fixture.pem'
        cert.write_text(self.row['access']['certificate'])
        with patch.dict(os.environ, {'SSL_CERT_FILE': str(cert)}):
            process = self.launch(kind, config, 'profile-' + kind + '-' + mode)
        deadline = time.monotonic() + 6
        while not m.listening(port, '127.0.0.1'):
            self.assertIsNone(process.poll())
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.05)
        return port

    def query(self, port):
        return m.health('127.0.0.1', port, self.row['client_user'], self.row['client_password'], self.manager.ip_url)[0]

    def test_tuic_only_closes_tcp_and_exports_no_ss(self):
        self.choose('1')
        self.assertFalse(m.listening(self.row['access']['port'], '127.0.0.1'))
        files = access.configs([self.row], '203.0.113.1')
        self.assertNotIn('v2rayn-tcp.json', files)
        self.assertNotIn('ss://', files['v2rayN-一键导入.txt'])
        for kind in ('sing', 'mihomo'):
            self.assertEqual(self.query(self.client(kind, 'tuic')), '127.0.0.2')
        saved = copy.deepcopy(self.row['access'])
        self.choose('3')
        self.assertTrue(m.listening(self.row['access']['port'], '127.0.0.1'))
        self.assertEqual(self.row['access'], {k: v for k, v in saved.items() if k != 'profile'})
        self.assertEqual(self.query(self.client('sing', 'tcp')), '127.0.0.2')

    def test_hy2_sing_and_mihomo_fixed_exit_and_verified_tls(self):
        self.choose('2')
        self.assertFalse(m.listening(self.row['access']['port'], '127.0.0.1'))
        for kind in ('sing', 'mihomo'):
            self.assertEqual(self.query(self.client(kind, 'hysteria2')), '127.0.0.2')
        for bad_password, bad_certificate in ((True, False), (False, True)):
            before = len(self.fixture.target.hits)
            with self.assertRaises(m.Error):
                self.query(self.client('sing', 'hysteria2', bad_password, bad_certificate))
            self.assertEqual(len(self.fixture.target.hits), before)
        for content in access.configs([self.row], '203.0.113.1').values():
            self.assertNotIn(self.row['upstream_password'], content)
            self.assertNotIn('PRIVATE KEY', content)

    def test_switch_cleanup_qr_refusal_and_mixed_exports(self):
        import tuic_qr
        with patch.object(m, 'public_address', return_value='203.0.113.1'), contextlib.redirect_stdout(io.StringIO()):
            directory = m.export_dual(self.manager)
            self.assertTrue((directory / 'v2rayn-tcp.json').exists())
            self.choose('2')
            m.export_dual(self.manager)
        self.assertFalse((directory / 'v2rayn-tcp.json').exists())
        self.assertFalse((directory / 'v2rayn-tuic.json').exists())
        self.assertTrue((directory / 'v2rayn-hysteria2.json').exists())
        with self.assertRaises(access.AccessError):
            tuic_qr.build(self.row, '203.0.113.1')
        legacy = copy.deepcopy(self.row)
        legacy['port'] += 1
        legacy['access'].pop('profile')
        legacy['access'].pop('hy2_password')
        legacy['access']['port'] += 1
        files = access.configs([self.row, legacy], '203.0.113.1')
        clash = json.loads(files['clash-dual.yaml'])
        self.assertEqual([n['type'] for n in clash['proxies']], ['hysteria2', 'ss', 'tuic'])
        self.assertEqual(len(json.loads(files['v2rayn-tcp.json'])['outbounds']), 1)
        self.assertEqual(len(json.loads(files['v2rayn-hysteria2.json'])['outbounds']), 1)

    def test_failed_upstream_switch_rolls_back_and_keeps_other_node(self):
        self.choose('1')
        other = self.fixture.row(self.fixture.upstream(3))
        other['bind'] = '127.0.0.1'
        other['access'] = access.generate([self.row], other['port'])
        self.manager.apply({other['port']: other})
        survivor = self.backend.fronts[other['port']].pid
        before = self.manager.pointers()
        broken = copy.deepcopy(self.row)
        broken['upstream_password'] = 'wrong-fixture-upstream'
        with self.assertRaises(m.Error):
            profiles.configure(self.manager, broken, '3')
        self.assertEqual(before, self.manager.pointers())
        self.assertEqual(survivor, self.backend.fronts[other['port']].pid)
        self.assertEqual(self.query(self.client('sing', 'tuic')), '127.0.0.2')

    def test_unauthenticated_http3_returns_web_content_without_upstream(self):
        try:
            from aioquic.asyncio import QuicConnectionProtocol, connect
            from aioquic.h3.connection import H3Connection
            from aioquic.h3.events import HeadersReceived, DataReceived
            from aioquic.quic.configuration import QuicConfiguration
        except ImportError:
            self.skipTest('aioquic is required for the independent HTTP/3 test')
        self.choose('2')
        cert = self.root / 'http3-trust.pem'
        cert.write_text(self.row['access']['certificate'])
        front = self.row['access']
        class Client(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.http = H3Connection(self._quic)
                self.done = asyncio.get_running_loop().create_future()
                self.headers, self.body = [], b''

            def quic_event_received(self, event):
                for item in self.http.handle_event(event):
                    if isinstance(item, HeadersReceived):
                        self.headers.extend(item.headers)
                    if isinstance(item, DataReceived):
                        self.body += item.data
                    if getattr(item, 'stream_ended', False) and not self.done.done():
                        self.done.set_result((self.headers, self.body))

        async def fetch(path, invalid_auth=False):
            config = QuicConfiguration(is_client=True, alpn_protocols=['h3'], server_name=access.SNI)
            config.load_verify_locations(cafile=str(cert))
            async with connect('127.0.0.1', front['port'], configuration=config, create_protocol=Client) as client:
                stream = client._quic.get_next_available_stream_id()
                headers = [(b':method', b'POST' if invalid_auth else b'GET'), (b':scheme', b'https'),
                           (b':authority', access.SNI.encode()), (b':path', path)]
                if invalid_auth:
                    headers += [(b'hysteria-auth', b'invalid-fixture-auth')]
                client.http.send_headers(stream, headers, end_stream=True)
                client.transmit()
                return await asyncio.wait_for(client.done, 8)
        before = len(self.fixture.target.hits)
        for path, invalid_auth in ((b'/', False), (b'/auth', True)):
            headers, body = asyncio.run(asyncio.wait_for(fetch(path, invalid_auth), 12))
            self.assertIn((b':status', b'200'), headers)
            self.assertIn(b'<!doctype html>', body)
            self.assertNotIn(b'hysteria', body.lower())
        self.assertEqual(len(self.fixture.target.hits), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
