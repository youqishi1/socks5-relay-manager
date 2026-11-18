"""Certificate identity/trust, safe exports, unchanged credentials and failure isolation."""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import access as a
import certificates as c
import manager as m


class CertificateToolFailures(unittest.TestCase):
    def test_manual_dns_bypasses_both_ports_and_uses_terminal(self):
        app = Path('unused')
        settings = dict(domain='tuic.example.test', email='', webroot='', challenge=c.DNS01)
        with patch.object(c.sys.stdin, 'isatty', return_value=True), \
             patch.object(c, 'check_binding') as bind, patch.object(c, 'ensure_client', return_value=app / 'lego'), \
             patch.object(c.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run, \
             patch.object(c, 'load_material', return_value=('cert', 'key', 'fingerprint')):
            self.assertEqual(c.obtain(app, settings), ('cert', 'key', 'fingerprint'))
        bind.assert_not_called()
        self.assertEqual(run.call_args.args[0][-2:], ['--dns', 'manual'])
        self.assertNotIn('--http', run.call_args.args[0])
        self.assertNotIn('--tls', run.call_args.args[0])
        self.assertNotIn('capture_output', run.call_args.kwargs)

    def test_manual_mode_does_not_wait_for_input_from_renewal_timer(self):
        with tempfile.TemporaryDirectory() as folder:
            manager = Mock(root=Path(folder))
            m.write_json(manager.root / c.SETTING,
                         dict(domain='tuic.example.test', email='', webroot='', challenge=c.DNS01))
            with patch.object(c, 'obtain') as obtain:
                c.renew(manager)
            obtain.assert_not_called()
            manager.apply.assert_not_called()

    def test_interrupted_download_retries_from_clean_file_and_verifies_archive(self):
        package = io.BytesIO()
        with tarfile.open(fileobj=package, mode='w:gz') as stream:
            member = tarfile.TarInfo('lego')
            member.size = 3
            stream.addfile(member, io.BytesIO(b'bin'))
        archive_bytes = package.getvalue()
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder)
            calls = []

            def download(command, **kwargs):
                archive = Path(command[-1])
                self.assertFalse(archive.exists(), 'a retry must discard the partial archive')
                self.assertEqual(command[command.index('--proto-redir') + 1], '=https')
                calls.append(command)
                archive.write_bytes(b'partial' if len(calls) == 1 else archive_bytes)
                if len(calls) == 1:
                    raise subprocess.TimeoutExpired(command, kwargs['timeout'])
                return subprocess.CompletedProcess(command, 0)

            with patch.object(c.platform, 'machine', return_value='x86_64'), \
                 patch.dict(c.LEGO_HASHES, amd64=hashlib.sha256(archive_bytes).hexdigest()), \
                 patch.object(c.subprocess, 'run', side_effect=download):
                self.assertEqual(c.ensure_client(app).read_bytes(), b'bin')
                self.assertEqual(c.ensure_client(app).read_bytes(), b'bin')
                self.assertEqual(len(calls), 2)

    def test_bad_hash_or_malformed_archive_never_replaces_tool(self):
        for valid_hash, expected in ((False, 'SHA-256'), (True, '无法解包')):
            with self.subTest(valid_hash=valid_hash), tempfile.TemporaryDirectory() as folder:
                app = Path(folder)
                def download(url, archive):
                    archive.write_bytes(b'not a tarball')
                digest = hashlib.sha256(b'not a tarball').hexdigest() if valid_hash else '0' * 64
                with patch.object(c.platform, 'machine', return_value='x86_64'), \
                     patch.dict(c.LEGO_HASHES, amd64=digest), patch.object(c, 'download_lego', side_effect=download):
                    with self.assertRaisesRegex(a.AccessError, expected):
                        c.ensure_client(app)
                self.assertFalse((app / 'acme' / 'lego').exists())

    def test_permanent_download_failure_is_not_retried_or_printed_raw(self):
        response = subprocess.CompletedProcess([], 60, stderr=b'PRIVATE_PROXY_DETAIL')
        with patch.object(c.subprocess, 'run', return_value=response) as run:
            with self.assertRaisesRegex(a.AccessError, 'HTTPS 证书校验失败') as caught:
                c.download_lego('https://example.test/file', Path('unused'))
        run.assert_called_once()
        self.assertNotIn('PRIVATE_PROXY_DETAIL', str(caught.exception))

    def test_acme_refusal_uses_safe_phase_specific_messages(self):
        cases = [
            (b'urn:ietf:params:acme:error:dns', '未能解析域名'),
            (b'urn:ietf:params:acme:error:unauthorized: Invalid response', 'HTTP-01 验证失败'),
            (b'urn:ietf:params:acme:error:rateLimited', '频率限制'),
            (b'Get https://ca.test/directory: dial tcp: i/o timeout', 'HTTPS 接口'),
        ]
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder)
            settings = dict(domain='tuic.example.test', email='', webroot=folder)
            for detail, expected in cases:
                with self.subTest(detail=detail), patch.object(c, 'ensure_client', return_value=app / 'lego'), \
                     patch.object(c.subprocess, 'run', return_value=subprocess.CompletedProcess(
                         [], 1, stdout=b'', stderr=detail + b' PRIVATE_CHALLENGE_TOKEN')), \
                     patch.object(c, 'load_material') as load:
                    with self.assertRaisesRegex(a.AccessError, expected) as caught:
                        c.obtain(app, settings)
                    load.assert_not_called()
                    self.assertNotIn('PRIVATE_CHALLENGE_TOKEN', str(caught.exception))

    def test_alpn_fallback_does_not_take_occupied_443_or_persist_failure(self):
        settings = dict(domain='tuic.example.test', email='', webroot='')
        denied = a.AccessError('本机 TCP 443 已被占用')
        failed_http = subprocess.CompletedProcess([], 1, stdout=b'',
            stderr=b'urn:ietf:params:acme:error:connection :: Timeout during connect')
        with patch.object(c, 'check_binding', side_effect=[None, denied]) as binding, \
             patch.object(c, 'ensure_client', return_value=Path('lego')), \
             patch.object(c.subprocess, 'run', return_value=failed_http) as run, \
             patch.object(c, 'load_material') as load:
            with self.assertRaisesRegex(a.AccessError, '443 已被占用'):
                c.obtain(Path('unused'), settings)
        self.assertEqual([call.args[0] for call in binding.call_args_list], [80, 443])
        run.assert_called_once()
        load.assert_not_called()
        self.assertNotIn('challenge', settings)

    def test_renew_remembers_successful_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            settings = dict(domain='tuic.example.test', email='', webroot='')
            m.write_json(root / c.SETTING, settings)
            failed_http = subprocess.CompletedProcess([], 1, stdout=b'',
                stderr=b'urn:ietf:params:acme:error:connection :: Timeout during connect')
            success = subprocess.CompletedProcess([], 0)
            manager = Mock(root=root)
            manager.rows.return_value = []
            with patch.object(c, 'check_binding'), patch.object(c, 'ensure_client', return_value=root / 'lego'), \
                 patch.object(c.subprocess, 'run', side_effect=[failed_http, success, success]) as run, \
                 patch.object(c, 'load_material', return_value=('cert', 'key', 'fingerprint')):
                c.renew(manager)
                c.renew(manager)
            self.assertEqual(m.read_json(root / c.SETTING)['challenge'], c.TLS01)
            self.assertEqual([('--http' in call.args[0], '--tls' in call.args[0]) for call in run.call_args_list],
                             [(True, False), (False, True), (False, True)])

    def test_fallback_renewal_noop_does_not_remember_unverified_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder)
            settings = dict(domain='tuic.example.test', email='', webroot='')
            cert, _ = c.material_paths(app, settings['domain'])
            cert.parent.mkdir(parents=True)
            cert.write_bytes(b'existing certificate')
            material = ('existing certificate', 'existing key', 'fingerprint')
            with patch.object(c, '_obtain', side_effect=[c.HTTPUnavailable('80 busy'), material]):
                self.assertEqual(c.obtain(app, settings, renew=True), material)
            self.assertNotIn('challenge', settings)


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='relay-cert-test-')
        cls.root = Path(cls.folder.name)
        cls.domain = 'tuic.example.test'
        (cls.root / 'openssl.cnf').write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n'
            '[dn]\nCN=' + cls.domain + '\n[ext]\nsubjectAltName=DNS:' + cls.domain + '\nbasicConstraints=critical,CA:TRUE\n')
        subprocess.run([os.environ.get('OPENSSL_BINARY', 'openssl'), 'req', '-x509', '-newkey', 'rsa:2048',
            '-nodes', '-days', '2', '-keyout', str(cls.root / 'key.pem'), '-out', str(cls.root / 'cert.pem'),
            '-config', str(cls.root / 'openssl.cnf')], check=True, capture_output=True)
        cls.cert = (cls.root / 'cert.pem').read_text()
        cls.key = (cls.root / 'key.pem').read_text()

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def context(self):
        return ssl.create_default_context(cadata=self.cert)

    def front(self):
        return dict(port=30001, uuid='00000000-0000-4000-8000-000000000001', tuic_password='fixture-password-only',
            ss_password=base64.b64encode(b'x' * 32).decode(), certificate=self.cert, private_key=self.key,
            fingerprint=hashlib.sha256(a.leaf_der(self.cert)).hexdigest())

    def row(self):
        return dict(port=20001, enabled=True, access=self.front(), client_user='local', client_password='local-only')

    def test_chain_key_and_hostname_check_with_explicit_fixture_ca(self):
        digest = c.validate_material(self.cert, self.key, self.domain, self.context())
        self.assertEqual(digest, self.front()['fingerprint'])

    def test_self_signed_rejected_by_default_system_trust(self):
        with self.assertRaises(a.AccessError):
            c.validate_material(self.cert, self.key, self.domain)

    def test_wrong_domain_and_unverified_context_rejected(self):
        for context, domain in [(self.context(), 'wrong.example.test'),
                                (ssl._create_unverified_context(), self.domain)]:
            with self.assertRaises(a.AccessError):
                c.validate_material(self.cert, self.key, domain, context)

    def test_invalid_key_and_chain_never_echo_material(self):
        for cert, key in [(self.cert, 'PRIVATE_TEST_SENTINEL'), (self.cert + 'PRIVATE_TEST_SENTINEL', self.key)]:
            with self.assertRaises(a.AccessError) as caught:
                c.validate_material(cert, key, self.domain, self.context())
            self.assertNotIn('PRIVATE_TEST_SENTINEL', str(caught.exception))

    def test_legacy_pin_and_public_ca_exports_are_distinct(self):
        row = self.row()
        old = a.configs([row], '203.0.113.1')
        self.assertIn('certificate', json.loads(old['v2rayn-tuic.json'])['outbounds'][0]['tls'])
        row['access'] = c.public_front(row['access'], self.cert, self.key, self.domain, row['access']['fingerprint'])
        exports = a.configs([row], '203.0.113.1')
        tls = json.loads(exports['v2rayn-tuic.json'])['outbounds'][0]['tls']
        self.assertNotIn('certificate', tls)
        self.assertFalse(tls['insecure'])
        self.assertEqual(tls['server_name'], self.domain)
        proxy = json.loads(exports['clash-dual.yaml'])['proxies'][1]
        self.assertNotIn('fingerprint', proxy)
        self.assertFalse(proxy['skip-cert-verify'])
        query = parse_qs(urlsplit(exports['TUIC-普通链接.txt'].strip()).query)
        self.assertEqual(query['sni'], [self.domain])
        self.assertEqual(query['allow_insecure'], ['0'])
        for content in exports.values():
            self.assertNotIn('PRIVATE KEY', content)
        internal = a.v2rayn_link(row['access'], '203.0.113.1', 'test').split('/')[-1]
        profile = json.loads(base64.urlsafe_b64decode(internal + '=' * (-len(internal) % 4)))
        self.assertEqual(profile['Cert'], '')
        self.assertEqual(profile['AllowInsecure'], 'false')
        self.assertEqual(profile['Sni'], self.domain)

    def test_apply_preserves_all_credentials_and_noop_does_not_restart(self):
        original = self.row()
        manager = Mock()
        manager.rows.return_value = [original]
        settings = dict(domain=self.domain, email='', webroot='')
        material = (self.cert, self.key, original['access']['fingerprint'])
        self.assertEqual(c.apply_material(manager, settings, material), 1)
        updated = manager.apply.call_args.args[0][20001]
        for field in ('port', 'uuid', 'tuic_password', 'ss_password'):
            self.assertEqual(updated['access'][field], original['access'][field])
        self.assertEqual(original['access'], self.front())
        manager.rows.return_value = [updated]
        manager.apply.reset_mock()
        self.assertEqual(c.apply_material(manager, settings, material), 0)
        manager.apply.assert_not_called()

    def test_failed_acme_keeps_rows_settings_and_timer_untouched(self):
        with tempfile.TemporaryDirectory() as folder:
            manager = Mock(root=Path(folder))
            manager.rows.return_value = [self.row()]
            with patch.object(m, 'ask', side_effect=[self.domain, '', '1']), \
                 patch('webroot.detect', return_value=''), \
                 patch.object(c, 'obtain', side_effect=a.AccessError('fixture issuance failure')), \
                 patch.object(c, 'install_timer') as timer:
                with self.assertRaises(m.Error):
                    c.configure(manager)
            manager.apply.assert_not_called()
            timer.assert_not_called()
            self.assertFalse((manager.root / c.SETTING).exists())

    def test_menu_manual_choice_bypasses_webroot_and_disables_automatic_renewal(self):
        with tempfile.TemporaryDirectory() as folder:
            manager = Mock(root=Path(folder))
            manager.rows.return_value = []
            with patch.object(m, 'ask', side_effect=[self.domain, '', '2']), patch('webroot.detect') as detect, \
                 patch.object(c, 'obtain', return_value=('cert', 'key', 'fingerprint')), \
                 patch.object(c, 'install_timer') as timer:
                c.configure(manager)
            self.assertEqual(m.read_json(manager.root / c.SETTING)['challenge'], c.DNS01)
            detect.assert_not_called()
            timer.assert_not_called()

    def test_domains_settings_and_command_cannot_inject_options(self):
        for value in ['../test', '--domain.test', 'test\n.example', '203.0.113.1', '*.example.com', 'https://example.com']:
            with self.assertRaises(a.AccessError):
                a.domain_name(value)
        args = c.acme_command(Path('/project/lego'), Path('/project/acme'), dict(domain=self.domain, email='', webroot=''))
        self.assertEqual(args[:2], [str(Path('/project/lego')), 'run'])
        self.assertNotIn('--tls-skip-verify', args)
        self.assertEqual(args[args.index('--http.address') + 1], '0.0.0.0:80')
        web = c.acme_command(Path('/project/lego'), Path('/project/acme'), dict(domain=self.domain, email='', webroot=str(self.root)))
        self.assertNotIn('--http.address', web)
        self.assertIn('--http.webroot', web)

    def test_new_nodes_automatically_inherit_this_vps_domain(self):
        with tempfile.TemporaryDirectory() as folder:
            manager = Mock(root=Path(folder))
            settings = dict(domain=self.domain, email='', webroot='')
            m.write_json(manager.root / c.SETTING, settings)
            front = a.generate([], 20001)
            material = self.cert, self.key, hashlib.sha256(a.leaf_der(self.cert)).hexdigest()
            with patch.object(c, 'load_material', return_value=material):
                public = c.for_new(manager, front)
            self.assertEqual(public['server_name'], self.domain)
            for name in ('uuid', 'tuic_password', 'ss_password', 'port'):
                self.assertEqual(public[name], front[name])

    def test_actual_misub_parser_and_uri_converter_preserve_public_tls(self):
        import shutil
        from misub_fixture import roundtrip
        if not os.environ.get('NODE_BINARY') and not shutil.which('node'):
            self.skipTest('Node required for upstream MiSub converter')
        front = a.generate([], 20001)
        fp = c.validate_material(self.cert, self.key, self.domain, context=self.context())
        front = c.public_front(front, self.cert, self.key, self.domain, fp)
        result = roundtrip(a.tuic_link(front, '203.0.113.1', '测试 TUIC'))
        for node in (result['parsed'], result['reparsed']):
            self.assertEqual(node['uuid'], front['uuid'])
            self.assertEqual(node['password'], front['tuic_password'])
            self.assertEqual(node['sni'], self.domain)
            self.assertEqual(node['alpn'], ['h3'])
            self.assertEqual(node['congestion-controller'], 'bbr')
            self.assertFalse(node.get('skip-cert-verify', False))
            self.assertNotIn('fingerprint', node)
        self.assertNotIn('PRIVATE KEY', json.dumps(result))

    @unittest.skipUnless(os.environ.get('RELAY_DISPOSABLE_HOST') == 'YES', 'Real systemd only on disposable CI hosts')
    def test_real_certificate_timer_on_installed_systemd(self):
        try:
            c.install_timer()
            subprocess.run(['systemctl', 'is-enabled', 'socks-relay-cert.timer'], check=True, capture_output=True)
            subprocess.run(['systemctl', 'is-active', 'socks-relay-cert.timer'], check=True, capture_output=True)
            subprocess.run(['systemd-analyze', 'verify', '/etc/systemd/system/socks-relay-cert.service',
                '/etc/systemd/system/socks-relay-cert.timer'], check=True, capture_output=True)
        finally:
            subprocess.run(['systemctl', 'stop', 'socks-relay-cert.timer'], capture_output=True)
            subprocess.run(['systemctl', 'disable', 'socks-relay-cert.timer'], capture_output=True)
            for name in ('socks-relay-cert.service', 'socks-relay-cert.timer'):
                (Path('/etc/systemd/system') / name).unlink(missing_ok=True)
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)

    @unittest.skipUnless(os.environ.get('RELAY_DISPOSABLE_HOST') == 'YES', 'Real Linux certificate tool installation on disposable CI hosts')
    def test_real_private_certificate_tool_install_and_verified_cache(self):
        with tempfile.TemporaryDirectory(prefix='relay-lego-install-test-') as folder:
            app = Path(folder)
            binary = c.ensure_client(app)
            result = subprocess.run([str(binary), '--version'], capture_output=True, check=True)
            self.assertIn(b'5.5.2', result.stdout)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            self.assertEqual((binary.parent / 'lego.sha256').read_text().strip(), digest)
            self.assertEqual(binary.stat().st_mode & 0o777, 0o700)
            with patch.object(c.subprocess, 'run', side_effect=AssertionError('Verified cache should not download again')):
                self.assertEqual(c.ensure_client(app), binary)


if __name__ == '__main__':
    unittest.main(verbosity=2)
