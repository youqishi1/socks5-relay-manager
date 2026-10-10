"""Actual HTTP proof, include hints and safe cleanup for automatic webroot detection."""
import functools
import http.server
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import access
import certificates as c
import manager as m
import webroot as w


class Webroot(unittest.TestCase):
    domain = 'tuic.example.test'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='relay-webroot-test-')
        self.root = Path(self.temp.name)
        self.site = self.root / 'site with spaces'
        self.site.mkdir()
        (self.site / 'index.html').write_text('existing website')

    def tearDown(self):
        self.temp.cleanup()

    def serve(self, *, redirect=False, wrong=False):
        domain = self.domain
        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(handler):
                if handler.headers.get('Host') != f'{domain}:{handler.server.server_port}':
                    handler.send_error(404)
                elif redirect:
                    handler.send_response(301)
                    handler.send_header('Location', 'https://example.com/')
                    handler.end_headers()
                elif wrong:
                    handler.send_response(200)
                    handler.end_headers()
                    handler.wfile.write(b'not this VPS or not this website')
                else:
                    super().do_GET()
            def log_message(self, *_):
                pass
        handler = functools.partial(Handler, directory=str(self.site))
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        # Only DNS routing is a fixture; the real curl request, HTTP Host header,
        # status, body and file cleanup all go through production code.
        original = subprocess.run
        def run(args, **kwargs):
            args = list(args)
            args[1:1] = ['--resolve', f'{domain}:{server.server_port}:127.0.0.1']
            return original(args, **kwargs)
        routing = patch.object(w.subprocess, 'run', side_effect=run)
        routing.start()
        self.addCleanup(routing.stop)
        return server.server_port

    def test_free_port_needs_no_directory_or_configuration(self):
        with patch.object(w, 'port_free', return_value=True), \
             patch.object(w, 'candidates', side_effect=AssertionError('No webroot needed')):
            self.assertEqual(w.detect(self.domain), '')

    def test_real_domain_host_selects_served_root_and_preserves_other_sites(self):
        other = self.root / 'other-domain'
        other.mkdir()
        (other / 'index.html').write_text('other site')
        port = self.serve()
        result = w.detect(self.domain, port=port, roots=[str(other), str(self.site)])
        self.assertEqual(Path(result), self.site.resolve())
        self.assertEqual((self.site / 'index.html').read_text(), 'existing website')
        self.assertEqual((other / 'index.html').read_text(), 'other site')
        self.assertFalse((self.site / '.well-known').exists())
        self.assertFalse((other / '.well-known').exists())

    def test_wrong_domain_response_rejected_and_all_probe_files_removed(self):
        port = self.serve(wrong=True)
        with self.assertRaisesRegex(access.AccessError, '没有返回本机'):
            w.detect(self.domain, port=port, roots=[str(self.site)])
        self.assertFalse((self.site / '.well-known').exists())

    def test_redirect_rejected_without_following_other_domain(self):
        port = self.serve(redirect=True)
        with self.assertRaisesRegex(access.AccessError, 'HTTP 301'):
            w.detect(self.domain, port=port, roots=[str(self.site)])
        self.assertFalse((self.site / '.well-known').exists())

    def test_existing_challenge_files_and_permissions_untouched(self):
        directory = self.site / '.well-known' / 'acme-challenge'
        directory.mkdir(parents=True)
        before = directory / 'other-client-token'
        before.write_text('keep another ACME client')
        mode = directory.stat().st_mode
        port = self.serve()
        w.detect(self.domain, port=port, roots=[str(self.site)])
        self.assertEqual(list(directory.iterdir()), [before])
        self.assertEqual(before.read_text(), 'keep another ACME client')
        self.assertEqual(directory.stat().st_mode, mode)

    def test_probe_collision_never_overwrites_or_removes_existing_file(self):
        directory = self.site / '.well-known' / 'acme-challenge'
        directory.mkdir(parents=True)
        target = directory / 'collision'
        target.write_text('original')
        with self.assertRaises(FileExistsError):
            with w.challenge(self.site, 'collision', b'new'):
                self.fail('Must not overwrite')
        self.assertEqual(target.read_text(), 'original')

    @unittest.skipUnless(os.name == 'posix', 'Linux directory descriptors and permissions')
    def test_new_challenge_public_permissions_even_under_private_umask(self):
        previous = os.umask(0o077)
        try:
            with w.challenge(self.site, 'fixture', b'public random token'):
                for directory in (self.site / '.well-known', self.site / '.well-known/acme-challenge'):
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
                self.assertEqual((self.site / '.well-known/acme-challenge/fixture').stat().st_mode & 0o777, 0o644)
        finally:
            os.umask(previous)
        self.assertFalse((self.site / '.well-known').exists())

    @unittest.skipUnless(os.name == 'posix', 'Linux symlink protection')
    def test_symlink_directory_is_not_used_and_target_is_not_modified(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.site / '.well-known').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            with w.challenge(self.site, 'fixture', b'public'):
                self.fail('Symlink must not be followed')
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue((self.site / '.well-known').is_symlink())

    def test_nginx_apache_includes_quoted_roots_and_comments(self):
        nginx = self.root / 'nginx.conf'
        included = self.root / 'vhost.conf'
        apache = self.root / 'apache.conf'
        another = self.root / 'apache-site'
        another.mkdir()
        included.write_text(f'server {{ server_name {self.domain}; root "{self.site.as_posix()}"; }}\n')
        nginx.write_text('http { include vhost.conf; }\n# root /do-not-read;\n')
        apache.write_text(f'<VirtualHost *:80>\n ServerName {self.domain}\n'
            f' DocumentRoot "{another.as_posix()}" # trailing comment\n</VirtualHost>\n')
        found = w.candidates(self.domain, patterns=[str(nginx), str(apache)])
        self.assertIn(str(self.site.resolve()), found)
        self.assertIn(str(another.resolve()), found)
        port = self.serve()
        self.assertEqual(Path(w.detect(self.domain, port=port, roots=found)), self.site.resolve())

    def test_missing_roots_failure_does_not_run_certificate_client(self):
        with patch.object(w, 'port_free', return_value=False), patch.object(w, 'fetch') as fetch:
            with self.assertRaisesRegex(access.AccessError, '未找到'):
                w.detect(self.domain, roots=[str(self.root / 'missing')])
            fetch.assert_not_called()

    def test_relative_include_keeps_main_prefix_when_vhost_is_also_seeded(self):
        vhosts = self.root / 'vhosts'
        vhosts.mkdir()
        main, vhost, validation = self.root / 'nginx.conf', vhosts / 'site.conf', self.root / 'validation.conf'
        main.write_text('http { include vhosts/*.conf; }')
        vhost.write_text(f'server {{ server_name {self.domain}; include validation.conf; }}')
        validation.write_text(f'location /.well-known/acme-challenge/ {{ root "{self.site.as_posix()}"; }}')
        self.assertIn(str(self.site.resolve()), w.candidates(self.domain, patterns=[str(main), str(vhosts / '*.conf')]))

    def test_configure_only_asks_domain_email_when_auto_succeeds(self):
        manager = Mock(root=self.root)
        manager.rows.return_value = []
        settings = dict(domain=self.domain, email='', webroot=str(self.site))
        with patch.object(m, 'ask', side_effect=[self.domain, '']) as ask, \
             patch.object(w, 'detect', return_value=str(self.site)), \
             patch.object(c, 'obtain', return_value=('cert', 'key', 'fingerprint')) as obtain, \
             patch.object(c, 'apply_material', return_value=0), patch.object(c, 'install_timer'):
            c.configure(manager)
        self.assertEqual(ask.call_count, 2)
        obtain.assert_called_once_with(m.APP, settings)
        self.assertEqual(m.read_json(self.root / c.SETTING), settings)

    def test_failed_auto_and_cancel_keep_settings_and_services_untouched(self):
        manager = Mock(root=self.root)
        previous = dict(domain='previous.example.test', email='', webroot='')
        m.write_json(self.root / c.SETTING, previous)
        with patch.object(m, 'ask', side_effect=[self.domain, '', '']), \
             patch.object(w, 'detect', side_effect=access.AccessError('fixture failure')) as detect, \
             patch.object(c, 'obtain') as obtain, patch.object(c, 'install_timer') as timer:
            with self.assertRaises(m.Error):
                c.configure(manager)
        detect.assert_called_once_with(self.domain, '')  # Never reuse another domain's root.
        obtain.assert_not_called()
        timer.assert_not_called()
        manager.apply.assert_not_called()
        self.assertEqual(m.read_json(self.root / c.SETTING), previous)


if __name__ == '__main__':
    unittest.main(verbosity=2)
