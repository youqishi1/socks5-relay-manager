"""Real pinned Lego/Pebble HTTP-01 issuance and renewal, on local high ports only."""
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import certificates as c
import webroot as w


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class DNS(socketserver.BaseRequestHandler):
    @staticmethod
    def response(data):
        end = 12
        while data[end]:
            end += data[end] + 1
        end += 1
        kind = struct.unpack('!H', data[end:end + 2])[0]
        question = data[12:end + 4]
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton('127.0.0.1') if kind == 1 else b''
        return data[:2] + struct.pack('!HHHHH', 0x8180, 1, bool(answer), 0, 0) + question + answer

    def handle(self):
        data, sock = self.request
        sock.sendto(self.response(data), self.client_address)


class DNSTCP(DNS):
    def handle(self):
        self.request.settimeout(3)
        size = struct.unpack('!H', self.request.recv(2))[0]
        data = b''
        while len(data) < size:
            part = self.request.recv(size - len(data))
            if not part:
                return
            data += part
        answer = self.response(data)
        self.request.sendall(struct.pack('!H', len(answer)) + answer)


class QuietHTTP(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if os.name == 'posix' and '/.well-known/acme-challenge/' in self.path:
            target = Path(self.translate_path(self.path))
            if not (target.stat().st_mode & 0o004) or any(not (p.stat().st_mode & 0o001)
                    for p in (target.parent, target.parent.parent)):
                self.send_error(403, 'Challenge must be readable by an existing web-server account')
                return
        super().do_GET()

    def log_message(self, *_):
        pass


class ACME(unittest.TestCase):
    def test_real_http01_empty_email_noop_renewal_and_existing_webroot(self):
        lego, pebble = os.environ.get('LEGO_BINARY'), os.environ.get('PEBBLE_BINARY')
        if not lego or not pebble:
            self.skipTest('Pinned official Lego and Pebble binaries required')
        with tempfile.TemporaryDirectory(prefix='relay-acme-test-') as folder:
            root = Path(folder)
            config = root / 'openssl.cnf'
            config.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n'
                '[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\n')
            subprocess.run([os.environ.get('OPENSSL_BINARY', 'openssl'), 'req', '-x509', '-newkey', 'rsa:2048',
                '-nodes', '-days', '2', '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                '-config', str(config)], check=True, capture_output=True)
            dns = socketserver.ThreadingUDPServer(('127.0.0.1', 0), DNS)
            threading.Thread(target=dns.serve_forever, daemon=True).start()
            dns_tcp = socketserver.ThreadingTCPServer(dns.server_address, DNSTCP)
            threading.Thread(target=dns_tcp.serve_forever, daemon=True).start()
            api, management, challenge = free_port(), free_port(), free_port()
            cfg = {'pebble': {'listenAddress': f'127.0.0.1:{api}', 'managementListenAddress': f'127.0.0.1:{management}',
                'certificate': str(root / 'cert.pem'), 'privateKey': str(root / 'key.pem'),
                'httpPort': challenge, 'tlsPort': free_port(), 'externalAccountBindingRequired': False,
                'domainBlocklist': [], 'retryAfter': {'authz': 1, 'order': 1}, 'keyAlgorithm': 'ecdsa',
                'profiles': {'default': {'description': 'private fixture', 'validityPeriod': 7776000}}}}
            (root / 'pebble.json').write_text(json.dumps(cfg))
            env = dict(os.environ, PEBBLE_VA_NOSLEEP='1', PEBBLE_WFE_NONCEREJECT='0', PEBBLE_AUTHZREUSE='0')
            with (root / 'pebble.log').open('wb') as log:
                process = subprocess.Popen([pebble, '-config', str(root / 'pebble.json'), '-dnsserver',
                    '127.0.0.1:' + str(dns.server_address[1])], env=env, stdout=log, stderr=log)
                try:
                    ctx = ssl.create_default_context(cafile=str(root / 'cert.pem'))
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
                    directory = f'https://localhost:{api}/dir'
                    deadline = time.monotonic() + 15
                    while True:
                        try:
                            opener.open(directory, timeout=1).close()
                            break
                        except OSError:
                            if process.poll() is not None or time.monotonic() >= deadline:
                                self.fail('Pebble failed to start: ' + (root / 'pebble.log').read_text())
                            time.sleep(.1)
                    settings = dict(domain='tuic.example.test', email='', webroot='')
                    args = c.acme_command(Path(lego), root / 'acme', settings)
                    args[args.index('--server') + 1] = directory
                    args[args.index('--http.address') + 1] = f'127.0.0.1:{challenge}'
                    env = {k: v for k, v in os.environ.items() if not k.startswith('LEGO_')}
                    env['LEGO_CA_CERTIFICATES'] = str(root / 'cert.pem')
                    def run(command):
                        permissions = {'umask': 0o022 if '--http.webroot' in command else 0o077} if os.name == 'posix' else {}
                        result = subprocess.run(command, env=env, capture_output=True, timeout=60, **permissions)
                        self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace') + '\n' + (root / 'pebble.log').read_text())
                    run(args)
                    cert, key = c.material_paths(root, settings['domain'])
                    self.assertTrue(cert.is_file())
                    ca = opener.open(f'https://localhost:{management}/roots/0', timeout=5).read().decode()
                    issued_ctx = ssl.create_default_context(cadata=ca)
                    before = c.validate_material(cert.read_text(), key.read_text(), settings['domain'], context=issued_ctx)
                    digest = hashlib.sha256(cert.read_bytes()).hexdigest()
                    run(args)
                    self.assertEqual(hashlib.sha256(cert.read_bytes()).hexdigest(), digest)
                    run(args + ['--renew-force'])
                    after = c.validate_material(cert.read_text(), key.read_text(), settings['domain'], context=issued_ctx)
                    self.assertNotEqual(before, after)
                    site = root / 'site'
                    site.mkdir()
                    (site / 'index.html').write_text('existing website')
                    handler = functools.partial(QuietHTTP, directory=str(site))
                    server = http.server.ThreadingHTTPServer(('127.0.0.1', challenge), handler)
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                    try:
                        # Discover and prove the existing root before real ACME
                        # issuance; DNS routing alone is local test infrastructure.
                        config = root / 'nginx.conf'
                        config.write_text(f'server {{ server_name {settings["domain"]}; root "{site.as_posix()}"; }}')
                        original_run = subprocess.run
                        def routed(command, **kwargs):
                            command = list(command)
                            command[1:1] = ['--resolve', f'{settings["domain"]}:{challenge}:127.0.0.1']
                            return original_run(command, **kwargs)
                        with patch.object(w.subprocess, 'run', side_effect=routed):
                            detected = w.detect(settings['domain'], port=challenge,
                                roots=w.candidates(settings['domain'], patterns=[str(config)]))
                        self.assertEqual(Path(detected), site.resolve())
                        webargs = c.acme_command(Path(lego), root / 'web-acme', dict(settings, webroot=detected))
                        webargs[webargs.index('--server') + 1] = directory
                        run(webargs)
                        self.assertEqual((site / 'index.html').read_text(), 'existing website')
                        self.assertTrue((root / 'web-acme' / 'certificates' / (settings['domain'] + '.crt')).is_file())
                    finally:
                        server.shutdown()
                        server.server_close()
                finally:
                    process.terminate()
                    process.wait(timeout=10)
                    dns.shutdown()
                    dns.server_close()
                    dns_tcp.shutdown()
                    dns_tcp.server_close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
