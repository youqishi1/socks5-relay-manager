"""Real pinned Lego/Pebble HTTP-01 and TLS-ALPN-01 issuance, on local high ports."""
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import queue
import re
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
    def response(data, txt=None):
        end = 12
        labels = []
        while data[end]:
            size = data[end]
            labels.append(data[end + 1:end + 1 + size])
            end += size + 1
        end += 1
        kind = struct.unpack('!H', data[end:end + 2])[0]
        question = data[12:end + 4]
        name = b'.'.join(labels).lower()
        value = None
        if kind == 1:
            value = socket.inet_aton('127.0.0.1')
        elif kind == 16 and txt and name in txt:
            value = bytes([len(txt[name])]) + txt[name]
        elif kind == 6 and name == b'example.test':
            value = b'\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00' + struct.pack('!IIIII', 1, 60, 60, 3600, 5)
        answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 5, len(value)) + value if value is not None else b''
        return data[:2] + struct.pack('!HHHHH', 0x8180, 1, bool(answer), 0, 0) + question + answer

    def handle(self):
        data, sock = self.request
        sock.sendto(self.response(data, self.server.txt), self.client_address)


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
        answer = self.response(data, self.server.txt)
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
            dns.txt = dns_tcp.txt = {}
            threading.Thread(target=dns_tcp.serve_forever, daemon=True).start()
            api, management, challenge = free_port(), free_port(), free_port()
            tls_challenge = free_port()
            cfg = {'pebble': {'listenAddress': f'127.0.0.1:{api}', 'managementListenAddress': f'127.0.0.1:{management}',
                'certificate': str(root / 'cert.pem'), 'privateKey': str(root / 'key.pem'),
                'httpPort': challenge, 'tlsPort': tls_challenge, 'externalAccountBindingRequired': False,
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
                    settings = dict(domain='tuic.example.test', email='', webroot='',
                                    additional_domains=['cover.example.test'])
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
                    c.validate_material(cert.read_text(), key.read_text(), settings['additional_domains'][0], context=issued_ctx)
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
                    # The CA's HTTP port has no listener. Lego listens on a
                    # different HTTP port on its first attempt so that only a
                    # real CA-side connection failure triggers the TLS path.
                    fallback_root = root / 'fallback'
                    fallback = dict(domain='fallback.example.test', email='', webroot='')
                    modes = []
                    build = c.acme_command

                    def local_command(binary, base, selected, renew=False):
                        command = build(binary, base, selected, renew=renew)
                        command[command.index('--server') + 1] = directory
                        tls = '--tls' in command
                        modes.append(tls)
                        flag, port = ('--tls.address', tls_challenge) if tls else ('--http.address', free_port())
                        command[command.index(flag) + 1] = f'127.0.0.1:{port}'
                        return command

                    def local_run(command, **kwargs):
                        kwargs['env'] = env
                        if os.name != 'posix':
                            kwargs.pop('umask', None)
                        return original_run(command, **kwargs)

                    def local_material(app, selected):
                        cert_file, key_file = c.material_paths(app, selected['domain'])
                        chain = cert_file.read_text()
                        private_key = key_file.read_text()
                        fingerprint = c.validate_material(chain, private_key, selected['domain'], context=issued_ctx)
                        return chain, private_key, fingerprint

                    with patch.object(c, 'acme_command', side_effect=local_command), \
                         patch.object(c, 'check_binding'), patch.object(c, 'ensure_client', return_value=Path(lego)), \
                         patch.object(c, 'load_material', side_effect=local_material), \
                         patch.object(c.subprocess, 'run', side_effect=local_run):
                        first = c.obtain(fallback_root, fallback)
                        self.assertEqual(fallback.get('challenge'), c.TLS01)
                        again = c.obtain(fallback_root, fallback, renew=True)
                    self.assertEqual(modes, [False, True, True])
                    self.assertEqual(first[2], again[2])
                    self.verify_manual_dns(lego, root, dns, directory, env, issued_ctx)
                finally:
                    process.terminate()
                    process.wait(timeout=10)
                    dns.shutdown()
                    dns.server_close()
                    dns_tcp.shutdown()
                    dns_tcp.server_close()

    def verify_manual_dns(self, lego, root, dns, directory, env, issued_ctx):
        manual_root = root / 'manual'
        settings = dict(domain='manual.example.test', email='', webroot='', challenge=c.DNS01)
        args = c.acme_command(Path(lego), manual_root / 'acme', settings)
        args[args.index('--server') + 1] = directory
        # The fixture's recursive resolver runs on a high port. Restrict
        # fixture lookups to it; production still checks authoritative DNS.
        args += ['--dns.resolvers', '127.0.0.1:' + str(dns.server_address[1]), '--dns.propagation.disable-ans']
        with subprocess.Popen(args, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT) as process:
            lines = queue.Queue()
            def collect():
                for line in process.stdout:
                    lines.put(line)
                lines.put(None)
            threading.Thread(target=collect, daemon=True).start()
            deadline = time.monotonic() + 55
            received = []
            added = False
            try:
                while True:
                    line = lines.get(timeout=max(.1, deadline - time.monotonic()))
                    if line is None:
                        break
                    received.append(line)
                    match = re.fullmatch(rb'(_acme-challenge\.manual\.example\.test)\. \d+ IN TXT "([A-Za-z0-9_-]{43})"\s*', line)
                    if match and not added:
                        dns.txt[match[1]] = match[2]
                        process.stdin.write(b'\n')
                        process.stdin.flush()
                        added = True
                self.assertEqual(process.wait(timeout=2), 0, b''.join(received).decode(errors='replace'))
                self.assertTrue(added, 'Lego must prompt for a real challenge record')
                cert, key = c.material_paths(manual_root, settings['domain'])
                c.validate_material(cert.read_text(), key.read_text(), settings['domain'], context=issued_ctx)
            finally:
                if process.poll() is None:
                    process.kill()


if __name__ == '__main__':
    unittest.main(verbosity=2)
