"""Real nginx virtual-host selection and inherited/included challenge roots."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import access
import webroot as w


@unittest.skipUnless(os.name == 'posix' and os.environ.get('NGINX_BINARY'), 'Dedicated Linux nginx fixture')
class Nginx(unittest.TestCase):
    def test_real_vhost_include_location_root_and_rewrite_failure(self):
        binary = os.environ['NGINX_BINARY']
        with tempfile.TemporaryDirectory(prefix='relay-nginx-webroot-') as folder:
            base = Path(folder)
            site, challenge, other = (base / name for name in ('website', 'validation', 'other-site'))
            for root in (site, challenge, other):
                root.mkdir()
                (root / 'index.html').write_text('preserve existing ' + root.name)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            included = base / 'challenge.conf'
            included.write_text(f'location ^~ /.well-known/acme-challenge/ {{ root "{challenge}"; }}\n')
            config = base / 'nginx.conf'
            config.write_text(f'user root;\npid "{base}/nginx.pid";\nerror_log "{base}/error.log";\n'
                'events {}\nhttp { access_log off;\n'
                f'server {{ listen 127.0.0.1:{port} default_server; server_name other.example.test; root "{other}"; }}\n'
                f'server {{ listen 127.0.0.1:{port}; server_name tuic.example.test; root "{site}"; include "{included}"; }}\n'
                f'server {{ listen 127.0.0.1:{port}; server_name blocked.example.test; root "{site}"; return 403; }}\n}}\n')
            with (base / 'process.log').open('wb') as log:
                process = subprocess.Popen([binary, '-p', str(base) + '/', '-c', str(config), '-g', 'daemon off;'], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 8
                    while True:
                        try:
                            socket.create_connection(('127.0.0.1', port), timeout=.2).close()
                            break
                        except OSError:
                            if process.poll() is not None or time.monotonic() > deadline:
                                self.fail('nginx fixture failed: ' + (base / 'process.log').read_text())
                            time.sleep(.05)
                    original = subprocess.run
                    def routed(args, **kwargs):
                        args = list(args)
                        args[1:1] = ['--resolve', f'tuic.example.test:{port}:127.0.0.1',
                                     '--resolve', f'blocked.example.test:{port}:127.0.0.1']
                        return original(args, **kwargs)
                    roots = w.candidates('tuic.example.test', patterns=[str(config)])
                    self.assertIn(str(challenge), roots)
                    with patch.object(w.subprocess, 'run', side_effect=routed):
                        self.assertEqual(w.detect('tuic.example.test', port=port, roots=roots), str(challenge))
                        with self.assertRaisesRegex(access.AccessError, 'HTTP 403'):
                            w.detect('blocked.example.test', port=port, roots=roots)
                    for root in (site, challenge, other):
                        self.assertEqual((root / 'index.html').read_text(), 'preserve existing ' + root.name)
                        self.assertFalse((root / '.well-known').exists())
                finally:
                    process.terminate()
                    process.wait(timeout=8)


if __name__ == '__main__':
    unittest.main(verbosity=2)
