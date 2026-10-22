"""Installer failures exercised with isolated commands, never real apt paths."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

COMMON = Path(__file__).resolve().parents[1] / 'scripts/install_common.sh'


@unittest.skipUnless(os.name == 'posix', 'Linux shell helper tests run in CI')
class Helpers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.environment = {**os.environ, 'PATH': str(self.bin) + ':' + os.environ['PATH'],
                            'FIXTURE': str(self.root), 'SOCKS_DOWNLOAD_CACHE': str(self.root / 'cache')}

    def fake(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/bash\n' + body)
        path.chmod(0o700)

    def run_shell(self, script, **environment):
        return subprocess.run(['bash', '-c', 'set -Eeuo pipefail; source "$1"; ' + script, '_', str(COMMON)],
                              env={**self.environment, **environment}, text=True, capture_output=True, timeout=15)

    def test_waits_for_lock_and_retries_without_deleting_or_killing(self):
        self.fake('apt-get', '''
if [[ ! -e $FIXTURE/retried ]]; then
    touch "$FIXTURE/retried"
    echo 'E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 123 (unattended-upgr)'
    exit 100
fi
echo 'PACKAGE_SUCCESS'
''')
        self.fake('sleep', 'exit 0\n')
        result = self.run_shell('relay_apt install fixture')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('等待后自动重试', result.stdout)
        self.assertIn('PACKAGE_SUCCESS', result.stdout)

    def test_lock_timeout_preserves_lock_and_reports_reason(self):
        self.fake('apt-get', "echo 'E: Could not get lock /var/lib/dpkg/lock-frontend'; exit 100\n")
        result = self.run_shell('relay_apt install fixture', SOCKS_LOCK_WAIT_SECONDS='0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('不要删除锁文件', result.stderr)

    def test_non_lock_failure_does_not_loop(self):
        self.fake('apt-get', "echo 'E: Unable to locate package fixture'; exit 100\n")
        result = self.run_shell('relay_apt install fixture')
        self.assertEqual(result.returncode, 100)
        self.assertNotIn('等待后自动重试', result.stdout)

    def test_valid_offline_cache_never_connects(self):
        data = b'verified official source fixture'
        digest = hashlib.sha256(data).hexdigest()
        cache = self.root / 'cache'
        cache.mkdir()
        (cache / digest).write_bytes(data)
        self.fake('curl', 'touch "$FIXTURE/network-used"; exit 99\n')
        result = self.run_shell('relay_download https://example.test/source ' + digest + ' "$FIXTURE/result"', SOCKS_OFFLINE='1')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / 'result').read_bytes(), data)
        self.assertFalse((self.root / 'network-used').exists())

    def test_corrupt_offline_cache_fails_without_executing_or_downloading(self):
        digest = hashlib.sha256(b'good').hexdigest()
        cache = self.root / 'cache'
        cache.mkdir()
        (cache / digest).write_bytes(b'evil')
        self.fake('curl', 'touch "$FIXTURE/network-used"; exit 99\n')
        result = self.run_shell('relay_download https://example.test/source ' + digest + ' "$FIXTURE/result"', SOCKS_OFFLINE='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'result').exists())
        self.assertFalse((self.root / 'network-used').exists())

    def test_fresh_download_is_verified_and_failed_hash_is_not_cached(self):
        self.fake('curl', '''
while (($#)); do
    if [[ $1 == -o ]]; then printf good >"$2"; exit 0; fi
    shift
done
exit 2
''')
        digest = hashlib.sha256(b'good').hexdigest()
        result = self.run_shell('relay_download https://example.test/source ' + digest + ' "$FIXTURE/result"')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / 'cache' / digest).read_bytes(), b'good')
        bad = '0' * 64
        result = self.run_shell('relay_download https://example.test/source ' + bad + ' "$FIXTURE/bad"')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'bad').exists())
        self.assertFalse((self.root / 'cache' / bad).exists())
        self.assertFalse(list((self.root / 'cache').glob('.download-*')))

    def test_reuses_resolved_project_interpreter_without_self_link(self):
        app = self.root / 'app'
        app.mkdir()
        (app / 'python3').symlink_to(sys.executable)
        result = self.run_shell('APP="$FIXTURE/app"; relay_python')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), str(Path(sys.executable).resolve()))
        self.assertNotEqual(result.stdout.strip(), str(app / 'python3'))

    def test_debian11_archives_are_scoped_and_signature_checks_preserved(self):
        self.fake('apt-get', 'printf "%s\\n" "$@"\n')
        result = self.run_shell('APP="$FIXTURE/app"; ID=debian; VERSION_ID=11; relay_apt update')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        sources = (self.root / 'app/apt-compat/sources.list').read_text()
        self.assertIn('https://archive.debian.org/debian-security', sources)
        self.assertNotIn('trusted=yes', sources)
        self.assertNotIn('AllowUnauthenticated', (self.root / 'app/apt-compat/apt.conf').read_text())
        self.assertIn('Dir::Etc::sourcelist=' + str(self.root / 'app/apt-compat/sources.list'), result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
