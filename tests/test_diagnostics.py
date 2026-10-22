"""Diagnostics distinguish local connectivity from public reachability."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import diagnostics as d


class Failure(Exception):
    pass


class Diagnostics(unittest.TestCase):
    def test_firewall_range_and_protocol_are_matched(self):
        text = '30001:30002/tcp ALLOW IN Anywhere\n30004/udp ALLOW IN Anywhere\n130004/tcp ALLOW IN Anywhere\n'
        self.assertEqual(d.related_ufw(text, 30004), ['30004/udp ALLOW IN Anywhere'])
        self.assertEqual(d.related_ufw(text, 30001), ['30001:30002/tcp ALLOW IN Anywhere'])

    def run_report(self, upstream_ok):
        with tempfile.TemporaryDirectory() as folder:
            manager = Mock(root=Path(folder))
            manager.verify.side_effect = None if upstream_ok else Failure('上游连接超时')
            manager.verify.return_value = ('203.0.113.2', 123)
            row = dict(port=20001, client_password='DO_NOT_PRINT', upstream_password='PROVIDER_SECRET',
                       access=dict(port=30001, private_key='PRIVATE_KEY_DO_NOT_PRINT'))
            output = io.StringIO()
            with patch.object(d, 'dns_check', return_value=True), patch.object(d, 'certificate'), patch.object(d, 'firewall'), \
                 patch.object(d, 'local_entrance', return_value=('203.0.113.2', 123)) as entrance, contextlib.redirect_stdout(output):
                d.run(manager, [row], Failure)
            manager.apply.assert_not_called()
            manager.backend.apply.assert_not_called()
            text = output.getvalue()
            for secret in ('DO_NOT_PRINT', 'PROVIDER_SECRET', 'PRIVATE_KEY_DO_NOT_PRINT'):
                self.assertNotIn(secret, text)
            return text, entrance.call_count

    def test_success_does_not_claim_public_connectivity(self):
        text, count = self.run_report(True)
        self.assertEqual(count, 2)
        self.assertIn('不能证明青岛公网可达', text)
        self.assertIn('不是 ping', text)

    def test_upstream_failure_skips_duplicate_frontend_requests(self):
        text, count = self.run_report(False)
        self.assertEqual(count, 0)
        self.assertIn('先修复 SOCKS5', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
