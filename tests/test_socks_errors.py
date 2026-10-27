"""Distinguish connect, negotiation and authentication timeouts without secrets."""
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import manager as m


class SocksErrors(unittest.TestCase):
    def test_timeouts_identify_the_last_completed_stage_without_credentials(self):
        cases = [('connect', None, 'TCP 建连超时'),
                 ('method', [socket.timeout()], '协议协商超时'),
                 ('auth', [b'\x05\x02', socket.timeout()], '账号密码认证响应超时')]
        for stage, replies, expected in cases:
            with self.subTest(stage=stage):
                connection = Mock()
                connection.__enter__ = Mock(return_value=connection)
                connection.__exit__ = Mock(return_value=False)
                with patch.object(m.socket, 'create_connection', side_effect=socket.timeout() if stage == 'connect' else None,
                                  return_value=connection), patch.object(m, 'recv', side_effect=replies):
                    with self.assertRaises(m.Error) as caught:
                        m.socks_auth('203.0.113.1', 443, 'PRIVATE_USER', 'PRIVATE_PASSWORD')
                text = str(caught.exception)
                self.assertIn(expected, text)
                self.assertNotIn('PRIVATE_', text)
                self.assertNotIn('203.0.113.1', text)
                if stage == 'auth':
                    self.assertIn('不等于密码错误', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
