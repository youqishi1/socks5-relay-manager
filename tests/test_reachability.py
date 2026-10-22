"""A SOCKS success response alone must never count as an SSH connection."""
from pathlib import Path
import socketserver
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from check_reachability import probe, receive


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        if self.server.proxy:
            receive(self.request, 3)
            self.request.sendall(b'\x05\x00')
            receive(self.request, 10)
            self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x16')
        if self.server.banner:
            self.request.sendall(b'SSH-2.0-fixture\r\n')


class Reachability(unittest.TestCase):
    def server(self, proxy=False, banner=True):
        server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
        server.proxy, server.banner = proxy, banner
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_real_direct_ssh_banner(self):
        result = probe('127.0.0.1', self.server(), ssh=True)
        self.assertEqual(result['status'], '收到 SSH 握手')

    def test_real_proxy_ssh_banner(self):
        result = probe('203.0.113.1', 22, ssh=True, proxy_port=self.server(proxy=True))
        self.assertEqual(result['status'], '收到 SSH 握手')

    def test_optimistic_proxy_is_not_a_remote_success(self):
        result = probe('203.0.113.1', 22, ssh=True, proxy_port=self.server(proxy=True, banner=False))
        self.assertEqual(result['status'], '未收到 SSH 握手，不能确认远端可达')

    def test_tcp_success_does_not_claim_udp_or_proxy_success(self):
        result = probe('127.0.0.1', self.server(banner=False))
        self.assertIn('未验证代理协议或 UDP', result['status'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
