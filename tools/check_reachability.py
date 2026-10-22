#!/usr/bin/env python3
"""Small explicit port comparison, without credentials, proxy environment or scans."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import socket
import struct
import time


def receive(stream, size):
    data = b''
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise OSError('connection closed')
        data += part
    return data


def probe(address, port, ssh=False, proxy_port=None, timeout=5):
    started = time.monotonic()
    result = dict(route='本地 SOCKS5' if proxy_port else '直连', port=port, status='未完成')
    try:
        with socket.create_connection(('127.0.0.1', proxy_port) if proxy_port else (address, port), timeout) as stream:
            stream.settimeout(timeout)
            if proxy_port:
                stream.sendall(b'\x05\x01\x00')
                if receive(stream, 2) != b'\x05\x00':
                    raise OSError('local SOCKS authentication not supported')
                stream.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(address) + struct.pack('!H', port))
                reply = receive(stream, 4)
                if reply[:2] != b'\x05\x00':
                    raise OSError('SOCKS connection rejected')
                size = {1: 4, 4: 16}.get(reply[3])
                if reply[3] == 3:
                    size = receive(stream, 1)[0]
                if size is None:
                    raise OSError('invalid SOCKS address')
                receive(stream, size + 2)
            result['status'] = 'TCP 建连成功；未验证代理协议或 UDP'
            if ssh:
                # Some local proxies acknowledge CONNECT before the remote is
                # reachable. Only a real SSH banner demonstrates this path.
                banner = stream.recv(256)
                result['status'] = '收到 SSH 握手' if banner.startswith(b'SSH-') else '未收到 SSH 握手，不能确认远端可达'
    except socket.timeout:
        result['status'] = '超时；原因未确定'
    except OSError:
        result['status'] = '连接失败；原因未确定'
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return result


def main():
    parser = argparse.ArgumentParser(description='比较自己 VPS 的直连与本地代理路径；不需要密码。')
    parser.add_argument('ip', help='自己 VPS 的公网 IPv4')
    parser.add_argument('--ssh-port', type=int, default=22)
    parser.add_argument('--ports', default='', help='另外指定至多 3 个 TCP 端口，以逗号分隔')
    parser.add_argument('--socks-port', type=int, help='可选：电脑已运行的 127.0.0.1 SOCKS5 端口，如 10808')
    parser.add_argument('--timeout', type=int, default=5, choices=range(1, 16))
    args = parser.parse_args()
    try:
        address = ipaddress.ip_address(args.ip)
        ports = sorted({args.ssh_port, *[int(p) for p in args.ports.split(',') if p]})
        if address.version != 4 or not address.is_global or len(ports) > 4:
            raise ValueError()
        if any(not 1 <= port <= 65535 for port in ports + ([args.socks_port] if args.socks_port is not None else [])):
            raise ValueError()
    except ValueError:
        parser.error('请输入公网 IPv4 和有效端口；最多检测 4 个明确指定的端口。')
    jobs = [(port, proxy) for proxy in ([None, args.socks_port] if args.socks_port else [None]) for port in ports]
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda item: probe(str(address), item[0], item[0] == args.ssh_port,
                                                      item[1], args.timeout), jobs))
    print(json.dumps(results, ensure_ascii=False, indent=2))
    print('直连失败而代理收到 SSH 握手，说明路径或来源存在差异；仍需排查服务商 ACL、路由和区域阻断。')
    print('这不是被墙鉴定，也不是测速。TCP 建连不能证明 SS、TUIC 或 Hysteria 2 能联网。')


if __name__ == '__main__':
    main()
