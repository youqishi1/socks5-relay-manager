"""Bounded, credential-free diagnostics; never changes firewall/DNS/services."""
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


def command(arguments, data=None, timeout=8):
    try:
        result = subprocess.run(arguments, input=data, text=True, capture_output=True, timeout=timeout)
        return result.returncode, result.stdout[:65536]
    except (OSError, subprocess.TimeoutExpired):
        return -1, ''


def dns_check(name):
    code, _ = command([sys.executable, '-c',
        'import socket,sys; socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)', name], timeout=6)
    return code == 0


def local_entrance(manager, row, mode):
    import access
    from manager import free_port, health, listening, stop_process, Error
    config = json.loads(access.configs([row], '127.0.0.1')['v2rayn-' + mode + '.json'])
    port = free_port()
    config['inbounds'][0]['listen_port'] = port
    # Reuses the exported trust configuration; certificate checks stay enabled.
    with tempfile.TemporaryDirectory(prefix='relay-diagnose-') as folder:
        directory = Path(folder)
        directory.chmod(0o700)
        path = directory / 'client.json'
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        process = subprocess.Popen([str(manager.access_binary), 'run', '-c', str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 6
            while not listening(port, '127.0.0.1'):
                if process.poll() is not None or time.monotonic() > deadline:
                    raise Error('入口检查客户端未能启动，请核对核心和导出配置。')
                time.sleep(.1)
            return health('127.0.0.1', port, row['client_user'], row['client_password'], manager.ip_url)
        finally:
            stop_process(process)


def related_ufw(text, port):
    result = []
    for line in text.splitlines():
        match = re.match(r'^\s*(\d+)(?::(\d+))?(?:/(tcp|udp))?\s', line)
        if match and int(match[1]) <= port <= int(match[2] or match[1]):
            # No account, URI or upstream information is included in rule lines.
            result.append(line.strip())
    return result[:12]


def firewall(port):
    if shutil.which('ufw'):
        code, text = command(['ufw', 'status', 'verbose'])
        if code == 0:
            if 'Status: inactive' in text:
                print('UFW：未启用。仍需检查云安全组或其他防火墙。')
                return
            print('UFW：已启用。匹配端口的规则：')
            lines = related_ufw(text, port)
            for line in lines:
                print('  ' + line)
            if not lines:
                print('  未找到该端口的显式规则；这不是最终放行结论，请核对规则顺序和默认策略。')
            return
    if shutil.which('firewall-cmd') and command(['firewall-cmd', '--state'])[0] == 0:
        for protocol in ('tcp', 'udp'):
            code, _ = command(['firewall-cmd', '--query-port=' + str(port) + '/' + protocol])
            print('firewalld 默认区域 ' + str(port) + '/' + protocol.upper() + '：' + ('允许' if code == 0 else '未确认放行'))
        print('如网卡绑定了其他区域，还需核对该区域规则。')
        return
    print('防火墙：未通过 UFW/firewalld 确认放行；还需核对 iptables/nftables、云安全组和 NAT 映射。')


def certificate(front):
    import access
    trust = '公共 CA' if access.system_trust(front) else '项目自签名证书'
    print('TUIC 证书：' + trust + '；SNI：' + access.server_name(front))
    code, text = command(['openssl', 'x509', '-noout', '-enddate'], front['certificate'])
    if code == 0:
        try:
            expiry = datetime.datetime.strptime(text.strip().partition('=')[2], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc)
            days = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
            print('证书剩余有效期：' + str(days) + ' 天' + ('（已过期）' if days < 0 else ('（即将到期，请检查续期）' if days < 14 else '')))
        except ValueError:
            print('未能解析证书有效期，请通过菜单 22 检查域名证书。')
    if not access.system_trust(front):
        print('普通 tuic:// 无法携带自签名 CA；MiSub / 小火箭扫码请先选 22 配置域名证书，保持证书验证开启。')


def run(manager, rows, error_type=None):
    from manager import Error
    error_type = error_type or Error
    print('\n一键连接诊断：不修改 DNS、防火墙、节点配置或已有服务；不显示账号密码。')
    print('项目 Python：' + sys.version.split()[0])
    print('项目磁盘可用：' + str(shutil.disk_usage(manager.root).free // (1024 * 1024)) + ' MiB')
    for name in ('github.com', 'release-assets.githubusercontent.com'):
        print('DNS ' + name + '：' + ('正常' if dns_check(name) else '失败或超时（可能影响安装/更新）'))
    if not rows:
        print('还没有节点，请先选 1 添加完整 SOCKS5 信息。')
        return
    row = rows[0]
    print('\n诊断中转端口：' + str(row['port']))
    print('内部服务：' + ('运行中' if manager.backend.active(row['port']) else '未运行'))
    print('正在检测 VPS → 内部中转 → 上游 SOCKS5 → 出口查询网站...')
    try:
        _, duration = manager.verify(row)
        upstream_ok = True
        print('上游出口：通过，查询总耗时 ' + str(duration) + ' ms（不是 ping，也不是青岛线路延迟）。')
    except error_type as exc:
        upstream_ok = False
        print('上游出口：失败；' + str(exc))
    front = row.get('access')
    if not front:
        print('此条目没有 SS/TUIC 加密入口，可选 19 启用双模式。')
        return
    port = front['port']
    print('公网入口：' + str(port) + '/TCP（SS）与 ' + str(port) + '/UDP（TUIC）')
    unit = 'socks-access@' + str(row['port']) + '.service'
    print('入口监听归属：' + ('正常' if manager.backend.owns_listener(port, unit=unit, both=True) else '异常或端口被其他进程占用'))
    certificate(front)
    firewall(port)
    passed = []
    if upstream_ok:
        for mode, label in (('tcp', 'SS'), ('tuic', 'TUIC')):
            print('正在检测 VPS 回环 ' + label + ' → 上游，保持证书验证开启...')
            try:
                _, duration = local_entrance(manager, row, mode)
                passed.append(mode)
                print(label + ' 回环连接：通过，出口查询总耗时 ' + str(duration) + ' ms。')
            except Exception:
                print(label + ' 回环连接：失败；请检查入口配置、证书/SNI、核心和服务状态。')
    else:
        print('上游未通过，暂不重复探测 SS/TUIC；先修复 SOCKS5 地址、账密或上游线路。')
    if len(passed) == 2:
        print('\nVPS 内部两种入口均通过。若青岛客户端仍不通，重点检查公网 TCP/UDP 放行、云安全组和客户端导入配置。')
    print('本机监听和 VPS 回环成功都不能证明青岛公网可达；UDP 放行也不能用 TCP 测试代替。')
