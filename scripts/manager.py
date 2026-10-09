#!/usr/bin/env python3
"""Root-only, per-port 3proxy manager. No third-party Python dependencies."""
import contextlib
import copy
import datetime
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path('/etc/socks5-relay-manager')
LOG = Path('/var/log/socks5-relay-manager')
BINARY = Path('/opt/socks5-relay-manager/3proxy')
APP = Path('/opt/socks5-relay-manager')
IP_URL = 'https://api.ipify.org'
FIRST, LAST = 20001, 29999


class Error(Exception):
    pass


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def atomic(path, data):
    """Write, fsync, replace and fsync the containing directory."""
    private_dir(path.parent)
    fd, name = tempfile.mkstemp(prefix='.new-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.chmod(name, 0o600)
            stream.write(data.encode('utf-8') if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        if os.name != 'nt':
            dfd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, data):
    atomic(path, json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def read_json(path):
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            raise Error('配置文件过大。')
        return json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, OSError) as exc:
        raise Error('配置文件读取失败，请使用受信任的备份恢复。') from exc


def quote(value):
    return '"' + value.replace('"', '""') + '"'


def credential(value, label, username=False):
    if not isinstance(value, str) or not 1 <= len(value.encode('utf-8')) <= 128:
        raise Error(label + '必须为 1–128 字节。')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Error(label + '不能包含换行、制表符或控制字符。')
    if username and not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', value):
        raise Error(label + '仅允许字母、数字、下划线、点、@、短横线。')
    return value


def host(value):
    if not isinstance(value, str) or len(value) > 253:
        raise Error('上游地址无效。')
    try:
        addr = ipaddress.ip_address(value)
        if addr.is_unspecified or addr.is_multicast:
            raise Error('上游必须是有效的单播 IP 地址。')
        return str(addr)
    except ValueError:
        pass
    if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
        raise Error('请输入合法 IP 或域名，不要包含协议、路径或空格。')
    if any(not x or len(x) > 63 or x.startswith('-') or x.endswith('-') for x in value.split('.')):
        raise Error('域名格式无效。')
    return value


def validate(row):
    fields = {'port', 'upstream_host', 'upstream_port', 'upstream_user', 'upstream_password',
              'client_user', 'client_password', 'sources', 'bind', 'enabled'}
    if not isinstance(row, dict) or set(row) - fields - {'resolved_ip'} or fields - set(row):
        raise Error('配置字段不完整或含有未知字段。')
    for key, low, high in [('port', FIRST, LAST), ('upstream_port', 1, 65535)]:
        if type(row[key]) is not int or not low <= row[key] <= high:
            raise Error('端口范围无效。')
    host(row['upstream_host'])
    credential(row['upstream_user'], '上游账号')
    if row['upstream_user'] == '*':
        raise Error('上游账号不能为 *（3proxy 保留语法）。')
    credential(row['upstream_password'], '上游密码')
    credential(row['client_user'], '客户端账号', True)
    credential(row['client_password'], '客户端密码')
    if type(row['enabled']) is not bool:
        raise Error('启用状态无效。')
    try:
        bind = ipaddress.ip_address(row['bind'])
        if bind.version != 4 or bind.is_multicast:
            raise ValueError()
    except ValueError as exc:
        raise Error('监听地址必须为本机 IPv4 或 0.0.0.0。') from exc
    sources = row['sources']
    if not isinstance(sources, list) or not 1 <= len(sources) <= 100:
        raise Error('至少需要一个允许来源 IP/CIDR，或 *。')
    try:
        for source in sources:
            if source != '*':
                if ipaddress.ip_network(source, strict=False).version != 4:
                    raise ValueError()
    except (ValueError, TypeError) as exc:
        raise Error('来源列表只接受 IPv4、IPv4 CIDR 或 *。') from exc
    if 'resolved_ip' in row:
        try:
            resolved = ipaddress.ip_address(row['resolved_ip'])
            if resolved.is_unspecified or resolved.is_multicast:
                raise ValueError()
        except ValueError as exc:
            raise Error('解析后的上游地址无效。') from exc
    return row


def resolve(value):
    host(value)
    try:
        # Resolve before fakeresolve; never hand a parent domain to fakeresolve.
        results = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
        return str(ipaddress.ip_address(results[0][4][0]))
    except (OSError, ValueError) as exc:
        raise Error('上游 DNS 解析失败或地址不可用。') from exc


def render(row, logdir=LOG, probe_port=None):
    validate(row)
    if 'resolved_ip' not in row:
        raise Error('配置生成失败：缺少已解析的上游 IP。')
    # Exactly one allow and exactly one weight-1000 parent. Only TCP CONNECT.
    sources = '*' if '*' in row['sources'] else ','.join(sorted(set(row['sources'] + ['127.0.0.1'])))
    return '\n'.join([
        '# Generated by socks5-relay-manager; do not edit.',
        'maxconn 512', 'timeouts 1 5 15 30 60 300 5 10 8 5',
        'nscache 65536', 'fakeresolve', 'parentretries 1',
        'log ' + quote(str(logdir / ('relay-' + str(row['port']) + '.log'))),
        'logformat "L%Y-%m-%d %H:%M:%S port=%p error=%E in=%I out=%O duration=%D"',
        'users ' + quote(row['client_user'] + ':CL:' + row['client_password']),
        'auth strong', 'flush',
        'allow ' + quote(row['client_user']) + ' ' + sources + ' * * CONNECT',
        'parent 1000 socks5+ ' + quote(row['resolved_ip']) + ' ' + str(row['upstream_port'])
        + ' ' + quote(row['upstream_user']) + ' ' + quote(row['upstream_password']),
        'deny *',
        'socks -u2 -p' + str(probe_port or row['port']) + ' -i' + ('127.0.0.1' if probe_port else row['bind']),
        '',
    ])


def free_port(bind='127.0.0.1'):
    with socket.socket() as sock:
        sock.bind((bind, 0))
        return sock.getsockname()[1]


def recv(sock, count):
    result = b''
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise Error('SOCKS5 服务提前断开连接。')
        result += part
    return result


def socks_auth(address, port, user, password):
    try:
        with socket.create_connection((address, port), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(b'\x05\x01\x02')
            if recv(sock, 2) != b'\x05\x02':
                raise Error('SOCKS5 服务不支持所需的账号密码认证。')
            u, p = user.encode(), password.encode()
            sock.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if recv(sock, 2) != b'\x01\x00':
                raise Error('SOCKS5 账号或密码认证失败。')
    except socket.timeout as exc:
        raise Error('SOCKS5 连接或认证超时。') from exc
    except OSError as exc:
        raise Error('无法连接 SOCKS5 服务（连接被拒绝或网络不可达）。') from exc


def health(address, port, user, password, url=IP_URL):
    from urllib.parse import quote as urlquote
    start = time.monotonic()
    socks_auth(address, port, user, password)
    proxy_host = '[' + address + ']' if ':' in address else address
    proxy = 'socks5h://' + urlquote(user, safe='') + ':' + urlquote(password, safe='') + '@' + proxy_host + ':' + str(port)
    def curl_quote(v):
        return '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'
    config = 'proxy = ' + curl_quote(proxy) + '\nurl = ' + curl_quote(url) + '\nnoproxy = ""\n'
    env = {k: v for k, v in os.environ.items() if k.lower() not in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}}
    try:
        result = subprocess.run(['curl', '-q', '--config', '-', '--silent', '--show-error', '--fail',
                                 '--connect-timeout', '5', '--max-time', '15', '--max-filesize', '128',
                                 '--proto', '=https,http'], input=config, text=True, capture_output=True,
                                timeout=18, env=env)
    except subprocess.TimeoutExpired as exc:
        raise Error('出口检测超时。') from exc
    if result.returncode:
        # Never print curl stderr: it may contain provider credentials or a URL.
        reasons = {5: '代理地址解析失败', 6: '目标域名解析失败', 7: '无法连接代理',
                   22: '出口检测网站返回 HTTP 错误', 28: '上游或目标超时',
                   35: '目标 TLS 握手失败', 60: '目标 TLS 证书校验失败',
                   97: '上游 SOCKS5 认证失败、DNS 失败或拒绝连接'}
        raise Error('出口检测失败：' + reasons.get(result.returncode, '连接失败') + '（curl ' + str(result.returncode) + '）。')
    try:
        exit_ip = str(ipaddress.ip_address(result.stdout.strip()))
    except ValueError as exc:
        raise Error('检测返回内容不是有效 IP 地址。') from exc
    return exit_ip, round((time.monotonic() - start) * 1000)


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def check_config(row, binary=BINARY):
    """Real 3proxy parser and loopback listener, not a fictitious --check flag."""
    with tempfile.TemporaryDirectory(prefix='socks-config-') as folder:
        directory = Path(folder)
        os.chmod(directory, 0o700)
        port = free_port()
        config = directory / 'check.cfg'
        atomic(config, render(row, directory, port))
        with open(directory / 'stderr', 'wb') as stderr:
            process = subprocess.Popen([str(binary), str(config)], stdout=subprocess.DEVNULL, stderr=stderr)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise Error('3proxy 配置语法验证失败；旧配置未变。')
                    try:
                        socks_auth('127.0.0.1', port, row['client_user'], row['client_password'])
                        return
                    except Error:
                        time.sleep(0.1)
                raise Error('3proxy 配置验证失败：未启动认证监听端口。')
            finally:
                stop_process(process)


class Systemd:
    @staticmethod
    def unit(port):
        return 'socks-relay@' + str(port) + '.service'

    def call(self, *args, required=True):
        result = subprocess.run(['systemctl', *args], capture_output=True, timeout=35)
        if required and result.returncode:
            raise Error('systemd 操作失败；请查看运行状态或受保护的日志。')
        return result.returncode == 0

    def apply(self, port, row):
        if row and row['enabled']:
            self.call('enable', self.unit(port))
            self.call('restart', self.unit(port))
            deadline = time.monotonic() + 7
            while time.monotonic() < deadline:
                if self.active(port) and self.owns_listener(port):
                    return
                time.sleep(0.1)
            raise Error('服务启动失败或端口未监听。')
        else:
            self.call('stop', self.unit(port))
            self.call('disable', self.unit(port), required=False)

    def active(self, port):
        return self.call('is-active', '--quiet', self.unit(port), required=False)

    def owns_listener(self, port):
        # A different process occupying the port must not satisfy startup checks.
        pid = subprocess.run(['systemctl', 'show', self.unit(port), '--property=MainPID', '--value'],
                             capture_output=True, text=True, timeout=5).stdout.strip()
        sockets = subprocess.run(['ss', '-H', '-lntp', 'sport = :' + str(port)],
                                 capture_output=True, text=True, timeout=5).stdout
        return pid.isdecimal() and pid != '0' and re.search(r'pid=' + pid + r'[,)]', sockets) is not None


def listening(port, bind='0.0.0.0'):
    try:
        with socket.create_connection(('127.0.0.1' if bind == '0.0.0.0' else bind, port), timeout=0.3):
            return True
    except OSError:
        return False


class Manager:
    def __init__(self, root=ROOT, log=LOG, binary=BINARY, backend=None, ip_url=IP_URL):
        self.root, self.log, self.binary = Path(root), Path(log), Path(binary)
        self.backend = backend or Systemd()
        self.ip_url = ip_url
        private_dir(self.root)
        private_dir(self.log)

    @contextlib.contextmanager
    def lock(self):
        # No credentials in the lock. flock is per-process and crash-safe.
        import fcntl
        with open(self.root / 'manager.lock', 'a+b') as stream:
            os.chmod(stream.name, 0o600)
            fcntl.flock(stream, fcntl.LOCK_EX)
            self.recover()
            yield

    def pointer_path(self, port):
        return self.root / 'ports' / str(port) / 'active.json'

    def pointers(self):
        return {str(p.parent.name): read_json(p) for p in (self.root / 'ports').glob('*/active.json')}

    def revision(self, port, pointer):
        revision = pointer.get('revision') if isinstance(pointer, dict) else None
        if not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{32}', revision):
            raise Error('配置版本标识无效。')
        return self.root / 'ports' / str(int(port)) / 'revisions' / revision

    def row(self, port, pointer=None):
        pointer = pointer or read_json(self.pointer_path(port))
        row = validate(read_json(self.revision(port, pointer) / 'relay.json'))
        if row['port'] != int(port):
            raise Error('配置中的端口与服务编号不一致。')
        return row

    def rows(self):
        return [self.row(p, pointer) for p, pointer in sorted(self.pointers().items(), key=lambda x: int(x[0]))]

    def allocate(self):
        existing = self.pointers()
        for port in range(FIRST, LAST + 1):
            if str(port) in existing:
                continue
            try:
                with socket.socket() as sock:
                    # Don't use SO_REUSEADDR; also catches a wildcard listener.
                    sock.bind(('0.0.0.0', port))
                return port
            except OSError:
                continue
        raise Error('20001–29999 没有可用端口。')

    def verify(self, row):
        address = '127.0.0.1' if row['bind'] == '0.0.0.0' else row['bind']
        return health(address, row['port'], row['client_user'], row['client_password'], self.ip_url)

    def backup(self):
        directory = self.root / 'backups'
        name = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8] + '.backup.json'
        write_json(directory / name, {'schema': 1, 'relays': self.rows()})
        return directory / name

    def set_pointer(self, port, pointer):
        path = self.pointer_path(port)
        if pointer:
            write_json(path, pointer)
        else:
            path.unlink(missing_ok=True)

    def recover(self):
        journal = self.root / 'pending.json'
        if not journal.exists():
            return
        pending = read_json(journal)
        failures = []
        for port in pending['ports']:
            try:
                self.backend.apply(int(port), None)
                pointer = pending['old'].get(str(port))
                self.set_pointer(int(port), pointer)
                self.backend.apply(int(port), self.row(port, pointer) if pointer else None)
            except Exception:
                failures.append(str(port))
        if failures:
            raise Error('回滚尚未完成，受影响端口：' + ', '.join(failures) + '；事务记录已保留，请修复后再次运行菜单。')
        journal.unlink()

    def apply(self, changes, verify=True):
        """Prepare every revision first, journal, atomically switch per-port, rollback."""
        old = self.pointers()
        self.backup()
        prepared = {}
        for port, row in changes.items():
            if row is None:
                prepared[str(port)] = None
                continue
            row = copy.deepcopy(validate(row))
            if row['enabled']:
                row['resolved_ip'] = resolve(row['upstream_host'])
                check_config(row, self.binary)
            pointer = {'revision': uuid.uuid4().hex}
            directory = self.revision(port, pointer)
            write_json(directory / 'relay.json', row)
            if row['enabled']:
                atomic(directory / '3proxy.cfg', render(row, self.log))
                for kind in ('relay', 'service'):
                    log = self.log / (kind + '-' + str(port) + '.log')
                    log.touch(mode=0o600, exist_ok=True)
                    os.chmod(log, 0o600)
            prepared[str(port)] = pointer
        pending = {'old': old, 'ports': list(prepared)}
        write_json(self.root / 'pending.json', pending)
        try:
            for port, pointer in prepared.items():
                self.set_pointer(int(port), pointer)
                row = self.row(port, pointer) if pointer else None
                self.backend.apply(int(port), row)
                if verify and row and row['enabled']:
                    self.verify(row)
            (self.root / 'pending.json').unlink()
        except Exception as exc:
            try:
                self.recover()
            except Error as rollback:
                raise rollback from exc
            raise Error('操作失败，已自动回滚到旧配置。' + (str(exc) if isinstance(exc, Error) else '')) from exc

    def restore(self, path):
        data = read_json(path)
        if not isinstance(data, dict) or set(data) != {'schema', 'relays'} or data['schema'] != 1 or not isinstance(data['relays'], list):
            raise Error('备份格式无效。')
        desired = {}
        for row in data['relays']:
            validate(row)
            if row['port'] in desired:
                raise Error('备份中存在重复端口。')
            desired[row['port']] = row
        current = {row['port']: row for row in self.rows()}
        changes = {p: desired.get(p) for p in current.keys() | desired.keys() if current.get(p) != desired.get(p)}
        if changes:
            self.apply(changes)

    def run(self, port):
        row = self.row(port)
        if not row['enabled']:
            raise Error('此端口未启用。')
        directory = self.revision(port, read_json(self.pointer_path(port)))
        config = directory / '3proxy.cfg'
        if config.read_text(encoding='utf-8') != render(row, self.log):
            raise Error('生成配置与保存数据不一致，拒绝启动。')
        os.execv(str(self.binary), [str(self.binary), str(config)])


def ask(prompt, default=None):
    value = input(prompt + ((' [' + str(default) + ']') if default is not None else '') + '：').strip()
    return value or default or ''


def confirm(prompt, default=False):
    value = input(prompt + (' [Y/n]：' if default else ' [y/N]：')).strip().lower()
    return value in ('y', 'yes') or (not value and default)


def number(prompt, default=None):
    value = ask(prompt, default)
    if not value.isdecimal():
        raise Error('请输入数字。')
    return int(value)


def new_row(manager, previous=None):
    old = previous or {}
    port = old.get('port') or manager.allocate()
    row = {'port': port,
           'upstream_host': host(ask('请输入上游 SOCKS5 IP/域名', old.get('upstream_host'))),
           'upstream_port': number('请输入上游端口', old.get('upstream_port')),
           'upstream_user': ask('请输入上游用户名', old.get('upstream_user'))}
    password = getpass.getpass('请输入上游密码' + ('（回车保留）' if previous else '') + '：')
    row['upstream_password'] = password or old.get('upstream_password', '')
    if confirm('手动指定客户端账号密码？'):
        row['client_user'] = ask('客户端账号', old.get('client_user', 'client' + str(port - FIRST + 1).zfill(2)))
        password = getpass.getpass('客户端密码' + ('（回车保留）' if previous else '') + '：')
        row['client_password'] = password or old.get('client_password', '')
    else:
        row['client_user'] = old.get('client_user', 'client' + str(port - FIRST + 1).zfill(2))
        row['client_password'] = old.get('client_password', secrets.token_urlsafe(24))
    sources = ask('允许来源 IPv4/CIDR（逗号分隔；* 允许公网，默认仅本机）', ','.join(old.get('sources', ['127.0.0.1'])))
    row['sources'] = [x.strip() for x in sources.split(',')]
    row['bind'] = ask('监听 IPv4（可填 WireGuard 地址）', old.get('bind', '0.0.0.0'))
    row['enabled'] = True
    validate(row)
    if '*' in row['sources']:
        print('警告：SOCKS5 本身不加密，公网传输会暴露账号密码和流量。建议通过 WireGuard 访问，并限制来源 IP。')
        if not confirm('确认允许所有来源使用账号密码连接？'):
            raise Error('已取消。')
    print('正在检测上游代理...')
    try:
        row['resolved_ip'] = resolve(row['upstream_host'])
        exit_ip, latency = health(row['resolved_ip'], row['upstream_port'], row['upstream_user'], row['upstream_password'], manager.ip_url)
        print('上游连接成功！出口 IP：' + exit_ip + '，耗时 ' + str(latency) + ' ms')
    except Error as exc:
        print(str(exc))
        if not confirm('上游不可用，是否保存为未启用状态？'):
            raise Error('已取消。')
        row['enabled'] = False
    print('VPS 端口：' + str(port) + '，客户端账号：' + row['client_user'] + '，密码：********')
    if not confirm('是否保存并' + ('启用' if row['enabled'] else '保持停用') + '？', True):
        raise Error('已取消。')
    return row


def show_connection(row):
    # No public-IP probe over direct HTTP. Explicit user-supplied advertised address.
    address = ask('VPS 公网 IP/域名（仅用于显示连接信息）', row['bind'] if row['bind'] != '0.0.0.0' else '你的VPS公网IP')
    print('\n========================================\nSOCKS5 中转保存成功' + ('（已启用且出口验证成功）' if row['enabled'] else '（未启用）'))
    print('VPS 地址：' + address + '\nVPS 端口：' + str(row['port']))
    print('客户端账号：' + row['client_user'] + '\n客户端密码：' + row['client_password'])
    print('连接格式：\n' + address + ':' + str(row['port']) + ':' + row['client_user'] + ':' + row['client_password'])
    print('========================================\n凭据只在此终端显示，请妥善保存。')


def select_row(manager):
    port = number('请输入 VPS 监听端口')
    if str(port) not in manager.pointers():
        raise Error('未找到此端口。')
    return manager.row(port)


def show_rows(manager):
    for i, row in enumerate(manager.rows(), 1):
        print(str(i) + '. 端口 ' + str(row['port']) + ' | 上游 ' + row['upstream_host'] + ':' + str(row['upstream_port'])
              + ' | 客户端 ' + row['client_user'] + ' | ' + ('启用' if row['enabled'] else '停用')
              + ' | 服务 ' + ('运行中' if manager.backend.active(row['port']) else '未运行')
              + ' | 监听 ' + ('是' if listening(row['port'], row['bind']) else '否'))


def test_row(manager, row):
    if not row['enabled']:
        print('端口 ' + str(row['port']) + '：未启用')
        return
    try:
        ip, latency = manager.verify(row)
        print('端口 ' + str(row['port']) + ' | 出口 IP ' + ip + ' | 连接成功 | ' + str(latency) + ' ms')
    except Error as exc:
        print('端口 ' + str(row['port']) + ' | 连接失败 | ' + str(exc))


def uninstall(manager):
    print('卸载仅删除本项目程序、服务和命令；默认保留 root 可读配置、凭据、备份和日志。')
    if ask('请输入 UNINSTALL 确认卸载') != 'UNINSTALL':
        raise Error('已取消。')
    with manager.lock():
        manager.backup()
        for row in manager.rows():
            manager.backend.apply(row['port'], None)
    for path in (Path('/etc/systemd/system/socks-relay@.service'), Path('/etc/logrotate.d/socks5-relay-manager'),
                 Path('/usr/local/bin/socks-menu'), Path('/usr/local/bin/socks-relay-uninstall')):
        path.unlink(missing_ok=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    # Fixed, project-specific target, never computed from user input.
    if APP == Path('/opt/socks5-relay-manager'):
        shutil.rmtree(APP)
    print('卸载完成。配置保留在 ' + str(ROOT) + '，日志保留在 ' + str(LOG) + '。')


def menu(manager):
    print('建议通过 WireGuard 等加密隧道使用；默认来源仅本机，可在添加/修改时指定客户端 IP。')
    while True:
        try:
            with manager.lock():
                rows = manager.rows()
            enabled = [r for r in rows if r['enabled']]
            running = sum(manager.backend.active(r['port']) for r in enabled)
            state = '运行中' if enabled and running == len(enabled) else ('部分运行/异常' if running else '未运行/暂无启用代理')
            print('\n========================================\n        SOCKS5 中转管理系统\n========================================')
            print('系统状态：' + state + '\n代理数量：' + str(len(rows)) + '\n端口范围：20001-29999')
            print('1. 添加 SOCKS5 中转\n2. 查看全部中转\n3. 删除 SOCKS5 中转\n4. 修改 SOCKS5 中转\n5. 检测所有代理出口 IP\n6. 检测指定代理\n7. 重启代理服务\n8. 查看运行状态\n9. 查看日志\n10. 备份配置\n11. 恢复配置\n12. 更新程序\n13. 卸载程序\n0. 退出')
            option = ask('请输入选项')
            if option == '0':
                return
            if option == '12':
                ref = ask('请输入受信任的版本标签（例如 v1.0.0）')
                if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', ref):
                    raise Error('只接受明确的版本标签。')
                if confirm('更新前会备份；确认安装版本 ' + ref + '？'):
                    with manager.lock():
                        manager.backup()
                    # Version is passed as environment, never shell code.
                    result = subprocess.run(['bash', str(APP / 'current' / 'install.sh')], env={**os.environ, 'SOCKS_REPO_REF': ref})
                    if result.returncode:
                        raise Error('更新失败；原程序版本已保留或回滚。')
                    print('更新完成，请重新打开 socks-menu。')
                    return
                continue
            if option == '13':
                uninstall(manager)
                return
            with manager.lock():
                if option in ('1', '4'):
                    previous = select_row(manager) if option == '4' else None
                    row = new_row(manager, previous)
                    manager.apply({row['port']: row})
                    show_connection(row)
                elif option in ('2', '8'):
                    show_rows(manager)
                elif option == '3':
                    row = select_row(manager)
                    print('删除端口 ' + str(row['port']) + '，上游 ' + row['upstream_host'] + ':' + str(row['upstream_port']))
                    if confirm('确认删除？'):
                        manager.apply({row['port']: None})
                        print('已删除，其他端口继续运行。')
                elif option == '5':
                    for row in manager.rows():
                        test_row(manager, row)
                elif option == '6':
                    test_row(manager, select_row(manager))
                elif option == '7':
                    row = select_row(manager)
                    row['enabled'] = True
                    manager.apply({row['port']: row})
                    print('指定端口重启成功，出口已验证。')
                elif option == '9':
                    from collections import deque
                    row = select_row(manager)
                    for path in (manager.log / ('relay-' + str(row['port']) + '.log'), manager.log / ('service-' + str(row['port']) + '.log')):
                        if path.exists():
                            with path.open(encoding='utf-8', errors='replace') as stream:
                                lines = [line.rstrip('\n') for line in deque(stream, maxlen=50)]
                            for line in lines:
                                # Defense in depth for older imported logs.
                                for secret in (row['upstream_password'], row['client_password'], row['upstream_user']):
                                    line = line.replace(secret, '********')
                                print(line)
                elif option == '10':
                    print('备份已保存：' + str(manager.backup()))
                elif option == '11':
                    backups = sorted((manager.root / 'backups').glob('*.backup.json'))
                    for i, path in enumerate(backups, 1):
                        print(str(i) + '. ' + path.name)
                    index = number('选择备份编号')
                    if not 1 <= index <= len(backups):
                        raise Error('编号无效。')
                    if confirm('恢复会替换当前中转配置，确认？'):
                        manager.restore(backups[index - 1])
                        print('恢复完成，启用端口的出口已验证。')
                else:
                    print('无效选项，请输入 0–13。')
        except Error as exc:
            print('错误：' + str(exc))
        except (EOFError, KeyboardInterrupt):
            print('\n已退出。未完成事务将在下次管理操作时回滚。')
            return


def main():
    if os.name != 'posix' or os.geteuid() != 0:
        raise Error('管理操作需要 root 权限，请使用 sudo socks-menu。')
    os.umask(0o077)
    manager = Manager()
    args = sys.argv[1:]
    if args == ['menu']:
        menu(manager)
    elif args == ['uninstall']:
        uninstall(manager)
    elif len(args) == 2 and args[0] == 'run' and args[1].isdecimal() and FIRST <= int(args[1]) <= LAST:
        manager.run(int(args[1]))
    elif args == ['check']:
        with manager.lock():
            for row in manager.rows():
                if row['enabled']:
                    check_config(row, manager.binary)
    elif args == ['restart-installed']:
        with manager.lock():
            for row in manager.rows():
                manager.backend.apply(row['port'], row)
    elif args == ['status']:
        with manager.lock():
            show_rows(manager)
    else:
        raise Error('用法：socks-menu，或 manager.py status/check。')


if __name__ == '__main__':
    try:
        main()
    except Error as error:
        print('错误：' + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Never expose exception values that may contain a credential.
        print('错误：操作未完成。请查看服务状态；配置事务会在下次操作时尝试回滚。', file=sys.stderr)
        sys.exit(1)
