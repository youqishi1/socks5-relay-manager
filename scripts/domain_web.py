"""Opt-in HTTPS administration activated by a systemd listening socket."""
import os
from pathlib import Path
import socket
from socketserver import ThreadingMixIn
import ssl
import tempfile
import threading
import time

from access import AccessError, domain_name
import certificates
from manager import APP, Error, ask, read_json, write_json
from web_admin import AdminServer, IDLE, PASSWORD_FILE, safe_destination, set_password


SETTING = 'web-domain.json'
SERVICE = 'socks-relay-web.service'
SOCKET = 'socks-relay-web.socket'
UNITS = Path('/etc/systemd/system')


class DomainServer(ThreadingMixIn, AdminServer):
    def __init__(self, manager, listener, settings, tls):
        self.tls = tls
        self.slots = threading.BoundedSemaphore(6)
        super().__init__(manager, settings['port'], settings['domain'], listener)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(4)
            try:
                encrypted = self.tls.wrap_socket(request, server_side=True)
            except OSError:
                self.shutdown_request(request)
                return
            super().process_request_thread(encrypted, client_address)
        finally:
            self.slots.release()


def settings_for(manager):
    path = manager.root / SETTING
    if not path.exists():
        return None
    item = read_json(path)
    try:
        if set(item) != {'domain', 'port'} or type(item['port']) is not int or not allowed_port(item['port']):
            raise ValueError()
        domain_name(item['domain'])
    except (AccessError, AttributeError, KeyError, TypeError, ValueError):
        raise Error('网页后台的域名设置无效。') from None
    return item


def allowed_port(port):
    return port == 443 or 1024 <= port <= 65535


def domain_url(manager, path='/'):
    item = settings_for(manager)
    if item:
        port = '' if item['port'] == 443 else ':' + str(item['port'])
        return 'https://' + item['domain'] + port + safe_destination(path)
    return None


def cert_settings(manager):
    path = manager.root / certificates.SETTING
    if not path.exists():
        raise Error('请先用菜单 22 给你的域名配置公共 CA 证书。')
    try:
        return certificates.validate_settings(read_json(path))
    except AccessError as exc:
        raise Error(str(exc)) from None


def tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    return context


def activated_socket(port):
    if os.environ.pop('LISTEN_PID', '') != str(os.getpid()) or os.environ.pop('LISTEN_FDS', '') != '1':
        raise Error('域名后台必须从 systemd 监听单元启动。')
    os.environ.pop('LISTEN_FDNAMES', None)
    listener = socket.socket(fileno=3)
    try:
        listener.set_inheritable(False)
        if (listener.family != socket.AF_INET or listener.type != socket.SOCK_STREAM
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                or listener.getsockname() != ('0.0.0.0', port)):
            raise Error('systemd 交付的公网监听端口无效。')
        return listener
    except Exception:
        listener.close()
        raise


def run(manager):
    item = settings_for(manager)
    if not item or not (manager.root / PASSWORD_FILE).is_file():
        raise Error('未启用域名后台或尚未设置后台密码。')
    renewal = cert_settings(manager)
    if item['domain'] != renewal['domain']:
        raise Error('证书域名已变化，请在菜单 28 重新开启域名后台。')
    cert, key = certificates.material_paths(APP, item['domain'])
    context = tls_context(cert, key)
    with DomainServer(manager, activated_socket(item['port']), item, context) as server:
        while (remaining := IDLE - (time.monotonic() - server.last_used)) > 0:
            server.timeout = remaining
            server.handle_request()


def unit_data(port):
    sockets = f'''[Unit]
Description=SOCKS5 Relay HTTPS web listener

[Socket]
ListenStream=0.0.0.0:{port}
Accept=no
Backlog=24

[Install]
WantedBy=sockets.target
'''
    service = f'''[Unit]
Description=SOCKS5 Relay HTTPS administration
Requires={SOCKET}
After={SOCKET}

[Service]
Type=simple
ExecStart={APP}/python3 {APP}/current/scripts/manager.py web-domain-run
UMask=0077
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=true
LimitNOFILE=256
TimeoutStopSec=30
'''
    return {UNITS / SERVICE: service.encode(), UNITS / SOCKET: sockets.encode()}


def replace_unit(path, data):
    # Do not change ownership or permissions of the systemd unit directory.
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
        staged = Path(file.name)
        try:
            file.write(data)
            file.flush()
            os.fchmod(file.fileno(), 0o644)
            os.replace(staged, path)
        finally:
            staged.unlink(missing_ok=True)


def install(manager, port, cert):
    if not (manager.root / PASSWORD_FILE).is_file():
        raise Error('请先设置网页后台密码。')
    try:
        certificates.load_material(APP, cert)
    except AccessError as exc:
        raise Error(str(exc)) from None
    current = settings_for(manager)
    active = manager.backend.call('is-active', '--quiet', SOCKET, required=False)
    files = unit_data(port)
    previous = {path: path.read_bytes() for path in files if path.is_file()}
    if previous and not current:
        raise Error('系统已存在同名的网页后台单元，请先检查。')
    if not current or port != current['port'] or not active:
        try:
            certificates.check_binding(port)
        except AccessError as exc:
            raise Error(str(exc)) from None
    try:
        if current:
            manager.backend.call('stop', SOCKET, SERVICE)
        for path, data in files.items():
            replace_unit(path, data)
        write_json(manager.root / SETTING, {'domain': cert['domain'], 'port': port})
        manager.backend.call('daemon-reload')
        manager.backend.call('enable', SOCKET)
        manager.backend.call('start', SOCKET)
    except Exception:
        manager.backend.call('stop', SOCKET, SERVICE, required=False)
        if not current:
            manager.backend.call('disable', SOCKET, required=False)
        for path in files:
            if path in previous:
                replace_unit(path, previous[path])
            else:
                path.unlink(missing_ok=True)
        settings_path = manager.root / SETTING
        if current:
            write_json(settings_path, current)
        else:
            settings_path.unlink(missing_ok=True)
        manager.backend.call('daemon-reload')
        if active:
            manager.backend.call('start', SOCKET)
        raise


def disable(manager):
    if not (manager.root / SETTING).exists():
        return
    if (UNITS / SOCKET).is_file():
        manager.backend.call('stop', SOCKET, SERVICE)
        manager.backend.call('disable', SOCKET)
        for name in (SOCKET, SERVICE):
            (UNITS / name).unlink(missing_ok=True)
        manager.backend.call('daemon-reload')
    (manager.root / SETTING).unlink(missing_ok=True)


def configure(manager):
    with manager.lock():
        current = settings_for(manager)
        if current:
            print('当前域名地址：' + domain_url(manager))
    choice = ask('1 启用或修改 HTTPS 域名后台，2 关闭域名访问，0 返回', '1')
    if choice == '0':
        return
    if choice == '2':
        with manager.lock():
            disable(manager)
        print('域名访问已关闭。')
        return
    if choice != '1':
        raise Error('请选择 1、2 或 0。')
    with manager.lock():
        cert = cert_settings(manager)
    print('使用已有证书域名：' + cert['domain'])
    print('如 TCP 443 被占用或云防火墙不通，可填写 8443 等可达端口。')
    value = ask('HTTPS TCP 端口', str(current['port'] if current else 443))
    if not value.isdecimal() or len(value) > 5 or not allowed_port(int(value)):
        raise Error('请输入 443 或 1024–65535 之间的端口。')
    if not (manager.root / PASSWORD_FILE).is_file():
        set_password(manager)
    with manager.lock():
        install(manager, int(value), cert_settings(manager))
        print('浏览器地址：' + domain_url(manager))
        print('域名需解析到此 VPS，云安全组需允许 TCP ' + value + '。')
