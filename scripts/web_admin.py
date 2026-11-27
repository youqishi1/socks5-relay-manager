"""Temporary, loopback-only administration over an existing SSH connection."""
import getpass
import hashlib
from hmac import compare_digest
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import secrets
import threading
import time
from urllib.parse import parse_qs, quote, urlsplit

from access import AccessError, share_links, validate_export_address
from manager import Error, OperationBusy, add_access, public_address, read_json, upstream_row, write_json
from tuic_qr import build, png
import web_views as views


PORT = 18765
IDLE = 900
LOCKOUT = 300
ATTEMPTS = 5
PASSWORD_FILE = 'web-password.json'
HOST = re.compile(r'(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?\Z', re.ASCII)
NODE = re.compile(r'/nodes/(2[0-9]{4})(?:/(edit|qr|qr\.png|detect|note))?\Z', re.ASCII)
ASSETS = Path(__file__).resolve().parent.parent / 'web'
EXIT_COOLDOWN = 60


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000)


def set_password(manager):
    password = getpass.getpass('设置网页后台密码（至少 12 字符，输入隐藏）：')
    if len(password) < 12 or len(password.encode('utf-8')) > 256:
        raise Error('后台密码至少 12 个字符，且最多 256 字节。')
    if password != getpass.getpass('再次输入后台密码：'):
        raise Error('两次密码不一致。')
    salt = secrets.token_bytes(16)
    with manager.lock():
        write_json(manager.root / PASSWORD_FILE, {'salt': salt.hex(), 'digest': password_digest(password, salt).hex()})
    print('网页后台密码已保存。')


def safe_destination(value):
    match = NODE.fullmatch(value)
    if value == '/add' or match and match.group(2) in (None, 'edit', 'qr'):
        return value
    return '/'


class AdminServer(HTTPServer):
    def __init__(self, manager, port=PORT, domain='', listener=None):
        self.manager = manager
        self.credentials = manager.root / PASSWORD_FILE
        self.password_version = None
        self.session = self.csrf = ''
        self.failed_logins = {}
        self.next_login = 0
        self.auth_lock = threading.RLock()
        self.last_used = time.monotonic()
        self.domain, self.port = domain, port
        self.scheme = 'https' if domain else 'http'
        super().__init__(('127.0.0.1', port), AdminHandler, bind_and_activate=listener is None)
        if listener is not None:
            self.socket.close()
            self.socket = listener
            self.server_address = listener.getsockname()

    def origin(self, host):
        if self.domain:
            authority = self.domain + (':' + str(self.port) if self.port != 443 else '')
            if host != authority and (self.port != 443 or host != authority + ':443'):
                raise Error('请使用 VPS 菜单显示的 HTTPS 域名链接。')
            return 'https://' + authority
        elif not HOST.fullmatch(host):
            raise Error('请使用 SSH 隧道显示的本机链接。')
        return self.scheme + '://' + host

    def refresh_password_version(self):
        stat = self.credentials.stat()
        version = (stat.st_ino, stat.st_mtime_ns)
        if version != self.password_version:
            self.session = self.csrf = ''
            self.failed_logins.clear()
            self.next_login = 0
            self.password_version = version

    def login(self, client, password):
        with self.auth_lock:
            self.refresh_password_version()
            now = time.monotonic()
            for address, (_, expiry) in list(self.failed_logins.items()):
                if expiry <= now:
                    del self.failed_logins[address]
            count, expiry = self.failed_logins.get(client, (0, 0))
            if count >= ATTEMPTS:
                return '', max(1, int(expiry - now + .999))
            if now < self.next_login or (count == 0 and len(self.failed_logins) >= 256):
                return '', 1
            # Public requests cannot repeatedly invoke the password KDF in parallel,
            # even if a caller rotates their source IP.
            if self.domain:
                self.next_login = now + 1
            record = read_json(self.credentials)
            salt, digest = bytes.fromhex(record['salt']), bytes.fromhex(record['digest'])
            if 0 < len(password.encode('utf-8')) <= 256 and compare_digest(password_digest(password, salt), digest):
                self.session, self.csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                self.last_used = now
                self.failed_logins.pop(client, None)
                return self.session, 0
            self.failed_logins[client] = (count + 1, now + LOCKOUT)
            return '', LOCKOUT if count + 1 >= ATTEMPTS else 0


class AdminHandler(BaseHTTPRequestHandler):
    server_version = 'RelayAdmin'
    sys_version = ''

    def setup(self):
        self.csrf = self.session = ''
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *_):
        pass

    def response(self, status, payload=b'', kind='text/html; charset=utf-8', headers=(), cache='no-store'):
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', cache)
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; "
                         "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def redirect(self, path, *headers):
        self.response(303, headers=(('Location', path), *headers))

    def error(self, status, message, authenticated=False):
        if self.headers.get('Accept') == 'application/json':
            return self.response(status, json.dumps({'error': message}, ensure_ascii=False), 'application/json; charset=utf-8')
        self.response(status, views.notice(status, message, self.csrf if authenticated else ''))

    def link_address(self):
        address = public_address(self.server.manager, detect=False, fallback=self.server.domain)
        validate_export_address(address)
        return address

    def node_shares(self, row, locations):
        if row['enabled'] and row.get('access'):
            try:
                return share_links(row, self.link_address(), locations)
            except (AccessError, Error):
                pass
        return {}

    def request_target(self):
        host = self.headers.get('Host', '')
        origin = self.server.origin(host)
        if self.command == 'POST' and self.headers.get('Sec-Fetch-Site') == 'cross-site':
            raise Error('请直接打开后台链接。')
        target = urlsplit(self.path)
        if target.scheme or target.netloc or not target.path.startswith('/'):
            raise Error('请求地址无效。')
        return origin, target

    def authenticated(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get('Cookie', ''))
        except CookieError:
            return False
        token = cookies.get('__Host-relay_admin' if self.server.domain else 'relay_admin')
        with self.server.auth_lock:
            self.server.refresh_password_version()
            now = time.monotonic()
            if not self.server.session or now - self.server.last_used >= IDLE:
                return False
            if token and token.value.isascii() and compare_digest(token.value, self.server.session):
                self.session, self.csrf = self.server.session, self.server.csrf
                self.server.last_used = now
                return True
        return False

    def fields(self):
        if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/x-www-form-urlencoded':
            raise Error('表单格式无效。')
        length = self.headers.get('Content-Length', '')
        if not re.fullmatch(r'[0-9]{1,4}', length) or not 0 < int(length) <= 8192:
            raise Error('表单长度无效。')
        data = self.rfile.read(int(length))
        if len(data) != int(length):
            raise Error('表单接收不完整。')
        try:
            fields = parse_qs(data.decode('utf-8'), keep_blank_values=True, max_num_fields=8, errors='strict')
        except ValueError:
            raise Error('表单格式无效。') from None
        if any(len(values) != 1 for values in fields.values()):
            raise Error('表单字段重复。')
        return {key: values[0] for key, values in fields.items()}

    def do_GET(self):
        try:
            _, target = self.request_target()
        except (Error, ValueError):
            return self.error(403, '请直接使用 VPS 菜单显示的后台地址。')
        asset = {'/style.css': ('style.css', 'text/css'), '/app.js': ('app.js', 'text/javascript'),
                 '/icon.png': ('icon.png', 'image/png')}.get(target.path)
        if asset:
            cache = 'public, max-age=86400, immutable' if target.query == 'v=' + views.VERSION else 'no-store'
            return self.response(200, (ASSETS / asset[0]).read_bytes(), asset[1], cache=cache)
        try:
            if target.path == '/login':
                destination = safe_destination(parse_qs(target.query, max_num_fields=4).get('next', [''])[0])
                return self.response(200, views.login(destination))
            if not self.authenticated():
                return self.redirect('/login?next=' + quote(safe_destination(target.path), safe='/'))
            self.page(target.path)
        except OperationBusy as exc:
            self.error(409, str(exc), True)
        except (AccessError, Error) as exc:
            self.error(400, str(exc), bool(self.session))
        except (OSError, KeyError, TypeError, ValueError):
            self.error(500, '暂时无法读取后台或节点配置，请从 VPS 终端检查状态。')

    def page(self, path):
        manager = self.server.manager
        csrf = self.csrf
        match = NODE.fullmatch(path)
        if path == '/add':
            return self.response(200, views.edit(None, csrf))
        if path != '/' and (not match or match.group(2) in ('detect', 'note')):
            return self.error(404, '找不到此页面。', True)
        with manager.lock(wait=False, read_only=True):
            if path == '/':
                rows = manager.rows(with_note=True)
                row, action = None, None
            else:
                port, action = int(match.group(1)), match.group(2)
                if str(port) not in manager.pointers():
                    return self.error(404, '此中转已不存在。', True)
                row = manager.row(port, with_note=True)
                rows = [row]
            metadata = ({node['port']: manager.exit_location(node, cached_only=True)
                         for node in rows if node['enabled']} if action != 'edit' else {})
            locations = {port: (entry['ip'], entry['country']) for port, entry in metadata.items()}
            checked = {port for port, entry in metadata.items() if entry['checked']}
            address, warning = None, ''
            if action != 'edit' and any(node['enabled'] and node.get('access') for node in rows):
                try:
                    address = self.link_address()
                except (AccessError, Error) as exc:
                    warning = str(exc)
        if path == '/':
            return self.response(200, views.index(rows, locations, csrf, address, warning, checked))
        if action == 'edit':
            return self.response(200, views.edit(row, csrf))
        if action in ('qr', 'qr.png'):
            if not views.has_qr(row):
                raise Error('此节点的 TUIC 二维码需要启用 TUIC 并配置公共 CA 证书。')
            if not address:
                raise Error(warning)
            if action == 'qr':
                return self.response(200, views.qr(row, locations, csrf))
            _, code = build(row, address, locations)
            return self.response(200, png(code), 'image/png')
        links = share_links(row, address, locations) if address else {}
        self.response(200, views.detail(row, locations, links, warning, csrf, checked))

    def do_POST(self):
        try:
            origin, target = self.request_target()
            if self.headers.get('Origin') != origin:
                return self.error(403, '请求来源无效，请从后台页面重新操作。')
            if target.path == '/login':
                return self.sign_in()
            if not self.authenticated():
                if self.headers.get('Accept') == 'application/json':
                    return self.error(401, '登录已过期，请刷新页面后重新登录。')
                return self.redirect('/login')
            fields = self.fields()
            token = fields.get('csrf', '')
            if not token.isascii() or not compare_digest(token, self.csrf):
                return self.error(403, '会话验证失败，请刷新页面。', True)
            self.update(target.path, fields)
        except OperationBusy as exc:
            self.error(409, str(exc), True)
        except (AccessError, Error) as exc:
            self.error(400, str(exc), bool(self.session))
        except (OSError, KeyError, TypeError, ValueError):
            self.error(500, '操作未完成，请重新打开节点详情核对结果。')

    def sign_in(self):
        fields = self.fields()
        destination = safe_destination(fields.get('next', ''))
        session, wait = self.server.login(self.client_address[0], fields.get('password', ''))
        if session:
            return self.redirect(destination, ('Set-Cookie', self.cookie(session)))
        if wait:
            return self.response(429, views.login(destination, '尝试次数过多，请在 ' + str(wait) + ' 秒后重试。'),
                                 headers=(('Retry-After', str(wait)),))
        self.response(401, views.login(destination, '后台密码不正确。'))

    def cookie(self, value):
        name = '__Host-relay_admin' if self.server.domain else 'relay_admin'
        secure = '; Secure' if self.server.domain else ''
        return name + '=' + value + '; Path=/; HttpOnly; SameSite=Strict' + secure + ('' if value else '; Max-Age=0')

    def update(self, path, fields):
        manager = self.server.manager
        if path == '/logout':
            with self.server.auth_lock:
                if self.session == self.server.session:
                    self.server.session = self.server.csrf = ''
            return self.redirect('/login', ('Set-Cookie', self.cookie('')))
        match = NODE.fullmatch(path)
        action = match.group(2) if match else ''
        if path != '/add' and action not in ('edit', 'detect', 'note'):
            return self.error(404, '找不到此操作。', True)
        with manager.lock(wait=False):
            port = int(match.group(1)) if match else None
            if port and str(port) not in manager.pointers():
                return self.error(404, '此中转已不存在。', True)
            if action == 'note':
                if 'note' not in fields:
                    raise Error('未收到备注，请重新提交。')
                row = manager.set_note(port, fields['note'])
                if self.headers.get('Accept') == 'application/json':
                    locations = {}
                    if row['enabled'] and row.get('access'):
                        entry = manager.exit_location(row, cached_only=True)
                        locations[port] = (entry['ip'], entry['country'])
                    data = {'note': row.get('note', ''), 'links': self.node_shares(row, locations)}
                    return self.response(200, json.dumps(data, ensure_ascii=False), 'application/json; charset=utf-8')
                return self.redirect('/')
            previous = manager.row(port, with_note=action == 'detect') if port else None
            if action == 'detect':
                if not previous['enabled']:
                    raise Error('请先启用此中转。')
                result = manager.exit_location(previous, refresh=True, cooldown=EXIT_COOLDOWN)
                if self.headers.get('Accept') == 'application/json':
                    locations = {port: (result['ip'], result['country'])}
                    data = {'ok': bool(result['ip']), 'text': views.exit_text(previous, locations, {port}),
                            'links': self.node_shares(previous, locations)}
                    return self.response(200, json.dumps(data, ensure_ascii=False), 'application/json; charset=utf-8')
                return self.redirect('/nodes/' + str(port))
            try:
                saved = save_node(manager, fields, previous)
            except (Error, AccessError) as exc:
                return self.response(400, views.edit(previous, self.csrf, str(exc)))
        self.redirect('/nodes/' + str(saved['port']))


def save_node(manager, fields, previous=None):
    line, mode = fields.get('upstream', '').strip(), fields.get('mode', '')
    has_access = previous is None or bool(previous.get('access'))
    if has_access and mode not in ('shared', 'independent'):
        raise Error('请选择有效的运行方式。')
    if not line and previous is None:
        raise Error('请粘贴完整 SOCKS5 信息。')
    row = upstream_row(manager, line, previous) if line else previous.copy()
    if previous is None:
        add_access(manager, row, mode == 'shared')
    else:
        row['enabled'] = previous['enabled']
        if has_access and mode == 'shared':
            row['shared'] = True
        else:
            row.pop('shared', None)
    if row != previous:
        manager.apply({row['port']: row})
    return row


def serve(manager, path='/'):
    if not (manager.root / PASSWORD_FILE).exists():
        set_password(manager)
    try:
        with AdminServer(manager) as server:
            print(f'网页后台仅通过 SSH 隧道访问。打开 http://127.0.0.1:{PORT}{safe_destination(path)}')
            print(f'如需另开 SSH 隧道：ssh -o ExitOnForwardFailure=yes -N -L 127.0.0.1:{PORT}:127.0.0.1:{PORT} 用户@VPS地址')
            print('按 Ctrl+C 关闭后台，闲置 15 分钟自动关闭。')
            while (remaining := IDLE - (time.monotonic() - server.last_used)) > 0:
                server.timeout = remaining
                server.handle_request()
    except KeyboardInterrupt:
        print('\n网页后台已关闭。')
    except OSError as exc:
        raise Error('无法启动网页后台。请检查 18765 端口是否已被使用。') from exc
