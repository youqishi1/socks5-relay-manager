"""Optional per-VPS domain certificate; preserve credentials and TLS verification."""
import copy
import errno
import hashlib
import os
from pathlib import Path
import platform
import re
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading

from access import AccessError, domain_name, leaf_der, validate

LEGO_VERSION = '5.5.2'
LEGO_RETRYABLE_CURL_CODES = {5, 6, 7, 18, 28, 52, 55, 56, 92}
LEGO_DOWNLOAD_ERRORS = {
    5: '代理 DNS 解析失败', 6: 'GitHub 域名解析失败', 7: '无法连接 GitHub',
    18: '下载不完整', 22: 'GitHub 返回 HTTP 错误', 23: '无法写入下载文件',
    28: '连接或下载超时', 35: 'TLS 握手失败', 60: 'HTTPS 证书校验失败',
}
LEGO_HASHES = {
    'amd64': '2a35505089e7772c92e1e9ac144df91151ef2eca8568630db0ff91fca06d9bef',
    'arm64': '15b14ec2ab14fde69cc8396eb0204c5ce4327e31a486953225a6059b26db3e8c',
    'armv6': '2829eed8dca0a7589c8354bce7406aea1ecd1a79b18dfa969c0b4ce034a4611b',
    '386': '425b111caf39273424f811e05fdf83ceb21b929aebf578ca5c4524f0816ceec9',
}
ACME_SERVER = 'https://acme-v02.api.letsencrypt.org/directory'
SETTING = 'domain-certificate.json'
HTTP01 = 'http-01'
TLS01 = 'tls-alpn-01'
DNS01 = 'dns-01-manual'


class HTTPUnavailable(AccessError):
    """Only a known HTTP ingress failure should trigger the second ACME attempt."""


def validate_settings(settings):
    required = {'domain', 'email', 'webroot'}
    if not isinstance(settings, dict) or required - set(settings) or set(settings) - required - {'additional_domains', 'challenge'}:
        raise AccessError('域名证书设置无效。')
    mode = settings.get('challenge', HTTP01)
    if mode not in (HTTP01, TLS01, DNS01) or (mode != HTTP01 and settings['webroot']):
        raise AccessError('证书验证方式设置无效。')
    domain_name(settings['domain'])
    additional = settings.get('additional_domains', [])
    if not isinstance(additional, list) or len(additional) > 1:
        raise AccessError('最多允许一个 ECH 公开证书域名。')
    for name in additional:
        domain_name(name)
        if name == settings['domain']:
            raise AccessError('ECH 公开域名不能与真实 TUIC 域名相同。')
    email = settings['email']
    if not isinstance(email, str) or len(email) > 254 or (email and not re.fullmatch(r'[^\s@]+@[^\s@]+', email)):
        raise AccessError('证书联系邮箱格式无效，可留空。')
    webroot = settings['webroot']
    if not isinstance(webroot, str) or '\n' in webroot or '\r' in webroot:
        raise AccessError('网站根目录无效。')
    if webroot and not Path(webroot).is_absolute():
        raise AccessError('网站根目录需要绝对路径。')
    return settings


def validate_material(certificate, private_key, domain, context=None):
    """Check key, complete chain, expiry and hostname in a local TLS handshake."""
    domain_name(domain)
    try:
        fingerprint = hashlib.sha256(leaf_der(certificate)).hexdigest()
        if not isinstance(private_key, str) or len(private_key) > 12000:
            raise ValueError()
        with tempfile.TemporaryDirectory(prefix='relay-cert-check-') as folder:
            cert, key = Path(folder) / 'chain.pem', Path(folder) / 'key.pem'
            cert.write_text(certificate, encoding='ascii')
            key.write_text(private_key, encoding='ascii')
            cert.chmod(0o600)
            key.chmod(0o600)
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.load_cert_chain(cert, key)
            client = context or ssl.create_default_context()
            if not client.check_hostname or client.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError()
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(4)
                def handshake():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(4)
                            with server.wrap_socket(connection, server_side=True) as secure:
                                secure.sendall(b'1')
                    except (OSError, ssl.SSLError):
                        pass
                worker = threading.Thread(target=handshake, daemon=True)
                worker.start()
                try:
                    with socket.create_connection(listener.getsockname(), timeout=4) as connection:
                        with client.wrap_socket(connection, server_hostname=domain) as secure:
                            if secure.recv(1) != b'1':
                                raise ValueError()
                finally:
                    worker.join(timeout=5)
        return fingerprint
    except (ValueError, TypeError, OSError, UnicodeError, ssl.SSLError):
        raise AccessError('证书验证失败：请检查域名、有效期、完整证书链和私钥；原节点保留。') from None


def public_front(front, certificate, private_key, domain, fingerprint):
    result = copy.deepcopy(front)
    result.update(certificate=certificate, private_key=private_key, server_name=domain,
                  certificate_trust='system', fingerprint=fingerprint)
    return validate(result)


def ensure_client(app):
    from manager import private_dir, atomic
    base = app / 'acme'
    try:
        if base.is_symlink():
            raise AccessError('证书工具目录不应是符号链接；请检查项目目录。')
        private_dir(base)
        return _ensure_client(base, atomic)
    except OSError:
        raise AccessError('无法读写项目证书工具目录；请检查磁盘空间、权限和只读挂载。') from None


def _ensure_client(base, atomic):
    binary, marker = base / 'lego', base / 'lego.sha256'
    if binary.is_file() and not binary.is_symlink() and marker.is_file() and not marker.is_symlink():
        expected = marker.read_bytes().strip()
        if (re.fullmatch(rb'[a-f0-9]{64}', expected)
                and hashlib.sha256(binary.read_bytes()).hexdigest().encode('ascii') == expected):
            return binary
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64', 'armv7l': 'armv6', 'i686': '386'}.get(platform.machine())
    if architecture not in LEGO_HASHES:
        raise AccessError('当前 CPU 暂不支持自动申请域名证书。')
    with tempfile.TemporaryDirectory(prefix='.acme-download-', dir=base) as folder:
        archive = Path(folder) / 'lego.tar.gz'
        url = f'https://github.com/go-acme/lego/releases/download/v{LEGO_VERSION}/lego_v{LEGO_VERSION}_linux_{architecture}.tar.gz'
        download_lego(url, archive)
        if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != LEGO_HASHES[architecture]:
            raise AccessError('证书工具安装包 SHA-256 校验失败，未执行安装。')
        try:
            with tarfile.open(archive, 'r:gz') as stream:
                member = stream.getmember('lego')
                if not member.isfile() or not 0 < member.size < 160 * 1024 * 1024:
                    raise ValueError()
                with stream.extractfile(member) as source:
                    data = source.read()
                if len(data) != member.size:
                    raise ValueError()
        except (tarfile.TarError, EOFError, KeyError, ValueError):
            raise AccessError('证书工具安装包无法解包或缺少 lego 可执行文件，未执行安装。') from None
        atomic(binary, data)
        binary.chmod(0o700)
        atomic(marker, hashlib.sha256(data).hexdigest() + '\n')
    return binary


def download_lego(url, archive):
    for attempt in range(2):
        try:
            response = subprocess.run(['curl', '-q', '--proto', '=https', '--proto-redir', '=https',
                '--tlsv1.2', '-fsSL', '--connect-timeout', '15', '--max-time', '120',
                url, '-o', str(archive)], capture_output=True, timeout=125)
            code = response.returncode
        except subprocess.TimeoutExpired:
            code = 28
        except OSError:
            raise AccessError('无法启动 curl 下载证书工具；请检查 curl 是否已安装及其执行权限。') from None
        if code == 0:
            return
        if attempt == 0 and code in LEGO_RETRYABLE_CURL_CODES:
            archive.unlink(missing_ok=True)
            print('证书工具下载暂时失败，正在重试一次…', flush=True)
            continue
        reason = LEGO_DOWNLOAD_ERRORS.get(code, '下载失败')
        raise AccessError(f'证书工具下载失败：{reason}（curl {code}）；请检查 VPS 到 GitHub 的 HTTPS 连接。')


def acme_failure(output, mode=HTTP01):
    # Only emit fixed messages; subprocess output can contain challenge tokens or account details.
    detail = output[-65536:].lower()
    port = 443 if mode == TLS01 else 80
    label = 'TLS-ALPN-01' if mode == TLS01 else 'HTTP-01'
    if b'ratelimited' in detail or b'rate limit' in detail or b'too many certificates' in detail:
        return '证书机构触发频率限制，请稍后再试，避免连续重复申请。'
    if b'address already in use' in detail:
        return f'本机 TCP {port} 已被占用；不会停止或覆盖现有服务。'
    if b'no valid ip addresses' in detail or b'nxdomain' in detail or b':dns' in detail:
        return '证书机构未能解析域名，请检查 A/AAAA 记录及 DNS 是否已生效。'
    if b':caa' in detail:
        return '域名的 CAA 记录不允许此次签发，请核对 DNS 设置。'
    if b'badcontact' in detail or b'invalidcontact' in detail:
        return '证书联系邮箱被拒绝，请使用有效邮箱或留空。'
    if any(term in detail for term in (b'/acme-challenge/', b':unauthorized', b':connection', b'error presenting token')):
        hint = '以及验证目录。' if mode == HTTP01 else '，确保直接访问此 VPS，未经过 CDN 或其他 TLS 终止代理。'
        return f'{label} 验证失败；请核对域名 A/AAAA、公网 TCP {port} 放行' + hint
    if any(term in detail for term in (b'dial tcp', b'no such host', b'x509:', b'tls handshake', b'context deadline exceeded')):
        return 'VPS 无法正常访问证书机构的 HTTPS 接口，请检查该 VPS 的 DNS、出口和系统时间。'
    return f'证书机构未能完成 {label} 验证；请核对域名解析及公网 TCP {port}。'


def acme_command(binary, base, settings, renew=False):
    validate_settings(settings)
    args = [str(binary), 'run', '--path', str(base), '--server', ACME_SERVER, '--accept-tos',
            '--email', settings['email'], '--domains', settings['domain'], '--key-type', 'RSA2048',
            '--no-random-sleep', '--renew-days', '30']
    for name in settings.get('additional_domains', []):
        args.extend(['--domains', name])
    if settings.get('challenge') == DNS01:
        return args + ['--dns', 'manual']
    if settings.get('challenge') == TLS01:
        return args + ['--tls', '--tls.address', ':443']
    args.append('--http')
    if settings['webroot']:
        args.extend(['--http.webroot', settings['webroot']])
    else:
        args.extend(['--http.address', '0.0.0.0:80'])
    return args


def material_paths(app, domain):
    domain_name(domain)
    base = app / 'acme' / 'certificates'
    return base / (domain + '.crt'), base / (domain + '.key')


def load_material(app, settings):
    validate_settings(settings)
    cert, key = material_paths(app, settings['domain'])
    try:
        if not cert.is_file() or not key.is_file() or cert.stat().st_size > 65536 or key.stat().st_size > 12000:
            raise AccessError('没有有效的域名证书文件，请重新运行菜单 22。')
        certificate, private_key = cert.read_text(encoding='ascii'), key.read_text(encoding='ascii')
    except (OSError, UnicodeError):
        raise AccessError('无法读取签发的证书或私钥，请检查文件权限和格式。') from None
    fingerprint = validate_material(certificate, private_key, settings['domain'])
    for name in settings.get('additional_domains', []):
        validate_material(certificate, private_key, name)
    return certificate, private_key, fingerprint


def check_binding(port, ipv6=False):
    families = [(socket.AF_INET, '0.0.0.0')]
    if ipv6 and socket.has_ipv6:
        families.append((socket.AF_INET6, '::'))
    for family, address in families:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as check:
                if family == socket.AF_INET6:
                    check.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                if os.name == 'posix':
                    check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                elif hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    check.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                check.bind((address, port))
                check.listen(1)
        except OSError as exc:
            if family == socket.AF_INET6 and exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL):
                continue
            if exc.errno == errno.EADDRINUSE:
                error = HTTPUnavailable if port == 80 else AccessError
                raise error(f'本机 TCP {port} 已被占用；不会停止现有服务。') from None
            raise AccessError(f'无法绑定本机 TCP {port}，请检查系统权限和监听限制。') from None


def obtain(app, settings, renew=False):
    """Remember a fallback only after validating the issued certificate."""
    validate_settings(settings)
    if settings.get('challenge') == DNS01:
        return obtain_manual_dns(app, settings)
    try:
        return _obtain(app, settings, renew)
    except HTTPUnavailable as exc:
        print(str(exc), flush=True)
        print('改用 TLS-ALPN-01（公网 TCP 443）验证一次。', flush=True)
        fallback = dict(settings, challenge=TLS01, webroot='')
        cert, _ = material_paths(app, settings['domain'])
        try:
            with cert.open('rb') as stream:
                previous = stream.read(65537)
        except FileNotFoundError:
            previous = None
        except OSError:
            raise AccessError('无法读取旧证书，已停止切换验证方式。') from None
        material = _obtain(app, fallback, renew)
        # Lego run may exit successfully without a challenge when renewal is
        # not due. Do not pin an untested fallback in that case.
        if previous != material[0].encode('ascii'):
            settings.update(challenge=TLS01, webroot='')
        return material


def obtain_manual_dns(app, settings):
    if not sys.stdin.isatty():
        raise AccessError('手动 DNS-01 需要交互终端；请登录 VPS 运行 sb1 → 22。')
    print('正在准备证书工具…', flush=True)
    binary = ensure_client(app)
    print('DNS-01 不使用入站 TCP 80 或 443。按下方提示添加 TXT，保存后按回车。', flush=True)
    print('类型选 TXT；名称填提示行的第一列（可去掉末尾的点），值填引号内的内容，不含引号。', flush=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('LEGO_', 'MANUAL_'))}
    env['MANUAL_PROPAGATION_TIMEOUT'] = '180'
    try:
        result = subprocess.run(acme_command(binary, app / 'acme', settings), env=env,
                                timeout=900, umask=0o077)
    except subprocess.TimeoutExpired:
        raise AccessError('手动 DNS 验证等待超时，请返回菜单 22 重试。') from None
    except OSError:
        raise AccessError('无法启动证书工具；请检查执行权限。') from None
    if result.returncode:
        raise AccessError('DNS-01 未通过；请核对上方提示、TXT 名称和值是否正确，以及 DNS 是否已生效。')
    material = load_material(app, settings)
    print('如本次已签发，可删除刚添加的验证 TXT；请保留其他已有 TXT。', flush=True)
    return material


def _obtain(app, settings, renew):
    tls = settings.get('challenge') == TLS01
    port = 443 if tls else 80
    if settings['webroot']:
        if not Path(settings['webroot']).is_dir():
            raise HTTPUnavailable('HTTP-01 网站验证目录已不存在。')
    else:
        check_binding(port, ipv6=tls)
    print('正在准备证书工具…', flush=True)
    binary = ensure_client(app)
    cert, key = material_paths(app, settings['domain'])
    command = acme_command(binary, app / 'acme', settings, renew=renew or (cert.exists() and key.exists()))
    try:
        print(f'正在通过 HTTPS 联系证书机构，使用公网 TCP {port} 验证域名…', flush=True)
        result = subprocess.run(command, capture_output=True, timeout=240,
            env={k: v for k, v in os.environ.items() if not k.startswith('LEGO_')},
            # Challenge files must be readable by the existing web-server user.
            # Lego writes account/key files as 0600 within our private 0700 base.
            umask=0o022 if settings['webroot'] else 0o077)
    except subprocess.TimeoutExpired:
        raise AccessError(f'证书申请或续期进程超时；请检查 VPS 到证书机构的 HTTPS 连接，以及公网 TCP {port}。') from None
    except OSError:
        raise AccessError('无法启动证书工具；请检查 CPU 架构、执行权限和项目目录是否以 noexec 挂载。') from None
    if result.returncode:
        output = result.stdout + b'\n' + result.stderr
        message = acme_failure(output, TLS01 if tls else HTTP01)
        # A CA connection problem during HTTP validation, or a local bind
        # race, merits one alternate challenge. DNS/CAA/rate limit / CLI
        # timeouts do not establish a blocked public HTTP port.
        detail = output[-65536:].lower()
        blocked = any(b'urn:ietf:params:acme:error:' + kind in detail for kind in (b'ratelimited', b'dns', b'caa'))
        if not tls and not blocked and (b'urn:ietf:params:acme:error:connection' in detail or b'address already in use' in detail):
            raise HTTPUnavailable(message)
        raise AccessError(message)
    return load_material(app, settings)


def apply_material(manager, settings, material):
    certificate, private_key, fingerprint = material
    changes = {}
    for saved in manager.rows():
        row = copy.deepcopy(saved)
        if row.get('access'):
            front = public_front(row['access'], certificate, private_key, settings['domain'], fingerprint)
            if front != row['access']:
                row['access'] = front
                changes[row['port']] = row
    if changes:
        manager.apply(changes)
    return len(changes)


def for_new(manager, front):
    from manager import read_json, APP
    path = manager.root / SETTING
    if not path.exists():
        return front
    settings = validate_settings(read_json(path))
    certificate, private_key, fingerprint = load_material(APP, settings)
    return public_front(front, certificate, private_key, settings['domain'], fingerprint)


def install_timer():
    from manager import atomic, APP, Error
    units = Path('/etc/systemd/system')
    atomic(units / 'socks-relay-cert.service', '[Unit]\nDescription=Renew relay domain certificate\nAfter=network-online.target\nWants=network-online.target\n\n'
        '[Service]\nType=oneshot\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nTimeoutStartSec=900\n'
        f'ExecStart={APP}/python3 {APP}/current/scripts/manager.py renew-cert\n')
    atomic(units / 'socks-relay-cert.timer', '[Unit]\nDescription=Daily relay domain certificate renewal\n\n'
        '[Timer]\nOnBootSec=10min\nOnCalendar=*-*-* 00:15:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n')
    for args in (['daemon-reload'], ['enable', 'socks-relay-cert.timer'], ['start', 'socks-relay-cert.timer']):
        if subprocess.run(['systemctl', *args], capture_output=True).returncode:
            raise Error('证书已配置，但自动续期定时器未启动，请重新运行菜单 22。')


def configure(manager, cover_domain=None):
    from manager import ask, APP, read_json, write_json, export_dual, Error
    from webroot import detect, HTTPPathUnavailable
    print('域名 A 记录需指向此 VPS；Cloudflare 使用仅 DNS。可选自动 TCP 80/443 或手动 DNS TXT 验证。')
    previous = read_json(manager.root / SETTING) if (manager.root / SETTING).exists() else {}
    try:
        domain = domain_name(ask('TUIC 域名', previous.get('domain')).strip().lower())
        email = ask('证书联系邮箱（可留空）', previous.get('email', ''))
        settings = validate_settings(dict(domain=domain, email=email, webroot=''))
        additional = ([cover_domain] if cover_domain else
                      previous.get('additional_domains', []) if previous.get('domain') == domain else [])
        if additional:
            settings['additional_domains'] = additional
            validate_settings(settings)
        same_domain = previous.get('domain') == domain
        default = '2' if same_domain and previous.get('challenge') == DNS01 else '1'
        mode = ask('验证方式：1 自动 TCP 80/443；2 手动 DNS TXT（无需 80/443）', default)
        if mode not in ('1', '2'):
            raise AccessError('请输入 1 或 2 选择证书验证方式。')
        if mode == '2':
            settings['challenge'] = DNS01
        elif same_domain and previous.get('challenge') == TLS01:
            settings['challenge'] = TLS01
        else:
            preferred = previous.get('webroot', '') if same_domain else ''
            try:
                try:
                    settings['webroot'] = detect(domain, preferred)
                except HTTPPathUnavailable:
                    raise
                except AccessError as exc:
                    print('自动识别未通过：' + str(exc))
                    manual = ask('可选：手动网站根目录（不知道请回车取消，原节点保留）', '').strip()
                    if not manual:
                        raise exc
                    validate_settings(dict(settings, webroot=manual))
                    settings['webroot'] = detect(domain, roots=[manual])
                if settings['webroot']:
                    for name in additional:
                        if detect(name, settings['webroot']) != settings['webroot']:
                            raise AccessError('两个域名的验证目录不同，请先把两个域名的 HTTP-01 验证路径指向同一目录。')
            except HTTPPathUnavailable as exc:
                print(str(exc), flush=True)
                try:
                    check_binding(443, ipv6=True)
                except AccessError as tls_error:
                    # If neither standalone listener works, keep the manual webroot option.
                    print(str(tls_error), flush=True)
                    manual = ask('可选：手动网站根目录（不知道请回车取消，原节点保留）', '').strip()
                    if not manual:
                        raise tls_error
                    validate_settings(dict(settings, webroot=manual))
                    settings['webroot'] = detect(domain, roots=[manual])
                    for name in additional:
                        if detect(name, roots=[manual]) != settings['webroot']:
                            raise AccessError('两个域名的验证目录不同，无法使用同一 HTTP-01 验证目录。')
                else:
                    print('改用 TLS-ALPN-01（公网 TCP 443）验证一次。', flush=True)
                    settings.update(challenge=TLS01, webroot='')
        material = obtain(APP, settings)
        changed = apply_material(manager, settings, material)
        write_json(manager.root / SETTING, settings)
        if settings.get('challenge') != DNS01:
            install_timer()
        if any(r['enabled'] and r.get('access') for r in manager.rows()):
            export_dual(manager)
    except AccessError as exc:
        raise Error(str(exc)) from None
    renewal = ('手动续期：到期前再次运行菜单 22，按提示添加新的 TXT。' if settings.get('challenge') == DNS01
               else '自动续期已启用。')
    print('域名证书已配置，已更新 ' + str(changed) + ' 个入口；端口和账密保留。' + renewal)
    print('菜单 16 查看、18 重新导出；普通 TUIC 可用 tuic://。')


def renew(manager):
    from manager import APP, read_json, write_json, export_dual, Error
    path = manager.root / SETTING
    if not path.exists():
        raise Error('尚未配置域名证书，请先运行菜单 22。')
    try:
        settings = validate_settings(read_json(path))
        if settings.get('challenge') == DNS01:
            print('当前使用手动 DNS-01；后台不发起验证。请在证书到期前运行菜单 22 手动续期。')
            return
        previous = dict(settings)
        changed = apply_material(manager, settings, obtain(APP, settings, renew=True))
        if settings != previous:
            write_json(path, settings)
        if changed and any(r['enabled'] and r.get('access') for r in manager.rows()):
            export_dual(manager)
    except AccessError as exc:
        raise Error(str(exc)) from None
    print('证书检查完成；更新入口数：' + str(changed) + '。')
