"""Optional per-VPS domain certificate; preserve credentials and TLS verification."""
import copy
import hashlib
import os
from pathlib import Path
import platform
import re
import socket
import ssl
import subprocess
import tarfile
import tempfile
import threading

from access import AccessError, domain_name, leaf_der, validate

LEGO_VERSION = '5.5.2'
LEGO_HASHES = {
    'amd64': '2a35505089e7772c92e1e9ac144df91151ef2eca8568630db0ff91fca06d9bef',
    'arm64': '15b14ec2ab14fde69cc8396eb0204c5ce4327e31a486953225a6059b26db3e8c',
    'armv6': '2829eed8dca0a7589c8354bce7406aea1ecd1a79b18dfa969c0b4ce034a4611b',
    '386': '425b111caf39273424f811e05fdf83ceb21b929aebf578ca5c4524f0816ceec9',
}
ACME_SERVER = 'https://acme-v02.api.letsencrypt.org/directory'
SETTING = 'domain-certificate.json'


def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) != {'domain', 'email', 'webroot'}:
        raise AccessError('域名证书设置无效。')
    domain_name(settings['domain'])
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
    private_dir(base)
    binary, marker = base / 'lego', base / 'lego.sha256'
    if binary.is_file() and not binary.is_symlink() and marker.is_file() and not marker.is_symlink():
        expected = marker.read_text().strip()
        if re.fullmatch(r'[a-f0-9]{64}', expected) and hashlib.sha256(binary.read_bytes()).hexdigest() == expected:
            return binary
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64', 'armv7l': 'armv6', 'i686': '386'}.get(platform.machine())
    if architecture not in LEGO_HASHES:
        raise AccessError('当前 CPU 暂不支持自动申请域名证书。')
    with tempfile.TemporaryDirectory(prefix='.acme-download-', dir=base) as folder:
        archive = Path(folder) / 'lego.tar.gz'
        url = f'https://github.com/go-acme/lego/releases/download/v{LEGO_VERSION}/lego_v{LEGO_VERSION}_linux_{architecture}.tar.gz'
        response = subprocess.run(['curl', '-q', '--proto', '=https', '--tlsv1.2', '-fsSL',
            '--connect-timeout', '10', '--max-time', '180', url, '-o', str(archive)],
            capture_output=True, timeout=190)
        if response.returncode or hashlib.sha256(archive.read_bytes()).hexdigest() != LEGO_HASHES[architecture]:
            raise AccessError('证书工具下载或 SHA-256 校验失败。')
        with tarfile.open(archive) as stream:
            member = stream.getmember('lego')
            if not member.isfile() or not 0 < member.size < 160 * 1024 * 1024:
                raise AccessError('证书工具安装包无效。')
            with stream.extractfile(member) as source:
                data = source.read()
        atomic(binary, data)
        binary.chmod(0o700)
        atomic(marker, hashlib.sha256(data).hexdigest() + '\n')
    return binary


def acme_command(binary, base, settings, renew=False):
    validate_settings(settings)
    args = [str(binary), 'run', '--path', str(base), '--server', ACME_SERVER, '--accept-tos',
            '--email', settings['email'], '--domains', settings['domain'], '--key-type', 'RSA2048',
            '--no-random-sleep', '--renew-days', '30', '--http']
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
    if not cert.is_file() or not key.is_file() or cert.stat().st_size > 65536 or key.stat().st_size > 12000:
        raise AccessError('没有有效的域名证书文件，请重新运行菜单 22。')
    certificate, private_key = cert.read_text(encoding='ascii'), key.read_text(encoding='ascii')
    fingerprint = validate_material(certificate, private_key, settings['domain'])
    return certificate, private_key, fingerprint


def obtain(app, settings, renew=False):
    validate_settings(settings)
    if settings['webroot']:
        if not Path(settings['webroot']).is_dir():
            raise AccessError('网站根目录不存在；不会停止现有网站。')
    else:
        try:
            with socket.socket() as check:
                check.bind(('0.0.0.0', 80))
        except OSError:
            raise AccessError('80 端口已有服务；请填写该域名网站根目录后使用 webroot 验证，不会停止网站。') from None
    binary = ensure_client(app)
    cert, key = material_paths(app, settings['domain'])
    command = acme_command(binary, app / 'acme', settings, renew=renew or (cert.exists() and key.exists()))
    try:
        result = subprocess.run(command, capture_output=True, timeout=240,
            env={k: v for k, v in os.environ.items() if not k.startswith('LEGO_')})
    except (OSError, subprocess.TimeoutExpired):
        raise AccessError('证书申请或续期超时，原节点保留。') from None
    if result.returncode:
        raise AccessError('证书申请或续期失败：检查域名 A 记录、TCP 80 放行及网站根目录；原节点保留。')
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
        '[Service]\nType=oneshot\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nTimeoutStartSec=600\n'
        f'ExecStart={APP}/python3 {APP}/current/scripts/manager.py renew-cert\n')
    atomic(units / 'socks-relay-cert.timer', '[Unit]\nDescription=Daily relay domain certificate renewal\n\n'
        '[Timer]\nOnBootSec=10min\nOnCalendar=*-*-* 00:15:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n')
    for args in (['daemon-reload'], ['enable', '--now', 'socks-relay-cert.timer']):
        if subprocess.run(['systemctl', *args], capture_output=True).returncode:
            raise Error('证书已配置，但自动续期定时器未启动，请重新运行菜单 22。')


def configure(manager):
    from manager import ask, APP, read_json, write_json, export_dual, Error
    print('域名 A 记录需指向此 VPS；Cloudflare 使用仅 DNS。申请/续期需要 TCP 80，可复用网站根目录。')
    previous = read_json(manager.root / SETTING) if (manager.root / SETTING).exists() else {}
    try:
        domain = domain_name(ask('TUIC 域名', previous.get('domain')).strip().lower())
        email = ask('证书联系邮箱（可留空）', previous.get('email', ''))
        webroot = ask('该域名网站根目录（80 端口空闲时可留空）', previous.get('webroot', ''))
        settings = validate_settings(dict(domain=domain, email=email, webroot=webroot))
        material = obtain(APP, settings)
        changed = apply_material(manager, settings, material)
        write_json(manager.root / SETTING, settings)
        install_timer()
        if any(r['enabled'] and r.get('access') for r in manager.rows()):
            export_dual(manager)
    except AccessError as exc:
        raise Error(str(exc)) from None
    print('域名证书已配置，已更新 ' + str(changed) + ' 个入口；端口和账密保留。自动续期已启用。')
    print('菜单 16 查看、18 重新导出；把 TUIC-普通链接.txt 中的 tuic:// 链接交给 MiSub 分发。')


def renew(manager):
    from manager import APP, read_json, export_dual, Error
    path = manager.root / SETTING
    if not path.exists():
        raise Error('尚未配置域名证书，请先运行菜单 22。')
    try:
        settings = validate_settings(read_json(path))
        changed = apply_material(manager, settings, obtain(APP, settings, renew=True))
        if changed and any(r['enabled'] and r.get('access') for r in manager.rows()):
            export_dual(manager)
    except AccessError as exc:
        raise Error(str(exc)) from None
    print('证书检查完成；更新入口数：' + str(changed) + '。')
