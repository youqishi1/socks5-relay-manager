"""Automatically provision two authenticated, encrypted entrances per relay."""
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import uuid

METHOD = '2022-blake3-aes-256-gcm'
SNI = 'socks-relay.local'


class AccessError(Exception):
    pass


def domain_name(value):
    if not isinstance(value, str) or len(value) > 253 or value != value.lower() or '.' not in value:
        raise AccessError('请输入小写的完整域名，例如 tuic.example.com。')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.')):
        raise AccessError('域名格式无效。')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise AccessError('此功能需要域名，不能填写 IP。')


def leaf_der(certificate):
    if not isinstance(certificate, str) or len(certificate) > 65536:
        raise ValueError('Invalid certificate chain')
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----', certificate)
    if not 1 <= len(blocks) <= 8 or re.sub(r'\s', '', certificate) != re.sub(r'\s', '', ''.join(blocks)):
        raise ValueError('Invalid certificate chain')
    return ssl.PEM_cert_to_DER_cert(blocks[0])


def server_name(front):
    return front.get('server_name', SNI)


def system_trust(front):
    return front.get('certificate_trust') == 'system'


def validate(front):
    fields = {'port', 'ss_password', 'uuid', 'tuic_password', 'certificate', 'private_key', 'fingerprint'}
    if not isinstance(front, dict) or set(front) not in (fields, fields | {'server_name', 'certificate_trust'}):
        raise AccessError('双模式入口配置字段无效。')
    if 'server_name' in front:
        domain_name(front['server_name'])
        if front['certificate_trust'] != 'system':
            raise AccessError('域名证书信任模式无效。')
    if type(front['port']) is not int or not 30001 <= front['port'] <= 39999:
        raise AccessError('双模式入口端口必须为 30001–39999。')
    try:
        if len(base64.b64decode(front['ss_password'], validate=True)) != 32:
            raise ValueError()
        uuid.UUID(front['uuid'])
        if not isinstance(front['tuic_password'], str) or not 16 <= len(front['tuic_password']) <= 128 or not all(32 <= ord(char) < 127 for char in front['tuic_password']):
            raise ValueError()
        if not front['private_key'].startswith(('-----BEGIN PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN EC PRIVATE KEY-----')) or len(front['private_key']) >= 12000:
            raise ValueError()
        cert = leaf_der(front['certificate'])
        if hashlib.sha256(cert).hexdigest() != front['fingerprint']:
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError):
        raise AccessError('双模式入口的凭据或证书无效。') from None
    return front


def free_public_port(rows, preferred):
    used = {row['access']['port'] for row in rows if row.get('access')}
    candidates = [preferred] + [port for port in range(30001, 40000) if port != preferred]
    for port in candidates:
        if port in used:
            continue
        try:
            with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
                tcp.bind(('0.0.0.0', port))
                tcp.listen(1)
                udp.bind(('0.0.0.0', port))
            return port
        except OSError:
            continue
    raise AccessError('没有同时可用于 TCP 和 UDP 的双模式入口端口。')


def generate(rows, inner_port):
    with tempfile.TemporaryDirectory(prefix='socks-relay-cert-') as folder:
        directory = Path(folder)
        directory.chmod(0o700)
        cert, key = directory / 'certificate.pem', directory / 'private-key.pem'
        config = directory / 'openssl.cnf'
        config.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n'
                          '[dn]\nCN=' + SNI + '\n[extensions]\nsubjectAltName=DNS:' + SNI + '\n'
                          'basicConstraints=critical,CA:TRUE\n')
        try:
            result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
                                     '-keyout', str(key), '-out', str(cert), '-config', str(config)],
                                    capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise AccessError('证书生成失败，请检查 OpenSSL 依赖。') from None
        if result.returncode:
            raise AccessError('证书生成失败，未创建入口。')
        certificate, private_key = cert.read_text(), key.read_text()
    return validate(dict(port=free_public_port(rows, inner_port + 10000),
                         ss_password=base64.b64encode(secrets.token_bytes(32)).decode(),
                         uuid=str(uuid.uuid4()), tuic_password=secrets.token_urlsafe(32),
                         certificate=certificate, private_key=private_key,
                         fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()))


def render(row, directory):
    front = validate(row['access'])
    return json.dumps({
        'log': {'level': 'error'},
        'inbounds': [
            {'type': 'shadowsocks', 'tag': 'encrypted-tcp', 'listen': '0.0.0.0',
             'listen_port': front['port'], 'network': 'tcp', 'method': METHOD, 'password': front['ss_password']},
            {'type': 'tuic', 'tag': 'tuic', 'listen': '0.0.0.0', 'listen_port': front['port'],
             'users': [{'uuid': front['uuid'], 'password': front['tuic_password']}],
             'congestion_control': 'bbr', 'zero_rtt_handshake': False,
             'tls': {'enabled': True, 'alpn': ['h3'], 'certificate_path': str(Path(directory) / 'certificate.pem'),
                     'key_path': str(Path(directory) / 'private-key.pem')}}],
        'outbounds': [{'type': 'socks', 'tag': 'fixed-upstream', 'server': '127.0.0.1',
                       'server_port': row['port'], 'username': row['client_user'],
                       'password': row['client_password'], 'network': 'tcp'}],
        'route': {'rules': [{'network': 'udp', 'action': 'reject'}], 'final': 'fixed-upstream'}
    }, ensure_ascii=False, indent=2) + '\n'


def v2rayn_link(front, address, label):
    # Official v2rayN InnerFmt ConfigVersion 4 preserves the embedded CA,
    # unlike a standard tuic:// link whose exporter drops certificate trust.
    profile = {'ConfigVersion': 4, 'ConfigType': 8, 'CoreType': 24, 'Remarks': label,
               'Address': address, 'Port': front['port'], 'Username': front['uuid'],
               'Password': front['tuic_password'], 'StreamSecurity': 'tls',
               'AllowInsecure': 'false', 'Sni': server_name(front), 'Alpn': 'h3',
               'Cert': '' if system_trust(front) else front['certificate'],
               'ProtoExtraObj': {'CongestionControl': 'bbr'}}
    data = base64.urlsafe_b64encode(json.dumps(profile, ensure_ascii=False, separators=(',', ':')).encode()).decode().rstrip('=')
    return 'v2rayn://tuic/' + data


def tuic_link(front, address, label):
    """Common TUIC URI. Certificate trust is supplied separately, never disabled."""
    from urllib.parse import quote, urlencode
    server = '[' + address + ']' if ':' in address else address
    query = urlencode({'sni': server_name(front), 'alpn': 'h3', 'congestion_control': 'bbr', 'allow_insecure': '0'})
    return ('tuic://' + front['uuid'] + ':' + quote(front['tuic_password'], safe='') + '@' + server
            + ':' + str(front['port']) + '?' + query + '#' + quote(label, safe=''))


def configs(rows, address):
    from urllib.parse import quote
    clash = {'mode': 'rule', 'allow-lan': False, 'log-level': 'error',
             'proxies': [], 'proxy-groups': [], 'listeners': [], 'rules': []}
    clients = {mode: {'log': {'level': 'error'}, 'inbounds': [], 'outbounds': [],
                      'route': {'rules': []}} for mode in ('tcp', 'tuic')}
    links, quick, standard, certificates = [], [], [], {}
    rows = sorted((row for row in rows if row['enabled'] and row.get('access')), key=lambda row: row['port'])
    if not rows:
        raise AccessError('暂无启用的双模式中转。')
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        if not isinstance(address, str) or not address or any(char not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for char in address):
            raise AccessError('VPS 地址无效。') from None
        if any(not part or len(part) > 63 or part.startswith('-') or part.endswith('-') for part in address.split('.')):
            raise AccessError('VPS 域名无效。')
    else:
        if parsed.version != 4 or parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback:
            raise AccessError('请使用 VPS 公网 IPv4 或对应域名，入口目前监听 IPv4。')
    groups = []
    for row in rows:
        front = validate(row['access'])
        port, public = row['port'], front['port']
        tcp_tag, tuic_tag, selector = '出口-' + str(port) + '-TCP', '出口-' + str(port) + '-TUIC', '出口-' + str(port) + '-模式'
        groups.append(selector)
        clash['proxies'] += [
            {'name': tcp_tag, 'type': 'ss', 'server': address, 'port': public, 'cipher': METHOD,
             'password': front['ss_password'], 'udp': False},
            {'name': tuic_tag, 'type': 'tuic', 'server': address, 'port': public, 'uuid': front['uuid'],
             'password': front['tuic_password'], 'sni': server_name(front), 'alpn': ['h3'],
             'fingerprint': front['fingerprint'], 'skip-cert-verify': False,
             'congestion-controller': 'bbr', 'reduce-rtt': False}]
        clash['proxy-groups'].append({'name': selector, 'type': 'select', 'proxies': [tuic_tag, tcp_tag]})
        if system_trust(front):
            del clash['proxies'][-1]['fingerprint']
        clash['listeners'].append({'name': '本机-' + str(port), 'type': 'socks', 'listen': '127.0.0.1',
                                   'port': port, 'udp': False, 'proxy': selector,
                                   'users': [{'username': row['client_user'], 'password': row['client_password']}]})
        for mode, tag in (('tcp', tcp_tag), ('tuic', tuic_tag)):
            if mode == 'tcp':
                outbound = {'type': 'shadowsocks', 'tag': tag, 'server': address, 'server_port': public,
                            'method': METHOD, 'password': front['ss_password'], 'network': 'tcp'}
            else:
                outbound = {'type': 'tuic', 'tag': tag, 'server': address, 'server_port': public,
                            'uuid': front['uuid'], 'password': front['tuic_password'], 'congestion_control': 'bbr',
                            'zero_rtt_handshake': False, 'tls': {'enabled': True, 'server_name': server_name(front),
                            'alpn': ['h3'], 'insecure': False, 'certificate': front['certificate'].splitlines()}}
                if system_trust(front):
                    del outbound['tls']['certificate']
            clients[mode]['outbounds'].append(outbound)
            clients[mode]['inbounds'].append({'type': 'socks', 'tag': 'local-' + str(port), 'listen': '127.0.0.1',
                                            'listen_port': port, 'users': [{'username': row['client_user'], 'password': row['client_password']}]})
            clients[mode]['route']['rules'].append({'inbound': ['local-' + str(port)], 'action': 'route', 'outbound': tag})
        server = '[' + address + ']' if ':' in address else address
        link = 'ss://' + METHOD + ':' + quote(front['ss_password'], safe='') + '@' + server + ':' + str(public) + '#' + quote(tcp_tag)
        internal = v2rayn_link(front, address, tuic_tag)
        ordinary = tuic_link(front, address, tuic_tag)
        cert_name = 'TUIC-' + str(port) + '-证书.pem'
        certificates[cert_name] = front['certificate']
        standard.append(ordinary)
        quick += [link, internal]
        trust_note = ('TUIC 普通链接（公开 CA 证书，可用于 MiSub、小火箭、v2rayN，保持证书验证开启）：'
                      if system_trust(front) else 'TUIC 常见分享格式（自签证书，需同时信任配套证书，不能仅导入此链接就保证可用）：')
        cert_note = ('域名/SNI：' + server_name(front) + '；客户端使用系统 CA 信任，无需手动安装配套证书。'
                     if system_trust(front) else 'v2rayN 导入上面短链接后，在 TUIC 节点编辑页的证书/Cert 字段粘贴配套 PEM 全文；保持证书验证开启。')
        links += ['端口 ' + str(port) + ' 的加密 TCP 分享链接（v2rayN 可直接导入）：', link,
                  trust_note, ordinary,
                  '配套公开证书：' + cert_name + '；证书 SHA-256：' + front['fingerprint'],
                  cert_note,
                  '更方便的安全导入：复制 v2rayN-一键导入.txt 全部内容，或 Clash 导入 clash-dual.yaml。',
                  'TUIC：v2rayN 内部分享链接（支持 ConfigVersion 4 的版本，保留证书验证）：', internal,
                  '若旧版 v2rayN 不支持内部分享链接，使用自定义 v2rayn-tuic.json；Clash 使用 clash-dual.yaml。',
                  '本地 SOCKS5：127.0.0.1:' + str(port) + ' 账号：' + row['client_user'] + ' 密码：' + row['client_password'], '']
    clash['proxy-groups'].append({'name': '中转出口', 'type': 'select', 'proxies': groups})
    clash['rules'] = ['MATCH,中转出口']
    for client in clients.values():
        client['route']['final'] = client['outbounds'][0]['tag']
    return {**certificates, 'clash-dual.yaml': json.dumps(clash, ensure_ascii=False, indent=2) + '\n',
            'v2rayn-tcp.json': json.dumps(clients['tcp'], ensure_ascii=False, indent=2) + '\n',
            'v2rayn-tuic.json': json.dumps(clients['tuic'], ensure_ascii=False, indent=2) + '\n',
            'v2rayN-一键导入.txt': '\n'.join(quick) + '\n',
            'TUIC-普通链接.txt': '\n'.join(standard) + '\n',
            '连接信息.txt': '\n'.join(links) + '\n'}
