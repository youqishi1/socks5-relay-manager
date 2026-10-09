"""Offline TUIC v5 client exporters. Never include provider credentials."""
import ipaddress
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit
import uuid


class ConfigError(Exception):
    pass


def text_field(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 1024:
        raise ConfigError('TUIC 字段为空或过长。')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigError('TUIC 字段不能包含控制字符。')
    return value


def server_field(value):
    text_field(value)
    try:
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ConfigError('TUIC 入口必须是 VPS 的可访问地址。')
        return str(address)
    except ValueError:
        pass
    if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
        raise ConfigError('TUIC 地址必须为 IP 或域名。')
    if any(not part or len(part) > 63 or part.startswith('-') or part.endswith('-') for part in value.split('.')):
        raise ConfigError('TUIC 域名格式无效。')
    return value


def parse_tuic(link):
    """Parse the common v2rayN TUIC v5 URL, fail closed on unsupported options."""
    try:
        text_field(link)
        url = urlsplit(link.strip())
        if url.scheme.lower() != 'tuic' or not url.hostname or not url.port or url.path not in ('', '/'):
            raise ConfigError('请粘贴完整的 TUIC v5 链接：tuic://UUID:密码@地址:端口?...')
        if not url.username or url.password is None:
            raise ConfigError('目前仅支持带 UUID 和密码的 TUIC v5 链接。')
        identity = str(uuid.UUID(unquote(url.username)))
        password = text_field(unquote(url.password))
        query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
        allowed = {'sni', 'peer', 'alpn', 'congestion_control', 'congestion-controller',
                   'udp_relay_mode', 'udp-relay-mode', 'allow_insecure', 'allowInsecure',
                   'insecure', 'skip-cert-verify', 'security', 'type'}
        if set(query) - allowed or any(len(values) != 1 for values in query.values()):
            raise ConfigError('TUIC 链接含未支持或重复参数，请使用 v2rayN 导出的标准 TUIC v5 链接。')
        def pick(*keys, default=''):
            values = [query[key][0] for key in keys if key in query]
            if len(set(values)) > 1:
                raise ConfigError('TUIC 链接中的同义参数互相冲突。')
            return values[0] if values else default
        if pick('security', default='tls') != 'tls' or pick('type', default='tuic') not in ('tuic', ''):
            raise ConfigError('该 TUIC 链接使用了未支持的传输参数。')
        insecure = pick('allow_insecure', 'allowInsecure', 'insecure', 'skip-cert-verify', default='0').lower()
        if insecure not in ('0', '1', 'false', 'true'):
            raise ConfigError('TUIC 证书验证参数无效。')
        cc = pick('congestion_control', 'congestion-controller', default='cubic')
        udp = pick('udp_relay_mode', 'udp-relay-mode', default='native')
        if cc not in ('cubic', 'new_reno', 'bbr') or udp not in ('native', 'quic'):
            raise ConfigError('TUIC 拥塞控制或 UDP 转发模式无效。')
        alpn = pick('alpn')
        protocols = [text_field(value) for value in alpn.split(',')] if alpn else []
        sni = pick('sni', 'peer')
        if sni:
            server_field(sni)
        return dict(server=server_field(url.hostname), port=url.port, uuid=identity,
                    password=password, sni=sni, alpn=protocols, cc=cc, udp=udp,
                    insecure=insecure in ('1', 'true'))
    except ConfigError:
        raise
    except (ValueError, TypeError, UnicodeError):
        # Exception text can contain the entire URL/password: never echo it.
        raise ConfigError('TUIC 链接格式无效，请重新从客户端复制分享链接。') from None


def export_configs(rows, node, allow_insecure=False):
    if node['insecure'] and not allow_insecure:
        raise ConfigError('原 TUIC 链接关闭了证书验证，需要明确确认才能按原设置导出。')
    rows = sorted((row for row in rows if row['enabled']), key=lambda row: row['port'])
    if not rows:
        raise ConfigError('暂无已启用中转，请先添加并检测成功。')
    if any(row['bind'] not in ('127.0.0.1', '0.0.0.0') for row in rows):
        raise ConfigError('TUIC 本机模式要求中转监听 127.0.0.1 或 0.0.0.0，请先修改对应监听地址。')
    tag = '青岛到VPS-TUIC'
    tuic = {'name': tag, 'type': 'tuic', 'server': node['server'], 'port': node['port'],
            'uuid': node['uuid'], 'password': node['password'],
            'congestion-controller': node['cc'], 'udp-relay-mode': node['udp'],
            'skip-cert-verify': node['insecure'], 'reduce-rtt': False}
    tls = {'enabled': True, 'insecure': node['insecure']}
    if node['sni']:
        tuic['sni'] = node['sni']
        tls['server_name'] = node['sni']
    if node['alpn']:
        tuic['alpn'] = node['alpn']
        tls['alpn'] = node['alpn']
    sing_tuic = {'type': 'tuic', 'tag': tag, 'server': node['server'], 'server_port': node['port'],
                 'uuid': node['uuid'], 'password': node['password'], 'tls': tls,
                 'congestion_control': node['cc'], 'udp_relay_mode': node['udp'], 'zero_rtt_handshake': False}
    clash = {'mode': 'rule', 'log-level': 'error', 'allow-lan': False,
             'proxies': [tuic], 'listeners': [], 'proxy-groups': [], 'rules': []}
    sing = {'log': {'level': 'error'}, 'inbounds': [], 'outbounds': [sing_tuic],
            'dns': {'servers': [{'type': 'local', 'tag': 'bootstrap-dns'}]},
            'route': {'auto_detect_interface': True, 'default_domain_resolver': 'bootstrap-dns', 'rules': []}}
    names = []
    for row in rows:
        port = row['port']
        name = '固定出口-' + str(port)
        names.append(name)
        user, password = row['client_user'], row['client_password']
        clash['proxies'].append({'name': name, 'type': 'socks5', 'server': '127.0.0.1', 'port': port,
                                 'username': user, 'password': password, 'udp': False, 'dialer-proxy': tag})
        clash['listeners'].append({'name': '本机-' + str(port), 'type': 'socks', 'listen': '127.0.0.1',
                                   'port': port, 'udp': False, 'users': [{'username': user, 'password': password}],
                                   'proxy': name})
        sing['inbounds'].append({'type': 'socks', 'tag': 'local-' + str(port), 'listen': '127.0.0.1',
                                 'listen_port': port, 'users': [{'username': user, 'password': password}]})
        sing['outbounds'].append({'type': 'socks', 'tag': name, 'server': '127.0.0.1', 'server_port': port,
                                  'username': user, 'password': password, 'network': 'tcp', 'detour': tag})
        sing['route']['rules'].append({'inbound': ['local-' + str(port)], 'action': 'route', 'outbound': name})
    clash['proxy-groups'] = [{'name': '中转出口', 'type': 'select', 'proxies': names}]
    clash['rules'] = ['MATCH,中转出口']
    sing['route']['final'] = names[0]
    # JSON is a valid YAML document; serialization prevents config injection.
    return {'clash-verge.yaml': json.dumps(clash, ensure_ascii=False, indent=2) + '\n',
            'v2rayn-sing-box.json': json.dumps(sing, ensure_ascii=False, indent=2) + '\n'}
