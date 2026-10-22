"""Opt-in UDP-only entrances; legacy SS/TUIC data and exports stay compatible."""
import copy
import json
import secrets
from urllib.parse import quote, urlencode

PROFILES = {'compat': 'SS + TUIC', 'tuic-only': '仅 TUIC', 'hysteria2-only': '仅 Hysteria 2（HTTP/3）'}


def profile(front):
    return front.get('profile', 'compat')


def modes(front):
    return {'compat': ('tcp', 'tuic'), 'tuic-only': ('tuic',),
            'hysteria2-only': ('hysteria2',)}[profile(front)]


def validate_profile(front):
    from access import AccessError, system_trust
    if not isinstance(profile(front), str) or profile(front) not in PROFILES:
        raise AccessError('入口模式无效。')
    secret = front.get('hy2_password')
    if secret is not None and (not isinstance(secret, str) or not 32 <= len(secret) <= 128
                               or not all(33 <= ord(char) < 127 for char in secret)):
        raise AccessError('Hysteria 2 凭据无效。')
    if profile(front) == 'hysteria2-only' and (not system_trust(front) or not secret):
        raise AccessError('Hysteria 2 普通链接需要先在菜单 22 配置公共 CA 域名证书。')


def render_profile(config, front):
    chosen = profile(front)
    if chosen == 'compat':
        return config
    inbound = config['inbounds'][1]
    if chosen == 'hysteria2-only':
        # Keep QUIC/HTTP3 intact: no random-data obfuscation or forced bandwidth.
        inbound = {key: inbound[key] for key in ('listen', 'listen_port', 'tls')}
        inbound.update(type='hysteria2', tag='hysteria2',
                       users=[{'password': front['hy2_password']}], ignore_client_bandwidth=True,
                       masquerade={'type': 'string', 'status_code': 200,
                                   'headers': {'content-type': 'text/html; charset=utf-8'},
                                   'content': '<!doctype html><html><head><title>Welcome</title></head>'
                                              '<body><h1>Welcome</h1><p>This website is available.</p></body></html>'})
    config['inbounds'] = [inbound]
    return config


def export_profiles(rows, address):
    import access
    rows = sorted((row for row in rows if row['enabled'] and row.get('access')), key=lambda row: row['port'])
    if not rows:
        raise access.AccessError('暂无启用的加密入口。')
    base_rows = copy.deepcopy(rows)
    for original, clean in zip(rows, base_rows):
        access.validate(original['access'])
        clean['access'].pop('profile', None)
        clean['access'].pop('hy2_password', None)
    files = access.configs(base_rows, address)
    clash = json.loads(files['clash-dual.yaml'])
    tcp = json.loads(files['v2rayn-tcp.json'])
    tuic = json.loads(files['v2rayn-tuic.json'])
    clients = {mode: {'log': {'level': 'error'}, 'inbounds': [], 'outbounds': [], 'route': {'rules': []}}
               for mode in ('tcp', 'tuic', 'hysteria2')}
    proxies, quick, ordinary, hy2_links, details = [], [], [], [], []
    for index, row in enumerate(rows):
        front = row['access']
        allowed = modes(front)
        tcp_node, udp_node = clash['proxies'][index * 2:index * 2 + 2]
        group = clash['proxy-groups'][index]
        nodes = {'tcp': tcp_node, 'tuic': udp_node}
        if 'hysteria2' in allowed:
            tag = '出口-' + str(row['port']) + '-HY2'
            nodes['hysteria2'] = dict(name=tag, type='hysteria2', server=address, port=front['port'],
                                     password=front['hy2_password'], sni=access.server_name(front),
                                     alpn=['h3'], **{'skip-cert-verify': False})
        group['proxies'] = [nodes[mode]['name'] for mode in allowed]
        proxies.extend(nodes[mode] for mode in allowed)
        for mode in allowed:
            source = tcp if mode == 'tcp' else tuic
            outbound = copy.deepcopy(source['outbounds'][index])
            if mode == 'hysteria2':
                outbound = {key: outbound[key] for key in ('server', 'server_port', 'tls')}
                outbound.update(type='hysteria2', tag=tag, password=front['hy2_password'], network='tcp')
            client = clients[mode]
            client['outbounds'].append(outbound)
            client['inbounds'].append(source['inbounds'][index])
            rule = copy.deepcopy(source['route']['rules'][index])
            rule['outbound'] = outbound['tag']
            client['route']['rules'].append(rule)
        legacy = access.configs([base_rows[index]], address)
        ss_link, internal = legacy['v2rayN-一键导入.txt'].splitlines()
        common = legacy['TUIC-普通链接.txt'].strip()
        details += ['中转 ' + str(row['port']) + '：' + PROFILES[profile(front)]]
        if 'tcp' in allowed:
            quick.append(ss_link)
            details += ['SS：', ss_link]
        if 'tuic' in allowed:
            quick.append(internal)
            ordinary.append(common)
            details += ['TUIC：', common, '自签模式请使用保留证书的内部链接或完整 YAML/JSON，不能关闭证书验证。']
        if 'hysteria2' in allowed:
            query = urlencode({'sni': access.server_name(front), 'alpn': 'h3', 'insecure': '0'})
            link = ('hysteria2://' + quote(front['hy2_password'], safe='') + '@' + address + ':'
                    + str(front['port']) + '/?' + query + '#' + quote(tag, safe=''))
            quick.append(link)
            hy2_links.append(link)
            details += ['Hysteria 2：', link]
        details += ['本地 SOCKS5：127.0.0.1:' + str(row['port']) + ' 账号：' + row['client_user']
                    + ' 密码：' + row['client_password'], '']
    clash['proxies'] = proxies
    files['clash-dual.yaml'] = json.dumps(clash, ensure_ascii=False, indent=2) + '\n'
    for mode, client in clients.items():
        name = 'v2rayn-' + mode + '.json'
        files.pop(name, None)
        if client['outbounds']:
            client['route']['final'] = client['outbounds'][0]['tag']
            files[name] = json.dumps(client, ensure_ascii=False, indent=2) + '\n'
    files['v2rayN-一键导入.txt'] = '\n'.join(quick) + '\n'
    files['TUIC-普通链接.txt'] = '\n'.join(ordinary) + '\n'
    files['HY2-普通链接.txt'] = '\n'.join(hy2_links) + '\n'
    files['连接信息.txt'] = '\n'.join(details) + '\n'
    return files


def configure(manager, row, choice):
    from access import AccessError, validate
    if choice not in ('1', '2', '3'):
        raise AccessError('请选择 1–3。')
    if not row.get('access'):
        raise AccessError('请先给此中转启用加密入口。')
    changed = copy.deepcopy(row)
    front = changed['access']
    chosen = ('tuic-only', 'hysteria2-only', 'compat')[int(choice) - 1]
    front['profile'] = chosen
    if chosen == 'hysteria2-only' and not front.get('hy2_password'):
        front['hy2_password'] = secrets.token_urlsafe(32)
    validate(front)
    if chosen == 'compat':
        front.pop('profile', None)
        front.pop('hy2_password', None)
    if changed != row:
        manager.apply({row['port']: changed})
    return changed
