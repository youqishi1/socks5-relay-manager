"""Assemble multiple isolated inlet routes for one sing-box process."""
import json

from access import AccessError, render

UNIT = 'socks-access-shared.service'
CONFIG = 'shared-access.json'


def unit_for(row):
    return UNIT if row.get('shared') else f"socks-access@{row['port']}.service"


def render_group(entries):
    config = {'log': {'level': 'error'}, 'inbounds': [], 'outbounds': [],
              'route': {'rules': [{'network': 'udp', 'action': 'reject'}]}}
    rules = config['route']['rules']
    ports = set()
    for row, directory in entries:
        public_port = row['access']['port']
        if public_port in ports:
            raise AccessError('共享组内有重复的公网端口，已取消。')
        ports.add(public_port)
        node = json.loads(render(row, directory))
        suffix = '-' + str(row['port'])
        inbounds = node['inbounds']
        for inbound in inbounds:
            inbound['tag'] += suffix
        outbound, = node['outbounds']
        outbound['tag'] += suffix
        config['inbounds'].extend(inbounds)
        config['outbounds'].append(outbound)
        rules.append({'inbound': [inbound['tag'] for inbound in inbounds],
                      'action': 'route', 'outbound': outbound['tag']})
    rules.append({'action': 'reject'})
    return json.dumps(config, ensure_ascii=False, indent=2) + '\n'
