"""Country lookup for a previously measured public exit IP."""
import ipaddress
import json
import subprocess


def country_for(ip):
    address = ipaddress.ip_address(ip)
    if not address.is_global or address.is_multicast:
        return ''
    # Send only the measured public IP. This is independent of the proxy
    # account, and location lookup failure must never block an export.
    url = 'https://ipwho.is/' + str(address) + '?fields=success,ip,country&lang=zh-CN'
    try:
        result = subprocess.run(
            ['curl', '-q', '--silent', '--fail', '--noproxy', '*',
             '--proto', '=https', '--connect-timeout', '3', '--max-time', '5',
             '--max-filesize', '2048', url], capture_output=True, timeout=6)
        if result.returncode or len(result.stdout) > 2048:
            return ''
        data = json.loads(result.stdout)
        if data.get('success') is not True or ipaddress.ip_address(data.get('ip')) != address:
            return ''
        country = data.get('country')
        if isinstance(country, str):
            name = ''.join(char for char in country if char.isalnum() or char in ' -')
            return ' '.join(name.split())[:24].strip(' -')
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, AttributeError):
        pass
    return ''


def label(port, protocol, locations, note=''):
    if locations is None or port not in locations:
        prefix = '出口'
    else:
        ip, country = locations[port]
        prefix = (country or '地区未知') + '-' + ip if ip else '出口未验证'
    return (note + '-' if note else '') + f'{prefix}-{port}-{protocol}'
