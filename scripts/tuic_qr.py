"""Private, offline TUIC QR sharing; no network or image-library dependency."""
import struct
import zlib

from access import AccessError, share_links, system_trust, validate, validate_export_address
from qrcodegen import QrCode

BORDER = 4


def build(row, address, locations=None):
    front = row.get('access') or {}
    if front.get('profile') == 'hysteria2-only':
        raise AccessError('当前已切换为 Hysteria 2，未启用 TUIC；请用菜单 16 的 HY2 普通链接导入。')
    if not system_trust(front):
        raise AccessError('手机扫码请先用菜单 22 配置域名公共 CA 证书；自签证书不能只靠普通链接完成信任。')
    validate(front)
    validate_export_address(address)
    link = share_links(row, address, locations).get('tuic')
    if not link:
        raise AccessError('请先启用此节点的 TUIC 入口。')
    if not row.get('note') and (locations is None or row['port'] not in locations):
        link = link.split('#', 1)[0] + '#TUIC-' + str(row['port'])
    return link, QrCode.encode_text(link, QrCode.Ecc.MEDIUM)


def _black(code, x, y):
    return code.get_module(x - BORDER, y - BORDER)


def png(code, scale=4):
    """Lossless grayscale PNG with an intact four-module quiet zone."""
    if type(scale) is not int or not 2 <= scale <= 16:
        raise ValueError('二维码缩放无效。')
    modules = code.get_size() + BORDER * 2
    size = modules * scale
    raw = bytearray()
    for y in range(modules):
        scanline = b'\x00' + b''.join((b'\x00' if _black(code, x, y) else b'\xff') * scale for x in range(modules))
        raw.extend(scanline * scale)

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)

    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 0, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(bytes(raw), 9)) + chunk(b'IEND', b''))


def terminal(code):
    """Two QR rows per terminal line; fixed white background on dark themes."""
    size = code.get_size() + BORDER * 2
    glyphs = {(False, False): ' ', (True, False): '▀', (False, True): '▄', (True, True): '█'}
    lines = []
    for y in range(0, size, 2):
        line = ''.join(glyphs[(_black(code, x, y), _black(code, x, y + 1))] for x in range(size))
        lines.append('\x1b[30;107m' + line + '\x1b[0m')
    return '\n'.join(lines)
