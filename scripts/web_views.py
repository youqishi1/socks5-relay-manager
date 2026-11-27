"""Small server-rendered views. All stored values are HTML-escaped."""
from html import escape

from access import system_trust
from entrance_profiles import PROFILES, profile
from exit_location import label


def page(title, body, csrf='', layout=''):
    logout = (f'<form action="/logout" method="post">{hidden("csrf", csrf)}'
              '<button class="subtle" type="submit">退出后台</button></form>') if csrf else ''
    return f'''<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} · SOCKS5 中转管理</title><link rel="stylesheet" href="/style.css">
<link rel="icon" type="image/png" href="/icon.png"><script defer src="/app.js"></script>
<header><div class="bar"><a class="brand" href="/"><img src="/icon.png" width="36" height="36" alt="">
<span>SOCKS5 中转管理</span></a>{logout}</div></header>
<main class="{layout}">{body}</main></html>'''


def hidden(name, value):
    return f'<input type="hidden" name="{name}" value="{escape(value)}">'


def alert(message):
    return f'<p class="warning" role="alert">{escape(message)}</p>' if message else ''


def text(value):
    return escape(str(value))


def notice(status, message, csrf=''):
    return page('操作提示', f'<section class="panel"><h1>操作提示</h1>{alert(message)}'
                '<a class="button secondary" href="/">返回后台</a></section>', csrf, 'narrow')


def login(destination, error=''):
    return page('登录', f'''<section class="panel login"><h1>登录管理后台</h1>
<p class="muted">输入你在 VPS 上设置的后台密码。</p>{alert(error)}
<form action="/login" method="post">{hidden('next', destination)}
<label for="password">后台密码</label>
<input id="password" type="password" name="password" autocomplete="current-password" required autofocus maxlength="256">
<button class="wide" type="submit">登录</button></form></section>''', layout='narrow login-layout')


def exit_text(row, locations):
    ip, country = locations.get(row['port'], ('', ''))
    return ((country or '地区未知') + ' · ' + ip) if ip else '出口未检测'


def topology(row):
    return ('共享' if row.get('shared') else '独立') if row.get('access') else '原生 SOCKS5'


def has_qr(row):
    front = row.get('access', {})
    return row['enabled'] and system_trust(front) and profile(front) != 'hysteria2-only'


def index(rows, locations, csrf):
    entries = []
    for row in rows:
        port = row['port']
        front = row.get('access')
        upstream = text(row['upstream_host']) + ':' + text(row['upstream_port'])
        status = '已启用' if row['enabled'] else '已停用'
        entry_port = str(front['port']) if front else '—'
        qr_link = f'<a class="button small secondary" href="/nodes/{port}/qr">二维码</a>' if has_qr(row) else ''
        entries.append(f'''<tr>
<td data-label="中转"><a class="entry" href="/nodes/{port}">{port}</a><small>{text(PROFILES[profile(front)]) if front else '原生 SOCKS5'}</small></td>
<td data-label="入口端口" class="mono">{entry_port}</td>
<td data-label="当前上游" class="mono">{upstream}</td>
<td data-label="实测出口">{text(exit_text(row, locations))}</td>
<td data-label="模式 / 状态">{topology(row)}<small class="state">{status}</small></td>
<td class="actions" data-label="操作">{qr_link}<a class="button small secondary" href="/nodes/{port}/edit">修改</a></td>
</tr>''')
    table = ('''<div class="table"><table aria-label="中转列表"><thead><tr><th scope="col">中转</th>
<th scope="col">入口端口</th><th scope="col">当前上游</th><th scope="col">实测出口</th>
<th scope="col">模式 / 状态</th><th scope="col">操作</th></tr></thead><tbody id="relay-rows">'''
             + ''.join(entries) + '</tbody></table><p class="empty" id="filter-empty" hidden>没有匹配的中转。</p></div>'
             if rows else '<p class="empty panel">还没有中转。点击「添加中转」开始。</p>')
    search = ('<label class="sr-only" for="search">搜索中转</label><input id="search" class="search" '
              'type="search" placeholder="搜索中转编号、地址或地区" autocomplete="off">') if rows else ''
    return page('中转列表', f'''<div class="heading"><div><h1>中转列表</h1><p class="muted">{len(rows)} 条中转</p></div>
<a class="button" href="/add"><span aria-hidden="true">＋</span> 添加中转</a></div>{search}{table}''', csrf)


def edit(row, csrf, error=''):
    port = row['port'] if row else None
    title = '修改中转 ' + str(port) if row else '添加中转'
    selected = 'independent' if row and not row.get('shared') else 'shared'
    mode = ''
    if not row or row.get('access'):
        options = ''.join(f'<option value="{key}"{" selected" if key == selected else ""}>{name}</option>'
                          for key, name in (('shared', '共享 sing-box'), ('independent', '独立 sing-box')))
        mode = f'''<label for="mode">运行方式</label><select id="mode" name="mode">{options}</select>
<p class="muted field-note">加入或修改共享组时，组内连接可能短暂断开。</p>'''
    helper = '留空保留当前上游。需替换时，粘贴新 SOCKS5 的完整信息。' if row else '支持 IP:端口:账号:密码 或 socks5:// 链接。'
    target = '/nodes/' + str(port) + '/edit' if row else '/add'
    back = '/nodes/' + str(port) if row else '/'
    return page(title, f'''<a class="back" href="{back}">← 返回</a><section class="panel">
<h1>{title}</h1>{alert(error)}<form method="post" action="{target}" data-save>{hidden('csrf', csrf)}
<label for="upstream">完整 SOCKS5</label>
<input id="upstream" name="upstream" type="password" autocomplete="new-password" maxlength="2048" {"required" if not row else ""} aria-describedby="upstream-help">
<p id="upstream-help" class="muted field-note">{helper}</p>{mode}
<div class="buttons"><button type="submit">保存中转</button><a class="button secondary" href="{back}">取消</a></div>
</form></section>''', csrf, 'form-layout')


def detail(row, locations, exports, warning, csrf):
    port, front = row['port'], row.get('access')
    base = '/nodes/' + str(port)
    actions = f'<a class="button secondary" href="{base}/edit">修改</a>'
    if has_qr(row):
        actions += f'<a class="button" href="{base}/qr">查看 TUIC 二维码</a>'
    detect = ''
    if front and row['enabled']:
        detect = (f'<form method="post" action="{base}/detect" data-save>{hidden("csrf", csrf)}'
                  '<button class="secondary small" type="submit">检测出口</button></form>')
    upstream = text(row['upstream_host']) + ':' + text(row['upstream_port'])
    fields = f'''<dl><div><dt>当前上游</dt><dd class="mono">{upstream}</dd></div>
<div><dt>入口 / 模式</dt><dd>{text(front['port']) if front else '—'} / {topology(row)}</dd></div>
<div><dt>配置状态</dt><dd>{'已启用' if row['enabled'] else '已停用'}</dd></div>
<div><dt>实测出口</dt><dd>{text(exit_text(row, locations))}</dd></div></dl>
<details class="credentials"><summary>查看本机 SOCKS5 账密</summary><dl>
<div><dt>监听地址</dt><dd class="mono">{text(row['bind'])}:{port}</dd></div>
<div><dt>账号</dt><dd>{text(row['client_user'])}</dd></div>
<div><dt>密码</dt><dd class="mono">{text(row['client_password'])}</dd></div></dl></details>'''
    links = []
    for index, (caption, name) in enumerate((('v2rayN 导入链接', 'v2rayN-一键导入.txt'),
                                              ('TUIC 普通链接', 'TUIC-普通链接.txt'),
                                              ('Hysteria 2 普通链接', 'HY2-普通链接.txt'))):
        value = exports.get(name, '').strip()
        if value:
            field = 'copy-' + str(index)
            links.append(f'''<div class="link-area"><div class="link-title"><label for="{field}">{caption}</label>
<button class="subtle small" type="button" data-copy="{field}">复制</button></div>
<textarea id="{field}" rows="2" readonly>{text(value)}</textarea></div>''')
    details = (f'<section class="panel"><h2>连接链接</h2>{"".join(links)}</section>') if links else ''
    return page('中转 ' + str(port), f'''<a class="back" href="/">← 返回中转列表</a>
<div class="heading"><h1>中转 {port}</h1><div class="buttons">{actions}</div></div>
<section class="panel"><div class="section-heading"><h2>中转信息</h2>{detect}</div>{fields}{alert(warning)}</section>{details}''',
                csrf, 'detail-layout')


def qr(row, locations, csrf):
    port = row['port']
    name = label(port, 'TUIC', locations)
    return page('TUIC 二维码', f'''<a class="back" href="/nodes/{port}">← 返回中转详情</a>
<section class="panel qr"><h1>TUIC 二维码</h1><p class="muted">{text(name)}</p>
<img class="qr-image" src="/nodes/{port}/qr.png" alt="中转 {port} 的 TUIC 二维码" width="300" height="300">
<p class="muted">用小火箭扫描此二维码。</p></section>''', csrf, 'narrow')
