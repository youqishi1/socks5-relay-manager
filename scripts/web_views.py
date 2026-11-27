"""Small server-rendered views. All stored values are HTML-escaped."""
from html import escape
from pathlib import Path

from access import share_links, system_trust
from entrance_profiles import PROFILES, profile
from exit_location import label

VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text(encoding='utf-8').strip()


def page(title, body, csrf='', layout=''):
    logout = (f'<form action="/logout" method="post">{hidden("csrf", csrf)}'
              '<button class="subtle" type="submit">退出后台</button></form>') if csrf else ''
    return f'''<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} · SOCKS5 中转管理</title><link rel="stylesheet" href="/style.css?v={VERSION}">
<link rel="icon" type="image/png" href="/icon.png?v={VERSION}"><script defer src="/app.js?v={VERSION}"></script>
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
<p class="muted">输入后台密码。需要设置或修改时，在 VPS 运行 <code>sb1 web-password</code>。</p>{alert(error)}
<form action="/login" method="post">{hidden('next', destination)}
<label for="password">后台密码</label>
<input id="password" type="password" name="password" autocomplete="current-password" required autofocus maxlength="256">
<button class="wide" type="submit">登录</button></form></section>''', layout='narrow login-layout')


def exit_text(row, locations, checked=()):
    ip, country = locations.get(row['port'], ('', ''))
    if ip:
        return (country or '地区未知') + ' · ' + ip
    return '检测失败' if row['port'] in checked else '出口未检测'


def topology(row):
    return ('共享' if row.get('shared') else '独立') if row.get('access') else '原生 SOCKS5'


def has_qr(row):
    front = row.get('access') or {}
    return row['enabled'] and system_trust(front) and profile(front) != 'hysteria2-only'


def copy_buttons(row, links):
    if not links:
        return ''
    buttons = []
    variants = [('ss', '复制 SS'), ('hy2', '复制 HY2')]
    variants.append(('tuic', '复制 TUIC') if system_trust(row.get('access', {}))
                    else ('tuic_v2rayn', '复制 TUIC · v2rayN'))
    for key, caption in variants:
        if key in links:
            buttons.append(f'<button class="small secondary" type="button" data-share-kind="{key}" data-share="{text(links[key])}">{caption}</button>')
    return ''.join(buttons)


def activity_status(value):
    count, recent = value['connections'], value['recent']
    text_status = '连接状态未读到' if count is None else ('有连接（' + str(count) + '）' if count else '当前未见连接')
    recent_status = '最近转发 ' + recent if recent else '近期日志未见转发'
    return f'<small class="activity-now">{text(text_status)}</small><small>{text(recent_status)}</small>'


def index(rows, locations, csrf, address=None, warning='', checked=(), activity=None):
    entries = []
    has_links = False
    for row in rows:
        port = row['port']
        front = row.get('access')
        upstream = text(row['upstream_host']) + ':' + text(row['upstream_port'])
        status = '已启用' if row['enabled'] else '已停用'
        entry_port = str(front['port']) if front else '—'
        qr_link = f'<a class="button small secondary" href="/nodes/{port}/qr">二维码</a>' if has_qr(row) else ''
        copies = copy_buttons(row, share_links(row, address, locations)) if address else ''
        has_links = has_links or bool(copies)
        observed = activity_status(activity[port]) if activity is not None and port in activity else ''
        detect = (f'<button type="button" class="small secondary" data-detect="/nodes/{port}/detect">检测</button>'
                  if row['enabled'] else '')
        note = row.get('note', '')
        entries.append(f'''<tr data-exit-ready="{'yes' if locations.get(port, ('', ''))[0] else 'no'}">
<td data-label="中转"><a class="entry" href="/nodes/{port}">{port}</a>
<small>{text(PROFILES[profile(front)]) if front else '原生 SOCKS5'}</small>
<span class="node-note" data-node-note{'' if note else ' hidden'}>{text(note)}</span>
<details class="note-editor"><summary>改备注</summary>
<form method="post" action="/nodes/{port}/note" data-note>
{hidden('csrf', csrf)}
<label class="sr-only" for="note-{port}">中转 {port} 的备注</label>
<input id="note-{port}" name="note" value="{text(note)}" maxlength="32" placeholder="留空清除备注" autocomplete="off">
<button class="small secondary" type="submit">保存</button>
</form></details><small class="note-status" data-note-status role="status" hidden></small></td>
<td data-label="入口端口" class="mono">{entry_port}</td>
<td data-label="当前上游" class="mono">{upstream}</td>
<td data-label="实测出口"><span data-exit-result>{text(exit_text(row, locations, checked))}</span>{detect}</td>
<td data-label="模式 / 状态">{topology(row)}<small class="state">{status}</small>{observed}</td>
<td class="actions" data-label="操作"><div class="buttons row-actions">{copies}{qr_link}<a class="button small secondary" href="/nodes/{port}/edit">修改</a></div></td>
</tr>''')
    table = ('''<div class="table"><table aria-label="中转列表"><thead><tr><th scope="col">中转</th>
<th scope="col">入口端口</th><th scope="col">当前上游</th><th scope="col">实测出口</th>
<th scope="col">模式 / 状态</th><th scope="col">操作</th></tr></thead>'''
             + f'<tbody id="relay-rows" data-csrf="{text(csrf)}">'
             + ''.join(entries) + '</tbody></table><p class="empty" id="filter-empty" hidden>没有匹配的中转。</p></div>'
             if rows else '<p class="empty panel">还没有中转。点击「添加中转」开始。</p>')
    search = ('<label class="sr-only" for="search">搜索中转</label><input id="search" class="search" '
              'type="search" placeholder="搜索编号、备注、地址或地区" autocomplete="off">') if rows else ''
    copy_all = '<button class="secondary" type="button" id="copy-list">复制当前列表链接</button>' if has_links else ''
    can_detect = any(row['enabled'] for row in rows)
    detect_all = '<button class="secondary" type="button" id="detect-missing">检测未测出口</button>' if can_detect else ''
    usage = ''
    usage_hint = ''
    if rows:
        usage = '<a class="button secondary" href="/?activity=1">查看使用情况</a>'
        if activity is not None:
            usage = ('<a class="button secondary" href="/?activity=1">刷新使用情况</a>'
                     '<a class="button subtle" href="/">隐藏使用情况</a>')
            usage_hint = '<p class="muted activity-hint">连接为本次快照。最近转发取自当前日志尾部，含检测流量，时间以 VPS 为准。</p>'
    detect_result = '<p id="detect-status" class="muted copy-status" role="status" hidden></p>' if can_detect else ''
    copy_result = ('''<p id="copy-status" class="muted copy-status" role="status" hidden></p>
<textarea id="copy-fallback" rows="3" readonly aria-label="待复制的节点链接" hidden></textarea>''' if has_links else '')
    return page('中转列表', f'''<div class="heading"><div><h1>中转列表</h1><p class="muted">{len(rows)} 条中转</p></div>
<div class="buttons">{usage}{detect_all}{copy_all}<a class="button" href="/add"><span aria-hidden="true">＋</span> 添加中转</a></div></div>
{alert(warning)}{search}{detect_result}{copy_result}{usage_hint}{table}''', csrf)


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
<h1>{title}</h1>{alert(error)}<form method="post" action="{target}" data-save="正在验证并保存…">{hidden('csrf', csrf)}
<label for="upstream">完整 SOCKS5</label>
<input id="upstream" name="upstream" type="password" autocomplete="new-password" maxlength="2048" {"required" if not row else ""} aria-describedby="upstream-help">
<p id="upstream-help" class="muted field-note">{helper}</p>{mode}
<div class="buttons"><button type="submit">保存中转</button><a class="button secondary" href="{back}">取消</a></div>
</form></section>''', csrf, 'form-layout')


def detail(row, locations, shares, warning, csrf, checked=()):
    port, front = row['port'], row.get('access')
    base = '/nodes/' + str(port)
    actions = f'<a class="button secondary" href="{base}/edit">修改</a>'
    if has_qr(row):
        actions += f'<a class="button" href="{base}/qr">查看 TUIC 二维码</a>'
    detect = ''
    if row['enabled']:
        detect = (f'<form method="post" action="{base}/detect" data-save="正在检测…">{hidden("csrf", csrf)}'
                  '<button class="secondary small" type="submit">检测出口</button></form>')
    upstream = text(row['upstream_host']) + ':' + text(row['upstream_port'])
    fields = f'''<dl><div><dt>当前上游</dt><dd class="mono">{upstream}</dd></div>
<div><dt>入口 / 模式</dt><dd>{text(front['port']) if front else '—'} / {topology(row)}</dd></div>
<div><dt>配置状态</dt><dd>{'已启用' if row['enabled'] else '已停用'}</dd></div>
<div><dt>实测出口</dt><dd>{text(exit_text(row, locations, checked))}</dd></div>
{'<div><dt>备注</dt><dd>' + text(row['note']) + '</dd></div>' if row.get('note') else ''}</dl>
<details class="credentials"><summary>查看本机 SOCKS5 账密</summary><dl>
<div><dt>监听地址</dt><dd class="mono">{text(row['bind'])}:{port}</dd></div>
<div><dt>账号</dt><dd>{text(row['client_user'])}</dd></div>
<div><dt>密码</dt><dd class="mono">{text(row['client_password'])}</dd></div></dl></details>'''
    links = []
    quick = '\n'.join(shares[key] for key in ('ss', 'tuic_v2rayn', 'hy2') if key in shares)
    for index, (caption, value) in enumerate((('v2rayN 导入链接', quick),
                                              ('TUIC 普通链接', shares.get('tuic', '')),
                                              ('Hysteria 2 普通链接', shares.get('hy2', '')))):
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
    name = label(port, 'TUIC', locations, row.get('note', ''))
    return page('TUIC 二维码', f'''<a class="back" href="/nodes/{port}">← 返回中转详情</a>
<section class="panel qr"><h1>TUIC 二维码</h1><p class="muted">{text(name)}</p>
<img class="qr-image" src="/nodes/{port}/qr.png" alt="中转 {port} 的 TUIC 二维码" width="300" height="300">
<p class="muted">用小火箭扫描此二维码。</p></section>''', csrf, 'narrow')
