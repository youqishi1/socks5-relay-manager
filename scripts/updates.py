"""Select and install verified, published releases without asking for a tag."""
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

REPO = 'youqishi1/socks5-relay-manager'
API = 'https://api.github.com/repos/' + REPO
TAG = re.compile(r'v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z')
MAX_ARCHIVE = 16 * 1024 * 1024


class UpdateError(Exception):
    pass


class SecureRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        if not url.startswith('https://'):
            raise UpdateError('下载重定向不是 HTTPS，已停止。')
        return super().redirect_request(request, response, code, message, headers, url)


def open_url(url):
    request = urllib.request.Request(url, headers={
        'User-Agent': 'socks5-relay-manager', 'Accept': 'application/vnd.github+json'})
    return urllib.request.build_opener(SecureRedirect()).open(request, timeout=20)


def metadata(path):
    for attempt in range(3):
        try:
            with open_url(API + path) as response:
                data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise UpdateError('版本列表过大，已停止。')
            return json.loads(data)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                raise UpdateError('GitHub 查询受限，请稍后重试；现有节点不受影响。') from None
            if exc.code == 404:
                raise UpdateError('未找到可用的正式版本。') from None
        except (OSError, ValueError):
            pass
        if attempt < 2:
            time.sleep(attempt + 1)
    raise UpdateError('查询版本失败，请检查 VPS 的 DNS 和 GitHub 连接，稍后重试。')


def release(value):
    if not isinstance(value, dict) or value.get('draft') or value.get('prerelease'):
        return None
    tag = value.get('tag_name', '')
    if not isinstance(tag, str) or not TAG.fullmatch(tag):
        return None
    name = 'socks5-relay-manager-' + tag + '-install.tar.gz'
    expected = 'https://github.com/' + REPO + '/releases/download/' + tag + '/' + name
    assets = value.get('assets')
    if not isinstance(assets, list):
        return None
    for asset in assets:
        if not isinstance(asset, dict) or asset.get('name') != name:
            continue
        digest, size = asset.get('digest', ''), asset.get('size')
        if (not isinstance(digest, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest)
                or type(size) is not int or not 0 < size <= MAX_ARCHIVE
                or asset.get('browser_download_url') != expected):
            return None
        return {'tag': tag, 'url': expected, 'sha256': digest[7:], 'size': size}
    return None


def releases():
    result = []
    # At most 100 releases; fetch pages only while populated to bound API usage.
    for page in range(1, 5):
        values = metadata('/releases?per_page=25&page=' + str(page))
        if not isinstance(values, list):
            raise UpdateError('GitHub 版本列表格式无效。')
        for value in values:
            item = release(value)
            if item and item['tag'] not in {r['tag'] for r in result}:
                result.append(item)
        if len(values) < 25:
            break
    return sorted(result, key=lambda r: tuple(map(int, r['tag'][1:].split('.'))), reverse=True)


def latest():
    result = release(metadata('/releases/latest'))
    if not result:
        raise UpdateError('最新版缺少可校验的正式安装包，已取消更新。')
    return result


def download(item, cache):
    cache = Path(cache)
    if cache.is_symlink():
        raise UpdateError('下载缓存不能是符号链接。')
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    cache.chmod(0o700)
    target = cache / item['sha256']
    if target.is_file() and not target.is_symlink() and target.stat().st_size == item['size']:
        if hashlib.sha256(target.read_bytes()).hexdigest() == item['sha256']:
            print('复用已校验的安装包缓存。')
            return target
    for attempt in range(3):
        fd, name = tempfile.mkstemp(prefix='.update-', dir=cache)
        try:
            count, digest, deadline = 0, hashlib.sha256(), time.monotonic() + 300
            with os.fdopen(fd, 'wb') as output, open_url(item['url']) as response:
                while True:
                    if time.monotonic() > deadline:
                        raise OSError('download timeout')
                    block = response.read(65536)
                    if not block:
                        break
                    count += len(block)
                    if count > item['size']:
                        raise UpdateError('安装包大小异常，未执行。')
                    output.write(block)
                    digest.update(block)
                output.flush()
                os.fsync(output.fileno())
            if count != item['size']:
                raise OSError('incomplete download')
            if digest.hexdigest() != item['sha256']:
                raise UpdateError('安装包 SHA-256 校验失败，未执行。')
            os.replace(name, target)
            return target
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            if attempt == 2:
                raise UpdateError('下载更新失败；现有版本和节点保留，请稍后重试。') from None
            print('下载中断，正在重试...')
            time.sleep(attempt + 1)
        finally:
            Path(name).unlink(missing_ok=True)
    raise UpdateError('更新下载未完成。')


def unpack(archive, folder, tag):
    folder = Path(folder)
    try:
        with tarfile.open(archive, 'r:gz') as source:
            seen, total, count = set(), 0, 0
            for member in source:
                total += member.size
                count += 1
                if count > 1000 or total > 32 * 1024 * 1024:
                    raise UpdateError('安装包展开大小异常。')
                path = PurePosixPath(member.name)
                if (not member.name or path.is_absolute() or '..' in path.parts or '\\' in member.name or ':' in member.name
                        or any(ord(c) < 32 for c in member.name) or member.name in seen
                        or not (member.isfile() or member.isdir())):
                    raise UpdateError('安装包包含不安全路径或文件类型。')
                seen.add(member.name)
                destination = folder.joinpath(*path.parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with source.extractfile(member) as data, destination.open('xb') as output:
                    shutil.copyfileobj(data, output)
                destination.chmod(0o700 if member.name.endswith('.sh') else 0o600)
        for required in ('VERSION', 'install.sh', 'scripts/manager.py', 'socks-menu.sh', 'uninstall.sh', 'systemd/socks-relay@.service'):
            if not (folder / required).is_file():
                raise UpdateError('安装包缺少必要文件。')
        if (folder / 'VERSION').read_text().strip() != tag[1:]:
            raise UpdateError('安装包版本与所选版本不符。')
    except (OSError, tarfile.TarError, UnicodeError):
        raise UpdateError('安装包无法安全展开，现有程序未修改。') from None


def install(manager, item, app):
    app = Path(app)
    archive = download(item, app / 'cache/downloads')
    with tempfile.TemporaryDirectory(prefix='socks-relay-update-') as temporary:
        folder = Path(temporary)
        folder.chmod(0o700)
        unpack(archive, folder, item['tag'])
        # Check the selected old parser before it can replace services/configuration.
        probe = 'import sys;sys.path.insert(0,sys.argv[1]);from manager import Manager;Manager().rows()'
        try:
            result = subprocess.run([sys.executable, '-c', probe, str(folder / 'scripts')],
                                    capture_output=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            raise UpdateError('目标版本的配置兼容检查未完成，已取消。') from None
        if result.returncode:
            raise UpdateError('所选旧版本不能读取当前配置，已取消；请保留当前版本或选择较新的历史版本。')
        with manager.lock():
            manager.backup()
        environment = dict(os.environ)
        # Resolve first: old installers must not produce a self-referencing python3 link.
        executable = Path(sys.executable).resolve()
        environment['PATH'] = str(executable.parent) + os.pathsep + environment.get('PATH', '/usr/bin:/bin')
        environment['SOCKS_REPO_REF'] = item['tag']
        archive_config = app / 'apt-compat/apt.conf'
        if archive_config.is_file() and 'APT_CONFIG' not in environment:
            environment['APT_CONFIG'] = str(archive_config)
        result = subprocess.run(['bash', str(folder / 'install.sh'), '--local'], env=environment)
        if result.returncode:
            raise UpdateError('安装未完成；请查看上方错误。原有配置已备份，安装器会尝试回滚。')


def menu(manager, app, ask, confirm):
    app = Path(app)
    try:
        current = (app / 'current/VERSION').read_text().strip()
        print('当前版本：v' + current + '\n1. 更新到最新稳定版\n2. 选择历史版本 / 重新安装\n0. 返回')
        option = ask('请选择更新方式')
        if option == '0':
            return False
        if option == '1':
            print('正在查询最新稳定版...')
            item = latest()
            if item['tag'] == 'v' + current:
                print('当前已经是最新稳定版：' + item['tag'] + '。需要修复安装可选择历史版本列表中的当前版本。')
                return False
        elif option == '2':
            print('正在查询正式版本列表（排除草稿、测试版和无法校验的安装包）...')
            choices = releases()
            if not choices:
                raise UpdateError('没有可用的正式安装包。')
            for index, choice in enumerate(choices, 1):
                print(str(index) + '. ' + choice['tag'] + ('（当前版本）' if choice['tag'] == 'v' + current else ''))
            print('0. 返回')
            selected = ask('请选择版本编号')
            if selected == '0':
                return False
            if not selected.isdecimal() or not 1 <= int(selected) <= len(choices):
                raise UpdateError('版本编号无效。')
            item = choices[int(selected) - 1]
        else:
            raise UpdateError('请选择 0、1 或 2。')
        print('准备安装：v' + current + ' → ' + item['tag'] + '。回退旧版可能缺少新功能，将先检查配置兼容性。')
        if not confirm('安装前自动备份，是否继续？'):
            return False
        install(manager, item, app)
        print('版本安装完成：' + item['tag'] + '。请执行 sb1 重新打开菜单。')
        return True
    except (OSError, UnicodeError):
        raise UpdateError('无法读取当前版本或启动安装器，现有配置保留。') from None
