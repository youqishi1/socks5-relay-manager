"""Find HTTP-01 roots by configuration hints and an actual domain HTTP proof.

Configuration parsing supplies candidates only: the web server, not this parser,
decides which root serves the domain. Never reload or edit a web server.
"""
from contextlib import ExitStack, contextmanager
import glob
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import subprocess
import tempfile

from access import AccessError, domain_name

CONFIGS = (
    '/etc/nginx/nginx.conf', '/etc/nginx/conf.d/*', '/etc/nginx/sites-enabled/*',
    '/usr/local/nginx/conf/nginx.conf', '/www/server/nginx/conf/nginx.conf',
    '/www/server/panel/vhost/nginx/*.conf',
    '/etc/apache2/apache2.conf', '/etc/apache2/sites-enabled/*',
    '/etc/httpd/conf/httpd.conf', '/etc/httpd/conf.d/*.conf',
    '/www/server/apache/conf/httpd.conf', '/www/server/panel/vhost/apache/*.conf',
)


def directives(text):
    """Read literal root/include hints, ignoring comments and quoted delimiters."""
    # shlex's built-in comments consume the newline, which would merge two
    # Apache directives. Strip comments while retaining quoted text/newlines.
    text = re.sub(r'''("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\\.)|\#[^\n]*''',
                  lambda match: match.group(1) or '', text)
    lexer = shlex.shlex(text, posix=True, punctuation_chars=';{}\n')
    lexer.commenters = ''
    lexer.whitespace = ' \t\r'
    lexer.whitespace_split = True
    item = []
    for token in lexer:
        if token and all(c in ';{}\n' for c in token):
            if token.strip('\n') == '' and len(item) == 1 and item[0].lower() in (
                    'root', 'documentroot', 'include', 'includeoptional', 'serverroot'):
                continue  # nginx permits a literal argument on the next line.
            if item:
                yield item
            item = []
        else:
            item.append(token)
    if item:
        yield item


def candidates(domain, patterns=CONFIGS):
    domain_name(domain)
    queue = [(Path(name), None) for pattern in patterns for name in sorted(glob.glob(pattern))]
    seen, roots, total = set(), [], 0
    # Bound file reads and include expansion; never walk website contents.
    for path, base in queue:
        if len(seen) >= 512 or total >= 8 * 1024 * 1024:
            break
        try:
            path = path.resolve(strict=True)
            if path in seen or not path.is_file() or path.stat().st_size > 1024 * 1024:
                continue
            seen.add(path)
            text = path.read_text(encoding='utf-8', errors='replace')
            total += len(text)
            base = base or path.parent
            entries = list(directives(text))
        except (OSError, ValueError):
            continue
        # Apache's ServerRoot resolves relative includes; nginx uses its main
        # config directory. Files included from a main config keep that base.
        for item in entries:
            if len(item) == 2 and item[0].lower() == 'serverroot' and Path(item[1]).is_absolute():
                base = Path(item[1])
        for item in entries:
            if len(item) != 2 or '$' in item[1] or '\x00' in item[1]:
                continue
            name, value = item[0].lower(), item[1]
            if name in ('root', 'documentroot') and Path(value).is_absolute():
                priority = 0 if domain in text.lower() else 1
                roots.append((priority, value))
            elif name in ('include', 'includeoptional'):
                pattern = value if Path(value).is_absolute() else str(base / value)
                queue.extend((Path(found), base) for found in sorted(glob.glob(pattern))[:512])
    roots.extend((2, path) for path in ('/www/wwwroot/' + domain, '/var/www/' + domain,
                                       '/var/www/html', '/usr/share/nginx/html'))
    result = []
    for _, value in sorted(roots, key=lambda row: row[0]):
        try:
            root = Path(value).resolve(strict=True)
            if root.is_dir() and root != Path(root.anchor) and str(root) not in result:
                result.append(str(root))
        except (OSError, ValueError):
            continue
        if len(result) >= 32:
            break
    return result


def port_free(port=80):
    try:
        with socket.socket() as check:
            if os.name == 'posix':
                check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            elif hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                check.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            check.bind(('0.0.0.0', port))
        return True
    except OSError:
        return False


@contextmanager
def challenge(root, name, content):
    """Stage only a new random public token; keep existing files/permissions.

    Linux directory descriptors prevent symlink replacement redirecting writes
    or cleanup. The Windows branch is used only by local fixture tests.
    """
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or root == Path(root.anchor):
        raise OSError('Not a website directory')
    if os.name == 'posix':
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        handles, made, written = [os.open(root, flags)], [], False
        try:
            for part in ('.well-known', 'acme-challenge'):
                parent = handles[-1]
                created = False
                try:
                    os.mkdir(part, mode=0o755, dir_fd=parent)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=parent)
                handles.append(child)
                if created:
                    os.fchmod(child, 0o755)
                    made.append((parent, part, os.fstat(child).st_ino))
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o644, dir_fd=handles[-1])
            written = True
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(content)
            yield
        finally:
            if written:
                os.unlink(name, dir_fd=handles[-1])
            for parent, part, inode in reversed(made):
                try:
                    if os.stat(part, dir_fd=parent, follow_symlinks=False).st_ino == inode:
                        os.rmdir(part, dir_fd=parent)
                except OSError:
                    pass  # Existing/concurrently created website contents stay.
            for handle in reversed(handles):
                os.close(handle)
    else:
        made, target, written = [], root, False
        try:
            for part in ('.well-known', 'acme-challenge'):
                target /= part
                if target.is_symlink():
                    raise OSError('Symlink challenge directory')
                if not target.exists():
                    target.mkdir(mode=0o755)
                    made.append(target)
                if not target.is_dir():
                    raise OSError('Not a challenge directory')
            target /= name
            with target.open('xb') as stream:
                written = True
                stream.write(content)
            yield
        finally:
            if written:
                target.unlink()
            for directory in reversed(made):
                try:
                    directory.rmdir()
                except OSError:
                    pass


def fetch(domain, name, port=80):
    """Use bounded curl timeouts, no proxy and no redirects/authentication."""
    with tempfile.TemporaryDirectory(prefix='relay-webroot-check-') as folder:
        body = Path(folder) / 'response'
        url = f'http://{domain}:{port}/.well-known/acme-challenge/{name}'
        try:
            result = subprocess.run(['curl', '-q', '--noproxy', '*', '--proto', '=http',
                '--connect-timeout', '3', '--max-time', '8', '--max-filesize', '512',
                '-sS', '-o', str(body), '-w', '%{http_code}', url],
                capture_output=True, timeout=10)
            status = result.stdout.decode('ascii', errors='replace').strip()
            if result.returncode:
                raise AccessError('域名 HTTP 验证请求失败：检查 A/AAAA 解析、TCP 80 和云安全组。')
            if status != '200':
                raise AccessError('域名验证路径返回 HTTP ' + status +
                    '；请让 /.well-known/acme-challenge/ 可直接访问，排除重定向、反向代理或访问限制。')
            with body.open('rb') as stream:
                return stream.read(513)
        except (OSError, subprocess.TimeoutExpired):
            raise AccessError('域名 HTTP 验证请求失败：检查 A/AAAA 解析、TCP 80 和云安全组。') from None


def detect(domain, preferred='', port=80, roots=None):
    domain_name(domain)
    if port_free(port):
        print('80 端口空闲，自动使用独立 HTTP 验证，无需网站根目录。')
        return ''
    choices = ([preferred] if preferred else []) + (candidates(domain) if roots is None else roots)
    name = 'sb1-check-' + secrets.token_hex(24)
    staged, seen = {}, set()
    with ExitStack() as stack:
        for choice in choices[:33]:
            try:
                root = str(Path(choice).resolve(strict=True))
                if root in seen:
                    continue
                seen.add(root)
                content = ('sb1-webroot-' + secrets.token_hex(24)).encode('ascii')
                stack.enter_context(challenge(root, name, content))
                staged[content] = root
            except (OSError, ValueError):
                continue
        if not staged:
            raise AccessError('80 端口已占用，未找到可验证的网站目录。支持宝塔/Nginx/Apache；'
                '容器或纯反向代理网站需提供可公开访问的 HTTP-01 目录。')
        content = fetch(domain, name, port)
        if content not in staged:
            raise AccessError('域名没有返回本机验证文件：检查解析是否指向此 VPS，'
                '以及网站的反向代理、验证目录映射和访问规则。')
        root = staged[content]
    print('已自动识别并通过域名 HTTP 验证：' + root)
    return root
