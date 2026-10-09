#!/usr/bin/env bash
# Private repositories: run through authenticated gh api, or clone then --local.
set -Eeuo pipefail
trap 'echo "错误：安装步骤失败，请检查上方的软件源、网络或文件权限错误。" >&2' ERR
umask 077
REPO='youqishi1/socks5-relay-manager'
REF="${SOCKS_REPO_REF:-v1.1.0}"
CORE_COMMIT='da99424eac4092e3722f1a5b1844cfe80478f580'
CORE_SHA256='9541e866d9ce04d051b07aa7b7c23bf717c5bc5ef7a9f07963e31a139038faeb'
CORE_VERSION='0.9.9.0'
APP='/opt/socks5-relay-manager'
STATE='/etc/socks5-relay-manager'
LOG='/var/log/socks5-relay-manager'
stage=''
old_release=''
switched=0
completed=0
local_mode=0
if [[ ${1:-} == --local && $# == 1 ]]; then
    local_mode=1
elif (( $# )); then
    echo '错误：只接受 --local（安装当前目录源码）或无参数。' >&2
    exit 1
fi
if (( EUID != 0 )); then
    echo '错误：请以 root 运行安装命令。' >&2
    exit 1
fi
if [[ ! -f /etc/os-release ]]; then
    echo '错误：无法识别系统版本。' >&2
    exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
    ubuntu|debian) ;;
    *) echo '错误：当前仅支持 Ubuntu/Debian。' >&2; exit 1 ;;
esac
if ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
    echo '错误：需要以 systemd 运行的完整 Ubuntu/Debian 主机。' >&2
    exit 1
fi
arch=$(uname -m)
case "$arch" in
    x86_64|aarch64|armv7l|i686|riscv64) ;;
    *) echo "错误：尚未支持的 CPU 架构：$arch" >&2; exit 1 ;;
esac
if [[ ! $REF =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ || $REF == *..* ]]; then
    echo '错误：仓库版本标识无效。' >&2
    exit 1
fi
echo "系统：$ID ${VERSION_ID:-未知}，架构：$arch"
case "$ID:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
    *) echo '提示：此发行版不在主要支持范围，仍会检查依赖和启动结果。' ;;
esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl python3 iproute2 logrotate util-linux tar gzip
install -d -m 700 "$APP" "$APP/releases" "$STATE" "$LOG"
exec 9>"$STATE/manager.lock"
chmod 600 "$STATE/manager.lock"
if ! flock -n 9; then
    echo '错误：其他管理或安装操作正在进行，请稍后重试。' >&2
    exit 1
fi
stage=$(mktemp -d "$APP/.install-XXXXXXXX")
cleanup() {
    local rc=$?
    if (( completed == 0 )); then
        if (( switched )); then
            if [[ -n $old_release ]]; then
                ln -s "$old_release" "$APP/current.rollback"
                mv -Tf "$APP/current.rollback" "$APP/current"
            else
                rm -f -- "$APP/current"
            fi
            if [[ -f $stage/old-unit ]]; then
                install -m 644 "$stage/old-unit" /etc/systemd/system/socks-relay@.service
            else
                rm -f -- /etc/systemd/system/socks-relay@.service
            fi
            if [[ -f $stage/old-core ]]; then
                install -m 755 "$stage/old-core" "$APP/3proxy"
            else
                rm -f -- "$APP/3proxy"
            fi
            systemctl daemon-reload || true
            if [[ -n $old_release ]]; then
                python3 - "$APP/current/scripts" <<'PY' || true
import sys
sys.path.insert(0, sys.argv[1])
from manager import Manager
m = Manager()
for row in m.rows():
    m.backend.apply(row['port'], row)
PY
            fi
        fi
        echo '错误：安装未完成；原有中转数据已保留，已切换的程序会尝试回滚。' >&2
    fi
    # stage is an absolute directory created by mktemp under this project's APP.
    if [[ -n $stage && $stage == "$APP"/.install-* ]]; then
        rm -rf -- "$stage"
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if (( local_mode )); then
    source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    mkdir "$stage/source"
    # Explicit source allowlist: don't copy .git, real settings, or local tools.
    for entry in install.sh socks-menu.sh uninstall.sh VERSION scripts systemd; do
        cp -a -- "$source_dir/$entry" "$stage/source/"
    done
else
    echo '正在下载管理程序源码...'
    if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
        gh api "repos/$REPO/tarball/$REF" >"$stage/manager.tar.gz"
    else
        # Works anonymously only if the owner later chooses to publish the repo.
        if ! curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 120 \
            "https://api.github.com/repos/$REPO/tarball/$REF" -o "$stage/manager.tar.gz"; then
            echo '错误：私有仓库需要 GitHub 认证。请安装 gh 并执行 gh auth login，或从已下载的源码执行 bash install.sh --local。' >&2
            exit 1
        fi
    fi
    mkdir "$stage/source"
    tar -xzf "$stage/manager.tar.gz" --strip-components=1 -C "$stage/source"
fi
python3 - "$stage/source" <<'PY'
import pathlib, py_compile, sys
p = pathlib.Path(sys.argv[1])
for name in ('install.sh', 'socks-menu.sh', 'uninstall.sh', 'VERSION', 'scripts/manager.py', 'scripts/client_config.py', 'systemd/socks-relay@.service'):
    if not (p / name).is_file() or (p / name).is_symlink():
        sys.exit('错误：管理程序源码不完整或含有不安全链接。')
for script in (p / 'scripts').glob('*.py'):
    py_compile.compile(str(script), doraise=True)
PY
bash -n "$stage/source/install.sh" "$stage/source/socks-menu.sh" "$stage/source/uninstall.sh"
if [[ -L $APP/current ]]; then
    old_release=$(readlink "$APP/current")
    cp -- /etc/systemd/system/socks-relay@.service "$stage/old-unit"
    cp -- "$APP/3proxy" "$stage/old-core"
    python3 - "$APP/current/scripts" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from manager import Manager
m = Manager()
m.recover()
m.backup()
PY
elif [[ -e $APP/current ]]; then
    echo '错误：项目 current 路径不是预期的版本链接，请先检查。' >&2
    exit 1
else
    for target in /etc/systemd/system/socks-relay@.service /etc/logrotate.d/socks5-relay-manager /usr/local/bin/socks-menu /usr/local/bin/socks-relay-uninstall; do
        if [[ -e $target ]]; then
            echo "错误：路径已存在，拒绝覆盖其他程序：$target" >&2
            exit 1
        fi
    done
fi
echo '正在准备 3proxy 核心...'
if [[ -x $APP/3proxy && -f $APP/core-version && $(cat "$APP/core-version") == "$CORE_VERSION" ]]; then
    cp -- "$APP/3proxy" "$stage/3proxy"
else
    # Only accept official Debian/Ubuntu package-index URLs, keep normal signature verification.
    package_version=''
    while IFS='|' read -r _ version origin; do
        version=${version// /}
        if [[ $origin =~ https?://([A-Za-z0-9.-]+\.)?(ubuntu.com|debian.org)/ ]] \
            && dpkg --compare-versions "$version" ge "$CORE_VERSION" \
            && dpkg --compare-versions "$version" lt 1.0; then
            package_version=$version
            break
        fi
    done < <(apt-cache madison 3proxy 2>/dev/null || true)
    if [[ -n $package_version ]]; then
        echo '使用发行版签名软件源中的 3proxy；只提取二进制，不运行默认服务。'
        mkdir "$stage/package"
        (cd "$stage/package" && apt-get download "3proxy=$package_version")
        debs=("$stage/package/"*.deb)
        dpkg-deb -x "${debs[0]}" "$stage/package/extracted"
        package_binary=$(find "$stage/package/extracted" -type f -name 3proxy -perm /111 -print -quit)
        if [[ -n $package_binary ]] && ! ldd "$package_binary" 2>&1 | grep -q 'not found'; then
            cp -- "$package_binary" "$stage/3proxy"
        fi
    fi
    if [[ ! -f $stage/3proxy ]]; then
        echo "发行版源无合适核心，构建固定官方 LTS 源码 $CORE_VERSION（SHA-256 校验）。"
        apt-get install -y --no-install-recommends build-essential
        curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 180 \
            "https://codeload.github.com/3proxy/3proxy/tar.gz/$CORE_COMMIT" -o "$stage/core.tar.gz"
        echo "$CORE_SHA256  $stage/core.tar.gz" | sha256sum -c -
        mkdir "$stage/core"
        tar -xzf "$stage/core.tar.gz" --strip-components=1 -C "$stage/core"
        make -C "$stage/core" -f Makefile.Linux -j"$(nproc)"
        # Never run 'make install': it would create unrelated default proxy services/config.
        cp -- "$stage/core/bin/3proxy" "$stage/3proxy"
    fi
fi
chmod 755 "$stage/3proxy"
python3 - "$stage/source/scripts" "$stage/3proxy" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from manager import check_config
row = dict(port=20001, upstream_host='127.0.0.1', upstream_port=1080, upstream_user='check',
           upstream_password='check', client_user='check', client_password='check',
           sources=['127.0.0.1'], bind='0.0.0.0', enabled=True, resolved_ip='127.0.0.1')
check_config(row, Path(sys.argv[2]))
PY
version=$(cat "$stage/source/VERSION")
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo '错误：源码版本号无效。' >&2
    exit 1
fi
release="$APP/releases/$version-$(date +%s)-$$"
mkdir -m 700 "$release"
for entry in install.sh socks-menu.sh uninstall.sh VERSION scripts systemd; do
    cp -a -- "$stage/source/$entry" "$release/"
done
# Local source trees may belong to an unprivileged login account. The service
# deliberately has no CAP_DAC_OVERRIDE, so copied 0700 directories must be root-owned.
chown -R root:root "$release"
chmod -R go-rwx "$release"
switched=1
install -m 755 "$stage/3proxy" "$APP/3proxy.new"
mv -f -- "$APP/3proxy.new" "$APP/3proxy"
ln -s "$release" "$APP/current.new"
mv -Tf "$APP/current.new" "$APP/current"
install -m 644 "$release/systemd/socks-relay@.service" /etc/systemd/system/socks-relay@.service
# Explicitly recreate both standard error/access logs with private permissions.
python3 - "$APP/current/scripts" <<'PY'
import sys, os
sys.path.insert(0, sys.argv[1])
from manager import Manager, check_config
m = Manager()
for row in m.rows():
    for kind in ('service', 'relay'):
        path = m.log / (kind + '-' + str(row['port']) + '.log')
        path.touch(mode=0o600, exist_ok=True)
        os.chmod(path, 0o600)
    if row['enabled']:
        check_config(row, m.binary)
PY
systemctl daemon-reload
python3 - "$APP/current/scripts" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from manager import Manager
m = Manager()
for row in m.rows():
    m.backend.apply(row['port'], row)
PY
# Only install public entrypoints after the program has passed startup checks.
install -m 755 "$release/socks-menu.sh" /usr/local/bin/socks-menu
install -m 755 "$release/uninstall.sh" /usr/local/bin/socks-relay-uninstall
install -m 644 "$release/systemd/logrotate" /etc/logrotate.d/socks5-relay-manager
printf '%s\n' "$CORE_VERSION" >"$APP/core-version"
chmod 600 "$APP/core-version"
completed=1
echo '安装成功！执行 socks-menu 打开中文菜单。首次安装暂无中转，选择 1 添加并生成安全账号密码。'
echo '已有同台 VPS 的 TUIC：选择 15 添加本机中转，再选 14 导出客户端配置；无需开放 SOCKS5 公网端口。'
echo '未修改 SSH、防火墙、云安全组或已有 TUIC 服务。'
