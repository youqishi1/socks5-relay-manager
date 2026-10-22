#!/usr/bin/env bash
# Generated fixed-release bootstrap. Its embedded helpers match the release.
set -Eeuo pipefail
umask 077
APP=/opt/socks5-relay-manager
#!/usr/bin/env bash
# Shared installer helpers; embedded verbatim in the standalone bootstrap.

relay_preflight() {
    local available memory
    available=$(df -Pk /opt 2>/dev/null | awk 'NR == 2 {print $4}')
    if [[ ! $available =~ ^[0-9]+$ ]] || (( available < 307200 )); then
        echo '错误：/opt 所在磁盘至少需要 300 MiB 可用空间。' >&2; return 1
    fi
    memory=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    echo "安装预检：可用磁盘 $((available / 1024)) MiB，内存 $((memory / 1024)) MiB。"
    echo '遇到系统更新会等待安装锁；不会删除锁文件、终止更新进程或修改系统 DNS。'
    if [[ ${SOCKS_OFFLINE:-0} != 1 ]] && command -v getent >/dev/null && command -v timeout >/dev/null; then
        if timeout 8 getent ahostsv4 github.com >/dev/null 2>&1; then
            echo '安装预检：GitHub DNS 解析正常。'
        else
            echo '提示：GitHub DNS 预检未通过；下载会自动重试，已有校验缓存仍可使用。'
        fi
    fi
}

relay_debian_archive() {
    local directory="$APP/apt-compat" temporary
    [[ ! -L $directory ]] || { echo '错误：项目软件源目录不能是符号链接。' >&2; return 1; }
    install -d -m 700 "$directory"
    temporary=$(mktemp "$directory/.sources-XXXXXXXX")
    # Frozen archives may have an old Valid-Until. Only archive freshness is relaxed;
    # HTTPS, Release signatures and package hashes remain mandatory.
    printf '%s\n' \
        'deb [check-valid-until=no] https://archive.debian.org/debian bullseye main' \
        'deb [check-valid-until=no] https://archive.debian.org/debian-security bullseye-security main' >"$temporary"
    chmod 600 "$temporary"
    mv -f -- "$temporary" "$directory/sources.list"
    temporary=$(mktemp "$directory/.config-XXXXXXXX")
    printf 'Dir::Etc::sourcelist "%s/sources.list";\nDir::Etc::sourceparts "-";\nDPkg::Lock::Timeout "600";\nAcquire::Retries "3";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' "$directory" >"$temporary"
    chmod 600 "$temporary"
    mv -f -- "$temporary" "$directory/apt.conf"
    echo 'Debian 11：本次操作使用项目专用官方归档源，保留签名验证，不改系统源；该系统已结束常规 LTS 安全维护。'
}

relay_apt() {
    local limit=${SOCKS_LOCK_WAIT_SECONDS:-600} deadline log rc
    local -a compatibility=()
    if [[ ${ID:-} == debian && ( ${VERSION_ID:-} == 11 || ${VERSION_ID:-} == 11.* ) ]]; then
        relay_debian_archive
        compatibility=(-o "Dir::Etc::sourcelist=$APP/apt-compat/sources.list" -o 'Dir::Etc::sourceparts=-')
    fi
    if [[ ! $limit =~ ^[0-9]{1,4}$ ]] || (( limit > 1800 )); then
        echo '错误：安装锁等待时间必须为 0–1800 秒。' >&2; return 1
    fi
    deadline=$((SECONDS + limit))
    log=$(mktemp /tmp/socks-relay-apt-XXXXXXXX)
    while true; do
        if apt-get "${compatibility[@]}" -o APT::Get::AllowUnauthenticated=false \
                -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false \
                -o DPkg::Lock::Timeout=5 -o Acquire::Retries=3 \
                -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 "$@" 2>&1 | tee "$log"; then
            rm -f -- "$log"
            return 0
        else
            rc=${PIPESTATUS[0]}
        fi
        if ! grep -Eq 'Could not get lock|Unable to acquire.*lock|Unable to lock|is another process using it|Waiting for cache lock' "$log"; then
            rm -f -- "$log"
            echo '错误：软件包操作失败；请查看上方的软件源或下载错误。' >&2
            return "$rc"
        fi
        if (( SECONDS >= deadline )); then
            rm -f -- "$log"
            echo '错误：系统更新仍占用安装锁，等待已结束。请稍后重试；不要删除锁文件或强杀更新进程。' >&2
            return 1
        fi
        echo "系统更新正在占用安装锁，等待后自动重试（最多剩余 $((deadline - SECONDS)) 秒）..."
        sleep 5
    done
}

relay_download() {
    local url=$1 digest=$2 destination=$3 cache file part attempt downloaded=0
    [[ $url == https://* && $digest =~ ^[a-f0-9]{64}$ ]] || {
        echo '错误：下载必须使用 HTTPS 和固定 SHA-256。' >&2; return 1;
    }
    cache=${SOCKS_DOWNLOAD_CACHE:-/opt/socks5-relay-manager/cache/downloads}
    [[ ! -L $cache ]] || { echo '错误：下载缓存目录不能是符号链接。' >&2; return 1; }
    install -d -m 700 "$cache"
    file="$cache/$digest"
    if [[ -f $file ]] && echo "$digest  $file" | sha256sum -c - >/dev/null 2>&1; then
        echo '复用已通过 SHA-256 校验的下载缓存。'
        cp -- "$file" "$destination"
        return 0
    fi
    if [[ ${SOCKS_OFFLINE:-0} == 1 ]]; then
        echo "错误：离线缓存缺失或校验不通过，需要 SHA-256 $digest。" >&2
        return 1
    fi
    part=$(mktemp "$cache/.download-XXXXXXXX")
    for attempt in 1 2 3; do
        if curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
                --connect-timeout 20 --max-time 300 "$url" -o "$part"; then
            downloaded=1
            break
        fi
        if (( attempt < 3 )); then
            echo "下载未完成，准备第 $((attempt + 1))/3 次尝试..."
            sleep 2
        fi
    done
    if (( downloaded == 0 )); then
        rm -f -- "$part"
        echo "错误：下载失败：$url。可重试或使用经过校验的离线缓存；未修改 DNS。" >&2
        return 1
    fi
    if ! echo "$digest  $part" | sha256sum -c -; then
        rm -f -- "$part"
        echo '错误：下载文件校验失败，未执行。' >&2
        return 1
    fi
    chmod 600 "$part"
    mv -f -- "$part" "$file"
    cp -- "$file" "$destination"
}

relay_python() {
    local candidate resolved
    # Resolve the existing link: never replace APP/python3 by a link to itself.
    for candidate in "$APP/python3" "$(command -v python3 || true)"; do
        [[ -n $candidate && -x $candidate ]] || continue
        resolved=$(readlink -f -- "$candidate") || continue
        if "$resolved" -c 'import sys,ssl,fcntl,zlib; assert sys.version_info >= (3,10)' >/dev/null 2>&1; then
            printf '%s\n' "$resolved"
            return 0
        fi
    done
    return 1
}

if (( EUID != 0 )); then
    echo '错误：请先 sudo -i，再运行安装命令。' >&2; exit 1
fi
[[ -f /etc/os-release ]] || { echo '错误：无法识别系统。' >&2; exit 1; }
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
    ubuntu|debian) ;;
    centos) [[ ${VERSION_ID%%.*} == 7 ]] || { echo '错误：CentOS 目前仅兼容 7。' >&2; exit 1; } ;;
    *) echo '错误：仅支持 Ubuntu/Debian/CentOS 7 VPS。' >&2; exit 1 ;;
esac
if ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
    echo '错误：需要以 systemd 运行的完整主机。' >&2; exit 1
fi
relay_preflight
work=$(mktemp -d /tmp/socks-relay-setup-XXXXXXXX)
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
trap 'echo "错误：安装未完成，请查看上方具体原因；未校验的安装包不会执行。" >&2' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
if ! command -v curl >/dev/null; then
    if [[ $ID == centos ]]; then
        mkdir "$work/repos"
        cat >"$work/repos/relay.repo" <<'EOF'
[relay-os]
name=CentOS 7.9.2009 official archive
baseurl=https://vault.centos.org/7.9.2009/os/$basearch/
enabled=1
gpgcheck=1
sslverify=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
EOF
        yum --setopt="reposdir=$work/repos" --disablerepo='*' --enablerepo=relay-os install -y curl ca-certificates
    else
        relay_apt update
        relay_apt install -y --no-install-recommends curl ca-certificates
    fi
fi
echo '正在下载固定版本 v1.5.0 安装包...'
relay_download 'https://github.com/youqishi1/socks5-relay-manager/releases/download/v1.5.0/socks5-relay-manager-v1.5.0-install.tar.gz' \
    'df3fcedb921670d8c51089602677fdb6a19b127f9c1ef2900a162f702a85cf55' "$work/install.tar.gz"
mkdir "$work/source"
tar -xzf "$work/install.tar.gz" -C "$work/source"
bash "$work/source/install.sh" --local
if [[ -t 0 ]]; then
    sb1
else
    echo '安装完成。执行 sb1 打开菜单，选 1 粘贴 SOCKS5 自动部署 TCP + TUIC；更新选 12，诊断选 24。'
fi
