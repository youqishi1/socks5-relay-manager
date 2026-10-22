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

relay_apt() {
    local limit=${SOCKS_LOCK_WAIT_SECONDS:-600} deadline log rc
    if [[ ! $limit =~ ^[0-9]{1,4}$ ]] || (( limit > 1800 )); then
        echo '错误：安装锁等待时间必须为 0–1800 秒。' >&2; return 1
    fi
    deadline=$((SECONDS + limit))
    log=$(mktemp /tmp/socks-relay-apt-XXXXXXXX)
    while true; do
        if apt-get -o DPkg::Lock::Timeout=5 -o Acquire::Retries=3 \
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
    local url=$1 digest=$2 destination=$3 cache file part
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
    if ! curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
            --connect-timeout 20 --max-time 300 --retry 3 --retry-delay 2 --retry-max-time 900 \
            "$url" -o "$part"; then
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
        if "$resolved" -c 'import sys,ssl,fcntl; assert sys.version_info >= (3,10)' >/dev/null 2>&1; then
            printf '%s\n' "$resolved"
            return 0
        fi
    done
    return 1
}
