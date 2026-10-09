#!/usr/bin/env bash
# Fixed public release bootstrap. Does not accept unverified alternate sources.
set -Eeuo pipefail
umask 077
if (( EUID != 0 )); then
    echo '错误：请先 sudo -i，再运行安装命令。' >&2
    exit 1
fi
if [[ ! -f /etc/os-release ]]; then
    echo '错误：仅支持 Ubuntu/Debian VPS。' >&2
    exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
    ubuntu|debian) ;;
    *) echo '错误：仅支持 Ubuntu/Debian VPS。' >&2; exit 1 ;;
esac
if ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
    echo '错误：需要以 systemd 运行的完整 Ubuntu/Debian 主机。' >&2
    exit 1
fi
work=$(mktemp -d /tmp/socks-relay-setup-XXXXXXXX)
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
trap 'echo "错误：下载、校验或安装失败，未验证的安装包不会执行。" >&2' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
if ! command -v curl >/dev/null; then
    apt-get update
    apt-get install -y --no-install-recommends curl ca-certificates
fi
echo '正在下载固定版本 v1.1.0 安装包...'
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 180 \
    https://github.com/youqishi1/socks5-relay-manager/releases/download/v1.1.0/socks5-relay-manager-v1.1.0-install.tar.gz \
    -o "$work/install.tar.gz"
echo "89157c315a53856363719baacee80ed56b04e24807d60ebbb3d0309197b13416  $work/install.tar.gz" | sha256sum -c -
mkdir "$work/source"
tar -xzf "$work/install.tar.gz" -C "$work/source"
bash "$work/source/install.sh" --local
if [[ -t 0 ]]; then
    socks-menu
else
    echo '安装完成。执行 socks-menu；已有同台 TUIC，请选 15 添加中转，再选 14 导出客户端配置。'
fi
