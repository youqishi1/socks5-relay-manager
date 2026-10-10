#!/usr/bin/env bash
# Fixed public release bootstrap. Does not accept unverified alternate sources.
set -Eeuo pipefail
umask 077
if (( EUID != 0 )); then
    echo '错误：请先 sudo -i，再运行安装命令。' >&2
    exit 1
fi
if [[ ! -f /etc/os-release ]]; then
    echo '错误：仅支持 Ubuntu/Debian/CentOS 7 VPS。' >&2
    exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
    ubuntu|debian) ;;
    centos)
        [[ ${VERSION_ID%%.*} == 7 ]] || { echo '错误：CentOS 目前仅兼容 7。' >&2; exit 1; } ;;
    *) echo '错误：仅支持 Ubuntu/Debian/CentOS 7 VPS。' >&2; exit 1 ;;
esac
if ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
    echo '错误：需要以 systemd 运行的完整主机。' >&2
    exit 1
fi
work=$(mktemp -d /tmp/socks-relay-setup-XXXXXXXX)
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
trap 'echo "错误：下载、校验或安装失败，未验证的安装包不会执行。" >&2' ERR
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
        apt-get update
        apt-get install -y --no-install-recommends curl ca-certificates
    fi
fi
echo '正在下载固定版本 v1.3.1 安装包...'
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 180 \
    https://github.com/youqishi1/socks5-relay-manager/releases/download/v1.3.1/socks5-relay-manager-v1.3.1-install.tar.gz \
    -o "$work/install.tar.gz"
echo "4c5d9b6a91d413202b7a8b6e06002ac4f23de67b7bebce01af46a61826ca0524  $work/install.tar.gz" | sha256sum -c -
mkdir "$work/source"
tar -xzf "$work/install.tar.gz" -C "$work/source"
bash "$work/source/install.sh" --local
if [[ -t 0 ]]; then
    sb1
else
    echo '安装完成。执行 sb1 打开菜单，选 1 粘贴 SOCKS5 自动部署 TCP + TUIC；旧中转选 19，凭据查看选 16。'
fi
