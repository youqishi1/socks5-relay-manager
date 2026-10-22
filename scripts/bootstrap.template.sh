#!/usr/bin/env bash
# Generated fixed-release bootstrap. Its embedded helpers match the release.
set -Eeuo pipefail
umask 077
APP=/opt/socks5-relay-manager
@INSTALL_COMMON@
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
echo '正在下载固定版本 v@VERSION@ 安装包...'
relay_download 'https://github.com/youqishi1/socks5-relay-manager/releases/download/v@VERSION@/socks5-relay-manager-v@VERSION@-install.tar.gz' \
    '@SHA256@' "$work/install.tar.gz"
mkdir "$work/source"
tar -xzf "$work/install.tar.gz" -C "$work/source"
bash "$work/source/install.sh" --local
if [[ -t 0 ]]; then
    sb1
else
    echo '安装完成。执行 sb1 打开菜单，选 1 粘贴 SOCKS5 自动部署 TCP + TUIC；更新选 12，诊断选 24。'
fi
