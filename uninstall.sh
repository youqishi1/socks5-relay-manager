#!/usr/bin/env bash
set -Eeuo pipefail
if (( EUID != 0 )); then
    echo '错误：卸载需要 root 权限，请执行 sudo socks-relay-uninstall。' >&2
    exit 1
fi
python=/opt/socks5-relay-manager/python3
[[ -x $python ]] || python=/usr/bin/python3
exec "$python" /opt/socks5-relay-manager/current/scripts/manager.py uninstall
