#!/usr/bin/env bash
set -Eeuo pipefail
if (( EUID != 0 )); then
    echo '错误：管理菜单需要 root 权限，请执行 sudo sb1。' >&2
    exit 1
fi
exec /usr/bin/python3 /opt/socks5-relay-manager/current/scripts/manager.py menu
