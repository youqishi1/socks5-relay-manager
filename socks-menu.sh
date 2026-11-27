#!/usr/bin/env bash
set -Eeuo pipefail
if (( EUID != 0 )); then
    echo '错误：管理菜单需要 root 权限，请执行 sudo sb1。' >&2
    exit 1
fi
python=/opt/socks5-relay-manager/python3
[[ -x $python ]] || python=/usr/bin/python3
case "${1:-menu}:$#" in
    menu:0) command=menu ;;
    web:1) command=web ;;
    web-password:1) command=web-password ;;
    *) echo '用法：sb1、sb1 web 或 sb1 web-password。' >&2; exit 1 ;;
esac
exec "$python" /opt/socks5-relay-manager/current/scripts/manager.py "$command"
