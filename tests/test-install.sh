#!/usr/bin/env bash
# Only run on a disposable Linux CI host; production project paths are used.
set -Eeuo pipefail
if [[ ${RELAY_DISPOSABLE_HOST:-} != YES ]]; then
    echo '只允许在明确标记的可丢弃测试主机运行。' >&2
    exit 1
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
bash install.sh --local
python3 tests/test_systemd.py
logrotate --debug /etc/logrotate.d/socks5-relay-manager
systemd-analyze verify /etc/systemd/system/socks-relay@.service /etc/systemd/system/socks-access@.service
