#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $(uname -m) == x86_64 ]] || { echo 'ACME fixture requires x86_64'; exit 1; }
work=$(mktemp -d /tmp/relay-acme-ci-XXXXXXXX)
cleanup() {
    [[ $work == /tmp/relay-acme-ci-* ]] && rm -rf -- "$work"
}
trap cleanup EXIT
curl --proto '=https' --tlsv1.2 -fsSL --max-time 180 \
    https://github.com/go-acme/lego/releases/download/v5.5.2/lego_v5.5.2_linux_amd64.tar.gz -o "$work/lego.tar.gz"
echo "2a35505089e7772c92e1e9ac144df91151ef2eca8568630db0ff91fca06d9bef  $work/lego.tar.gz" | sha256sum -c -
mkdir "$work/lego"
tar -xzf "$work/lego.tar.gz" -C "$work/lego"
curl --proto '=https' --tlsv1.2 -fsSL --max-time 180 \
    https://github.com/letsencrypt/pebble/releases/download/v2.10.1/pebble-linux-amd64.tar.gz -o "$work/pebble.tar.gz"
echo "4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed  $work/pebble.tar.gz" | sha256sum -c -
tar -xzf "$work/pebble.tar.gz" -C "$work"
export LEGO_BINARY="$work/lego/lego"
export PEBBLE_BINARY="$work/pebble-linux-amd64/linux/amd64/pebble"
chmod 700 "$LEGO_BINARY" "$PEBBLE_BINARY"
"$LEGO_BINARY" --version
"$PEBBLE_BINARY" -version
"${PYTHON_BINARY:-python3}" tests/test_certificates.py
"${PYTHON_BINARY:-python3}" tests/test_acme.py
