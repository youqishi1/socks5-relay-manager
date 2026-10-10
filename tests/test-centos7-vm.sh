#!/usr/bin/env bash
# Boot the original CentOS 7 kernel/systemd; never run on a production host.
set -Eeuo pipefail
[[ ${RELAY_DISPOSABLE_HOST:-} == YES ]] || { echo '仅限可丢弃 CI 主机。' >&2; exit 1; }
umask 077
work=$(mktemp -d /tmp/relay-centos7-ci-XXXXXXXX)
cleanup() {
    local rc=$?
    if (( rc )); then sudo tail -n 100 "$work/serial.log" || true; fi
    if [[ -f $work/vm.pid ]]; then sudo kill "$(sudo cat "$work/vm.pid")" || true; fi
    # work is an absolute mktemp directory with a fixed test-specific prefix.
    [[ $work == /tmp/relay-centos7-ci-* ]] && sudo rm -rf -- "$work"
    exit "$rc"
}
trap cleanup EXIT
curl --proto '=https' --tlsv1.2 -fsSL --max-time 300 \
    https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud-2009.qcow2 -o "$work/disk.qcow2"
echo "e38bab0475cc6d004d2e17015969c659e5a308111851b0e2715e84646035bdd3  $work/disk.qcow2" | sha256sum -c -
qemu-img resize "$work/disk.qcow2" 20G
ssh-keygen -q -t ed25519 -N '' -f "$work/key"
cat >"$work/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
ssh_authorized_keys:
  - $(cat "$work/key.pub")
runcmd:
  - touch /root/relay-ci-ready
EOF
printf 'instance-id: relay-centos7-ci\nlocal-hostname: relay-centos7-ci\n' >"$work/meta-data"
genisoimage -quiet -output "$work/seed.iso" -volid cidata -joliet -rock "$work/user-data" "$work/meta-data"
accel=tcg
[[ ! -e /dev/kvm ]] || accel=kvm
sudo qemu-system-x86_64 -machine "accel=$accel" -m 3072 -smp 2 \
    -drive "file=$work/disk.qcow2,format=qcow2,if=virtio" -cdrom "$work/seed.iso" \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:22227-:22 -device virtio-net-pci,netdev=net0 \
    -display none -serial "file:$work/serial.log" -daemonize -pidfile "$work/vm.pid"
ssh_args=(-i "$work/key" -p 22227 -o BatchMode=yes -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts")
ready=0
for (( i=0; i<120; i++ )); do
    if ssh "${ssh_args[@]}" root@127.0.0.1 test -f /root/relay-ci-ready 2>/dev/null; then ready=1; break; fi
    sleep 5
done
(( ready )) || { echo 'CentOS 虚拟机未能启动 SSH。' >&2; exit 1; }
git ls-files -z | tar --null -T - -czf "$work/source.tar.gz"
cache=${RELAY_CENTOS_CACHE:-}
if [[ -n $cache && -f $cache && -f $cache.sha256 ]]; then
    (cd "$(dirname "$cache")" && sha256sum -c "$(basename "$cache").sha256")
    scp -i "$work/key" -P 22227 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -o "UserKnownHostsFile=$work/known_hosts" "$cache" root@127.0.0.1:/root/relay-ci-runtime.tar.gz
fi
scp -i "$work/key" -P 22227 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$work/known_hosts" "$work/source.tar.gz" root@127.0.0.1:/root/source.tar.gz
ssh "${ssh_args[@]}" root@127.0.0.1 'bash -s' <<'GUEST'
set -Eeuo pipefail
umask 077
diagnostics() {
    local rc=$?
    journalctl -u 'socks-relay@*' -u 'socks-access@*' --no-pager -n 80 || true
    for file in /var/log/socks5-relay-manager/service-*.log /var/log/socks5-relay-manager/access-*.log; do
        [[ ! -f $file ]] || tail -n 30 "$file"
    done
    exit "$rc"
}
trap diagnostics ERR
uname -r
systemctl --version | head -n 1
[[ $(uname -r) == 3.10.* ]]
[[ $(systemctl --version | head -n 1) == 'systemd 219' ]]
sha256sum /usr/bin/python /usr/bin/openssl >/root/original-system-binaries.sha256
if [[ -f /root/relay-ci-runtime.tar.gz ]]; then
    mkdir -p /opt/socks5-relay-manager
    tar -xzf /root/relay-ci-runtime.tar.gz -C /opt/socks5-relay-manager
fi
mkdir /root/source
tar -xzf /root/source.tar.gz -C /root/source
cd /root/source
bash install.sh --local
tar -czf /root/relay-ci-runtime.tar.gz -C /opt/socks5-relay-manager \
    runtime-py3.12.15-ssl3.5.9 3proxy core-version
sha256sum -c /root/original-system-binaries.sha256
export RELAY_DISPOSABLE_HOST=YES
/opt/socks5-relay-manager/python3 tests/test_systemd.py
mkdir /root/relay-unit-check
cp /etc/systemd/system/socks-relay@.service /root/relay-unit-check/socks-relay@20001.service
cp /etc/systemd/system/socks-access@.service /root/relay-unit-check/socks-access@20001.service
systemd-analyze verify /root/relay-unit-check/socks-relay@20001.service /root/relay-unit-check/socks-access@20001.service
logrotate --debug /etc/logrotate.d/socks5-relay-manager
export SINGBOX_BINARY=/opt/socks5-relay-manager/sing-box
export OPENSSL_BINARY=/opt/socks5-relay-manager/runtime-py3.12.15-ssl3.5.9/ssl/bin/openssl
curl --proto '=https' --tlsv1.2 -fsSL --max-time 180 \
    https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-v1-v1.19.32.gz -o /root/mihomo.gz
echo '306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc  /root/mihomo.gz' | sha256sum -c -
gzip -d /root/mihomo.gz
chmod 700 /root/mihomo
export MIHOMO_BINARY=/root/mihomo
export PYTHON_BINARY=/opt/socks5-relay-manager/python3
bash tests/test-acme.sh
/opt/socks5-relay-manager/python3 tests/test_clients.py
/opt/socks5-relay-manager/python3 tests/test_access.py
sha256sum -c /root/original-system-binaries.sha256
echo 'PASS: CentOS 7 original 3.10 kernel, systemd 219, private runtime, SS/TUIC, repeat install and rollback'
GUEST
if [[ -n $cache ]]; then
    scp -i "$work/key" -P 22227 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -o "UserKnownHostsFile=$work/known_hosts" root@127.0.0.1:/root/relay-ci-runtime.tar.gz "$cache"
    (cd "$(dirname "$cache")" && sha256sum "$(basename "$cache")" >"$(basename "$cache").sha256")
fi
