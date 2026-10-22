#!/usr/bin/env bash
# Full systemd on official Debian cloud images, never on production.
set -Eeuo pipefail
[[ ${RELAY_DISPOSABLE_HOST:-} == YES ]] || { echo '仅限可丢弃 CI 主机。' >&2; exit 1; }
case "${1:-}" in
    11) suite=bullseye; build=20260821-2577; digest=eca21286cadc03444eba75c35c30869707c39867b7cd4a78fa315a021243e21898d2675f5de2c5d8bd1e33753d01a7364cd1f479dbcbd7ea83d72612219ffda5 ;;
    12) suite=bookworm; build=20261021-2638; digest=9f181877006e8d9ca4f4554eba8729a829936f0f7d1db5e77f69b1ef0f6bc372b4d46f3dae39b10d84f9131496c2cc1d449264f26577fe934a79de5a5512a3dd ;;
    13) suite=trixie; build=20261021-2638; digest=16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c ;;
    *) echo '请选择 Debian 11 / 12 / 13。' >&2; exit 1 ;;
esac
version=$1
umask 077
work=$(mktemp -d /tmp/relay-debian-ci-XXXXXXXX)
cleanup() {
    local rc=$?
    if (( rc )); then sudo tail -n 60 "$work/serial.log" || true; fi
    if [[ -f $work/vm.pid ]]; then sudo kill "$(sudo cat "$work/vm.pid")" || true; fi
    [[ $work == /tmp/relay-debian-ci-* ]] && sudo rm -rf -- "$work"
    exit "$rc"
}
trap cleanup EXIT
image="debian-$version-genericcloud-amd64-$build.qcow2"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --max-time 300 \
    "https://cloud.debian.org/images/cloud/$suite/$build/$image" -o "$work/disk.qcow2"
echo "$digest  $work/disk.qcow2" | sha512sum -c -
qemu-img resize "$work/disk.qcow2" 20G
ssh-keygen -q -t ed25519 -N '' -f "$work/key"
cat >"$work/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
package_update: false
package_upgrade: false
users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$work/key.pub")
runcmd:
  - touch /root/relay-ci-ready
EOF
printf 'instance-id: relay-debian-ci\nlocal-hostname: relay-debian-ci\n' >"$work/meta-data"
genisoimage -quiet -output "$work/seed.iso" -volid cidata -joliet -rock "$work/user-data" "$work/meta-data"
accel=tcg
[[ ! -e /dev/kvm ]] || accel=kvm
sudo qemu-system-x86_64 -machine "accel=$accel" -m 3072 -smp 2 \
    -drive "file=$work/disk.qcow2,format=qcow2,if=virtio" -cdrom "$work/seed.iso" \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:22228-:22 -device virtio-net-pci,netdev=net0 \
    -display none -serial "file:$work/serial.log" -daemonize -pidfile "$work/vm.pid"
ssh_args=(-i "$work/key" -p 22228 -o BatchMode=yes -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/known_hosts")
ready=0
for (( i=0; i<120; i++ )); do
    if ssh "${ssh_args[@]}" root@127.0.0.1 test -f /root/relay-ci-ready 2>/dev/null; then ready=1; break; fi
    sleep 5
done
(( ready )) || { echo 'Debian 虚拟机未能启动 SSH。' >&2; exit 1; }
python3 tools/build_release.py
git ls-files -z | tar --null -T - -czf "$work/source.tar.gz"
scp -i "$work/key" -P 22228 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$work/known_hosts" "$work/source.tar.gz" root@127.0.0.1:/root/source.tar.gz
ssh "${ssh_args[@]}" root@127.0.0.1 'mkdir -p /root/source/.tools'
release_version=$(cat VERSION)
scp -i "$work/key" -P 22228 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$work/known_hosts" ".tools/socks5-relay-manager-v$release_version-install.tar.gz" \
    root@127.0.0.1:/root/source/.tools/
ssh "${ssh_args[@]}" root@127.0.0.1 'bash -s' <<'GUEST'
set -Eeuo pipefail
umask 077
mkdir -p /root/source
tar -xzf /root/source.tar.gz -C /root/source
cd /root/source
systemctl mask --runtime --now apt-daily.service apt-daily-upgrade.service apt-daily.timer apt-daily-upgrade.timer
before_python=$(readlink -f /usr/bin/python3)
before_hash=$(sha256sum /usr/bin/python3)
bash install.sh --local
python=/opt/socks5-relay-manager/python3
"$python" tests/test_install_helpers.py
"$python" tests/test_updates.py
"$python" tests/test_diagnostics.py
"$python" tests/test_relay.py
RELAY_DISPOSABLE_HOST=YES "$python" tests/test_systemd.py
RELAY_DISPOSABLE_HOST=YES "$python" tests/test_update_systemd.py
test "$(readlink -f /usr/bin/python3)" = "$before_python"
test "$(sha256sum /usr/bin/python3)" = "$before_hash"
printf '0\n' | sb1
echo 'PASS: Debian fresh install, private runtime reuse, actual services, rollback, diagnostics and system Python preservation'
GUEST
