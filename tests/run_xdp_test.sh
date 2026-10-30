#!/bin/bash
# Sets up an isolated veth pair, runs the XDP integration test, tears it down.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PROJ="$(dirname "$HERE")"
TEST_BIN="$PROJ/build/test_xdp"

if [ "$(id -u)" != 0 ]; then
    echo "This test attaches a BPF program and creates network interfaces."
    echo "Run it as root:  sudo make test-xdp"
    exit 1
fi
if [ ! -x "$TEST_BIN" ]; then
    echo "$TEST_BIN is missing. Build it first:  make test-xdp"
    exit 1
fi

cleanup() {
    ip link set dev fwtest0 xdp off 2>/dev/null
    ip link del fwtest0 2>/dev/null
    ip netns del fwtest 2>/dev/null
}
trap cleanup EXIT

echo "=== 1. verifier load test (bpftool) ==="
mount | grep -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf 2>/dev/null
rm -f /sys/fs/bpf/fwtest_prog
if bpftool prog load "$PROJ/xdp/xdp_firewall.bpf.o" /sys/fs/bpf/fwtest_prog 2>&1; then
    echo "VERIFIER: ACCEPTED"
    bpftool prog show pinned /sys/fs/bpf/fwtest_prog | head -3
    rm -f /sys/fs/bpf/fwtest_prog
else
    echo "VERIFIER: REJECTED"
    exit 1
fi

echo
echo "=== 2. network setup ==="
cleanup
ip link add fwtest0 type veth peer name fwtest1 || exit 1
ip netns add fwtest || exit 1
ip link set fwtest1 netns fwtest || exit 1
ip addr add 10.77.0.1/24 dev fwtest0
ip link set fwtest0 up
ip netns exec fwtest ip addr add 10.77.0.2/24 dev fwtest1
ip netns exec fwtest ip link set fwtest1 up
ip netns exec fwtest ip link set lo up
echo "veth pair up: fwtest0 (10.77.0.1) <-> fwtest1 (10.77.0.2, netns fwtest)"
ip netns exec fwtest ping -c 1 -W 2 10.77.0.1 >/dev/null 2>&1 \
  && echo "baseline connectivity: OK" || { echo "baseline connectivity: FAILED"; exit 1; }

echo
echo "=== 3. integration test ==="
cd "$PROJ" || exit 1
"$TEST_BIN"
rc=$?

echo
echo "=== 4. leftover check ==="
ip link show fwtest0 | grep -q xdp && echo "WARNING: program still attached" || echo "interface clean"
exit $rc
