#!/bin/sh
# FireX - remove everything segmentation-up.sh and firexd installed.

for v in $(ip -o link show 2>/dev/null | sed -n 's/^[0-9]*: \([a-z0-9]*\.[0-9]*\)[@:].*/\1/p' | sort -u); do
    ip link del "$v" 2>/dev/null || true
done

iptables -D FORWARD -j FIREX_FWD 2>/dev/null || true
for c in FIREX_FWD; do
    iptables -F $c 2>/dev/null || true
    iptables -X $c 2>/dev/null || true
done
for c in FIREX_NAT FIREX_DNAT FIREX_PORTAL; do
    iptables -t nat -F $c 2>/dev/null || true
    iptables -t nat -X $c 2>/dev/null || true
done

ipset destroy firex_quarantine 2>/dev/null || true
iptables -P FORWARD ACCEPT
echo "[SEG] Torn down."
