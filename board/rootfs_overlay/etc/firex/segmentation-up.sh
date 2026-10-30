#!/bin/sh
# FireX - kernel prerequisites for segmentation and policy.
set -e

echo "[SEG] Loading kernel modules..."
for m in 8021q br_netfilter ip_set xt_set nfnetlink_queue; do
    modprobe "$m" 2>/dev/null || echo "[SEG] note: module $m unavailable"
done

# Bridged traffic must traverse iptables for inter-VLAN policy
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || true
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[SEG] Creating quarantine ipset..."
ipset create firex_quarantine hash:ip timeout 3600 2>/dev/null || true

echo "[SEG] Default-deny forwarding posture..."
iptables -P FORWARD DROP
iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[SEG] Prerequisites ready."
