#!/bin/bash
# SENTINEL Lab - Temizlik

echo "[LAB] Namespace'ler siliniyor..."
for i in $(seq 1 5); do
    ip netns del ns-dev${i} 2>/dev/null && echo "  [OK] ns-dev${i} silindi" || true
    ip link del veth${i} 2>/dev/null || true
done

ip link del br-lab 2>/dev/null && echo "  [OK] br-lab silindi" || true
iptables -t nat -D POSTROUTING -s 10.99.0.0/24 ! -d 10.99.0.0/24 -j MASQUERADE 2>/dev/null || true

pkill -f lab_traffic.py 2>/dev/null || true

echo "[LAB] Temizlik tamamlandi."
