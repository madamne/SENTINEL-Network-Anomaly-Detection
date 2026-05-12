#!/bin/bash
# SENTINEL Lab - Network Namespace Kurulumu
# 5 sanal cihaz oluşturur, tümü br-lab üzerinden iletişim kurar

set -e
BRIDGE="br-lab"
SUBNET="10.99.0"
N=5

echo "[LAB] Network namespace laboratuvarı kuruluyor..."

# Eski kurulumu temizle
for i in $(seq 1 $N); do
    ip netns del ns-dev${i} 2>/dev/null || true
    ip link del veth${i} 2>/dev/null || true
done
ip link del $BRIDGE 2>/dev/null || true

# Bridge oluştur
ip link add $BRIDGE type bridge
ip link set $BRIDGE up
ip addr add ${SUBNET}.1/24 dev $BRIDGE

# IP forwarding ve NAT
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s ${SUBNET}.0/24 ! -d ${SUBNET}.0/24 -j MASQUERADE 2>/dev/null || true

MACS=("aa:bb:cc:11:22:01" "aa:bb:cc:11:22:02" "aa:bb:cc:11:22:03" "aa:bb:cc:11:22:04" "de:ad:be:ef:ca:fe")
NAMES=("iPhone" "Laptop" "SmartTV" "Tablet" "Attacker")

for i in $(seq 1 $N); do
    idx=$((i-1))
    NS="ns-dev${i}"
    MAC="${MACS[$idx]}"
    IP="${SUBNET}.1${i}"

    ip netns add $NS
    ip link add veth${i} type veth peer name veth${i}p
    ip link set veth${i} master $BRIDGE
    ip link set veth${i} up
    ip link set veth${i}p netns $NS

    ip netns exec $NS ip link set lo up
    ip netns exec $NS ip link set veth${i}p name eth0
    ip netns exec $NS ip link set eth0 address $MAC
    ip netns exec $NS ip addr add ${IP}/24 dev eth0
    ip netns exec $NS ip link set eth0 up
    ip netns exec $NS ip route add default via ${SUBNET}.1

    echo "  [OK] ns-dev${i} | ${NAMES[$idx]} | ${IP} | ${MAC}"
done

echo ""
echo "[LAB] Kurulum tamamlandi!"
echo "[LAB] SENTINEL baslat: sudo python3 sentinel.py --interface $BRIDGE"
echo "[LAB] Trafik uret:     python3 lab_traffic.py"
echo "[LAB] Temizlik:        bash lab_teardown.sh"
