"""
SENTINEL - Saldırı Simülatörü
================================
Ne yapar:
  Jüriye canlı demo için 4 farklı saldırı
  senaryosunu simüle eder.

Kullanım:
  python3 sentinel.py --simulate exfiltration
  python3 sentinel.py --simulate port_scan
  python3 sentinel.py --simulate dns_tunnel
  python3 sentinel.py --simulate lateral
"""

import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.database import insert_window, upsert_device

ATTACKS = {
    "exfiltration": "Veri Sızdırma",
    "port_scan": "Port Taraması",
    "dns_tunnel": "DNS Tünelleme",
    "lateral": "Yanal Hareket",
}

TARGET_MAC = "aa:11:bb:22:cc:33"
TARGET_IP = "192.168.1.99"


def _base_window() -> dict:
    """Normal görünen temel pencere — tüm zaman alanları gerçek sistem saati."""
    now = time.localtime()
    real_ts = time.time()
    return {
        "ts": real_ts,
        "device_mac": TARGET_MAC,
        "device_ip": TARGET_IP,
        "hour": now.tm_hour,          # gerçek saat
        "is_weekend": 1 if now.tm_wday >= 5 else 0,  # gerçek gün
        "dns_count": random.randint(5, 20),
        "unique_domains": random.randint(3, 10),
        "external_ratio": round(random.uniform(0.6, 0.85), 3),
        "txt_queries": 0,
        "failed_dns": random.randint(0, 2),
        "upload_bytes": random.randint(10, 100) * 1024,
        "download_bytes": random.randint(100, 500) * 1024,
        "upload_ratio": round(random.uniform(0.05, 0.20), 3),
        "avg_packet_size": round(random.uniform(300, 700), 1),
        "unique_ips": random.randint(2, 8),
        "new_ip_ratio": round(random.uniform(0.0, 0.15), 3),
        "unique_ports": random.randint(2, 6),
        "high_ports": random.randint(0, 2),
        "http_count": random.randint(0, 5),
        "https_count": random.randint(5, 30),
        "arp_count": random.randint(0, 2),
        "anomaly_score": 0.0,
        "is_anomaly": 0,
        "attack_type": "normal",
        "shap_json": {},
    }


def simulate(attack_type: str, callback=None, windows: int = 5):
    """
    Saldırı simülasyonu başlatır.

    attack_type : exfiltration | port_scan | dns_tunnel | lateral
    callback    : Her pencerede çağrılacak AI fonksiyonu
    windows     : Kaç pencere üretilecek
    """
    label = ATTACKS.get(attack_type, attack_type)
    print(f"\n[Simülatör] ⚡ {label} saldırısı başlatılıyor...")
    print(f"[Simülatör] Hedef: {TARGET_MAC} ({TARGET_IP})")

    upsert_device(TARGET_MAC, TARGET_IP, "SEN-ATTK", time.time())

    result = []
    for i in range(windows):
        w = _base_window()

        if attack_type == "exfiltration":
            # Anormal upload — saat gerçek sistem saatinden alınır (_base_window)
            w.update(
                {
                    "upload_bytes": random.randint(50, 200) * 1024 * 1024,
                    "upload_ratio": round(random.uniform(0.75, 0.95), 3),
                    "dns_count": random.randint(100, 300),
                    "txt_queries": random.randint(20, 80),
                    "attack_type": "exfiltration",
                }
            )

        elif attack_type == "port_scan":
            # Çok sayıda port ve IP taraması
            w.update(
                {
                    "unique_ports": random.randint(500, 1024),
                    "high_ports": random.randint(200, 800),
                    "unique_ips": random.randint(50, 150),
                    "new_ip_ratio": round(random.uniform(0.80, 0.99), 3),
                    "arp_count": random.randint(100, 400),
                    "attack_type": "port_scan",
                }
            )

        elif attack_type == "dns_tunnel":
            # DNS üzerinden veri sızdırma
            w.update(
                {
                    "dns_count": random.randint(200, 500),
                    "txt_queries": random.randint(100, 300),
                    "unique_domains": random.randint(100, 400),
                    "failed_dns": random.randint(50, 200),
                    "attack_type": "dns_tunnel",
                }
            )

        elif attack_type == "lateral":
            # İç ağda yayılma
            w.update(
                {
                    "unique_ips": random.randint(20, 50),
                    "new_ip_ratio": round(random.uniform(0.6, 0.9), 3),
                    "arp_count": random.randint(100, 300),
                    "unique_ports": random.randint(50, 150),
                    "external_ratio": round(random.uniform(0.0, 0.1), 3),
                    "attack_type": "lateral_movement",
                }
            )

        insert_window(w)
        result.append(w)
        print(f"[Simülatör] Pencere {i+1}/{windows} — {label}")

        if callback:
            callback(w)

        time.sleep(1)

    print(f"[Simülatör] ✓ {label} simülasyonu tamamlandı")
    return result
