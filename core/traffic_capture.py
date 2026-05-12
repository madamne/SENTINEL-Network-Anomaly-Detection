"""
SENTINEL - Traffic Capture Engine
==================================
Ev ağındaki DNS, ARP, HTTP trafiğini yakalar.
Her cihaz için 5 dakikalık pencerede 18 özellik hesaplar.

Çalışma mantığı:
  1. wlan0mon ile ağdaki tüm paketleri dinle (monitor mode)
  2. Her paketi parse et → packets tablosuna kaydet
  3. Her 5 dakikada bir → o cihazın trafiğini özetle
  4. 18 özelliği hesapla → traffic_windows tablosuna kaydet
  5. AI motoruna gönder
"""

import os
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.database import init_db, insert_packet, insert_window, upsert_device

# ── Sabitler ─────────────────────────────────────────────────────────────────
WINDOW_SECONDS = 300  # 5 dakikalık pencere
ALERT_THRESHOLD = 0.65  # Anomali eşiği

# Bilinen iç ağ IP aralıkları (bunlar dışındaki = dış trafik)
PRIVATE_RANGES = [
    "192.168.",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "127.",
    "169.254.",
]


def is_private(ip: str) -> bool:
    return any(ip.startswith(r) for r in PRIVATE_RANGES)


def make_device_id(mac: str) -> str:
    return f"SEN-{abs(hash(mac)) % 9999:04d}"


# ── Paket Tamponu ─────────────────────────────────────────────────────────────
# Her cihazın son 5 dakikadaki paketleri burada birikir
# {mac: [paket_listesi]}
_buffer: dict = defaultdict(list)
_buffer_lock = threading.Lock()
_known_ips: set = set()  # Daha önce görülen IP'ler


# ── Paket Parser ─────────────────────────────────────────────────────────────
def _parse_packet(pkt) -> dict | None:
    """
    Scapy paketini alır, anlamlı alanlara dönüştürür.
    None dönerse paketi işleme.
    """
    try:
        from scapy.all import ARP, DNS, IP, TCP, UDP, Raw

        result = {
            "ts": time.time(),
            "src_mac": "",
            "src_ip": "",
            "dst_ip": "",
            "protocol": "OTHER",
            "length": len(pkt),
            "dns_query": "",
            "port": 0,
            "is_upload": False,
            "is_download": False,
        }

        # MAC adresi
        if hasattr(pkt, "src"):
            result["src_mac"] = str(pkt.src)

        # IP katmanı
        if pkt.haslayer(IP):
            result["src_ip"] = pkt[IP].src
            result["dst_ip"] = pkt[IP].dst

            # Upload mu download mu?
            # Cihaz → dış dünya = upload
            # Dış dünya → cihaz = download
            if not is_private(result["dst_ip"]):
                result["is_upload"] = True
            elif not is_private(result["src_ip"]):
                result["is_download"] = True

        # ARP (ağ keşfi)
        if pkt.haslayer(ARP):
            result["protocol"] = "ARP"
            result["src_mac"] = pkt[ARP].hwsrc
            result["src_ip"] = pkt[ARP].psrc
            result["dst_ip"] = pkt[ARP].pdst
            return result

        # DNS (alan adı sorguları)
        if pkt.haslayer(DNS):
            result["protocol"] = "DNS"
            result["port"] = 53
            try:
                if pkt[DNS].qd:
                    query = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    result["dns_query"] = query
                    # TXT sorgusu mu? (veri sızdırma tekniği)
                    if pkt[DNS].qd.qtype == 16:
                        result["protocol"] = "DNS_TXT"
                # Cevap yoksa → başarısız sorgu
                if pkt[DNS].ancount == 0 and pkt[DNS].qr == 1:
                    result["protocol"] = "DNS_FAIL"
            except Exception:
                pass
            return result

        # HTTP (şifresiz web)
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            result["port"] = dport

            if dport == 80 or sport == 80:
                result["protocol"] = "HTTP"
            elif dport == 443 or sport == 443:
                result["protocol"] = "HTTPS"
            elif dport > 1024:
                result["protocol"] = "HIGH_PORT"
            else:
                result["protocol"] = "TCP"

            return result

        # UDP
        if pkt.haslayer(UDP):
            result["protocol"] = "UDP"
            result["port"] = pkt[UDP].dport
            return result

        return result

    except Exception:
        return None


# ── 18 Özellik Hesaplayıcı ───────────────────────────────────────────────────
def _compute_features(mac: str, ip: str, packets: list) -> dict:
    """
    Bir cihazın 5 dakikalık paket listesinden
    18 davranışsal özellik çıkarır.
    """
    now = datetime.now()

    # Boş pencere kontrolü
    if not packets:
        return _empty_window(mac, ip, now)

    # ── Zaman özellikleri ─────────────────────────────────────
    hour = now.hour
    is_weekend = 1 if now.weekday() >= 5 else 0

    # ── DNS özellikleri ───────────────────────────────────────
    dns_pkts = [p for p in packets if "DNS" in p["protocol"]]
    dns_count = len(dns_pkts)
    domains = [p["dns_query"] for p in dns_pkts if p["dns_query"]]
    unique_domains = len(set(domains))

    # Dış domain oranı (google.com gibi = normal, rastgele = şüpheli)
    external_domains = [d for d in domains if not is_private_domain(d)]
    external_ratio = len(external_domains) / max(dns_count, 1)

    # TXT sorguları (DNS tünelleme / veri sızdırma işareti)
    txt_queries = len([p for p in packets if p["protocol"] == "DNS_TXT"])

    # Başarısız DNS sorguları (var olmayan domainler → keşif işareti)
    failed_dns = len([p for p in packets if p["protocol"] == "DNS_FAIL"])

    # ── Trafik özellikleri ────────────────────────────────────
    upload_bytes = sum(p["length"] for p in packets if p["is_upload"])
    download_bytes = sum(p["length"] for p in packets if p["is_download"])
    total_bytes = upload_bytes + download_bytes

    upload_ratio = upload_bytes / max(total_bytes, 1)
    avg_packet_size = total_bytes / max(len(packets), 1)

    # ── Bağlantı özellikleri ──────────────────────────────────
    dst_ips = [p["dst_ip"] for p in packets if p["dst_ip"]]
    unique_ips = len(set(dst_ips))

    # Daha önce hiç görülmemiş IP'ler (yeni hedefler = şüpheli)
    new_ips = [ip for ip in set(dst_ips) if ip not in _known_ips]
    new_ip_ratio = len(new_ips) / max(unique_ips, 1)
    _known_ips.update(dst_ips)
    if len(_known_ips) > 10000:
        remove = list(_known_ips)[: len(_known_ips) // 2]
        _known_ips.difference_update(remove)

    ports = [p["port"] for p in packets if p["port"] > 0]
    unique_ports = len(set(ports))
    high_ports = len([p for p in ports if p > 1024])

    # ── Protokol özellikleri ──────────────────────────────────
    http_count = len([p for p in packets if p["protocol"] == "HTTP"])
    https_count = len([p for p in packets if p["protocol"] == "HTTPS"])
    arp_count = len([p for p in packets if p["protocol"] == "ARP"])

    return {
        "ts": time.time(),
        "device_mac": mac,
        "device_ip": ip,
        # Zaman
        "hour": hour,
        "is_weekend": is_weekend,
        # DNS
        "dns_count": dns_count,
        "unique_domains": unique_domains,
        "external_ratio": round(external_ratio, 3),
        "txt_queries": txt_queries,
        "failed_dns": failed_dns,
        # Trafik
        "upload_bytes": upload_bytes,
        "download_bytes": download_bytes,
        "upload_ratio": round(upload_ratio, 3),
        "avg_packet_size": round(avg_packet_size, 1),
        # Bağlantı
        "unique_ips": unique_ips,
        "new_ip_ratio": round(new_ip_ratio, 3),
        "unique_ports": unique_ports,
        "high_ports": high_ports,
        # Protokol
        "http_count": http_count,
        "https_count": https_count,
        "arp_count": arp_count,
        # AI alanları (sonra doldurulacak)
        "anomaly_score": 0.0,
        "is_anomaly": 0,
        "attack_type": "normal",
        "shap_json": {},
    }


def _empty_window(mac, ip, now):
    return {
        "ts": time.time(),
        "device_mac": mac,
        "device_ip": ip,
        "hour": now.hour,
        "is_weekend": 1 if now.weekday() >= 5 else 0,
        "dns_count": 0,
        "unique_domains": 0,
        "external_ratio": 0.0,
        "txt_queries": 0,
        "failed_dns": 0,
        "upload_bytes": 0,
        "download_bytes": 0,
        "upload_ratio": 0.0,
        "avg_packet_size": 0.0,
        "unique_ips": 0,
        "new_ip_ratio": 0.0,
        "unique_ports": 0,
        "high_ports": 0,
        "http_count": 0,
        "https_count": 0,
        "arp_count": 0,
        "anomaly_score": 0.0,
        "is_anomaly": 0,
        "attack_type": "normal",
        "shap_json": {},
    }


def is_private_domain(domain: str) -> bool:
    """Bilinen büyük domainler normal kabul edilir."""
    known = [
        "google",
        "youtube",
        "netflix",
        "instagram",
        "twitter",
        "facebook",
        "microsoft",
        "apple",
        "amazon",
        "spotify",
        "whatsapp",
        "telegram",
        "tiktok",
        "reddit",
        "github",
    ]
    return any(k in domain.lower() for k in known)


# ── Pencere İşleyici ─────────────────────────────────────────────────────────
def _window_loop(callback=None):
    """
    Her WINDOW_SECONDS saniyede bir tamponu boşaltır,
    her cihaz için özellik vektörü hesaplar.
    """
    while True:
        time.sleep(WINDOW_SECONDS)

        with _buffer_lock:
            snapshot = dict(_buffer)
            _buffer.clear()

        for mac, packets in snapshot.items():
            if not packets:
                continue

            # Cihazın IP'sini bul
            ip = next((p["src_ip"] for p in packets if p["src_ip"]), "")

            # Cihazı kaydet
            upsert_device(mac, ip, make_device_id(mac), time.time())

            # 18 özelliği hesapla
            features = _compute_features(mac, ip, packets)

            # Veritabanına kaydet
            insert_window(features)

            print(
                f"[Capture] {make_device_id(mac)} | "
                f"{len(packets)} paket | "
                f"DNS:{features['dns_count']} | "
                f"UP:{features['upload_bytes']//1024}KB | "
                f"Domains:{features['unique_domains']}"
            )

            # AI motoruna gönder
            if callback:
                callback(features)


# ── Ana Capture Sınıfı ───────────────────────────────────────────────────────
class TrafficCapture:
    """
    Gerçek mod: wlan0mon ile ev ağını dinle
    """

    def __init__(self, interface="wlan0mon", callback=None):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.stats = {"packets": 0, "dns": 0, "http": 0, "arp": 0}
        init_db()

    def _on_packet(self, pkt):
        rec = _parse_packet(pkt)
        if not rec or not rec["src_mac"]:
            return

        mac = rec["src_mac"]

        # Tampona ekle
        with _buffer_lock:
            _buffer[mac].append(rec)

        # Ham paketi DB'ye kaydet
        insert_packet(
            rec["ts"],
            rec["src_mac"],
            rec["src_ip"],
            rec["dst_ip"],
            rec["protocol"],
            rec["length"],
            rec["dns_query"],
            rec["port"],
        )

        # İstatistik
        self.stats["packets"] += 1
        if "DNS" in rec["protocol"]:
            self.stats["dns"] += 1
        if rec["protocol"] == "HTTP":
            self.stats["http"] += 1
        if rec["protocol"] == "ARP":
            self.stats["arp"] += 1

    def start(self):
        from scapy.all import sniff

        self.running = True

        # Pencere işleyici thread
        wt = threading.Thread(target=_window_loop, args=(self.callback,), daemon=True)
        wt.start()

        # Scapy sniffer
        print(f"[SENTINEL] ✓ {self.interface} dinleniyor...")
        print(f"[SENTINEL] Her {WINDOW_SECONDS//60} dakikada özellik hesaplanacak")

        try:
            sniff(
                iface=self.interface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: not self.running,
                filter="ip or arp",  # Sadece IP ve ARP paketleri
            )
        except Exception as e:
            print(f"[Capture] Hata: {e}")

    def stop(self):
        self.running = False


# ── Demo Capture ─────────────────────────────────────────────────────────────
class DemoCapture:
    """
    Demo mod: Gerçek adaptör olmadan simüle edilmiş
    ev ağı trafiği üretir. Sunum için kullanılır.
    """

    import random as _r

    def __init__(self, callback=None):
        self.callback = callback
        self.running = False
        self.stats = {"packets": 0, "dns": 0, "http": 0, "arp": 0}
        init_db()

        # Simüle ev ağı cihazları
        self.devices = [
            {
                "mac": "aa:bb:cc:11:22:33",
                "ip": "192.168.1.10",
                "name": "iPhone (Sen)",
                "pattern": "normal",
            },
            {
                "mac": "de:ad:be:ef:00:01",
                "ip": "192.168.1.11",
                "name": "Samsung (Anne)",
                "pattern": "normal",
            },
            {
                "mac": "11:22:33:44:55:66",
                "ip": "192.168.1.12",
                "name": "Laptop (Baba)",
                "pattern": "normal",
            },
            {
                "mac": "ff:ee:dd:cc:bb:aa",
                "ip": "192.168.1.13",
                "name": "Smart TV",
                "pattern": "normal",
            },
            {
                "mac": "aa:11:bb:22:cc:33",
                "ip": "192.168.1.20",
                "name": "⚠ Şüpheli Cihaz",
                "pattern": "attack",
            },
        ]

    def _gen_normal(self, dev: dict) -> dict:
        import random

        now = datetime.now()
        hour = now.hour

        # Gece saatlerinde az trafik
        mult = 0.1 if hour < 6 else 0.3 if hour < 8 else 1.0

        return {
            "ts": time.time(),
            "device_mac": dev["mac"],
            "device_ip": dev["ip"],
            "hour": hour,
            "is_weekend": 1 if now.weekday() >= 5 else 0,
            "dns_count": int(random.randint(5, 30) * mult),
            "unique_domains": int(random.randint(3, 15) * mult),
            "external_ratio": round(random.uniform(0.6, 0.9), 3),
            "txt_queries": 0,
            "failed_dns": random.randint(0, 2),
            "upload_bytes": int(random.randint(10, 500) * 1024 * mult),
            "download_bytes": int(random.randint(100, 5000) * 1024 * mult),
            "upload_ratio": round(random.uniform(0.05, 0.25), 3),
            "avg_packet_size": round(random.uniform(200, 800), 1),
            "unique_ips": random.randint(2, 10),
            "new_ip_ratio": round(random.uniform(0, 0.2), 3),
            "unique_ports": random.randint(2, 8),
            "high_ports": random.randint(0, 3),
            "http_count": random.randint(0, 5),
            "https_count": random.randint(5, 40),
            "arp_count": random.randint(0, 3),
            "anomaly_score": 0.0,
            "is_anomaly": 0,
            "attack_type": "normal",
            "shap_json": {},
        }

    def _gen_attack(self, dev: dict, attack_type: str) -> dict:
        import random

        now = datetime.now()
        base = self._gen_normal(dev)

        if attack_type == "exfiltration":
            # Veri sızdırma: anormal upload
            base.update(
                {
                    "upload_bytes": random.randint(50, 200) * 1024 * 1024,
                    "upload_ratio": round(random.uniform(0.7, 0.95), 3),
                    "dns_count": random.randint(100, 300),
                    "txt_queries": random.randint(20, 80),
                    "unique_domains": random.randint(50, 150),
                    "attack_type": "exfiltration",
                }
            )
        elif attack_type == "port_scan":
            # Port taraması: çok sayıda port ve IP
            base.update(
                {
                    "unique_ports": random.randint(100, 500),
                    "high_ports": random.randint(80, 400),
                    "unique_ips": random.randint(30, 100),
                    "new_ip_ratio": round(random.uniform(0.7, 0.99), 3),
                    "arp_count": random.randint(50, 200),
                    "attack_type": "port_scan",
                }
            )
        elif attack_type == "dns_tunnel":
            # DNS tünelleme: çok TXT sorgusu
            base.update(
                {
                    "dns_count": random.randint(200, 500),
                    "txt_queries": random.randint(100, 300),
                    "unique_domains": random.randint(100, 400),
                    "failed_dns": random.randint(50, 200),
                    "attack_type": "dns_tunnel",
                }
            )
        elif attack_type == "lateral":
            # Yanal hareket: iç ağda dolaşım
            base.update(
                {
                    "unique_ips": random.randint(20, 50),
                    "new_ip_ratio": round(random.uniform(0.6, 0.9), 3),
                    "arp_count": random.randint(100, 300),
                    "unique_ports": random.randint(50, 150),
                    "external_ratio": round(random.uniform(0.0, 0.1), 3),
                    "attack_type": "lateral_movement",
                }
            )
        return base

    def _loop(self):
        import random

        attack_types = ["exfiltration", "port_scan", "dns_tunnel", "lateral"]
        tick = 0

        while self.running:
            for dev in self.devices:
                if dev["pattern"] == "normal":
                    features = self._gen_normal(dev)
                else:
                    # Şüpheli cihaz: her 3 pencerede bir saldırı
                    if tick % 3 == 0:
                        atype = random.choice(attack_types)
                        features = self._gen_attack(dev, atype)
                    else:
                        features = self._gen_normal(dev)

                upsert_device(dev["mac"], dev["ip"], make_device_id(dev["mac"]), time.time())
                insert_window(features)
                self.stats["packets"] += random.randint(50, 200)

                if self.callback:
                    self.callback(features)

            tick += 1
            print(f"[Demo] Pencere {tick} işlendi — " f"{len(self.devices)} cihaz")
            time.sleep(8)  # Demo'da 8 saniyede bir güncelle

    def start(self):
        self.running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print("[SENTINEL] Demo mod aktif")
        print("[SENTINEL] 5 simüle cihaz: 4 normal, 1 saldırgan")

    def stop(self):
        self.running = False
