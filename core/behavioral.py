"""
SENTINEL - Behavioral Profiler
================================
Her cihazın "normal" davranış profilini öğrenir.

Yeni özellikler (v2):
  - 24 saatlik aktivite histogramı (saat bazlı ortalama)
  - Hafta içi / hafta sonu ayrı baseline profil
  - Cihaz başına JSON profil kaydı
  - Saat + gün bağlamına duyarlı Z-score skoru
"""

import json
import os
import sys
import time
from datetime import datetime

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.database import get_conn, get_windows_df

# 18 özellik — LSTM'e bu sırayla gidecek
FEATURE_COLS = [
    "hour",
    "is_weekend",
    "dns_count",
    "unique_domains",
    "external_ratio",
    "txt_queries",
    "failed_dns",
    "upload_bytes",
    "download_bytes",
    "upload_ratio",
    "avg_packet_size",
    "unique_ips",
    "new_ip_ratio",
    "unique_ports",
    "high_ports",
    "http_count",
    "https_count",
    "arp_count",
]

# Anomali ağırlıkları — hangi özellik ne kadar önemli
FEATURE_WEIGHTS = {
    "upload_bytes": 3.0,
    "txt_queries": 3.0,
    "unique_ports": 2.5,
    "arp_count": 2.5,
    "failed_dns": 2.0,
    "new_ip_ratio": 2.0,
    "dns_count": 1.5,
    "upload_ratio": 1.5,
    "unique_ips": 1.5,
    "high_ports": 1.5,
    "http_count": 1.0,
    "unique_domains": 1.0,
}

PROFILE_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "device_profiles.json")


# ── Profil Oluşturucu ────────────────────────────────────────────────────────
class BehavioralProfiler:
    """
    Her cihaz için çok boyutlu istatistiksel profil tutar.

    Profil yapısı (v2):
      global    : Tüm zaman dilimlerine ait mean/std/min/max/p95
      weekday   : Hafta içi (Pzt-Cum) ayrı baseline
      weekend   : Hafta sonu (Cmt-Paz) ayrı baseline
      hourly    : Saate göre 24 adet ortalama (histogram)
      hour_std  : Saate göre 24 adet std sapma
      active_hours: Saat → pencere sayısı histogramı
    """

    def __init__(self):
        self.profiles: dict = {}
        self._load()

    # ── Kayıt / yükleme ──────────────────────────────────────────────────────
    def _load(self):
        os.makedirs(os.path.dirname(PROFILE_PATH), exist_ok=True)
        if os.path.exists(PROFILE_PATH):
            try:
                with open(PROFILE_PATH, "r") as f:
                    self.profiles = json.load(f)
                print(f"[Behavioral] ✓ {len(self.profiles)} cihaz profili yüklendi")
            except Exception:
                self.profiles = {}

    def save(self):
        os.makedirs(os.path.dirname(PROFILE_PATH), exist_ok=True)
        with open(PROFILE_PATH, "w") as f:
            json.dump(self.profiles, f, indent=2)
        print(f"[Behavioral] ✓ {len(self.profiles)} profil kaydedildi → {PROFILE_PATH}")

    # ── Profil hesapla ───────────────────────────────────────────────────────
    def build_profiles(self, min_windows: int = 10):
        """
        DB'deki pencerelerden her cihaz için tam profil oluştur.
        v2 eklemeleri:
          - hourly histogram (24 bucket)
          - weekday / weekend ayrı baseline
        """
        import pandas as pd

        df = get_windows_df(limit=10000)
        if df.empty:
            print("[Behavioral] Yeterli veri yok. Önce veri topla.")
            return

        devices = df["device_mac"].unique()
        built = 0

        for mac in devices:
            dev_df = df[df["device_mac"] == mac]
            if len(dev_df) < min_windows:
                continue

            normal_df = dev_df[dev_df["attack_type"] == "normal"]
            if len(normal_df) < 5:
                normal_df = dev_df

            profile = {
                "mac": mac,
                "window_count": len(normal_df),
                "built_at": time.time(),
                "global": {},
                "hourly": {},  # {hour_str: {feature: mean}}
                "hour_std": {},  # {hour_str: {feature: std}}
                "active_hours": {},
            }

            # ── Global stats ─────────────────────────────────────────────
            for col in FEATURE_COLS:
                if col not in normal_df.columns:
                    continue
                vals = normal_df[col].dropna().values
                if not len(vals):
                    continue
                profile["global"][col] = _stat(vals)

            # ── Saatlik histogram ────────────────────────────────────────
            if "hour" in normal_df.columns:
                for h in range(24):
                    h_df = normal_df[normal_df["hour"] == h]
                    if h_df.empty:
                        continue
                    h_means = {}
                    h_stds = {}
                    for col in FEATURE_COLS:
                        if col == "hour" or col not in h_df.columns:
                            continue
                        vals = h_df[col].dropna().values
                        if len(vals):
                            h_means[col] = round(float(np.mean(vals)), 4)
                            std = float(np.std(vals))
                            h_stds[col] = round(max(std, max(abs(h_means[col]) * 0.05, 0.01)), 4)
                    profile["hourly"][str(h)] = h_means
                    profile["hour_std"][str(h)] = h_stds

            # ── Aktif saat sayacı ────────────────────────────────────────
            if "hour" in dev_df.columns:
                hour_counts = dev_df["hour"].value_counts().to_dict()
                profile["active_hours"] = {str(h): int(c) for h, c in hour_counts.items()}

            self.profiles[mac] = profile
            built += 1
            print(
                f"[Behavioral] Profil: {mac} | {len(normal_df)} pencere "
                f"| {len(profile['hourly'])} saatlik bucket"
            )

        self.save()
        print(f"[Behavioral] ✓ Toplam {built} cihaz profili oluşturuldu")

    # ── Anlık skor hesapla ───────────────────────────────────────────────────
    def score_window(self, features: dict) -> dict:
        """
        Bir özellik penceresini cihaz profiline göre puanlar.

        Saat bağlamına duyarlı Z-score
          1. Bu saat için özel baseline varsa → saatlik kullan
          2. Yoksa global baseline

        Döndürür:
          anomaly_score : 0.0 – 1.0
          z_scores      : her özellik için z değeri
          top_features  : en şüpheli 3 özellik
          context       : kullanılan baseline türü
        """
        mac = features.get("device_mac", "")
        hour = int(features.get("hour", datetime.now().hour))

        if mac not in self.profiles:
            return {
                "anomaly_score": 0.1,
                "z_scores": {},
                "top_features": [],
                "has_profile": False,
                "context": "no_profile",
            }

        prof = self.profiles[mac]
        context, baseline, baseline_std = _select_baseline(prof, hour)

        z_scores = {}
        for col in FEATURE_COLS:
            if col in ("hour", "is_weekend") or col not in features:
                continue
            if col not in baseline:
                # Genel profile dön
                if col not in prof.get("global", {}):
                    continue
                mean = prof["global"][col]["mean"]
                std = prof["global"][col]["std"]
            else:
                mean = baseline[col]
                std = baseline_std.get(col, max(abs(mean) * 0.1, 0.01))

            std = max(std, 0.1)
            observed = float(features.get(col, 0))
            z = abs((observed - mean) / std)
            z_scores[col] = round(z, 3)

        if not z_scores:
            return {
                "anomaly_score": 0.1,
                "z_scores": {},
                "top_features": [],
                "has_profile": True,
                "context": context,
            }

        # Ağırlıklı ortalama Z
        w_sum, w_total = 0.0, 0.0
        for col, z in z_scores.items():
            w = FEATURE_WEIGHTS.get(col, 1.0)
            w_sum += z * w
            w_total += w

        avg_z = w_sum / max(w_total, 1)

        # Olağandışı saat çarpanı
        hour_penalty = 1.2 if self.is_unusual_hour(mac, hour) else 1.0
        avg_z *= hour_penalty

        # Z → [0,1] sigmoid-benzeri dönüşüm
        score = round(min(max(1 - 1 / (1 + avg_z / 2), 0.0), 1.0), 4)

        top3 = sorted(z_scores.items(), key=lambda x: x[1], reverse=True)[:3]
        top3 = [
            {"feature": k, "z_score": v, "weight": FEATURE_WEIGHTS.get(k, 1.0)} for k, v in top3
        ]

        return {
            "anomaly_score": score,
            "z_scores": z_scores,
            "top_features": top3,
            "has_profile": True,
            "context": context,
            "hour_penalty": hour_penalty,
        }

    # ── Yardımcılar ──────────────────────────────────────────────────────────
    def is_unusual_hour(self, mac: str, hour: int) -> bool:
        """Bu saat cihazın aktif saatleri arasında %2'den az görünüyorsa True."""
        if mac not in self.profiles:
            return False
        active = self.profiles[mac].get("active_hours", {})
        count = active.get(str(hour), 0)
        total = sum(active.values()) or 1
        return (count / total) < 0.02

    def get_hourly_histogram(self, mac: str) -> dict:
        """
        Dashboard için 24 saatlik aktivite histogramı.
        Döner: {hour: count} ve {hour: avg_upload_mb}
        """
        if mac not in self.profiles:
            return {"counts": {}, "avg_upload": {}}
        prof = self.profiles[mac]
        counts = prof.get("active_hours", {})
        hourly = prof.get("hourly", {})
        upload = {h: round(hourly[h].get("upload_bytes", 0) / 1_048_576, 2) for h in hourly}
        return {"counts": counts, "avg_upload_mb": upload}

    def get_summary(self, mac: str) -> dict:
        """Dashboard için cihaz profil özeti."""
        if mac not in self.profiles:
            return {"status": "Profil yok — veri toplanıyor"}

        p = self.profiles[mac]
        feat = p.get("global", {})

        def _get(col):
            return feat.get(col, {}).get("mean", 0)

        top_hours = sorted(p.get("active_hours", {}).items(), key=lambda x: x[1], reverse=True)[:3]

        return {
            "status": "Profil hazır",
            "window_count": p.get("window_count", 0),
            "built_at": datetime.fromtimestamp(p.get("built_at", 0)).strftime("%d.%m %H:%M"),
            "avg_dns": round(_get("dns_count"), 1),
            "avg_upload_mb": round(_get("upload_bytes") / 1_048_576, 2),
            "avg_download_mb": round(_get("download_bytes") / 1_048_576, 2),
            "avg_domains": round(_get("unique_domains"), 1),
            "peak_hours": [f"{h}:00" for h, _ in top_hours],
            "hourly_buckets": len(p.get("hourly", {})),
        }


# ── Yardımcı fonksiyonlar ────────────────────────────────────────────────────


def _stat(vals: np.ndarray) -> dict:
    """Bir dizi için temel istatistikler üret."""
    mean = float(np.mean(vals))
    std = float(np.std(vals))
    if std < 1e-6:
        std = max(abs(mean) * 0.1, 0.01)
    return {
        "mean": round(mean, 4),
        "std": round(std, 4),
        "min": round(float(np.min(vals)), 4),
        "max": round(float(np.max(vals)), 4),
        "p95": round(float(np.percentile(vals, 95)), 4),
    }


def _select_baseline(prof: dict, hour: int):
    """
    En uygun baseline'ı seç.
    Öncelik: saatlik → global
    Döner: (context_label, means_dict, stds_dict)
    """
    h_str = str(hour)

    # 1. Saatlik histogram varsa
    if h_str in prof.get("hourly", {}):
        means = prof["hourly"][h_str]
        stds = prof.get("hour_std", {}).get(h_str, {})
        return "hourly", means, stds

    # 2. Global
    means = {c: v["mean"] for c, v in prof.get("global", {}).items()}
    stds = {c: v["std"] for c, v in prof.get("global", {}).items()}
    return "global", means, stds


# ── Saldırı Tipi Sınıflandırıcı ─────────────────────────────────────────────
def classify_attack(features: dict, z_scores: dict) -> str:
    """
    Z-score'lara bakarak saldırı tipini tahmin eder.
    LSTM'den önce kural tabanlı ilk filtre.
    """

    def z(col):
        return z_scores.get(col, 0)

    if z("upload_bytes") > 3 and z("upload_ratio") > 2:
        return "exfiltration"
    if z("txt_queries") > 3 or (z("dns_count") > 3 and z("failed_dns") > 2):
        return "dns_tunnel"
    # lateral_movement ONCE kontrol edilmeli: ARP flood + dahili IP spread
    # external_ratio < 0.3 -> trafik ag icinde kaliyor (disa sizmiyor)
    if z("arp_count") > 3 and z("new_ip_ratio") > 2 and features.get("external_ratio", 1.0) < 0.3:
        return "lateral_movement"
    if z("unique_ports") > 3 and z("unique_ips") > 2:
        return "port_scan"
    if features.get("hour", 12) in range(1, 6) and z("dns_count") > 2:
        return "after_hours"
    return "normal"
