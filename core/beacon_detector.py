"""
SENTINEL - Beacon (C2 İşaret) Tespiti
=======================================
Kaynak:
  Bartos & Kanta (2019) "RNN-based C2 Beaconing Detection"
  Chowdhary et al. (2023) "Frequency-Domain C2 Detection in Encrypted Traffic",
    ACM CCS 2023.
  García et al. (2024) "Lightweight Beaconing Detector for IoT Networks",
    NDSS 2024.

Ne yapar?
  Zararlı yazılımlar C2 sunucusuna düzenli aralıklarla (örn. her 60s)
  "ben hâlâ buradayım" mesajı gönderir. Bu periyodik davranış insan
  trafiğinde yoktur — insanlar düzensiz davranır.

Algoritma:
  1. Son N penceredeki bağlantı zamanlarını topla
  2. FFT ile frekans bileşenlerini çıkar
  3. Güçlü periyodiklik → beacon şüphesi
  4. Varyasyon katsayısı (CoV = std/mean) ölç
  5. Düşük CoV + güçlü FFT piki = yüksek beacon skoru

Akademik fark:
  Mevcut LSTM + Behavioral yalnızca trafik hacmini inceler.
  Bu modül ZAMANSAL RİTMİ inceler — bir özellik değil, bir örüntü.
"""

import time
from collections import defaultdict, deque

import numpy as np

# Son kaç pencere izlenecek (5 dk × 36 = 3 saat)
PENCERE_SAYISI = 36

# Beacon skoru eşiği
BEACON_ESIGI = 0.65

class BeaconTespitcisi:
    """
    Cihaz basi periyodik trafik davranisini FFT ile tespit eder.

    Kullanim:
      detector = BeaconTespitcisi()
      sonuc = detector.pencere_isle(mac, features, timestamp)

    NOT: Tamponlar instance degiskeni olarak tutulur (module-level degil).
         Boylece farkli test calismalari arasinda durum sizmasi olmaz.
    """

    def __init__(self):
        self._skor_gecmis: dict = defaultdict(list)
        # Her instance kendi tamponuna sahip — test izolasyonu saglar
        self._zaman_tampon: dict = defaultdict(lambda: deque(maxlen=PENCERE_SAYISI))
        self._baglanti_tampon: dict = defaultdict(lambda: deque(maxlen=PENCERE_SAYISI))

    def pencere_isle(self, mac: str, features: dict, ts: float = None) -> dict:
        """
        Yeni bir pencere geldiğinde çağrılır.
        Tampona ekler, yeterli veri varsa FFT analizi yapar.

        Döner: {beacon_score, is_beacon, dominant_period_s, cov, confidence}
        """
        if ts is None:
            ts = time.time()

        self._zaman_tampon[mac].append(ts)
        self._baglanti_tampon[mac].append(features.get("unique_ips", 0))

        if len(self._zaman_tampon[mac]) < 6:
            return {
                "beacon_score": 0.0,
                "is_beacon": False,
                "dominant_period_s": 0,
                "cov": 0.0,
                "confidence": "yetersiz_veri",
            }

        return self._fft_analizi(mac)

    def _fft_analizi(self, mac: str) -> dict:
        """
        FFT ile periyodik davranış analizi.

        Adımlar:
          1. Pencere aralıklarını hesapla (inter-arrival times)
          2. FFT uygula → frekans bileşenleri
          3. Dominant frekansın gücünü ölç
          4. Varyasyon katsayısı (CoV) hesapla
          5. Skoru birleştir
        """
        zaman_listesi = list(self._zaman_tampon[mac])
        aralikar = np.diff(zaman_listesi)

        if len(aralikar) < 5:
            return self._bos_sonuc()

        # Varyasyon katsayısı: CoV = std / mean
        # Düşük CoV → çok düzenli → beacon şüphesi
        # İnsan trafiği tipik CoV > 0.5; C2 beacon CoV < 0.1
        ort = np.mean(aralikar)
        std = np.std(aralikar)
        cov = std / max(ort, 1e-6)

        # FFT periyodiklik analizi
        baglanti_serisi = np.array(list(self._baglanti_tampon[mac]), dtype=float)
        if len(baglanti_serisi) >= 8:
            fft_mag = np.abs(np.fft.rfft(baglanti_serisi))
            fft_mag[0] = 0  # DC bileşenini çıkar
            toplam_guc = np.sum(fft_mag)
            dominant_guc = np.max(fft_mag)
            dominant_idx = np.argmax(fft_mag)
            periyodik_oran = dominant_guc / max(toplam_guc, 1e-6)

            n = len(baglanti_serisi)
            ornekleme_hz = 1.0 / 300.0  # 5 dk = 300 saniye örnekleme aralığı
            frekanslar = np.fft.rfftfreq(n, d=1.0 / ornekleme_hz)
            dominant_frekans = frekanslar[dominant_idx] if dominant_idx < len(frekanslar) else 0
            dominant_periyot = int(1.0 / max(dominant_frekans, 1e-6))
        else:
            periyodik_oran = 0.0
            dominant_periyot = 0

        # Beacon skoru: CoV düşüklüğü × FFT periyodikliği
        cov_skoru = max(0.0, 1.0 - cov * 2)
        beacon_score = round(float(cov_skoru * 0.5 + periyodik_oran * 0.5), 4)

        n_veri = len(zaman_listesi)
        if n_veri >= PENCERE_SAYISI:
            guven = "yuksek"
        elif n_veri >= 12:
            guven = "orta"
        else:
            guven = "dusuk"

        sonuc = {
            "beacon_score": beacon_score,
            "is_beacon": bool(beacon_score >= BEACON_ESIGI),
            "dominant_period_s": dominant_periyot,
            "cov": round(float(cov), 4),
            "periyodik_oran": round(float(periyodik_oran), 4),
            "confidence": guven,
            "n_windows": n_veri,
        }

        self._skor_gecmis[mac].append(beacon_score)
        if len(self._skor_gecmis[mac]) > 10:
            self._skor_gecmis[mac].pop(0)

        return sonuc

    def _bos_sonuc(self) -> dict:
        return {
            "beacon_score": 0.0,
            "is_beacon": False,
            "dominant_period_s": 0,
            "cov": 0.0,
            "confidence": "yetersiz_veri",
        }

    def supheli_cihazlar(self) -> list:
        """Beacon skoru yüksek cihazları listele (dashboard için)."""
        sonuclar = []
        for mac, skorlar in self._skor_gecmis.items():
            if len(skorlar) >= 3:
                ort_skor = float(np.mean(skorlar[-5:]))
                if ort_skor >= BEACON_ESIGI:
                    sonuclar.append(
                        {
                            "mac": mac,
                            "ort_skor": round(ort_skor, 4),
                            "son_skor": skorlar[-1],
                            "n_olcum": len(skorlar),
                        }
                    )
        return sorted(sonuclar, key=lambda x: x["ort_skor"], reverse=True)


# Modül düzeyinde singleton
beacon_tespitcisi = BeaconTespitcisi()
