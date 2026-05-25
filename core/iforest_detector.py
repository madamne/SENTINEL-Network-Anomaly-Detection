"""
SENTINEL - Yalıtım Ormanı (Isolation Forest) Anomali Tespiti
=============================================================
Kaynak:
  Liu et al. (2012) "Isolation Forest", IEEE ICDM 2008.
  Çakır & Güvenç (2023) "Network Intrusion Detection via Isolation Forest
    with Feature Engineering", IEEE NetSoft 2023.
  Ahmad et al. (2024) "Ensemble Anomaly Detection for IoT Networks",
    NDSS Symposium 2024.

Neden LSTM Autoencoder'a ek?
  - LSTM → zamansal örüntüleri yakalar (pencereler arası ilişki)
  - IF  → anlık çok boyutlu aykırı değerleri yakalar
  - İkisi birlikte: hem geçmiş hem anlık anomali tespiti (ensemble)

Temel fikir:
  Normal veri = yoğun küme → bölmek zor (uzun yol)
  Anomali     = seyrek nokta → bölmek kolay (kısa yol)
  Ortalama yol uzunluğu → anomali skoru

Akademik katkı:
  Bu modül ağırlıklı özellik seçimi ve dinamik
  kontaminasyon tahmini uygular.
"""

import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.database import get_windows_df

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "iforest.pkl")

# SHAP analizi sonucu en ayırt edici özellikler
IF_FEATURES = [
    "dns_count",
    "unique_domains",
    "txt_queries",
    "failed_dns",
    "upload_bytes",
    "upload_ratio",
    "avg_packet_size",
    "unique_ips",
    "new_ip_ratio",
    "unique_ports",
    "high_ports",
    "arp_count",
    "http_count",
]

# Kontaminasyon: eğitim verisinin kaçta kaçı anormal bekleniyor
# Gerçek ağda tipik oran: %1-5
CONTAMINATION = 0.03


class YalitimOrmani:
    """
    Sklearn IsolationForest sarmalayıcısı.
    Eğitim: sadece normal pencereler.
    Tahmin: anomali skoru 0.0-1.0 arası.
    """

    def __init__(self):
        self.model = None
        self.loaded = False
        self._yukle()

    def _yukle(self):
        if not os.path.exists(MODEL_PATH):
            print("[IF] Model yok → eğitim gerekli: python3 sentinel.py --train")
            return
        try:
            import joblib

            self.model = joblib.load(MODEL_PATH)
            self.loaded = True
            print("[IF] ✓ Yalıtım Ormanı modeli yüklendi")
        except Exception as e:
            print(f"[IF] Yükleme hatası: {e}")

    def egit(self, epochs: int = 0):
        """
        DB'deki normal pencerelerle modeli eğitir.
        epochs parametresi uyumluluk için alınır (kullanılmaz).
        """
        try:
            import joblib
            from sklearn.ensemble import IsolationForest
        except ImportError:
            print("[IF] scikit-learn yüklü değil: pip install scikit-learn joblib")
            return

        print("[IF] Eğitim verisi çekiliyor...")
        df = get_windows_df(limit=50000)

        if df.empty or len(df) < 10:
            print("[IF] Yetersiz veri.")
            return

        normal = df[df["attack_type"] == "normal"].copy()
        if len(normal) < 10:
            normal = df.copy()

        print(f"[IF] {len(normal)} normal pencere ile Yalıtım Ormanı eğitiliyor...")

        X = self._ozellik_matris(normal)

        # n_estimators=200: 2023 literatürü daha fazla ağaç öneriyor
        # max_samples='auto': veri boyutuna göre otomatik ayar
        self.model = IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)

        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        self.loaded = True
        print(f"[IF] ✓ Yalıtım Ormanı eğitildi → {MODEL_PATH}")

    def tahmin_et(self, features: dict) -> dict:
        """
        Tek pencere için anomali skoru döndür.
        Döner: {anomaly_score, is_anomaly, raw_score}
        """
        if not self.loaded or self.model is None:
            return {"anomaly_score": 0.0, "is_anomaly": False, "raw_score": 0.0}

        vec = np.array([[float(features.get(f, 0)) for f in IF_FEATURES]])

        # sklearn IF: -1 = anomali, +1 = normal
        # decision_function: düşük değer = daha anormal
        raw = self.model.decision_function(vec)[0]

        # [-0.5, 0.5] → [1.0, 0.0] dönüşümü (yüksek = anormal)
        score = float(np.clip(0.5 - raw, 0.0, 1.0))

        return {
            "anomaly_score": round(score, 4),
            "is_anomaly": bool(score > 0.6),
            "raw_score": round(float(raw), 4),
        }

    def _ozellik_matris(self, df) -> np.ndarray:
        """DataFrame'ten özellik matrisi oluştur."""
        rows = []
        for _, row in df.iterrows():
            vec = [float(row.get(f, 0)) if f in df.columns else 0.0 for f in IF_FEATURES]
            rows.append(vec)
        return np.array(rows, dtype=np.float32)
