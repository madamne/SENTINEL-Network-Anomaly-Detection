"""
SENTINEL - SHAP Açıklanabilirlik Modülü (DEVRE DIŞI)
=====================================================
Bu modül devre dışı bırakılmıştır.
SHAPExplainer artık stub olarak çalışır — dış bağımlılık gerektirmez.
"""

ATTACK_TR = {
    "exfiltration": "Veri Sızdırma",
    "dns_tunnel": "DNS Tünelleme",
    "port_scan": "Port Taraması",
    "lateral_movement": "Yanal Hareket",
    "after_hours": "Mesai Dışı Anomali",
    "normal": "Normal",
}

ANOMALY_THRESH = 0.55


class SHAPExplainer:
    """
    Devre dışı stub — dış kütüphane gerektirmez.
    sentinel.py ile uyumlu arayüzü korur.
    """

    def __init__(self, lstm_model=None, scaler=None):
        pass

    def explain(
        self, features: dict, z_scores: dict, anomaly_score: float, attack_type: str
    ) -> dict:
        label = ATTACK_TR.get(attack_type, attack_type)
        hour = features.get("hour", 0)

        if attack_type == "normal":
            verdict = f"Cihaz normal davranış sergiledi. Anomali skoru: {anomaly_score:.2f}"
        else:
            top = sorted(z_scores.items(), key=lambda x: x[1], reverse=True)[:3]
            reasons = ", ".join(f"{k}({v:.1f})" for k, v in top)
            verdict = (
                f"{label} tespit edildi! "
                f"Skor: {anomaly_score:.2f} | "
                f"Saat: {hour}:00 | "
                f"Sebep: {reasons}"
            )

        return {
            "contributions": {},
            "top3": [],
            "verdict": verdict,
            "attack_label": label,
            "anomaly_score": anomaly_score,
            "is_anomaly": anomaly_score > ANOMALY_THRESH,
        }
