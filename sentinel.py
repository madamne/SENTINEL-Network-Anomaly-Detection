"""
SENTINEL - Ana Başlatıcı
=========================
Kullanım:
  Demo:      python3 sentinel.py --demo
  Gerçek:    sudo python3 sentinel.py --interface wlan0mon
  Eğitim:    python3 sentinel.py --train
  Simülasyon:python3 sentinel.py --simulate exfiltration
"""

import argparse
import os
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))

from core.beacon_detector import beacon_tespitcisi
from core.behavioral import BehavioralProfiler, classify_attack
from core.database import (
    init_db,
    insert_alert,
    update_device_threat,
    update_window_score,
)
from core.iforest_detector import YalitimOrmani
from core.lstm_model import SentinelLSTM
from core.shap_explainer import SHAPExplainer
from core.telegram_notifier import bildirim_gonder, baglanti_test

DASHBOARD_NOTIFY_URL = "http://127.0.0.1:8501/api/internal/notify"


def _telegram_baslangic_kontrol():
    """Uygulama başlarken Telegram bağlantısını doğrula."""
    ok, bilgi = baglanti_test()
    if ok:
        print(f"[Telegram] ✓ Bot hazır: {bilgi}")
    else:
        print(f"[Telegram] ✗ Bağlantı yok: {bilgi} (bildirimler devre dışı)")


def _notify_dashboard():
    """Dashboard broadcaster'ını non-blocking olarak uyarır."""
    try:
        urllib.request.urlopen(
            urllib.request.Request(DASHBOARD_NOTIFY_URL, method="POST"),
            timeout=1,
        )
    except Exception:
        pass


BANNER = """\033[36m
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
\033[33m  Ağ Davranışsal Anomali Tespit Sistemi v2.0
  Bilgisayar Mühendisliği Bitirme Projesi
  Yeni: Yalıtım Ormanı + Beacon/FFT Tespiti\033[0m
"""

UYARI_ESIGI = 0.65

# ── Yapay Zeka Boru Hattı ────────────────────────────────────────────────────
lstm = None
profiler = None
explainer = None
iforest = None


def ai_baslat():
    global lstm, profiler, explainer, iforest
    lstm = SentinelLSTM()
    profiler = BehavioralProfiler()
    explainer = SHAPExplainer(lstm, lstm.scaler)
    iforest = YalitimOrmani()
    print("[SENTINEL] ✓ Yapay zeka motoru hazır (LSTM + IF + Beacon)")
    _telegram_baslangic_kontrol()


def pencere_isle(features: dict):
    """
    Her 5 dakikalık pencere için çağrılır.
    4 katmanlı anomali analizi:
      1. Davranışsal Z-score profili
      2. LSTM Autoencoder yeniden üretim hatası
      3. Yalıtım Ormanı (Isolation Forest) çok boyutlu aykırı değer
      4. Beacon/FFT periyodik davranış analizi
    """
    mac = features.get("device_mac", "unknown")
    ts = features.get("ts", time.time())

    # Katman 1: Davranışsal Z-score profili
    behavioral = profiler.score_window(features)
    z_scores = behavioral.get("z_scores", {})

    # Katman 2: LSTM Autoencoder anomali skoru
    lstm_result = lstm.predict(features)
    lstm_score = lstm_result.get("anomaly_score", 0.0)

    # Katman 3: Yalıtım Ormanı skoru
    if_result = iforest.tahmin_et(features)
    if_score = if_result.get("anomaly_score", 0.0)

    # Katman 4: Beacon/FFT periyodik davranış
    beacon_result = beacon_tespitcisi.pencere_isle(mac, features, ts)
    beacon_score = beacon_result.get("beacon_score", 0.0)

    # Saldırı tipi sınıflandır
    attack_type = classify_attack(features, z_scores)
    if attack_type == "normal" and features.get("attack_type", "normal") != "normal":
        attack_type = features["attack_type"]

    # Beacon tespiti → C2 saldırısı olarak işaretle
    if beacon_result.get("is_beacon") and attack_type == "normal":
        attack_type = "c2_beacon"

    # Füzyon: mevcut modellere göre uyarlanabilir ağırlıklı ensemble
    # IF eğitimsizse orijinal 2-katman ağırlıklarına dön (B:0.40 + L:0.60)
    # IF eğitimliyse 4-katman tam ensemble: B:0.30 + L:0.35 + IF:0.25 + BCN:0.10
    # Akademik dayanak: Ensemble Anomaly Detectors (Ahmad et al., NDSS 2024)
    b_score = behavioral.get("anomaly_score", 0.0)
    if iforest and iforest.loaded:
        final = round(b_score * 0.30 + lstm_score * 0.35 + if_score * 0.25 + beacon_score * 0.10, 4)
    else:
        # IF eğitimsiz → 3 katman: B:0.35 + L:0.55 + BCN:0.10
        final = round(b_score * 0.35 + lstm_score * 0.55 + beacon_score * 0.10, 4)

    # SHAP açıklama
    explanation = explainer.explain(features, z_scores, final, attack_type)

    # Veritabanı güncelle
    threat_int = int(final * 100)
    update_device_threat(mac, threat_int, attack_type)
    update_window_score(mac, ts, final, int(final >= UYARI_ESIGI))

    # Uyarı üret
    if final >= UYARI_ESIGI:
        insert_alert(
            ts=ts,
            mac=mac,
            attack_type=attack_type.upper(),
            score=final,
            details=explanation["verdict"],
        )
        threading.Thread(target=_notify_dashboard, daemon=True).start()
        bildirim_gonder(mac, attack_type, final, ts)
        print(
            f"\033[31m[🔴 UYARI] {mac} | {explanation['attack_label']}"
            f" | Skor:{final:.2f}"
            f" [B:{b_score:.2f} L:{lstm_score:.2f}"
            f" IF:{if_score:.2f} BCN:{beacon_score:.2f}]\033[0m"
        )
        print(f"          Sebep: {explanation['verdict']}")
        if beacon_result.get("is_beacon"):
            print(
                f"          Beacon: {beacon_result['dominant_period_s']}s periyot"
                f" | CoV:{beacon_result['cov']:.3f}"
            )
    else:
        print(
            f"\033[32m[✓ Normal] {mac} | Skor:{final:.2f}"
            f" [B:{b_score:.2f} L:{lstm_score:.2f} IF:{if_score:.2f} BCN:{beacon_score:.2f}]\033[0m"
        )


def dashboard_baslat():
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "dashboard.api:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8501",
            "--log-level",
            "error",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=os.path.dirname(__file__),
    )
    print("\033[32m[SENTINEL] Dashboard → http://localhost:8501\033[0m")
    return proc


# ── Ana Program ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="wlan0mon")
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--simulate", type=str, default="")
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--no-dashboard", action="store_true")
    args = parser.parse_args()

    print(BANNER)
    init_db()

    # Eğitim modu: LSTM + Yalıtım Ormanı + Behavioral profil
    if args.train:
        ai_baslat()
        lstm.train(epochs=30)
        iforest.egit()
        profiler.build_profiles(min_windows=10)
        print("[SENTINEL] ✓ Tüm modeller eğitildi (LSTM + IF + Behavioral)")
        return

    # Veri toplama modu (48 saat)
    if args.collect:
        print("[SENTINEL] Veri toplama modu — 48 saat çalışacak")
        print("[SENTINEL] Bitince: python3 sentinel.py --train")
        if args.demo:
            from core.traffic_capture import DemoCapture

            cap = DemoCapture(callback=None)
        else:
            from core.traffic_capture import TrafficCapture

            cap = TrafficCapture(interface=args.interface, callback=None)
        cap.start()
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            cap.stop()
        return

    # Simülasyon modu
    if args.simulate:
        ai_baslat()
        from core.simulator import simulate

        simulate(args.simulate, callback=pencere_isle, windows=8)
        return

    # Normal çalışma modu
    dashboard_proc = None
    if not args.no_dashboard:
        dashboard_proc = dashboard_baslat()
        time.sleep(2)

    ai_baslat()

    if args.demo:
        from core.traffic_capture import DemoCapture

        cap = DemoCapture(callback=pencere_isle)
        print("[SENTINEL] Demo mod — 5 simüle cihaz izleniyor")
    else:
        from core.traffic_capture import TrafficCapture

        cap = TrafficCapture(interface=args.interface, callback=pencere_isle)

    cap.start()

    try:
        while True:
            time.sleep(30)
            supheli = beacon_tespitcisi.supheli_cihazlar()
            if supheli:
                print(f"[SENTINEL] Şüpheli beacon: {len(supheli)} cihaz")
            print(f"[SENTINEL] Çalışıyor | Paket: {cap.stats['packets']}")
    except KeyboardInterrupt:
        print("\n[SENTINEL] Durduruluyor...")
        cap.stop()
        if dashboard_proc is not None:
            dashboard_proc.terminate()


if __name__ == "__main__":
    main()

# run_tests.py uyumluluğu için kısayol isimler
# ── run_tests.py uyumluluk alias'lari ────────────────────────────────────────
# run_tests.py bu isimlerle import eder; fonksiyon isimleri degistirilmeden
# uyumluluk saglanir. Yeni kod icin dogrudan ai_baslat/pencere_isle kullanin.
ALERT_THRESHOLD = UYARI_ESIGI   # = 0.65
init_ai = ai_baslat              # AI modellerini yukler
on_window = pencere_isle         # Her trafik penceresi icin islem yapar
