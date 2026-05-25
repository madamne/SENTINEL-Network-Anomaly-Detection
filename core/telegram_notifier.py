"""
SENTINEL - Telegram Bildirim Modülü
=====================================
Saldırı tespitinde Telegram üzerinden anlık Türkçe bildirim gönderir.

Özellikler:
  - Cihaz başına 60s cooldown (aynı MAC'ten spam önlenir)
  - Non-blocking: daemon thread ile ana döngüyü durdurmaz
  - Retry: başarısızlıkta 2 deneme daha yapar
  - Bağlantı yoksa sessizce geçer (demo kesintisiz devam eder)
"""

import threading
import time
from datetime import datetime

import requests

# ── Yapılandırma ─────────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = "8873055379:AAHBXP24SFtWDcohmIS3rQ5Bwrx13UWmJhs"
TELEGRAM_CHAT_ID = "8069468806"
TELEGRAM_URL     = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

# Cihaz başına minimum bildirim aralığı (saniye)
COOLDOWN_SANIYE = 60

# ── Saldırı tipi Türkçe eşleştirme ───────────────────────────────────────────
SALDIRI_TR = {
    "exfiltration":    "🚨 Veri Sızdırma",
    "port_scan":       "🔍 Port Taraması",
    "dns_tunnel":      "🕳️  DNS Tünelleme",
    "lateral":         "🔄 Yanal Hareket",
    "lateral_movement":"🔄 Yanal Hareket",
    "c2_beacon":       "📡 C2 Beacon (Zararlı Yazılım)",
    "after_hours":     "🌙 Mesai Dışı Anomali",
    "normal":          "✅ Normal",
}

# ── Cooldown takibi ───────────────────────────────────────────────────────────
_son_bildirim: dict = {}   # {mac: unix_timestamp}
_kilit = threading.Lock()


def _cooldown_bekle(mac: str) -> bool:
    """True dönerse bildirim gönderilmeli, False ise cooldown'da."""
    with _kilit:
        simdi = time.time()
        son = _son_bildirim.get(mac, 0)
        if simdi - son < COOLDOWN_SANIYE:
            return False
        _son_bildirim[mac] = simdi
        return True


def _mesaj_olustur(mac: str, saldiri_tipi: str, skor: float, ts: float) -> str:
    """Telegram için Türkçe mesaj metni oluştur."""
    saat_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    tarih_str = datetime.fromtimestamp(ts).strftime("%d.%m.%Y")
    saldiri_label = SALDIRI_TR.get(saldiri_tipi.lower(), f"⚠️ {saldiri_tipi}")
    risk_pct = int(skor * 100)

    # Risk seviyesi göstergesi
    if risk_pct >= 85:
        risk_bar = "🔴🔴🔴🔴🔴"
        seviye   = "KRİTİK"
    elif risk_pct >= 75:
        risk_bar = "🟠🟠🟠🟠⚪"
        seviye   = "YÜKSEK"
    else:
        risk_bar = "🟡🟡🟡⚪⚪"
        seviye   = "ORTA"

    return (
        f"🔴 *SENTINEL UYARISI*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📍 *Cihaz:* `{mac}`\n"
        f"⚠️ *Saldırı:* {saldiri_label}\n"
        f"📊 *Risk Skoru:* %{risk_pct}  {risk_bar}\n"
        f"🎯 *Seviye:* {seviye}\n"
        f"🕐 *Saat:* {saat_str}\n"
        f"📅 *Tarih:* {tarih_str}\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"_SENTINEL Ağ Koruma Sistemi_"
    )


def _gonder_istegi(mesaj: str, deneme: int = 3) -> bool:
    """Telegram API'ye POST atar, başarısızlıkta retry."""
    for i in range(deneme):
        try:
            r = requests.post(
                TELEGRAM_URL,
                json={
                    "chat_id":    TELEGRAM_CHAT_ID,
                    "text":       mesaj,
                    "parse_mode": "Markdown",
                },
                timeout=5,
            )
            if r.status_code == 200 and r.json().get("ok"):
                return True
            # Hız sınırı (429) → bekle
            if r.status_code == 429:
                time.sleep(2 * (i + 1))
        except Exception:
            if i < deneme - 1:
                time.sleep(1)
    return False


def bildirim_gonder(mac: str, saldiri_tipi: str, skor: float, ts: float = None):
    """
    Saldırı tespitinde çağrılır.
    Non-blocking: daemon thread içinde çalışır.

    Kullanım (sentinel.py'den):
        from core.telegram_notifier import bildirim_gonder
        bildirim_gonder(mac, attack_type, final, ts)
    """
    if ts is None:
        ts = time.time()

    def _gonder():
        if not _cooldown_bekle(mac):
            return   # Bu cihaz için cooldown aktif
        mesaj = _mesaj_olustur(mac, saldiri_tipi, skor, ts)
        basari = _gonder_istegi(mesaj)
        if basari:
            print(f"[Telegram] ✓ Bildirim gönderildi → {saldiri_tipi.upper()} | {mac}")
        else:
            print(f"[Telegram] ✗ Bildirim gönderilemedi (ağ hatası)")

    threading.Thread(target=_gonder, daemon=True).start()


def baglanti_test():
    """
    Başlangıçta token/chat_id doğrula.
    Döner: (bool, mesaj_str)
    """
    try:
        r = requests.get(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getMe",
            timeout=5,
        )
        if r.status_code == 200 and r.json().get("ok"):
            bot_adi = r.json()["result"]["first_name"]
            return True, f"@{r.json()['result']['username']} ({bot_adi})"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)
