"""
SENTINEL - LLM Analisti (Claude API)
Anomali tespitlerini Türkçe doğal dil açıklamasına çevirir.
API key yoksa kural tabanlı açıklama üretir.
"""

import json
import os
import time

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

ATTACK_LABELS = {
    "port_scan": "Port Taraması",
    "dns_tunnel": "DNS Tünelleme",
    "exfiltration": "Veri Sızdırma",
    "lateral_movement": "Yanal Hareket",
    "normal": "Normal Trafik",
}

_RULE_TEMPLATES = {
    "port_scan": {
        "aciklama": (
            "Cihaz {unique_ports} farklı porta {unique_ips} farklı IP'ye bağlantı denedi. "
            "Bu tür tarama davranışı ağ keşfi veya zafiyet aramasına işaret eder."
        ),
        "oneri": [
            "Port tarama trafiğini güvenlik duvarında engelleyin.",
            "Şüpheli cihazı ağdan izole edin.",
            "IDS kurallarını port taramaya karşı güncelleyin.",
        ],
    },
    "dns_tunnel": {
        "aciklama": (
            "DNS sorguları anormal derecede yüksek: {dns_count} sorgu, "
            "{txt_queries} TXT kaydı, {failed_dns} başarısız yanıt. "
            "DNS tüneli veri sızdırma kanalı olarak kullanılıyor olabilir."
        ),
        "oneri": [
            "DNS trafiğini güvenilir çözücülerle sınırlayın.",
            "Uzun veya kodlanmış DNS sorgularını filtreleyin.",
            "DNS günlüklerini SIEM'e gönderin.",
        ],
    },
    "exfiltration": {
        "aciklama": (
            "Cihaz {upload_mb} MB veri yükledi (yükleme oranı: %{upload_pct}). "
            "Gece saati ({hour}:00) gerçekleşen yüksek hacimli çıkış trafiği "
            "yetkisiz veri sızdırmaya işaret eder."
        ),
        "oneri": [
            "DLP politikalarını gözden geçirin.",
            "Cihazın erişebildiği hassas verileri denetleyin.",
            "Çıkış bant genişliğine limit uygulayın.",
        ],
    },
    "lateral_movement": {
        "aciklama": (
            "Cihaz iç ağda {unique_ips} farklı hedefe yönelik ARP istekleri "
            "({arp_count} adet) ve port tarama ({unique_ports} port) gerçekleştirdi. "
            "Yanal hareket saldırısı tespit edildi."
        ),
        "oneri": [
            "Ağ segmentasyonunu (VLAN) güçlendirin.",
            "Cihazın erişim yetkilerini kısıtlayın.",
            "Makro segmentasyon politikalarını uygulayın.",
        ],
    },
    "normal": {
        "aciklama": "Trafik profili normal sınırlar içinde seyrediyor.",
        "oneri": [],
    },
}


def analyze(features: dict, attack_type: str, score: float) -> dict:
    """
    Anomali için Türkçe açıklama ve öneri üret.
    Döner: {aciklama, oneri, attack_label, score, ts}
    """
    if ANTHROPIC_API_KEY:
        try:
            return _llm_analyze(features, attack_type, score)
        except Exception as e:
            print(f"[LLM] API hatası, kural tabanlı açıklama: {e}")

    return _rule_based(features, attack_type, score)


def _rule_based(features: dict, attack_type: str, score: float) -> dict:
    template = _RULE_TEMPLATES.get(attack_type, _RULE_TEMPLATES["normal"])
    vals = {
        "unique_ports": features.get("unique_ports", 0),
        "unique_ips": features.get("unique_ips", 0),
        "dns_count": features.get("dns_count", 0),
        "txt_queries": features.get("txt_queries", 0),
        "failed_dns": features.get("failed_dns", 0),
        "upload_mb": round(features.get("upload_bytes", 0) / 1_048_576, 1),
        "upload_pct": round(features.get("upload_ratio", 0) * 100, 1),
        "hour": features.get("hour", 0),
        "arp_count": features.get("arp_count", 0),
    }
    try:
        aciklama = template["aciklama"].format(**vals)
    except KeyError:
        aciklama = template["aciklama"]

    return {
        "aciklama": aciklama,
        "oneri": template["oneri"],
        "attack_label": ATTACK_LABELS.get(attack_type, attack_type),
        "score": round(score, 4),
        "ts": time.time(),
        "source": "rule",
    }


def _llm_analyze(features: dict, attack_type: str, score: float) -> dict:
    import anthropic

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    feature_summary = (
        f"Saldırı tipi: {ATTACK_LABELS.get(attack_type, attack_type)}\n"
        f"Anomali skoru: {score:.4f}\n"
        f"DNS sorgu sayısı: {features.get('dns_count', 0)}\n"
        f"TXT sorguları: {features.get('txt_queries', 0)}\n"
        f"Başarısız DNS: {features.get('failed_dns', 0)}\n"
        f"Yükleme (MB): {round(features.get('upload_bytes', 0)/1_048_576, 1)}\n"
        f"Yükleme oranı: {features.get('upload_ratio', 0):.2%}\n"
        f"Benzersiz port: {features.get('unique_ports', 0)}\n"
        f"Benzersiz IP: {features.get('unique_ips', 0)}\n"
        f"ARP sayısı: {features.get('arp_count', 0)}\n"
        f"Saat: {features.get('hour', 0)}:00\n"
    )

    prompt = (
        "Aşağıdaki ağ trafik anomalisi verilerini analiz et ve "
        "kısa, anlaşılır Türkçe açıklama yaz.\n\n"
        f"{feature_summary}\n"
        "Yanıtını şu JSON formatında ver:\n"
        '{"aciklama": "tek paragraf açıklama", '
        '"oneri": ["öneri 1", "öneri 2", "öneri 3"]}'
    )

    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )

    text = message.content[0].text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        import re

        m = re.search(r"\{.*\}", text, re.DOTALL)
        data = json.loads(m.group()) if m else {}

    return {
        "aciklama": data.get("aciklama", "LLM açıklaması alınamadı."),
        "oneri": data.get("oneri", []),
        "attack_label": ATTACK_LABELS.get(attack_type, attack_type),
        "score": round(score, 4),
        "ts": time.time(),
        "source": "llm",
    }
