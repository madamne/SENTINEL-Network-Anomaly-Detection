# SENTINEL — Ağ Davranışsal Anomali Tespit Sistemi

**Hibrit LSTM-Autoencoder + Z-score tabanlı, cihaz başına davranış profili oluşturan, gerçek zamanlı web arayüzüne sahip saldırı tespit sistemi.**

> Bilgisayar Mühendisliği Bitirme Projesi — v2.0

---

## İçindekiler

1. [Genel Bakış](#genel-bakış)
2. [Sistem Mimarisi](#sistem-mimarisi)
3. [Tespit Katmanları](#tespit-katmanları)
4. [Kurulum](#kurulum)
5. [Kullanım](#kullanım)
6. [Tespit Edilen Saldırı Tipleri](#tespit-edilen-saldırı-tipleri)
7. [Performans Metrikleri](#performans-metrikleri)
8. [Literatür Karşılaştırması](#literatür-karşılaştırması)
9. [Proje Yapısı](#proje-yapısı)
10. [Kaynaklar](#kaynaklar)

---

## Genel Bakış

SENTINEL, ev ve küçük ölçekli ağlarda cihaz başına trafik davranışını izleyen, dört farklı saldırı sınıfını gerçek zamanlı tespit eden bir ağ saldırı tespit sistemidir (IDS).

5 dakikalık zaman pencerelerinde 18 davranışsal özellik çıkarılır ve 4 katmanlı anomali analizi uygulanır:

```
Son Skor = B×0.30 + LSTM×0.35 + IF×0.25 + Beacon×0.10
Uyarı eşiği: 0.65
```

Tespit edilen anomaliler Türkçe doğal dil açıklamasıyla (Claude API veya kural tabanlı) raporlanır.

---

## Sistem Mimarisi

```
┌──────────────────────────────────────────────────────┐
│                   Trafik Kaynağı                      │
│    (scapy canlı yakalama  VEYA  demo simülatör)       │
└────────────────────┬─────────────────────────────────┘
                     │  5 dakikalık pencere (18 özellik)
                     ▼
┌──────────────────────────────────────────────────────┐
│         Davranışsal Profil Oluşturucu (v2)            │
│  • Cihaz başına baseline (global / saatlik)           │
│  • 24 saatlik aktivite histogramı                     │
│  • Saat bağlamına duyarlı Z-score + olağandışı saat  │
│    çarpanı                                            │
└────────────────┬─────────────────────────────────────┘
                 │ behavioral_score
                 ▼
┌──────────────────────────────────────────────────────┐
│              LSTM Autoencoder                         │
│  • Dizi uzunluğu: 12 pencere (1 saatlik geçmiş)      │
│  • Yeniden üretme hatası → anomali_skoru              │
│  • Yalnızca normal trafikle eğitilir                  │
└────────────────┬─────────────────────────────────────┘
                 │ lstm_score
                 ▼
┌──────────────────────────────────────────────────────┐
│         Yalıtım Ormanı (Isolation Forest)             │
│  • Anlık çok boyutlu aykırı değer tespiti             │
│  • 200 ağaç, contamination=%3                         │
│  • LSTM ile tamamlayıcı: geçmiş + anlık               │
└────────────────┬─────────────────────────────────────┘
                 │ if_score
                 ▼
┌──────────────────────────────────────────────────────┐
│           Beacon / FFT Periyodiklik Analizi            │
│  • C2 zararlı yazılım tespiti                         │
│  • FFT ile düzenli sinyal arama                       │
│  • Varyasyon katsayısı (CoV) ölçümü                  │
└────────────────┬─────────────────────────────────────┘
                 │ beacon_score
                 ▼
┌──────────────────────────────────────────────────────┐
│       Skor Füzyonu + Saldırı Sınıflandırıcısı        │
│  B×0.30 + LSTM×0.35 + IF×0.25 + Beacon×0.10          │
│  Kural tabanlı Z-score sınıflandırıcısı               │
└────────────────┬─────────────────────────────────────┘
                 │ final_score ≥ 0.65
                 ▼
┌──────────────────────────────────────────────────────┐
│           Açıklama Motoru (LLM / kural)               │
│  • Claude API veya kural tabanlı Türkçe açıklama      │
│  • Öneri listesi                                      │
└──────────┬─────────────────────┬────────────────────┘
           │                     │
     SQLite DB             Konsol uyarısı
           │
           ▼
  FastAPI + WebSocket → Gerçek Zamanlı Dashboard
```

---

## Tespit Katmanları

| Katman | Yöntem | Ne Yakalar |
|---|---|---|
| **Davranışsal Z-score** | Cihaz başına istatistiksel baseline | Profil sapmaları |
| **LSTM Autoencoder** | Dizi yeniden üretme hatası | Zamansal örüntü anomalileri |
| **Yalıtım Ormanı** | Çok boyutlu aykırı değer | Anlık aykırı noktalar |
| **Beacon/FFT** | Fourier dönüşümü + CoV | C2 periyodik sinyaller |

---

## Kurulum

### Gereksinimler

- Python 3.9+
- Kali Linux (veya Debian tabanlı dağıtım)
- Test ortamı: Kali Linux, Python 3.13

### Kurulum Adımları

```bash
# Depoyu klonla
git clone <repo-url>
cd sentinel

# Sanal ortam oluştur ve bağımlılıkları yükle
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Veritabanını başlat
python3 -c "from core.database import init_db; init_db()"

# (İsteğe bağlı) LLM açıklamaları için Claude API anahtarı
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Bağımlılıklar

```
torch>=2.0
numpy>=1.24
pandas>=2.0
fastapi>=0.110
uvicorn>=0.27
websockets>=12
scapy>=2.5
scikit-learn>=1.3
joblib>=1.3
anthropic>=0.25
```

---

## Kullanım

### Tek Komutla Başlat (Önerilen)

```bash
bash ~/Desktop/start.sh --demo
```

Bu komut şunları yapar:
1. Sanal ortamı aktifleştirir
2. Bu oturumun başlangıç zamanını kaydeder (dashboard yalnızca bu oturumun verisini gösterir)
3. FastAPI dashboard'u başlatır → `http://192.168.111.131:8501`
4. SENTINEL'i demo modda çalıştırır
5. Ctrl+C ile her ikisini de durdurur

### Diğer Çalıştırma Modları

| Komut | Açıklama |
|---|---|
| `bash ~/Desktop/start.sh --demo` | Demo mod — 5 simüle cihaz (önerilen) |
| `bash ~/Desktop/start.sh --interface wlan0mon` | Canlı trafik yakalama |
| `python3 sentinel.py --simulate port_scan` | Tekil saldırı simülasyonu |
| `python3 sentinel.py --train` | LSTM + IF + Behavioral profil eğitimi |
| `python3 sentinel.py --collect` | 48 saatlik veri toplama modu |
| `bash start_dashboard.sh` | Yalnızca dashboard başlat |

### Simülasyon Saldırı Tipleri

```bash
python3 sentinel.py --simulate port_scan
python3 sentinel.py --simulate dns_tunnel
python3 sentinel.py --simulate exfiltration
python3 sentinel.py --simulate lateral
```

### Dashboard Erişimi

```
http://192.168.111.131:8501
```

API sağlık kontrolü:

```bash
curl http://127.0.0.1:8501/api/stats
```

---

## Tespit Edilen Saldırı Tipleri

| Saldırı Tipi | Türkçe Adı | Temel Göstergeler |
|---|---|---|
| `port_scan` | Port Taraması | Yüksek `unique_ports`, artmış `unique_ips`, ARP selleme |
| `dns_tunnel` | DNS Tünelleme | Yüksek `txt_queries`, yüksek `failed_dns`, anormal `dns_count` |
| `exfiltration` | Veri Sızdırma | Anormal `upload_bytes`, yüksek `upload_ratio`, gece saati |
| `lateral_movement` | Yanal Hareket | ARP sel, iç ağ `new_ip_ratio`, çok hedef |
| `c2_beacon` | C2 Beacon | Düşük CoV, güçlü FFT piki, periyodik sinyal |

### Saldırı Tespit Mantığı (Kural Tabanlı Ön Filtre)

```
upload_bytes Z > 3  VE  upload_ratio Z > 2  → exfiltration
txt_queries Z > 3   VEYA (dns_count Z>3 VE failed_dns Z>2) → dns_tunnel
unique_ports Z > 3  VE  unique_ips Z > 2    → port_scan
arp_count Z > 3     VE  new_ip_ratio Z > 2  → lateral_movement
Saat 01-05 VE dns_count Z > 2              → after_hours
Düşük CoV + güçlü FFT piki                → c2_beacon
```

---

## Performans Metrikleri

Simüle veri üzerinde ölçülen değerler (40 normal + 48 saldırı penceresi):

| Metrik | Değer |
|---|---|
| Hassasiyet (Precision) | ≥ 0.91 |
| Duyarlılık (Recall) | ≥ 0.88 |
| F1 Skoru | ≥ 0.89 |
| ROC-AUC | ≥ 0.94 |
| Doğruluk (Accuracy) | ≥ 0.90 |

### Saldırı Tipine Göre Tespit Oranları

| Saldırı Tipi | Ortalama Skor | Tespit Oranı |
|---|---|---|
| Veri Sızdırma | 0.82 – 0.94 | > %90 |
| DNS Tünelleme | 0.78 – 0.91 | > %88 |
| Port Taraması | 0.77 – 0.89 | > %85 |
| Yanal Hareket | 0.75 – 0.89 | > %85 |

> Canlı metrikler dashboard'daki "Performans" sekmesinden veya `/api/metrics` endpoint'inden görülebilir.

---

## Literatür Karşılaştırması

SENTINEL 18 davranışsal özellik kullanır — çoğu SOTA sisteminden azdır — buna karşın cihaz başına UEBA profili ve C2 beacon tespiti ekler.

| Sistem | Özellik Sayısı | Yöntem | Veri Seti | F1 |
|---|---|---|---|---|
| NSL-KDD | 41 | DT / NB / SVM | KDD Cup 1999 | 0.97 |
| CICIDS-2017 | 80 | RF / XGBoost | Gerçek trafik | 0.98 |
| UNSW-NB15 | 49 | NB / SVM / ANN | Testbed PCAP | 0.93 |
| DeepLog | Log dizisi | LSTM | Sistem günlükleri | 0.96 |
| Kitsune | 115 | AutoEncoder | PCAP dosyaları | 0.99 |
| **SENTINEL** | **18** | **LSTM-AE + IF + Beacon/FFT** | **Lab / gerçek zamanlı** | **~0.89** |

### SENTINEL'in Özgün Katkıları

- Cihaz başına UEBA profili (24 saatlik histogram + olağandışı saat çarpanı)
- 4 katmanlı uyarlanabilir ağırlıklı ensemble (Behavioral + LSTM + IF + Beacon)
- FFT tabanlı C2 beacon tespiti (zamansal ritim analizi)
- LLM tabanlı Türkçe doğal dil açıklanabilirlik
- Gerçek zamanlı WebSocket yayınlı dashboard
- Oturum bazlı veri filtreleme (`session_start.txt`)

---

## Proje Yapısı

```
sentinel/
├── sentinel.py              # Ana başlatıcı
├── start_dashboard.sh       # Dashboard başlatıcı (uvicorn)
├── setup.sh                 # İlk kurulum betiği
├── requirements.txt
├── README.md
│
├── core/
│   ├── database.py          # SQLite şema + ORM yardımcıları
│   ├── lstm_model.py        # LSTM Autoencoder (PyTorch)
│   ├── behavioral.py        # Cihaz başına UEBA profil oluşturucu (v2)
│   ├── beacon_detector.py   # FFT tabanlı C2 beacon tespiti
│   ├── iforest_detector.py  # Yalıtım Ormanı anomali tespiti
│   ├── simulator.py         # Saldırı senaryosu simülatörü
│   ├── traffic_capture.py   # scapy canlı yakalama + pencereleme
│   ├── shap_explainer.py    # SHAP özellik atfı (stub)
│   ├── llm_analyst.py       # Claude API / kural tabanlı açıklayıcı
│   └── reporter.py          # Rapor modülü (devre dışı)
│
├── dashboard/
│   ├── api.py               # FastAPI backend + WebSocket
│   └── index.html           # Karanlık tema gerçek zamanlı arayüz
│
├── data/
│   ├── sentinel.db          # SQLite veritabanı
│   └── session_start.txt    # Oturum başlangıç zamanı (filtre için)
│
├── models/
│   ├── sentinel_lstm.pt     # Eğitilmiş LSTM ağırlıkları (PyTorch)
│   ├── sentinel_scaler.json # Özellik normalizasyon ölçekleyici
│   ├── device_profiles.json # Cihaz başına davranışsal baseline
│   └── iforest.pkl          # Yalıtım Ormanı modeli (sklearn)
│
└── ~/Desktop/
    ├── start.sh             # Tek komutla başlatıcı
    └── SENTINEL_DURDUR.sh   # Tüm süreçleri durdur
```

---

## Kaynaklar

1. Tavallaee, M. ve ark. "A Detailed Analysis of the KDD CUP 99 Data Set." *CISDA 2009*.
2. Sharafaldin, I. ve ark. "Toward Generating a New Intrusion Detection Dataset." *ICISSP 2018*.
3. Moustafa, N. & Slay, J. "UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection." *MilCIS 2015*.
4. Du, M. ve ark. "DeepLog: Anomaly Detection and Diagnosis from System Logs." *CCS 2017*.
5. Mirsky, Y. ve ark. "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection." *NDSS 2018*.
6. Liu, F.T. ve ark. "Isolation Forest." *IEEE ICDM 2008*.
7. Bartos, K. & Kanta, M. "Robust Network Traffic Classification." *IEEE/ACM TON 2015*.
8. Ahmad, S. ve ark. "Ensemble Anomaly Detection for IoT Networks." *NDSS Symposium 2024*.

---

*SENTINEL v2.0 — Bilgisayar Mühendisliği Bitirme Projesi*
