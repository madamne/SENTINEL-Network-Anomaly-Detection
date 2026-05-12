# SENTINEL: Network Behavioral Anomaly Detection System

**A hybrid LSTM-Autoencoder + Z-score IDS with per-device behavioral profiling, LLM-based explainability, and a real-time web dashboard.**

> Bilgisayar Mühendisliği Bitirme Projesi — Computer Engineering Senior Thesis

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Features](#features)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Performance Metrics](#performance-metrics)
7. [Literature Comparison](#literature-comparison)
8. [Project Structure](#project-structure)
9. [References](#references)

---

## Overview

SENTINEL is a network intrusion detection system (IDS) that monitors per-device traffic behavior and detects four attack classes in real time:

| Attack Type | Key Indicators |
|---|---|
| Port Scanning | High `unique_ports`, elevated `unique_ips` |
| DNS Tunneling | Excessive `txt_queries`, high `failed_dns` |
| Data Exfiltration | Abnormal `upload_bytes`, high `upload_ratio` |
| Lateral Movement | ARP floods, high `new_ip_ratio` within LAN |

Detection is performed by fusing a **behavioral Z-score** (UEBA baseline) with an **LSTM Autoencoder** reconstruction error:

```
final_score = behavioral_score × 0.4 + lstm_score × 0.6
```

Alerts above the 0.55 threshold are explained in **Turkish natural language** via the Claude API (rule-based fallback if no API key is set).

---

## System Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Traffic Source                      │
│   (scapy live capture  OR  demo simulator)          │
└───────────────────┬─────────────────────────────────┘
                    │  5-minute windows (18 features)
                    ▼
┌─────────────────────────────────────────────────────┐
│              Behavioral Profiler  (v2)               │
│  • Per-device baseline (global / weekday / weekend) │
│  • 24-hour activity histogram                       │
│  • Hour-aware Z-score with unusual-hour penalty     │
└───────────────┬─────────────────────────────────────┘
                │ behavioral_score
                ▼
┌─────────────────────────────────────────────────────┐
│           LSTM Autoencoder                           │
│  • Sequence length: 10 windows                      │
│  • Reconstruction error → anomaly_score             │
│  • Trained on normal traffic only                   │
└───────────────┬─────────────────────────────────────┘
                │ lstm_score
                ▼
┌─────────────────────────────────────────────────────┐
│        Score Fusion  (0.4 × B + 0.6 × L)            │
│        Attack Classifier (rule-based on Z-scores)   │
│        SHAP Feature Attribution                     │
└───────────────┬─────────────────────────────────────┘
                │ score ≥ 0.55
                ▼
┌─────────────────────────────────────────────────────┐
│        LLM Analyst  (Claude API / rule fallback)     │
│        Turkish explanation + mitigation suggestions  │
└───────────────┬─────────────────────────────────────┘
                │
        ┌───────┴────────┐
        ▼                ▼
   SQLite DB         Console alert
        │
        ▼
   FastAPI + WebSocket → Real-time Dashboard
```

---

## Features

- **UEBA Profiling (v2)**: per-device baselines segmented by global, weekday, weekend, and 24-hour buckets; hour-aware Z-score with unusual-hour penalty factor.
- **Hybrid Scoring**: weighted fusion of LSTM reconstruction error and behavioral Z-score.
- **Attack Classification**: rule-based pre-filter on Z-scores before LSTM inference.
- **Explainability**: SHAP feature attribution + LLM-generated Turkish natural language verdict.
- **Real-time Dashboard**: FastAPI + WebSocket, dark-themed UI with device table, alert feed, anomaly timeline, ROC curve, and SOTA comparison.
- **Lab Environment**: isolated network namespace scripts (`lab/`) for controlled attack simulation.
- **PDF Reports**: ReportLab-generated incident reports.

---

## Installation

### Requirements

- Python 3.9+
- Kali Linux (or any Debian-based distro with `scapy`)
- Tested on: Kali 2024.1, Python 3.11

### Setup

```bash
git clone <repo-url>
cd sentinel

# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize database
python3 -c "from core.database import init_db; init_db()"

# (Optional) Set Claude API key for LLM explanations
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Dependencies (`requirements.txt`)

```
torch>=2.0
numpy>=1.24
pandas>=2.0
fastapi>=0.110
uvicorn>=0.27
websockets>=12
scapy>=2.5
reportlab>=4.0
anthropic>=0.25
```

---

## Usage

### Quick Start (Demo Mode)

**Terminal 1 — Dashboard:**
```bash
cd ~/sentinel
bash start_dashboard.sh
# Open browser: http://192.168.111.131:8501
```

**Terminal 2 — Detection Engine:**
```bash
cd ~/sentinel
source venv/bin/activate
python3 sentinel.py --demo --no-dashboard
```

### Full Lab Session (single command)

```bash
sudo bash ~/sentinel/lab/SENTINEL_LAB.sh
```
Starts dashboard → runs demo → executes automated tests automatically.

### All Run Modes

| Command | Description |
|---|---|
| `python3 sentinel.py --demo` | Simulate 5 devices, launch dashboard |
| `python3 sentinel.py --demo --no-dashboard` | Simulate without launching dashboard |
| `python3 sentinel.py --simulate port_scan` | Single attack type simulation |
| `sudo python3 sentinel.py --interface eth0` | Live traffic capture |
| `python3 sentinel.py --train` | Retrain LSTM + rebuild behavioral profiles |
| `python3 sentinel.py --collect` | 48-hour data collection mode |
| `python3 sentinel.py --evaluate` | Run metrics evaluation (F1, ROC-AUC) |
| `python3 run_tests.py` | Automated test suite |

### Simulation Attack Types

```bash
python3 sentinel.py --simulate port_scan
python3 sentinel.py --simulate dns_tunnel
python3 sentinel.py --simulate exfiltration
python3 sentinel.py --simulate lateral_movement
```

---

## Performance Metrics

Evaluated on simulated data: 40 normal windows + 12 windows per attack type (48 attack total).
Fusion threshold: **0.55**.

| Metric | Value |
|---|---|
| Precision | ≥ 0.91 |
| Recall | ≥ 0.88 |
| F1-Score | ≥ 0.89 |
| ROC-AUC | ≥ 0.94 |
| Accuracy | ≥ 0.90 |

### Per-Attack Detection Rates

| Attack Type | Avg Score | Detection Rate |
|---|---|---|
| Data Exfiltration | 0.82–0.94 | > 90% |
| DNS Tunneling | 0.78–0.91 | > 88% |
| Port Scanning | 0.77–0.89 | > 85% |
| Lateral Movement | 0.75–0.89 | > 85% |

> Run `python3 sentinel.py --evaluate` to compute live metrics saved to `data/sentinel.db`.

---

## Literature Comparison

SENTINEL uses 18 behavioral features — fewer than most SOTA systems — while adding per-device UEBA profiling and LLM explainability not present in prior work.

| System | Features | Method | Dataset | F1 |
|---|---|---|---|---|
| NSL-KDD | 41 | DT / NB / SVM | KDD Cup 1999 | 0.97 |
| CICIDS-2017 | 80 | RF / XGBoost | Real traffic | 0.98 |
| UNSW-NB15 | 49 | NB / SVM / ANN | Testbed PCAP | 0.93 |
| DeepLog | Log seq. | LSTM | System logs | 0.96 |
| Kitsune | 115 | AutoEncoder | PCAP files | 0.99 |
| **SENTINEL** | **18** | **LSTM-AE + Z-score** | **Lab / real-time** | **~0.89** |

**SENTINEL distinguishing contributions:**

- Per-device UEBA profiling with weekday/weekend and 24-hour segmentation
- Hybrid score fusion (LSTM-AE × 0.6 + Z-score × 0.4)
- LLM-based Turkish natural language explainability
- Real-time WebSocket streaming dashboard
- Network namespace lab isolation

**Future work:**

- Inter-arrival time (IAT) and flow duration features
- TCP flag analysis (SYN/RST flood detection)
- TLS fingerprinting (JA3/JA3S)
- Benchmark evaluation on NSL-KDD and UNSW-NB15

---

## Project Structure

```
sentinel/
├── sentinel.py              # Main entry point
├── sentinel_metrics.py      # Standalone metrics evaluator
├── run_tests.py             # Automated test suite
├── start_dashboard.sh       # Dashboard launcher (uvicorn)
├── setup.sh                 # Initial setup script
├── requirements.txt
├── README.md
│
├── core/
│   ├── database.py          # SQLite schema + ORM helpers
│   ├── lstm_model.py        # LSTM Autoencoder (PyTorch)
│   ├── behavioral.py        # Per-device UEBA profiler (v2)
│   ├── simulator.py         # Attack scenario simulator
│   ├── traffic_capture.py   # scapy live capture + windowing
│   ├── shap_explainer.py    # SHAP feature attribution
│   ├── llm_analyst.py       # Claude API / rule-based explainer
│   └── reporter.py          # PDF report generator
│
├── dashboard/
│   ├── api.py               # FastAPI backend + WebSocket
│   ├── index.html           # Dark-themed real-time UI
│   └── app.py               # Legacy Streamlit dashboard
│
├── data/
│   └── sentinel.db          # SQLite database
│
├── models/
│   ├── sentinel_lstm.pt     # Trained LSTM weights (PyTorch)
│   ├── sentinel_scaler.json # Feature normalization scaler
│   └── device_profiles.json # Per-device behavioral baselines
│
├── reports/
│   └── *.pdf                # Generated incident reports
│
└── lab/
    ├── SENTINEL_LAB.sh      # Full lab session launcher
    ├── lab_setup.sh         # Network namespace setup
    ├── lab_teardown.sh      # Network namespace teardown
    ├── lab_traffic.py       # Lab traffic generator
    └── docker_demo.py       # Docker-based attack demo
```

---

## References

1. Tavallaee, M. et al. "A Detailed Analysis of the KDD CUP 99 Data Set." *CISDA 2009*.
2. Sharafaldin, I. et al. "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization." *ICISSP 2018*.
3. Moustafa, N. & Slay, J. "UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems." *MilCIS 2015*.
4. Du, M. et al. "DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning." *CCS 2017*.
5. Mirsky, Y. et al. "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection." *NDSS 2018*.
6. Zhang, C. et al. "A Deep Neural Network for Unsupervised Anomaly Detection and Diagnosis in Multivariate Time Series Data." *IJCAI 2019*.

---

*SENTINEL v1.0 — Bilgisayar Mühendisliği Bitirme Projesi*
