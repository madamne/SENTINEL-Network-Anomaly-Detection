"""
SENTINEL Dashboard — FastAPI Backend
Çalıştır: uvicorn dashboard.api:app --host 0.0.0.0 --port 8501
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from core.database import (
    get_alerts_df,
    get_conn,
    get_devices_df,
    get_stats,
    get_windows_df,
    init_db,
)

app = FastAPI(title="SENTINEL Dashboard", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

INDEX_HTML = os.path.join(os.path.dirname(__file__), "index.html")

# ── WebSocket bağlantı yöneticisi ─────────────────────────────────────────────


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()
_demo_task: Optional[asyncio.Task] = None  # devre dışı — yalnızca canlı SQLite verisi kullanılır
_notify_event: asyncio.Event = asyncio.Event()  # sentinel.py → anlık broadcast tetikleyici


# ── Yardımcı ─────────────────────────────────────────────────────────────────


def _df_to_records(df):
    if df is None or df.empty:
        return []
    df = df.where(df.notna(), None)
    return df.to_dict(orient="records")


def _fmt_ts(val):
    try:
        return datetime.fromtimestamp(float(val)).strftime("%H:%M:%S")
    except Exception:
        return "—"


SESSION_START_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "session_start.txt")


def _get_session_start() -> float:
    """session_start.txt varsa unix timestamp döner, yoksa 0 (tüm veri)."""
    try:
        with open(SESSION_START_FILE) as f:
            return float(f.read().strip())
    except Exception:
        return 0.0


def _filtered_stats(since: float) -> dict:
    """get_stats() yerine — sadece bu oturumdan itibaren sayar."""
    if since <= 0:
        return get_stats()
    try:
        conn = get_conn()
        c = conn.cursor()
        r = {
            "total_packets": c.execute(
                "SELECT COUNT(*) FROM packets WHERE ts >= ?", (since,)
            ).fetchone()[0],
            "total_windows": c.execute(
                "SELECT COUNT(*) FROM traffic_windows WHERE ts >= ?", (since,)
            ).fetchone()[0],
            "devices": c.execute(
                "SELECT COUNT(DISTINCT device_mac) FROM traffic_windows WHERE ts >= ?", (since,)
            ).fetchone()[0],
            "alerts": c.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged=0 AND ts >= ?", (since,)
            ).fetchone()[0],
            "threats": c.execute(
                "SELECT COUNT(*) FROM devices WHERE threat_score>=60 AND last_seen >= ?", (since,)
            ).fetchone()[0],
            "safe": c.execute(
                "SELECT COUNT(*) FROM devices WHERE threat_score<30 AND last_seen >= ?", (since,)
            ).fetchone()[0],
        }
        conn.close()
        return r
    except Exception:
        return {}


# ── HTTP endpoint'leri ────────────────────────────────────────────────────────


@app.on_event("startup")
async def startup():
    init_db()
    asyncio.create_task(_broadcaster())


@app.get("/", response_class=HTMLResponse)
async def root():
    if os.path.exists(INDEX_HTML):
        with open(INDEX_HTML, "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h1>SENTINEL</h1><p>index.html bulunamadı.</p>")


@app.get("/api/stats")
async def api_stats():
    return _filtered_stats(_get_session_start())


@app.get("/api/devices")
async def api_devices():
    df = get_devices_df()
    since = _get_session_start()
    if since > 0 and df is not None and not df.empty and "last_seen" in df.columns:
        df = df[df["last_seen"] >= since]
    records = _df_to_records(df)
    for r in records:
        r["last_seen_fmt"] = _fmt_ts(r.get("last_seen"))
        r["first_seen_fmt"] = _fmt_ts(r.get("first_seen"))
    return records


@app.get("/api/alerts")
async def api_alerts(limit: int = 20):
    df = get_alerts_df(limit=limit * 10)  # fazla çek, sonra filtrele
    since = _get_session_start()
    if since > 0 and df is not None and not df.empty and "ts" in df.columns:
        df = df[df["ts"] >= since].head(limit)
    else:
        df = df.head(limit) if df is not None and not df.empty else df
    records = _df_to_records(df)
    for r in records:
        r["ts_fmt"] = _fmt_ts(r.get("ts"))
    return records


@app.get("/api/windows")
async def api_windows(limit: int = 200):
    """Son N traffic_windows satırını mac, ts, anomaly_score alanlarıyla döner (zaman sırası ASC)."""
    try:
        since = _get_session_start()
        conn = get_conn()
        if since > 0:
            rows = conn.execute(
                "SELECT device_mac AS mac, ts, anomaly_score "
                "FROM traffic_windows WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT device_mac AS mac, ts, anomaly_score "
                "FROM traffic_windows ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        conn.close()
        records = [
            {
                "mac": r["mac"],
                "ts": r["ts"],
                "anomaly_score": float(r["anomaly_score"] or 0),
                "ts_fmt": _fmt_ts(r["ts"]),
            }
            for r in rows
        ]
        records.reverse()  # grafik için eskiden yeniye sıra
        return records
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/metrics")
async def api_metrics():
    """
    traffic_windows + alerts tablosundan metrik hesapla.
    Döner:
      - f1, precision, recall, accuracy, roc_auc
      - roc_curve : [{fpr, tpr}, ...]   → drawROC() için
      - per_attack: {tip: {n, detected, rate}}
      - sota_comparison: literatür karşılaştırma tablosu
    """
    ESIK = 0.65
    try:
        since = _get_session_start()
        conn = get_conn()

        if since > 0:
            win_rows = conn.execute(
                "SELECT device_mac, ts, attack_type, anomaly_score FROM traffic_windows WHERE ts >= ?",
                (since,),
            ).fetchall()
            alert_keys = set()
            for mac, ts, score in conn.execute(
                "SELECT device_mac, ts, anomaly_score FROM alerts WHERE ts >= ?", (since,)
            ).fetchall():
                alert_keys.add((mac, round(float(ts or 0))))
            dagilim_rows = conn.execute(
                "SELECT attack_type, COUNT(*) as n FROM traffic_windows WHERE ts >= ? "
                "GROUP BY attack_type ORDER BY n DESC",
                (since,),
            ).fetchall()
        else:
            win_rows = conn.execute(
                "SELECT device_mac, ts, attack_type, anomaly_score FROM traffic_windows"
            ).fetchall()
            alert_keys = set()
            for mac, ts, score in conn.execute(
                "SELECT device_mac, ts, anomaly_score FROM alerts"
            ).fetchall():
                alert_keys.add((mac, round(float(ts or 0))))
            dagilim_rows = conn.execute(
                "SELECT attack_type, COUNT(*) as n FROM traffic_windows "
                "GROUP BY attack_type ORDER BY n DESC"
            ).fetchall()
        conn.close()

        if not win_rows:
            return {
                "available": False,
                "reason": "Pencere verisi yok — demo veya simülasyon çalıştırın.",
            }

        # ── Vektörler ────────────────────────────────────────────────────────
        labels, scores = [], []
        per_attack: dict = {}  # {attack_type: {"n":0,"detected":0}}

        tp = fp = tn = fn = 0

        for mac, ts, attack_type, score in win_rows:
            score = float(score or 0)
            atype = (attack_type or "normal").lower()
            key = (mac, round(float(ts or 0)))
            in_alert = key in alert_keys

            gercek_poz = atype != "normal"
            tahmin_poz = score >= ESIK or in_alert

            # ROC için efektif skor: alert varsa minimum 0.60 garantile
            eff_score = max(score, 0.60 if in_alert else 0.0)
            labels.append(1 if gercek_poz else 0)
            scores.append(eff_score)

            if gercek_poz:
                if atype not in per_attack:
                    per_attack[atype] = {"n": 0, "detected": 0}
                per_attack[atype]["n"] += 1
                if tahmin_poz:
                    per_attack[atype]["detected"] += 1

            if gercek_poz and tahmin_poz:
                tp += 1
            elif not gercek_poz and tahmin_poz:
                fp += 1
            elif not gercek_poz:
                tn += 1
            else:
                fn += 1

        toplam = tp + fp + tn + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / toplam if toplam > 0 else 0.0

        # ── ROC eğrisi ────────────────────────────────────────────────────
        roc_curve, roc_auc = _roc_egri_hesapla(labels, scores)

        # per_attack rate ekle
        for v in per_attack.values():
            v["rate"] = round(v["detected"] / v["n"], 4) if v["n"] else 0.0

        dagilim = {r[0] or "normal": r[1] for r in dagilim_rows}

        # ── Literatür SOTA karşılaştırması ───────────────────────────────
        # Kaynaklar:
        #   Kitsune: Mirsky et al., NDSS 2018
        #   DeepLog: Du et al., ACM CCS 2017
        #   CICIDS-RF: Sharafaldin et al., ICISSP 2018
        #   UNSW-AE: Vinayakumar et al., IEEE Access 2019
        #   E-GraphSAGE: Lo et al., NDSS 2022
        #   SENTINEL: Bu proje (hesaplanan F1)
        sota_comparison = {
            "Kitsune": {
                "features": "115 istatistik",
                "method": "AutoEncoder Ensemble",
                "dataset": "Mirai / ARP-MitM",
                "f1_reported": 0.87,
            },
            "DeepLog": {
                "features": "Log vektörü",
                "method": "LSTM (günlük)",
                "dataset": "HDFS / OpenStack",
                "f1_reported": 0.96,
            },
            "CICIDS-RF": {
                "features": "78 akış özelliği",
                "method": "Random Forest",
                "dataset": "CICIDS2017",
                "f1_reported": 0.97,
            },
            "UNSW-AE": {
                "features": "42 özellik",
                "method": "AutoEncoder + SVM",
                "dataset": "UNSW-NB15",
                "f1_reported": 0.89,
            },
            "E-GraphSAGE": {
                "features": "Ağ grafı",
                "method": "Graph Neural Net",
                "dataset": "NF-ToN-IoT / BoT-IoT",
                "f1_reported": 0.91,
            },
            "SENTINEL": {
                "features": "18 davranışsal",
                "method": "LSTM-AE + IF + Beacon/FFT",
                "dataset": "Lab (ev ağı)",
                "f1_reported": None,  # JS tarafında "Bu proje" gösterir
                "f1_live": round(f1, 4),
            },
        }

        return {
            "available": True,
            "f1": round(f1, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "accuracy": round(accuracy, 4),
            "roc_auc": round(roc_auc, 4),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "total": toplam,
            "threshold": ESIK,
            "dagilim": dagilim,
            "roc_curve": roc_curve,
            "per_attack": per_attack,
            "sota_comparison": sota_comparison,
        }
    except Exception as e:
        import traceback

        return {"available": False, "error": str(e), "trace": traceback.format_exc()}


def _roc_egri_hesapla(labels: list, scores: list) -> tuple:
    """
    (roc_noktalar, auc) döndür.
    roc_noktalar: [{fpr, tpr}, ...] — drawROC() formatı.
    """
    if len(set(labels)) < 2:
        return [{"fpr": 0.0, "tpr": 0.0}, {"fpr": 1.0, "tpr": 1.0}], 0.5

    pozitif = sum(labels)
    negatif = len(labels) - pozitif
    if pozitif == 0 or negatif == 0:
        return [{"fpr": 0.0, "tpr": 0.0}, {"fpr": 1.0, "tpr": 1.0}], 0.5

    # Sıralanmış eşikler üzerinden (FPR, TPR) üret
    esikler = sorted(set(scores), reverse=True)
    noktalar = [{"fpr": 0.0, "tpr": 0.0}]

    for esik in esikler:
        _tp = sum(1 for l, s in zip(labels, scores) if l == 1 and s >= esik)
        _fp = sum(1 for l, s in zip(labels, scores) if l == 0 and s >= esik)
        noktalar.append(
            {
                "fpr": round(_fp / negatif, 4),
                "tpr": round(_tp / pozitif, 4),
            }
        )

    noktalar.append({"fpr": 1.0, "tpr": 1.0})

    # Trapez AUC
    auc = 0.0
    for i in range(1, len(noktalar)):
        x0, y0 = noktalar[i - 1]["fpr"], noktalar[i - 1]["tpr"]
        x1, y1 = noktalar[i]["fpr"], noktalar[i]["tpr"]
        auc += (x1 - x0) * (y0 + y1) / 2

    return noktalar, round(abs(auc), 4)


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int):
    try:
        conn = get_conn()
        conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
        conn.commit()
        conn.close()
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/demo/start")
async def demo_start():
    return {"status": "disabled", "reason": "Canlı trafik modu aktif — simülasyon devre dışı."}


@app.post("/api/internal/notify")
async def internal_notify():
    """sentinel.py tarafından her anomali tespitinde çağrılır; broadcaster'ı anında uyarır."""
    _notify_event.set()
    return {"ok": True}


@app.get("/api/report")
async def generate_report():
    return JSONResponse({"error": "PDF rapor devre dışı bırakıldı."}, status_code=404)


# ── WebSocket ────────────────────────────────────────────────────────────────


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        await ws.send_json({"type": "connected", "ts": time.time()})
        # İlk yükleme verisini gönder
        since = _get_session_start()
        dev_df = get_devices_df()
        if since > 0 and dev_df is not None and not dev_df.empty and "last_seen" in dev_df.columns:
            dev_df = dev_df[dev_df["last_seen"] >= since]
        al_df = get_alerts_df(200)
        if since > 0 and al_df is not None and not al_df.empty and "ts" in al_df.columns:
            al_df = al_df[al_df["ts"] >= since].head(20)
        await ws.send_json(
            {
                "type": "snapshot",
                "stats": _filtered_stats(since),
                "devices": _df_to_records(dev_df),
                "alerts": _df_to_records(al_df),
            }
        )
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── Arka plan yayıncısı (5 sn'de bir anlık görüntü) ─────────────────────────


async def _broadcaster():
    """
    sentinel.py /api/internal/notify POST'u ateşlediğinde anında yayın yapar.
    Notify gelmezse 5 saniyede bir polling fallback çalışır.
    """
    while True:
        try:
            await asyncio.wait_for(_notify_event.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass
        _notify_event.clear()

        if manager.active:
            try:
                since = _get_session_start()
                dev_df = get_devices_df()
                if (
                    since > 0
                    and dev_df is not None
                    and not dev_df.empty
                    and "last_seen" in dev_df.columns
                ):
                    dev_df = dev_df[dev_df["last_seen"] >= since]
                al_df = get_alerts_df(200)
                if since > 0 and al_df is not None and not al_df.empty and "ts" in al_df.columns:
                    al_df = al_df[al_df["ts"] >= since].head(20)
                payload = {
                    "type": "update",
                    "ts": time.time(),
                    "stats": _filtered_stats(since),
                    "devices": _df_to_records(dev_df),
                    "alerts": _df_to_records(al_df),
                }
                await manager.broadcast(payload)
            except Exception:
                pass


# ── Demo çalıştırıcı ─────────────────────────────────────────────────────────


async def _run_demo():
    try:
        import subprocess
        import sys

        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import sys, os; sys.path.insert(0, '/home/kali/sentinel'); "
            "from core.database import init_db; init_db(); "
            "from core.simulator import simulate; "
            "import sentinel; sentinel.init_ai(); "
            "for atype in ['port_scan','dns_tunnel','exfiltration','lateral_movement']: "
            "    simulate(atype, callback=sentinel.on_window, windows=2)",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        await manager.broadcast({"type": "demo_done", "ts": time.time()})
    except Exception as e:
        await manager.broadcast({"type": "demo_error", "error": str(e)})
