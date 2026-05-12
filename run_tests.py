#!/usr/bin/env python3
"""
SENTINEL - Otomatik Saldiri Test Kosucusu
==========================================
Kullanim:
  python3 run_tests.py          # Tum senaryolar
  python3 run_tests.py exfiltration
  python3 run_tests.py port_scan
  python3 run_tests.py dns_tunnel
  python3 run_tests.py lateral
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import get_alerts_df, get_stats, init_db
from core.simulator import simulate
from sentinel import ALERT_THRESHOLD, init_ai, on_window

SCENARIOS = ["exfiltration", "port_scan", "dns_tunnel", "lateral"]
LABELS = {
    "exfiltration": "Veri Sizdirma",
    "port_scan": "Port Taramasi",
    "dns_tunnel": "DNS Tunelleme",
    "lateral": "Yanal Hareket",
}

G = "\033[32m"
R = "\033[31m"
Y = "\033[33m"
C = "\033[36m"
B = "\033[1m"
X = "\033[0m"


def _alert_count():
    from core.database import get_conn

    try:
        conn = get_conn()
        n = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        conn.close()
        return n
    except Exception:
        return 0


def run_scenario(name: str, windows: int = 15) -> int:
    label = LABELS.get(name, name)
    before = _alert_count()
    t0 = time.time()

    print(f"\n{C}{'─'*58}{X}")
    print(f"{B}  SENARYO: {label.upper()}{X}")
    print(f"{C}{'─'*58}{X}")

    simulate(name, callback=on_window, windows=windows)

    elapsed = time.time() - t0
    new_n = _alert_count() - before

    print(f"\n  Sure: {elapsed:.1f}s  |  Pencere: {windows}")

    if new_n > 0:
        print(f"  {G}{B}TESPIT EDILDI — {new_n} uyari{X}")
        df = get_alerts_df(new_n + 2)
        for _, row in df.head(new_n).iterrows():
            score = float(row.get("anomaly_score", 0))
            atype = str(row.get("attack_type", ""))
            try:
                llm = json.loads(str(row.get("llm_analysis", "{}")))
            except Exception:
                llm = {}
            print(f"    {R}> {atype}{X}  Skor: {B}{score:.3f}{X}")
            if llm.get("aciklama"):
                print(f"    AI   : {llm['aciklama']}")
            if llm.get("oneri"):
                print(f"    Oneri: {llm['oneri'][0]}")
    else:
        print(f"  {Y}Tespit yok  (esik: {ALERT_THRESHOLD}){X}")

    return new_n


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"

    if arg not in SCENARIOS and arg != "all":
        print(f"Gecersiz senaryo. Secenekler: all, {', '.join(SCENARIOS)}")
        sys.exit(1)

    print(f"\n{C}{'='*58}")
    print("  SENTINEL OTOMATIK SALDIRI TEST KOSUCUSU")
    print(f"{'='*58}{X}")

    init_db()
    init_ai()

    targets = SCENARIOS if arg == "all" else [arg]
    results = {}

    for s in targets:
        results[s] = run_scenario(s)
        time.sleep(2)

    stats = get_stats()
    print(f"\n{C}{'='*58}")
    print("  OZET")
    print(f"{'='*58}{X}")

    detected = sum(1 for v in results.values() if v > 0)
    for s, n in results.items():
        icon = f"{G}TESPIT{X}" if n > 0 else f"{Y}KACTI {X}"
        print(f"  [{icon}]  {LABELS.get(s, s):<22}  {n} uyari")

    print(f"\n  Tespit orani  : {detected}/{len(results)}")
    print(f"  Toplam uyari  : {stats.get('alerts', 0)}")
    print(f"  Tehdit cihaz  : {stats.get('threats', 0)}")
    print(f"  Dashboard     : http://localhost:8501\n")


if __name__ == "__main__":
    main()
