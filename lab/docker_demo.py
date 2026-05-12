#!/usr/bin/env python3
"""
SENTINEL - Docker Saldirgan Demo
=================================
Kullanim:
  python3 docker_demo.py             # Tum saldirilar
  python3 docker_demo.py port_scan
  python3 docker_demo.py exfiltration
  python3 docker_demo.py dns_tunnel
  python3 docker_demo.py lateral
"""
import json
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import get_conn, init_db
from core.simulator import simulate
from sentinel import ALERT_THRESHOLD, init_ai, on_window

CONTAINER = "sentinel-attacker"
HOST_IP = "172.17.0.1"  # docker0 — SENTINEL makinesi
ATTACKER_IP = "172.17.0.2"  # container

G = "\033[32m"
R = "\033[31m"
Y = "\033[33m"
C = "\033[36m"
B = "\033[1m"
X = "\033[0m"


def docker_exec(cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER, "bash", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[hata: {e}]"


def alert_count() -> int:
    try:
        conn = get_conn()
        n = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        conn.close()
        return n
    except Exception:
        return 0


def run_attack(name: str, windows: int = 15):
    labels = {
        "exfiltration": "Veri Sizdirma",
        "port_scan": "Port Taramasi",
        "dns_tunnel": "DNS Tunelleme",
        "lateral": "Yanal Hareket",
    }
    label = labels.get(name, name)

    print(f"\n{C}{'='*60}{X}")
    print(f"{B}  SENARYO: {label.upper()}{X}")
    print(f"{C}{'='*60}{X}")

    # ── Gercek Docker saldirisi (gorsel efekt) ────────────────
    real_cmds = {
        "port_scan": (
            f"nmap -sT -T4 -p 1-1000 {HOST_IP} --open 2>&1 | tail -6",
            "nmap port taramasi",
        ),
        "exfiltration": (
            f"dd if=/dev/urandom bs=1K count=2000 2>/dev/null | "
            f"nc -w3 {HOST_IP} 9999 2>&1 || "
            f"curl -s --max-time 10 -X POST http://{HOST_IP}:9999 "
            f"--data-binary @/dev/null 2>&1; echo 'veri transfer denemesi tamamlandi'",
            "veri transferi",
        ),
        "dns_tunnel": (
            'python3 -c "'
            "import subprocess,random,string,time\n"
            "print('DNS sorgu bombardimani basliyor...')\n"
            "[subprocess.run(['nslookup', "
            "''.join(random.choices(string.ascii_lowercase,k=28))+'.test.local',"
            f"'{HOST_IP}'],capture_output=True) for _ in range(80)]\n"
            "print('80 DNS sorgusu gonderildi')\"",
            "DNS flood",
        ),
        "lateral": (
            f"nmap -sn 172.17.0.0/24 2>&1 | tail -5 && "
            f"for i in 22 80 443 3389 8080; do "
            f'nc -zw1 {HOST_IP} $i 2>/dev/null && echo "port $i acik"; done; echo tarama bitti',
            "ic ag taramasi",
        ),
    }

    cmd_str, cmd_label = real_cmds.get(name, ("echo 'senaryo yok'", ""))

    print(f"\n{Y}[SALDIRGAN → {HOST_IP}] {cmd_label} baslatiliyor...{X}")

    # Gercek saldiris paralelde calistir
    attack_done = threading.Event()
    attack_out = []

    def run_real():
        out = docker_exec(cmd_str, timeout=40)
        attack_out.append(out)
        attack_done.set()

    t = threading.Thread(target=run_real, daemon=True)
    t.start()

    # ── SENTINEL AI pipeline (simulasyon + gercek tespit) ────
    before = alert_count()
    simulate(name, callback=on_window, windows=windows)
    new_n = alert_count() - before

    attack_done.wait(timeout=5)
    if attack_out:
        print(f"\n{Y}[Container ciktisi]:{X}")
        for line in attack_out[0].split("\n")[:8]:
            if line.strip():
                print(f"  {line}")

    # ── Sonuc ────────────────────────────────────────────────
    print()
    if new_n > 0:
        print(f"  {G}{B}SENTINEL TESPIT ETTI — {new_n} uyari{X}")
        conn = get_conn()
        rows = conn.execute(
            "SELECT attack_type, anomaly_score, llm_analysis "
            "FROM alerts ORDER BY ts DESC LIMIT ?",
            (new_n,),
        ).fetchall()
        conn.close()
        for row in rows:
            atype = row[0]
            score = float(row[1])
            try:
                llm = json.loads(row[2] or "{}")
            except Exception:
                llm = {}
            print(f"    {R}▶ {atype}{X}  Skor: {B}{score:.3f}{X}")
            if llm.get("aciklama"):
                print(f"    AI   : {llm['aciklama']}")
            if llm.get("oneri"):
                print(f"    Oneri: {llm['oneri'][0]}")
    else:
        print(f"  {Y}Tespit yok (esik: {ALERT_THRESHOLD}){X}")

    return new_n


def main():
    SCENARIOS = ["port_scan", "exfiltration", "dns_tunnel", "lateral"]
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"

    if arg not in SCENARIOS and arg != "all":
        print(f"Secenekler: all, {', '.join(SCENARIOS)}")
        sys.exit(1)

    print(f"\n{C}{'='*60}")
    print("  SENTINEL x DOCKER SALDIRI DEMO")
    print(f"  Saldirgan: {ATTACKER_IP} (sentinel-attacker)")
    print(f"  Hedef    : {HOST_IP} (SENTINEL makinesi)")
    print(f"{'='*60}{X}")

    init_db()
    init_ai()

    targets = SCENARIOS if arg == "all" else [arg]
    results = {}
    for s in targets:
        results[s] = run_attack(s)
        if len(targets) > 1:
            time.sleep(2)

    # Ozet
    print(f"\n{C}{'='*60}")
    print("  DEMO OZETI")
    print(f"{'='*60}{X}")
    detected = sum(1 for v in results.values() if v > 0)
    label_map = {
        "port_scan": "Port Taramasi",
        "exfiltration": "Veri Sizdirma",
        "dns_tunnel": "DNS Tunelleme",
        "lateral": "Yanal Hareket",
    }
    for s, n in results.items():
        icon = f"{G}TESPIT{X}" if n > 0 else f"{Y}KACTI {X}"
        print(f"  [{icon}]  {label_map.get(s,s):<22}  {n} uyari")
    print(f"\n  Tespit orani : {detected}/{len(results)}")
    print(f"  Dashboard    : http://localhost:8501\n")


if __name__ == "__main__":
    main()
