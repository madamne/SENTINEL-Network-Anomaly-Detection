"""
SENTINEL - Veritabanı Yöneticisi
"""

import json
import os
import sqlite3
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sentinel.db")


def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS traffic_windows (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ts               REAL,
            device_mac       TEXT,
            device_ip        TEXT,
            -- Zaman özellikleri
            hour             INTEGER,
            is_weekend       INTEGER,
            -- DNS özellikleri
            dns_count        INTEGER DEFAULT 0,
            unique_domains   INTEGER DEFAULT 0,
            external_ratio   REAL    DEFAULT 0,
            txt_queries      INTEGER DEFAULT 0,
            failed_dns       INTEGER DEFAULT 0,
            -- Trafik özellikleri
            upload_bytes     INTEGER DEFAULT 0,
            download_bytes   INTEGER DEFAULT 0,
            upload_ratio     REAL    DEFAULT 0,
            avg_packet_size  REAL    DEFAULT 0,
            -- Bağlantı özellikleri
            unique_ips       INTEGER DEFAULT 0,
            new_ip_ratio     REAL    DEFAULT 0,
            unique_ports     INTEGER DEFAULT 0,
            high_ports       INTEGER DEFAULT 0,
            -- Protokol özellikleri
            http_count       INTEGER DEFAULT 0,
            https_count      INTEGER DEFAULT 0,
            arp_count        INTEGER DEFAULT 0,
            -- AI çıktısı
            anomaly_score    REAL    DEFAULT 0,
            is_anomaly       INTEGER DEFAULT 0,
            attack_type      TEXT    DEFAULT 'normal',
            shap_json        TEXT    DEFAULT '{}',
            llm_analysis     TEXT    DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS devices (
            mac              TEXT PRIMARY KEY,
            ip               TEXT,
            device_id        TEXT,
            first_seen       REAL,
            last_seen        REAL,
            total_windows    INTEGER DEFAULT 0,
            anomaly_count    INTEGER DEFAULT 0,
            threat_score     INTEGER DEFAULT 0,
            label            TEXT    DEFAULT 'normal',
            profile_json     TEXT    DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ts               REAL,
            device_mac       TEXT,
            attack_type      TEXT,
            anomaly_score    REAL,
            details          TEXT,
            acknowledged     INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS packets (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ts               REAL,
            src_mac          TEXT,
            src_ip           TEXT,
            dst_ip           TEXT,
            protocol         TEXT,
            length           INTEGER,
            dns_query        TEXT,
            port             INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_windows_mac ON traffic_windows(device_mac);
        CREATE INDEX IF NOT EXISTS idx_windows_ts  ON traffic_windows(ts);
        CREATE INDEX IF NOT EXISTS idx_packets_ts  ON packets(ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts   ON alerts(ts);

        CREATE TABLE IF NOT EXISTS evaluation_results (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ts               REAL,
            n_normal         INTEGER,
            n_attack         INTEGER,
            threshold        REAL,
            precision        REAL,
            recall           REAL,
            f1_score         REAL,
            roc_auc          REAL,
            accuracy         REAL,
            tp               INTEGER,
            fp               INTEGER,
            tn               INTEGER,
            fn               INTEGER,
            per_attack_json  TEXT    DEFAULT '{}',
            roc_curve_json   TEXT    DEFAULT '[]',
            run_seconds      REAL
        );
    """
    )
    conn.commit()
    conn.close()


def insert_packet(ts, src_mac, src_ip, dst_ip, protocol, length, dns_query="", port=0):
    try:
        conn = get_conn()
        conn.execute(
            """
            INSERT INTO packets (ts,src_mac,src_ip,dst_ip,protocol,length,dns_query,port)
            VALUES (?,?,?,?,?,?,?,?)
        """,
            (ts, src_mac, src_ip, dst_ip, protocol, length, dns_query, port),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def insert_window(data: dict):
    try:
        conn = get_conn()
        conn.execute(
            """
            INSERT INTO traffic_windows
            (ts,device_mac,device_ip,hour,is_weekend,
             dns_count,unique_domains,external_ratio,txt_queries,failed_dns,
             upload_bytes,download_bytes,upload_ratio,avg_packet_size,
             unique_ips,new_ip_ratio,unique_ports,high_ports,
             http_count,https_count,arp_count,
             anomaly_score,is_anomaly,attack_type,shap_json,llm_analysis)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
            (
                data.get("ts", time.time()),
                data.get("device_mac", ""),
                data.get("device_ip", ""),
                data.get("hour", 0),
                data.get("is_weekend", 0),
                data.get("dns_count", 0),
                data.get("unique_domains", 0),
                data.get("external_ratio", 0),
                data.get("txt_queries", 0),
                data.get("failed_dns", 0),
                data.get("upload_bytes", 0),
                data.get("download_bytes", 0),
                data.get("upload_ratio", 0),
                data.get("avg_packet_size", 0),
                data.get("unique_ips", 0),
                data.get("new_ip_ratio", 0),
                data.get("unique_ports", 0),
                data.get("high_ports", 0),
                data.get("http_count", 0),
                data.get("https_count", 0),
                data.get("arp_count", 0),
                data.get("anomaly_score", 0),
                data.get("is_anomaly", 0),
                data.get("attack_type", "normal"),
                json.dumps(data.get("shap_json", {})),
                json.dumps(data.get("llm_analysis", {})),
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] insert_window hata: {e}")


def update_window_score(mac: str, ts: float, score: float, is_anomaly: int):
    """Hesaplanan anomali skorunu traffic_windows tablosuna geri yaz."""
    try:
        conn = get_conn()
        conn.execute(
            "UPDATE traffic_windows SET anomaly_score=?, is_anomaly=? "
            "WHERE device_mac=? AND ts=?",
            (score, is_anomaly, mac, ts),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] update_window_score hata: {e}")


def upsert_device(mac, ip, device_id, ts):
    try:
        conn = get_conn()
        conn.execute(
            """
            INSERT INTO devices (mac,ip,device_id,first_seen,last_seen)
            VALUES (?,?,?,?,?)
            ON CONFLICT(mac) DO UPDATE SET
                ip=excluded.ip, last_seen=excluded.last_seen,
                total_windows=total_windows+1
        """,
            (mac, ip, device_id, ts, ts),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def update_device_threat(mac, score, label):
    try:
        conn = get_conn()
        if label != "normal":
            conn.execute(
                """
                UPDATE devices SET threat_score=?, label=?,
                anomaly_count=anomaly_count+1 WHERE mac=?
            """,
                (score, label, mac),
            )
        else:
            conn.execute(
                "UPDATE devices SET threat_score=?, label=? WHERE mac=?", (score, label, mac)
            )
        conn.commit()
        conn.close()
    except Exception:
        pass


def insert_alert(ts, mac, attack_type, score, details=""):
    try:
        conn = get_conn()
        conn.execute(
            """
            INSERT INTO alerts (ts,device_mac,attack_type,anomaly_score,details)
            VALUES (?,?,?,?,?)
        """,
            (ts, mac, attack_type, score, details),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_stats():
    try:
        conn = get_conn()
        c = conn.cursor()
        r = {}
        r["total_packets"] = c.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        r["total_windows"] = c.execute("SELECT COUNT(*) FROM traffic_windows").fetchone()[0]
        r["devices"] = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        r["alerts"] = c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
        r["threats"] = c.execute("SELECT COUNT(*) FROM devices WHERE threat_score>=60").fetchone()[
            0
        ]
        r["safe"] = c.execute("SELECT COUNT(*) FROM devices WHERE threat_score<30").fetchone()[0]
        conn.close()
        return r
    except Exception:
        return {}


def get_devices_df():
    import pandas as pd

    try:
        conn = get_conn()
        df = pd.read_sql(
            """
            SELECT mac,ip,device_id,threat_score,label,
                   total_windows,anomaly_count,last_seen,first_seen
            FROM devices ORDER BY threat_score DESC
        """,
            conn,
        )
        conn.close()
        return df
    except Exception:
        return __import__("pandas").DataFrame()


def get_alerts_df(limit=50):
    import pandas as pd

    try:
        conn = get_conn()
        df = pd.read_sql(
            f"""
            SELECT id,ts,device_mac,attack_type,anomaly_score,details,acknowledged
            FROM alerts ORDER BY ts DESC LIMIT {limit}
        """,
            conn,
        )
        conn.close()
        return df
    except Exception:
        return __import__("pandas").DataFrame()


def get_windows_df(mac=None, limit=200):
    import pandas as pd

    try:
        conn = get_conn()
        where = f"WHERE device_mac='{mac}'" if mac else ""
        df = pd.read_sql(
            f"""
            SELECT * FROM traffic_windows
            {where} ORDER BY ts DESC LIMIT {limit}
        """,
            conn,
        )
        conn.close()
        return df
    except Exception:
        return __import__("pandas").DataFrame()
