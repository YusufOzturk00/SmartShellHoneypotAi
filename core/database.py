import json
import os
import time
import sqlite3
import threading

DB_PATH = "data/honeypot.db"
_lock = threading.Lock()

def _get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            log_type TEXT,
            message TEXT,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn

def insert_log(log_type, message, details=None):
    if details is None:
        details = {}
    with _lock:
        try:
            conn = _get_connection()
            conn.execute(
                "INSERT INTO logs (timestamp, log_type, message, details) VALUES (?, ?, ?, ?)",
                (time.time(), log_type, message, json.dumps(details, default=str))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB ERROR] {e}")

def get_logs(limit=100, log_type=None):
    try:
        conn = _get_connection()
        if log_type:
            cursor = conn.execute(
                "SELECT * FROM logs WHERE log_type = ? ORDER BY id DESC LIMIT ?",
                (log_type, limit)
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM logs ORDER BY id DESC LIMIT ?",
                (limit,)
            )
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception as e:
        print(f"[DB ERROR] {e}")
        return []
