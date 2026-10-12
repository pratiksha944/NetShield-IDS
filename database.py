import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "ids_events.db"

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                dst_port INTEGER,
                severity TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)

def add_event(source, src_ip, dst_ip, protocol, dst_port, severity, message, timestamp):
    with connect() as conn:
        conn.execute("""
            INSERT INTO events (timestamp, source, src_ip, dst_ip, protocol, dst_port, severity, message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, source, src_ip, dst_ip, protocol, dst_port, severity, message))

def get_events(limit=100):
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]

def get_stats():
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM events WHERE severity='HIGH'").fetchone()[0]
        medium = conn.execute("SELECT COUNT(*) FROM events WHERE severity='MEDIUM'").fetchone()[0]
        info = conn.execute("SELECT COUNT(*) FROM events WHERE severity='INFO'").fetchone()[0]
        sources = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip IS NOT NULL").fetchone()[0]
    return {"total_events": total, "high": high, "medium": medium, "info": info, "unique_sources": sources}

def clear_events():
    with connect() as conn:
        conn.execute("DELETE FROM events")
