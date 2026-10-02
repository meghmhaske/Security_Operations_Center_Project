import sqlite3
from .config import DB_PATH

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_type TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT,
            username TEXT,
            destination_port INTEGER,
            protocol TEXT,
            status TEXT,
            bytes_transferred INTEGER DEFAULT 0,
            metadata TEXT DEFAULT '{}'
        )
    """)
    conn.commit()
    conn.close()

def insert_event(event: dict) -> int:
    conn = get_connection()
    cur = conn.execute("""
        INSERT INTO events (
            timestamp, source_type, event_type, source_ip,
            destination_ip, username, destination_port, protocol,
            status, bytes_transferred, metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"], event["source_type"], event["event_type"],
        event["source_ip"], event.get("destination_ip"),
        event.get("username"), event.get("destination_port"),
        event.get("protocol"), event.get("status"),
        event.get("bytes_transferred", 0),
        str(event.get("metadata", {})),
    ))
    conn.commit()
    event_id = cur.lastrowid
    conn.close()
    return event_id

def recent_events(source_ip: str, limit: int = 100):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM events WHERE source_ip = ? ORDER BY id DESC LIMIT ?",
        (source_ip, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
