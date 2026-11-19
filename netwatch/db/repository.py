"""SQLite storage. All queries use parameters (never string formatting with data)."""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from netwatch.capture.packet import PacketInfo
from netwatch.config import DATA_DIR

DB_FILE = DATA_DIR / "netwatch.db"
MAX_PACKETS = 50_000  # row limit for the packets table (oldest rows are deleted)
FLUSH_EVERY = 200

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,          -- 'file' or 'live'
    name TEXT NOT NULL,            -- file name or interface
    created_at REAL NOT NULL,
    ended_at REAL,
    total INTEGER DEFAULT 0,
    discarded INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    ts REAL NOT NULL,
    protocol TEXT NOT NULL,
    src_mac TEXT, dst_mac TEXT,
    src_ip TEXT, dst_ip TEXT,
    sport INTEGER, dport INTEGER,
    length INTEGER,
    tcp_flags TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
CREATE TABLE IF NOT EXISTS conversations (
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    ip_a TEXT NOT NULL, ip_b TEXT NOT NULL,
    packets INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
    first_ts REAL, last_ts REAL,
    PRIMARY KEY (session_id, ip_a, ip_b)
);
CREATE TABLE IF NOT EXISTS ip_mac (
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    ip TEXT NOT NULL, mac TEXT NOT NULL,
    first_seen REAL, last_seen REAL,
    PRIMARY KEY (session_id, ip, mac)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    ts REAL NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT, dport INTEGER,
    username TEXT,
    password_masked TEXT
);
"""

TABLES = ("sessions", "packets", "conversations", "ip_mac", "alerts", "credentials")
PACKET_COLUMNS = ("session_id", "ts", "protocol", "src_mac", "dst_mac", "src_ip", "dst_ip",
                  "sport", "dport", "length", "tcp_flags")


class Repository:
    def __init__(self, path: Path = DB_FILE, max_packets: int = MAX_PACKETS):
        path.parent.mkdir(parents=True, exist_ok=True)
        # Live capture writes from the sniffer thread, so access is guarded by a lock.
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.max_packets = max_packets
        self._lock = threading.Lock()
        self._buffer: list[tuple] = []

    # --- sessions ---
    def create_session(self, source: str, name: str) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO sessions (source, name, created_at) VALUES (?, ?, ?)",
                (source, name, time.time()))
            self.conn.commit()
            return cur.lastrowid

    def finish_session(self, session_id: int, total: int, discarded: int) -> None:
        self.flush()
        with self._lock:
            self.conn.execute(
                "UPDATE sessions SET ended_at = ?, total = ?, discarded = ? WHERE id = ?",
                (time.time(), total, discarded, session_id))
            self.conn.commit()

    # --- packets ---
    def add_packet(self, session_id: int, p: PacketInfo) -> None:
        """Buffer a packet (payload is never stored). Flushed in batches."""
        with self._lock:
            self._buffer.append((session_id, p.ts, p.protocol, p.src_mac, p.dst_mac, p.src_ip,
                                 p.dst_ip, p.sport, p.dport, p.length, p.tcp_flags))
            full = len(self._buffer) >= FLUSH_EVERY
        if full:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            if self._buffer:
                placeholders = ", ".join("?" * len(PACKET_COLUMNS))
                self.conn.executemany(
                    f"INSERT INTO packets ({', '.join(PACKET_COLUMNS)}) VALUES ({placeholders})",
                    self._buffer)
                self._buffer.clear()
                self.conn.execute(
                    "DELETE FROM packets WHERE id <= (SELECT MAX(id) FROM packets) - ?",
                    (self.max_packets,))
            self.conn.commit()

    def filter_packets(self, session_id: int | None = None, ip: str | None = None,
                       protocol: str | None = None, port: int | None = None,
                       limit: int = 100) -> list[dict]:
        """RF11: filter packets by IP, protocol and/or port."""
        where, params = [], []
        if session_id is not None:
            where.append("session_id = ?")
            params.append(session_id)
        if ip:
            where.append("(src_ip = ? OR dst_ip = ?)")
            params += [ip, ip]
        if protocol:
            where.append("protocol = ?")
            params.append(protocol.upper())
        if port is not None:
            where.append("(sport = ? OR dport = ?)")
            params += [port, port]
        sql = "SELECT * FROM packets"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, params)]

    # --- conversations (RF4) ---
    def update_conversation(self, session_id: int, ip_a: str, ip_b: str, length: int, ts: float) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO conversations (session_id, ip_a, ip_b, packets, bytes, first_ts, last_ts)
                   VALUES (?, ?, ?, 1, ?, ?, ?)
                   ON CONFLICT (session_id, ip_a, ip_b) DO UPDATE SET
                       packets = packets + 1, bytes = bytes + excluded.bytes,
                       first_ts = MIN(first_ts, excluded.first_ts), last_ts = MAX(last_ts, excluded.last_ts)""",
                (session_id, ip_a, ip_b, length, ts, ts))

    def top_conversations(self, session_id: int, limit: int = 5) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM conversations WHERE session_id = ? ORDER BY packets DESC, bytes DESC LIMIT ?",
                (session_id, limit))
            return [dict(r) for r in rows]

    # --- IP <-> MAC (RF6) ---
    def update_ip_mac(self, session_id: int, ip: str, mac: str, ts: float) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO ip_mac (session_id, ip, mac, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT (session_id, ip, mac) DO UPDATE SET
                       first_seen = MIN(first_seen, excluded.first_seen),
                       last_seen = MAX(last_seen, excluded.last_seen)""",
                (session_id, ip, mac, ts, ts))

    def ip_mac_table(self, session_id: int) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM ip_mac WHERE session_id = ? ORDER BY ip, first_seen", (session_id,))
            return [dict(r) for r in rows]

    # --- alerts (RF12) ---
    def add_alert(self, session_id: int, ts: float, type_: str, severity: str, detail: str) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO alerts (session_id, ts, type, severity, detail) VALUES (?, ?, ?, ?, ?)",
                (session_id, ts, type_, severity, detail))
            return cur.lastrowid

    def update_alert_detail(self, alert_id: int, detail: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE alerts SET detail = ? WHERE id = ?", (detail, alert_id))

    def alerts(self, session_id: int) -> list[dict]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM alerts WHERE session_id = ? ORDER BY ts, id", (session_id,))
            return [dict(r) for r in rows]

    # --- credentials (RF5): only the masked password is stored ---
    def add_credential(self, session_id: int, cred) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO credentials (session_id, ts, protocol, src_ip, dst_ip, dport, username, password_masked)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, cred.ts, cred.protocol, cred.src_ip, cred.dst_ip, cred.dport,
                 cred.username, cred.password_masked))

    def credentials(self, session_id: int) -> list[dict]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM credentials WHERE session_id = ? ORDER BY ts, id", (session_id,))
            return [dict(r) for r in rows]

    # --- misc ---
    def table_counts(self) -> dict:
        with self._lock:
            # Table names come from the TABLES constant, not from user input.
            return {t: self.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLES}

    def close(self) -> None:
        self.flush()
        self.conn.close()
