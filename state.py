"""Persistent SQLite state for discovery/checking/publishing."""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)
DB_PATH = Path(os.getenv("STATE_DB", Path(__file__).with_name("proxy_state.db")))
SEEN_TTL = max(0, int(os.getenv("SEEN_TTL", 30 * 60)))
PUBLISHED_TTL = max(0, int(os.getenv("PUBLISHED_TTL", 6 * 3600)))
SOURCE_STATS_TTL = max(0, int(os.getenv("SOURCE_STATS_TTL", 7 * 24 * 3600)))


def proxy_identity(proxy: dict) -> str:
    protocol = str(proxy.get("protocol", "")).strip().upper()
    host = str(proxy.get("ip", proxy.get("host", ""))).strip().lower()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    secret = str(proxy.get("secret", "")).strip().lower() if protocol in {"MTPROTO", "WEB"} else ""
    return f"{protocol}|{host}|{port}|{secret}"


def _hash(proxy: dict) -> str:
    return hashlib.sha256(proxy_identity(proxy).encode()).hexdigest()[:20]


def _identity_digest(proxy: dict) -> str:
    return hashlib.sha256(proxy_identity(proxy).encode()).hexdigest()


@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with _connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS seen_proxies (
            hash TEXT PRIMARY KEY,
            identity TEXT NOT NULL,
            protocol TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            check_count INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS published_proxies (
            hash TEXT PRIMARY KEY,
            identity TEXT NOT NULL,
            protocol TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            published_at REAL NOT NULL,
            ping_ms INTEGER
        );
        CREATE TABLE IF NOT EXISTS source_stats (
            source TEXT PRIMARY KEY,
            total_fetched INTEGER NOT NULL DEFAULT 0,
            total_working INTEGER NOT NULL DEFAULT 0,
            last_success REAL,
            last_failure REAL,
            consecutive_failures INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_seen_last_seen ON seen_proxies(last_seen);
        CREATE INDEX IF NOT EXISTS idx_published_at ON published_proxies(published_at);
        """)


def _rows_to_hashes(proxies: list[dict]) -> list[tuple[dict, str]]:
    out = []
    for proxy in proxies:
        identity = proxy_identity(proxy)
        if identity.startswith("||"):
            continue
        out.append((proxy, _hash(proxy)))
    return out


def _blocked_hashes(table: str, column: str, hashes: list[str], cutoff: float) -> set[str]:
    if not hashes:
        return set()
    blocked: set[str] = set()
    with _connect() as conn:
        for start in range(0, len(hashes), 900):
            chunk = hashes[start:start + 900]
            placeholders = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT hash FROM {table} WHERE hash IN ({placeholders}) AND {column} > ?",
                (*chunk, cutoff),
            )
            blocked.update(row[0] for row in rows)
    return blocked


def filter_unpublished(proxies: list[dict]) -> list[dict]:
    pairs = _rows_to_hashes(proxies)
    cutoff = time.time() - PUBLISHED_TTL
    blocked = _blocked_hashes("published_proxies", "published_at", [h for _, h in pairs], cutoff)
    return [p for p, h in pairs if h not in blocked]


def mark_seen_many(proxies: list[dict]) -> None:
    now = time.time()
    rows = []
    for proxy, proxy_hash in _rows_to_hashes(proxies):
        protocol = str(proxy.get("protocol", "")).upper()
        host = str(proxy.get("ip", "")).strip()
        try:
            port = int(proxy.get("port", 0))
        except (TypeError, ValueError):
            continue
        rows.append((proxy_hash, _identity_digest(proxy), protocol, host, port, now, now))
    if not rows:
        return
    with _connect() as conn:
        conn.executemany("""
        INSERT INTO seen_proxies(hash,identity,protocol,host,port,first_seen,last_seen,check_count)
        VALUES (?,?,?,?,?,?,?,1)
        ON CONFLICT(hash) DO UPDATE SET
          last_seen=excluded.last_seen,
          check_count=seen_proxies.check_count+1
        """, rows)


def mark_seen(proxy: dict) -> None:
    mark_seen_many([proxy])


def mark_published(proxy: dict) -> None:
    now = time.time()
    protocol = str(proxy.get("protocol", "")).upper()
    host = str(proxy.get("ip", "")).strip()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    ping = proxy.get("ping_ms", proxy.get("ping"))
    try:
        ping = int(float(str(ping).replace("ms", "").strip())) if ping is not None else None
    except (TypeError, ValueError):
        ping = None
    with _connect() as conn:
        conn.execute("""
        INSERT INTO published_proxies(hash,identity,protocol,host,port,published_at,ping_ms)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(hash) DO UPDATE SET published_at=excluded.published_at,ping_ms=excluded.ping_ms
        """, (_hash(proxy), _identity_digest(proxy), protocol, host, port, now, ping))


def record_source_stats(source: str, fetched: int, working: int) -> None:
    if not source:
        return
    now = time.time()
    with _connect() as conn:
        if working > 0:
            conn.execute("""
            INSERT INTO source_stats(source,total_fetched,total_working,last_success,last_failure,consecutive_failures)
            VALUES (?,?,?, ?,NULL,0)
            ON CONFLICT(source) DO UPDATE SET
              total_fetched=source_stats.total_fetched+excluded.total_fetched,
              total_working=source_stats.total_working+excluded.total_working,
              last_success=excluded.last_success,
              consecutive_failures=0
            """, (source, fetched, working, now))
        else:
            conn.execute("""
            INSERT INTO source_stats(source,total_fetched,total_working,last_failure,consecutive_failures)
            VALUES (?, ?, 0, ?, 1)
            ON CONFLICT(source) DO UPDATE SET
              total_fetched=source_stats.total_fetched+excluded.total_fetched,
              last_failure=excluded.last_failure,
              consecutive_failures=source_stats.consecutive_failures+1
            """, (source, fetched, now))


def cleanup() -> None:
    now = time.time()
    with _connect() as conn:
        conn.execute("DELETE FROM seen_proxies WHERE last_seen < ?", (now - SEEN_TTL,))
        conn.execute("DELETE FROM published_proxies WHERE published_at < ?", (now - PUBLISHED_TTL,))
        conn.execute("DELETE FROM source_stats WHERE last_success IS NOT NULL AND last_success < ?", (now - SOURCE_STATS_TTL,))


def count_seen() -> int:
    with _connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM seen_proxies").fetchone()[0])


def count_published() -> int:
    with _connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM published_proxies").fetchone()[0])
