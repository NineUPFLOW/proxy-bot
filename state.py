"""Persistent SQLite state for proxy discovery, checking and publishing."""
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
    """Return a stable identity without exposing the secret in logs."""
    protocol = str(proxy.get("protocol", "")).strip().upper()
    host = str(proxy.get("ip", proxy.get("host", ""))).strip().lower()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    secret = str(proxy.get("secret", "")).strip().lower() if protocol in {"MTPROTO", "WEB"} else ""
    return f"{protocol}|{host}|{port}|{secret}"


def _hash(proxy: dict) -> str:
    return hashlib.sha256(proxy_identity(proxy).encode("utf-8")).hexdigest()[:20]


def _identity_digest(proxy: dict) -> str:
    return hashlib.sha256(proxy_identity(proxy).encode("utf-8")).hexdigest()


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
        conn.executescript(
            """
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
            """
        )
    logger.info("SQLite state ready: %s", DB_PATH)


def _rows_to_hashes(proxies: list[dict]) -> list[tuple[dict, str]]:
    result: list[tuple[dict, str]] = []
    for proxy in proxies:
        try:
            identity = proxy_identity(proxy)
            if not identity or identity.startswith("||"):
                continue
            result.append((proxy, _hash(proxy)))
        except Exception:
            logger.debug("Invalid proxy skipped in state: %r", proxy, exc_info=True)
    return result


def _blocked_hashes(table: str, column: str, hashes: list[str], cutoff: float) -> set[str]:
    if not hashes:
        return set()
    # SQLite's default variable limit is commonly 999; query in chunks.
    blocked: set[str] = set()
    with _connect() as conn:
        for start in range(0, len(hashes), 900):
            chunk = hashes[start : start + 900]
            placeholders = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT hash FROM {table} WHERE hash IN ({placeholders}) AND {column} > ?",
                (*chunk, cutoff),
            )
            blocked.update(row[0] for row in rows)
    return blocked


def filter_unseen(proxies: list[dict]) -> list[dict]:
    pairs = _rows_to_hashes(proxies)
    if not pairs:
        return []
    cutoff = time.time() - SEEN_TTL
    blocked = _blocked_hashes("seen_proxies", "last_seen", [h for _, h in pairs], cutoff)
    return [proxy for proxy, h in pairs if h not in blocked]


def filter_unpublished(proxies: list[dict]) -> list[dict]:
    pairs = _rows_to_hashes(proxies)
    if not pairs:
        return []
    cutoff = time.time() - PUBLISHED_TTL
    blocked = _blocked_hashes("published_proxies", "published_at", [h for _, h in pairs], cutoff)
    return [proxy for proxy, h in pairs if h not in blocked]


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
        conn.executemany(
            """
            INSERT INTO seen_proxies
                (hash, identity, protocol, host, port, first_seen, last_seen, check_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(hash) DO UPDATE SET
                last_seen=excluded.last_seen,
                check_count=seen_proxies.check_count + 1
            """,
            rows,
        )


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
        conn.execute(
            """
            INSERT INTO published_proxies
                (hash, identity, protocol, host, port, published_at, ping_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                published_at=excluded.published_at,
                ping_ms=excluded.ping_ms
            """,
            (_hash(proxy), _identity_digest(proxy), protocol, host, port, now, ping),
        )


def cleanup() -> None:
    now = time.time()
    with _connect() as conn:
        conn.execute("DELETE FROM seen_proxies WHERE last_seen < ?", (now - SEEN_TTL,))
        conn.execute("DELETE FROM published_proxies WHERE published_at < ?", (now - PUBLISHED_TTL,))
        conn.execute(
            "DELETE FROM source_stats WHERE last_success IS NOT NULL AND last_success < ?",
            (now - SOURCE_STATS_TTL,),
        )
    logger.info("State cleanup complete")


def count_seen() -> int:
    with _connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM seen_proxies").fetchone()[0])


def count_published() -> int:
    with _connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM published_proxies").fetchone()[0])
