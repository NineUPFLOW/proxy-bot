"""
Персистентное состояние.
Дедупликация через SQLite + защита от повторных публикаций.
"""

import sqlite3
import hashlib
import time
import logging
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "proxy_state.db"

SEEN_TTL = 2 * 3600              # 2 часа — не перепроверять прокси
PUBLISHED_TTL = 6 * 3600         # 6 часов — можно переопубликовать живые прокси
SOURCE_STATS_TTL = 7 * 24 * 3600 # 7 дней


def _normalize_proxy(proxy: dict) -> dict:
    """Возвращает канонический набор полей для расчёта хэша."""
    if not isinstance(proxy, dict):
        raise TypeError(f"proxy must be dict, got {type(proxy).__name__}")
    ip = str(proxy.get("ip", "")).strip()
    port = proxy.get("port")
    protocol = str(proxy.get("protocol", "")).strip()
    if not ip or not protocol or port is None:
        raise ValueError(f"Invalid proxy payload: {proxy!r}")
    return {"ip": ip, "port": int(port), "protocol": protocol}


def _hash_from_normalized(p: dict) -> str:
    """Хэш из уже нормализованного прокси (без повторной валидации)."""
    raw = f"{p['ip']}:{p['port']}:{p['protocol']}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _proxy_hash(proxy: dict) -> str:
    """Хэш из произвольного прокси (валидирует и нормализует сам)."""
    return _hash_from_normalized(_normalize_proxy(proxy))


def _parse_ping_ms(value) -> int | None:
    """Приводит 'ping' к целому числу ms, если возможно."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        s = value.strip().lower().replace("ms", "").strip()
        try:
            return int(float(s))
        except (ValueError, TypeError):
            return None
    return None


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS seen_proxies (
                hash TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                check_count INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS published_proxies (
                hash TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                published_at REAL NOT NULL,
                ping_ms INTEGER
            );
            CREATE TABLE IF NOT EXISTS source_stats (
                url TEXT PRIMARY KEY,
                total_fetched INTEGER DEFAULT 0,
                total_working INTEGER DEFAULT 0,
                last_success REAL,
                last_failure REAL,
                consecutive_failures INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_seen_last_seen
                ON seen_proxies(last_seen);
            CREATE INDEX IF NOT EXISTS idx_published_at
                ON published_proxies(published_at);
        """)
    logger.info("База состояния инициализирована: %s", DB_PATH)


def count_seen() -> int:
    with _connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM seen_proxies").fetchone()[0]


def count_published() -> int:
    with _connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM published_proxies").fetchone()[0]


def is_seen(proxy: dict) -> bool:
    h = _proxy_hash(proxy)
    cutoff = time.time() - SEEN_TTL
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM seen_proxies WHERE hash = ? AND last_seen > ?",
            (h, cutoff),
        ).fetchone()
        return row is not None


def mark_seen(proxy: dict):
    p = _normalize_proxy(proxy)
    h = _hash_from_normalized(p)
    now = time.time()
    with _connect() as conn:
        conn.execute("""
            INSERT INTO seen_proxies
                (hash, ip, port, protocol, first_seen, last_seen, check_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(hash) DO UPDATE SET
                last_seen = excluded.last_seen,
                check_count = check_count + 1
        """, (h, p["ip"], p["port"], p["protocol"], now, now))


def is_published(proxy: dict) -> bool:
    h = _proxy_hash(proxy)
    cutoff = time.time() - PUBLISHED_TTL
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM published_proxies WHERE hash = ? AND published_at > ?",
            (h, cutoff),
        ).fetchone()
        return row is not None


def mark_published(proxy: dict):
    p = _normalize_proxy(proxy)
    h = _hash_from_normalized(p)
    now = time.time()
    ping = proxy.get("ping_ms")
    if ping is None:
        ping = proxy.get("ping")
    ping_ms = _parse_ping_ms(ping)
    with _connect() as conn:
        conn.execute("""
            INSERT INTO published_proxies
                (hash, ip, port, protocol, published_at, ping_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                published_at = excluded.published_at,
                ping_ms = excluded.ping_ms
        """, (h, p["ip"], p["port"], p["protocol"], now, ping_ms))


def _bulk_filter(proxies: list, table: str, time_col: str, ttl: int) -> list:
    """
    Общая логика для filter_unseen / filter_unpublished.
    Возвращает ОРИГИНАЛЬНЫЕ прокси, которых нет в таблице за TTL.
    """
    if not proxies:
        return []

    pairs = []
    for item in proxies:
        try:
            h = _proxy_hash(item)
        except (TypeError, ValueError):
            continue
        pairs.append((item, h))

    if not pairs:
        return []

    hashes = [h for _, h in pairs]
    cutoff = time.time() - ttl
    placeholders = ",".join("?" for _ in hashes)
    query = (
        f"SELECT hash FROM {table} "
        f"WHERE hash IN ({placeholders}) AND {time_col} > ?"
    )
    with _connect() as conn:
        blocked = {
            row[0]
            for row in conn.execute(query, (*hashes, cutoff)).fetchall()
        }

    return [item for item, h in pairs if h not in blocked]


def filter_unseen(proxies: list) -> list:
    """Оригинальные прокси, не встречавшиеся в seen за SEEN_TTL."""
    return _bulk_filter(proxies, "seen_proxies", "last_seen", SEEN_TTL)


def filter_unpublished(proxies: list) -> list:
    """Оригинальные прокси, не публиковавшиеся за PUBLISHED_TTL."""
    return _bulk_filter(proxies, "published_proxies", "published_at", PUBLISHED_TTL)


def cleanup():
    now = time.time()
    seen_cutoff = now - SEEN_TTL
    published_cutoff = now - PUBLISHED_TTL
    stats_cutoff = now - SOURCE_STATS_TTL

    with _connect() as conn:
        conn.execute("DELETE FROM seen_proxies WHERE last_seen < ?", (seen_cutoff,))
        conn.execute("DELETE FROM published_proxies WHERE published_at < ?", (published_cutoff,))
        conn.execute(
            "DELETE FROM source_stats WHERE last_success IS NOT NULL AND last_success < ?",
            (stats_cutoff,),
        )
    logger.info("Очистка состояния выполнена")
