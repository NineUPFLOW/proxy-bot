"""
Модуль персистентного состояния.
Отслеживает просканированные прокси, предотвращает дубликаты,
ведёт статистику по источникам.
"""

import sqlite3
import hashlib
import time
import logging
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "proxy_state.db"

# TTL для записей (в секундах)
SEEN_TTL = 6 * 3600            # 6 часов — не сканировать повторно
PUBLISHED_TTL = 24 * 3600      # 24 часа — не публиковать повторно
SOURCE_STATS_TTL = 7 * 24 * 3600  # 7 дней — статистика источников


def _proxy_hash(proxy: dict) -> str:
    """Стабильный хэш прокси по IP:port:protocol."""
    raw = f"{proxy['ip']}:{proxy['port']}:{proxy['protocol']}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


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
    """Инициализация схемы БД."""
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


def is_seen(proxy: dict) -> bool:
    """Проверяет, сканировался ли прокси недавно."""
    h = _proxy_hash(proxy)
    cutoff = time.time() - SEEN_TTL
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM seen_proxies WHERE hash = ? AND last_seen > ?",
            (h, cutoff),
        ).fetchone()
        return row is not None


def mark_seen(proxy: dict):
    """Отмечает прокси как просканированный."""
    h = _proxy_hash(proxy)
    now = time.time()
    with _connect() as conn:
        conn.execute("""
            INSERT INTO seen_proxies
                (hash, ip, port, protocol, first_seen, last_seen, check_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(hash) DO UPDATE SET
                last_seen = excluded.last_seen,
                check_count = check_count + 1
        """, (h, proxy["ip"], proxy["port"], proxy["protocol"], now, now))


def is_published(proxy: dict) -> bool:
    """Проверяет, публиковался ли прокси недавно."""
    h = _proxy_hash(proxy)
    cutoff = time.time() - PUBLISHED_TTL
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM published_proxies WHERE hash = ? AND published_at > ?",
            (h, cutoff),
        ).fetchone()
        return row is not None


def mark_published(proxy: dict):
    """Отмечает прокси как опубликованный."""
    h = _proxy_hash(proxy)
    now = time.time()
    with _connect() as conn:
        conn.execute("""
            INSERT INTO published_proxies
                (hash, ip, port, protocol, published_at, ping_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                published_at = excluded.published_at,
                ping_ms = excluded.ping_ms
        """, (h, proxy["ip"], proxy["port"], proxy["protocol"], now,
              proxy.get("ping")))


def filter_unseen(proxies: list) -> list:
    """Возвращает только те прокси, которые не сканировались недавно."""
    return [p for p in proxies if not is_seen(p)]


def filter_unpublished(proxies: list) -> list:
    """Возвращает только те прокси, которые не публиковались недавно."""
    return [p for p in proxies if not is_published(p)]


def cleanup():
    """Удаляет устаревшие записи из БД."""
    now = time.time()
    seen_cutoff = now - SEEN_TTL
    published_cutoff = now - PUBLISHED_TTL
    stats_cutoff = now - SOURCE_STATS_TTL

    with _connect() as conn:
        conn.execute("DELETE FROM seen_proxies WHERE last_seen < ?", (seen_cutoff,))
        conn.execute("DELETE FROM published_proxies WHERE published_at < ?", (published_cutoff,))
        conn.execute("DELETE FROM source_stats WHERE last_success < ?", (stats_cutoff,))
    logger.info("Очистка состояния выполнена")
