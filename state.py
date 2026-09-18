""" Состояние бота: SQLite-хранилище просмотренных и опубликованных прокси. """

import sqlite3
import time
import logging
from contextlib import closing

logger = logging.getLogger("state")

DB_PATH = "proxy_state.db"

# TTL — сколько секунд хранить запись (по умолчанию 7 дней)
SEEN_TTL = 7 * 24 * 3600
PUBLISHED_TTL = 30 * 24 * 3600


def _conn():
    return sqlite3.connect(DB_PATH, timeout=30)


def init_db():
    with closing(_conn()) as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS seen (
                key TEXT PRIMARY KEY,
                ts  INTEGER NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS published (
                key TEXT PRIMARY KEY,
                ts  INTEGER NOT NULL
            )
        """)
        conn.commit()
    logger.debug("БД инициализирована")


def cleanup():
    now = int(time.time())
    with closing(_conn()) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM seen WHERE ts < ?", (now - SEEN_TTL,))
        cur.execute("DELETE FROM published WHERE ts < ?", (now - PUBLISHED_TTL,))
        conn.commit()
    logger.debug("Очистка завершена")


def _key(item: dict) -> str:
    return f"{item.get('protocol')}:{item.get('ip')}:{item.get('port')}"


def filter_unseen(items: list[dict]) -> list[dict]:
    if not items:
        return []
    keys = [_key(i) for i in items]
    with closing(_conn()) as conn:
        cur = conn.cursor()
        placeholders = ",".join("?" * len(keys))
        cur.execute(
            f"SELECT key FROM seen WHERE key IN ({placeholders})",
            keys,
        )
        seen = {row[0] for row in cur.fetchall()}
    return [i for i, k in zip(items, keys) if k not in seen]


def filter_unpublished(items: list[dict]) -> list[dict]:
    if not items:
        return []
    keys = [_key(i) for i in items]
    with closing(_conn()) as conn:
        cur = conn.cursor()
        placeholders = ",".join("?" * len(keys))
        cur.execute(
            f"SELECT key FROM published WHERE key IN ({placeholders})",
            keys,
        )
        published = {row[0] for row in cur.fetchall()}
    return [i for i, k in zip(items, keys) if k not in published]


def mark_seen(item: dict):
    now = int(time.time())
    with closing(_conn()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO seen (key, ts) VALUES (?, ?)",
            (_key(item), now),
        )
        conn.commit()


def mark_published(item: dict):
    now = int(time.time())
    with closing(_conn()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO published (key, ts) VALUES (?, ?)",
            (_key(item), now),
        )
        conn.commit()
