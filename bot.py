"""Main pipeline: collect -> filter -> check -> select -> publish."""
from __future__ import annotations

import asyncio
import logging
import os
import random

from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramRetryAfter
from aiogram.types import LinkPreviewOptions

import state
from checker import close_http_session, process_proxy
from formatter import build_keyboard, format_message
from sources import fetch_all_proxies

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    force=True,
)

# ─── Подавление шума ───
# CRITICAL для telethon: убирает "Unexpected exception in the receive loop"
# (readexactly size can not be less than zero) при handshake с мёртвыми MTProxy.
for name in (
    "telethon",
    "telethon.network",
    "telethon.client",
    "telethon.network.mtprotosender",
    "telethon.network.connection",
    "asyncio",
    "aiogram.event",
):
    logging.getLogger(name).setLevel(logging.CRITICAL)

# WARNING для telethon_webproxy: убирает ~500 строк INFO-логов на каждый WEB-чек
# (Session bootstrapped / WebSocket-lanes carrier ready / Relay returned 503).
for name in (
    "telethon_webproxy",
    "telethon_webproxy.carrier_base",
    "telethon_webproxy.carrier_lanes",
):
    logging.getLogger(name).setLevel(logging.WARNING)

logger = logging.getLogger("proxy-bot")


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value


BOT_TOKEN = _required("BOT_TOKEN")
CHAT_ID = int(_required("CHAT_ID"))
TOPIC_ID = int(os.getenv("TOPIC_ID", "0") or 0) or None
PUBLISH_COUNT = max(1, int(os.getenv("PUBLISH_COUNT", "9")))
TARGETS = {
    "MTPROTO": max(0, int(os.getenv("TARGET_MT", "3"))),
    "SOCKS5": max(0, int(os.getenv("TARGET_SOCKS5", "3"))),
    "WEB": max(0, int(os.getenv("TARGET_WEB", "3"))),
}
CONCURRENCY = max(1, int(os.getenv("CONCURRENCY", "15")))
MAX_CHECK = {
    "MTPROTO": max(0, int(os.getenv("MAX_MT_CHECK", "500"))),
    "SOCKS5": max(0, int(os.getenv("MAX_SOCKS5_CHECK", "200"))),
    "WEB": max(0, int(os.getenv("MAX_WEB_CHECK", "100"))),
}
SEND_DELAY = max(0.0, float(os.getenv("SEND_DELAY", "2")))
MAX_SEND_RETRIES = max(1, int(os.getenv("MAX_SEND_RETRIES", "4")))


def dedup(proxies: list[dict]) -> list[dict]:
    best: dict[str, dict] = {}
    for proxy in proxies:
        key = state.proxy_identity(proxy)
        if key not in best or int(proxy.get("score", 0)) > int(best[key].get("score", 0)):
            best[key] = proxy
    return list(best.values())


async def send_message(bot: Bot, text: str, *, proxy: dict | None = None) -> bool:
    global TOPIC_ID
    for attempt in range(1, MAX_SEND_RETRIES + 1):
        kwargs = {
            "chat_id": CHAT_ID,
            "text": text,
            "link_preview_options": LinkPreviewOptions(is_disabled=True),
        }
        if proxy is not None:
            keyboard = build_keyboard(proxy)
            if keyboard:
                kwargs["reply_markup"] = keyboard
        if TOPIC_ID is not None:
            kwargs["message_thread_id"] = TOPIC_ID
        try:
            await bot.send_message(**kwargs)
            return True
        except TelegramRetryAfter as exc:
            await asyncio.sleep(float(exc.retry_after) + 1)
        except TelegramAPIError as exc:
            if TOPIC_ID is not None and attempt == 1:
                logger.warning("Topic send failed; retrying without TOPIC_ID: %s", exc)
                TOPIC_ID = None
                continue
            if attempt < MAX_SEND_RETRIES:
                await asyncio.sleep(min(2 ** attempt, 10))
                continue
            logger.error("Telegram send failed: %s", exc)
            return False
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Unexpected Telegram send error")
            return False
    return False


async def check_group(group: list[dict], name: str) -> list[dict]:
    if not group:
        logger.info("Checking %s: 0 candidates", name)
        return []
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def one(proxy: dict):
        async with semaphore:
            try:
                return await process_proxy(proxy)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Check failed for %s:%s (%s)", proxy.get("ip"), proxy.get("port"), type(exc).__name__)
                return None

    logger.info("Checking %s: %d candidates", name, len(group))
    results = await asyncio.gather(*(one(proxy) for proxy in group))
    working = dedup([p for p in results if isinstance(p, dict)])
    state.mark_seen_many(group)

    source_groups: dict[str, list[dict]] = {}
    for proxy in group:
        source_groups.setdefault(str(proxy.get("source", "unknown")), []).append(proxy)
    for source, source_items in source_groups.items():
        source_ids = {state.proxy_identity(item) for item in source_items}
        source_working = sum(1 for item in working if state.proxy_identity(item) in source_ids)
        state.record_source_stats(source, len(source_items), source_working)

    logger.info("%s: %d/%d working", name, len(working), len(group))
    return working


def _sort_key(proxy: dict) -> tuple[int, int]:
    try:
        score = int(proxy.get("score", 0))
    except (TypeError, ValueError):
        score = 0
    try:
        ping = int(proxy.get("ping", 99999))
    except (TypeError, ValueError):
        ping = 99999
    return -score, ping


def select_proxies(working: list[dict]) -> list[dict]:
    pools = {protocol: [] for protocol in TARGETS}
    for proxy in working:
        protocol = str(proxy.get("protocol", "")).upper()
        if protocol in pools:
            pools[protocol].append(proxy)
    for pool in pools.values():
        pool.sort(key=_sort_key)

    selected: list[dict] = []
    used: set[str] = set()
    for protocol, target in TARGETS.items():
        for proxy in pools[protocol][:target]:
            identity = state.proxy_identity(proxy)
            if identity not in used:
                selected.append(proxy)
                used.add(identity)

    if len(selected) < PUBLISH_COUNT:
        remainder = sorted((p for p in working if state.proxy_identity(p) not in used), key=_sort_key)
        selected.extend(remainder[:PUBLISH_COUNT - len(selected)])
    return selected[:PUBLISH_COUNT]


async def run(bot: Bot) -> None:
    state.init_db()
    state.cleanup()
    logger.info("Starting proxy pipeline")

    raw = dedup(await fetch_all_proxies())
    if not raw:
        await send_message(bot, "⚠️ Источники не вернули ни одного прокси.")
        return

    groups = {protocol: [] for protocol in TARGETS}
    for proxy in raw:
        protocol = str(proxy.get("protocol", "")).upper()
        if protocol in groups:
            groups[protocol].append(proxy)
    logger.info("Collected: %s", {k: len(v) for k, v in groups.items()})

    working: list[dict] = []
    for protocol, group in groups.items():
        random.shuffle(group)
        fresh = group[:MAX_CHECK[protocol]]
        working.extend(await check_group(fresh, protocol))

    working = state.filter_unpublished(dedup(working))
    if not working:
        await send_message(bot, "💤 Новых рабочих прокси для публикации нет.")
        return

    final = select_proxies(working)
    logger.info("Selected: %s", {p: sum(1 for x in final if x.get("protocol") == p) for p in TARGETS})

    published = 0
    for proxy in final:
        if await send_message(bot, format_message(proxy), proxy=proxy):
            state.mark_published(proxy)
            published += 1
        if SEND_DELAY:
            await asyncio.sleep(SEND_DELAY)
    logger.info("Published %d/%d", published, len(final))


async def main() -> None:
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    try:
        await run(bot)
    finally:
        await close_http_session()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
