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
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format="%(asctime)s | %(levelname)s | %(name)s | %(message)s", force=True)
for name in ("telethon", "telethon.network", "telethon.client", "telethon.network.mtprotosender", "telethon.network.connection", "asyncio", "aiogram.event"):
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

PUBLISH_COUNT = int(os.getenv("PUBLISH_COUNT", "9"))
TARGETS = {"MTPROTO": int(os.getenv("TARGET_MT", "3")), "SOCKS5": int(os.getenv("TARGET_SOCKS5", "3")), "WEB": int(os.getenv("TARGET_WEB", "3"))}
CONCURRENCY = max(1, int(os.getenv("CONCURRENCY", "15")))
MAX_CHECK = {"MTPROTO": int(os.getenv("MAX_MT_CHECK", "500")), "SOCKS5": int(os.getenv("MAX_SOCKS5_CHECK", "200")), "WEB": int(os.getenv("MAX_WEB_CHECK", "100"))}
SEND_DELAY = float(os.getenv("SEND_DELAY", "2.0"))
MAX_SEND_RETRIES = int(os.getenv("MAX_SEND_RETRIES", "4"))


def dedup(proxies: list[dict]) -> list[dict]:
    best: dict[str, dict] = {}
    for p in proxies:
        key = state.proxy_identity(p)
        if key not in best or int(p.get("score", 0)) > int(best[key].get("score", 0)):
            best[key] = p
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
            kwargs["reply_markup"] = build_keyboard(proxy)
        if TOPIC_ID is not None:
            kwargs["message_thread_id"] = TOPIC_ID
        try:
            await bot.send_message(**kwargs)
            return True
        except TelegramRetryAfter as exc:
            await asyncio.sleep(float(exc.retry_after) + 1)
        except TelegramAPIError as exc:
            if TOPIC_ID is not None and attempt == 1:
                logger.warning("Topic send failed, retrying without TOPIC_ID: %s", exc)
                TOPIC_ID = None
                continue
            logger.error("Telegram send failed: %s", exc)
            return False
        except Exception:
            logger.exception("Unexpected Telegram send error")
            return False
    return False


async def check_group(group: list[dict], name: str) -> list[dict]:
    if not group:
        return []
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(proxy: dict):
        async with sem:
            try:
                return await process_proxy(proxy)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("Check failed for %s:%s", proxy.get("ip"), proxy.get("port"), exc_info=True)
                return None

    logger.info("Checking %s: %d candidates", name, len(group))
    results = await asyncio.gather(*(one(p) for p in group), return_exceptions=False)
    working = dedup([p for p in results if isinstance(p, dict)])
    state.mark_seen_many(group)
    logger.info("%s: %d working", name, len(working))
    return working


def select_proxies(working: list[dict]) -> list[dict]:
    pools = {proto: [] for proto in TARGETS}
    for p in working:
        proto = str(p.get("protocol", "")).upper()
        if proto in pools:
            pools[proto].append(p)
    for pool in pools.values():
        pool.sort(key=lambda p: (-int(p.get("score", 0)), int(p.get("ping", 99999))))

    selected = []
    used = set()
    for proto, target in TARGETS.items():
        for p in pools[proto][:target]:
            ident = state.proxy_identity(p)
            if ident not in used:
                selected.append(p); used.add(ident)

    if len(selected) < PUBLISH_COUNT:
        remainder = sorted(
            (p for p in working if state.proxy_identity(p) not in used),
            key=lambda p: (-int(p.get("score", 0)), int(p.get("ping", 99999))),
        )
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

    groups = {proto: [] for proto in TARGETS}
    for p in raw:
        proto = str(p.get("protocol", "")).upper()
        if proto in groups:
            groups[proto].append(p)
    logger.info("Collected: %s", {k: len(v) for k, v in groups.items()})

    working = []
    for proto, group in groups.items():
        random.shuffle(group)
        fresh = state.filter_unseen(group)[:MAX_CHECK[proto]]
        working.extend(await check_group(fresh, proto))

    working = state.filter_unpublished(dedup(working))
    if not working:
        await send_message(bot, "💤 Новых рабочих прокси для публикации нет.")
        return

    final = select_proxies(working)
    logger.info("Selected: %s", {proto: sum(1 for p in final if p.get("protocol") == proto) for proto in TARGETS})

    published = 0
    for proxy in final:
        if await send_message(bot, format_message(proxy), proxy=proxy):
            state.mark_published(proxy)
            published += 1
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
