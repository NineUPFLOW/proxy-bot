"""Collect -> independently check -> select -> recheck -> publish."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import random
from collections import Counter, defaultdict, deque

from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramRetryAfter
from aiogram.types import LinkPreviewOptions

import state
from checker import process_proxy, recheck_proxy
from formatter import build_keyboard, format_message
from network import detect_egress_country
from sources import fetch_all_proxies

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
for name in (
    "telethon_webproxy",
    "telethon_webproxy.carrier_base",
    "telethon_webproxy.carrier_lanes",
    "telethon_webproxy.carrier_https",
):
    logging.getLogger(name).setLevel(logging.ERROR)
logger = logging.getLogger("proxy-bot")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be 1/0, true/false, yes/no or on/off")


REQUIRE_RU_CHECK = _env_bool("REQUIRE_RU_CHECK", True)
SEND_STATUS = _env_bool("SEND_STATUS", False)
PUBLISH_COUNT = max(1, int(os.getenv("PUBLISH_COUNT", "9")))
TARGETS = {
    "MTPROTO": max(0, int(os.getenv("TARGET_MT", "3"))),
    "SOCKS5": max(0, int(os.getenv("TARGET_SOCKS5", "3"))),
    "WEB": max(0, int(os.getenv("TARGET_WEB", "3"))),
}
CONCURRENCY = max(1, int(os.getenv("CONCURRENCY", "20")))
MAX_CHECK = {
    "MTPROTO": max(0, int(os.getenv("MAX_MT_CHECK", "150"))),
    "SOCKS5": max(0, int(os.getenv("MAX_SOCKS5_CHECK", "150"))),
    "WEB": max(0, int(os.getenv("MAX_WEB_CHECK", "30"))),
}
MAX_PER_IP = max(0, int(os.getenv("MAX_PER_IP", "1")))  # 0 disables this limit
SEND_DELAY = max(0.0, float(os.getenv("SEND_DELAY", "2")))
MAX_SEND_RETRIES = max(1, int(os.getenv("MAX_SEND_RETRIES", "4")))


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value


def dedup(proxies: list[dict]) -> list[dict]:
    best: dict[str, dict] = {}
    for proxy in proxies:
        key = state.proxy_identity(proxy)
        current = best.get(key)
        if current is None or int(proxy.get("score", 0)) > int(current.get("score", 0)):
            best[key] = proxy
    return list(best.values())


def sample_fair(proxies: list[dict], limit: int) -> list[dict]:
    """Round-robin by source, so a 10k SOCKS list cannot bury smaller feeds."""
    if limit <= 0:
        return []
    buckets: dict[str, list[dict]] = defaultdict(list)
    for proxy in proxies:
        buckets[str(proxy.get("source", "unknown"))].append(proxy)
    queues = []
    for bucket in buckets.values():
        random.shuffle(bucket)
        queues.append(deque(bucket))
    # When the limit is smaller than the number of sources, a fixed bucket
    # order would permanently starve sources at the end of the configuration.
    random.shuffle(queues)
    selected = []
    while queues and len(selected) < limit:
        remaining = []
        for queue in queues:
            if len(selected) >= limit:
                break
            if queue:
                selected.append(queue.popleft())
            if queue:
                remaining.append(queue)
        queues = remaining
    return selected


async def send_message(
    bot: Bot,
    chat_id: int,
    topic_id: int | None,
    text: str,
    *,
    proxy: dict | None = None,
) -> bool:
    kwargs = {
        "chat_id": chat_id,
        "text": text,
        "link_preview_options": LinkPreviewOptions(is_disabled=True),
    }
    if proxy is not None:
        keyboard = build_keyboard(proxy)
        if keyboard is None:
            logger.error("Refusing to publish an invalid connection link")
            return False
        kwargs["reply_markup"] = keyboard
    if topic_id is not None:
        kwargs["message_thread_id"] = topic_id
    for attempt in range(1, MAX_SEND_RETRIES + 1):
        try:
            await bot.send_message(**kwargs)
            return True
        except TelegramRetryAfter as exc:
            delay = float(exc.retry_after) + 1
            if attempt == MAX_SEND_RETRIES or delay > 60:
                logger.error("Telegram rate limit; publication deferred")
                return False
            await asyncio.sleep(delay)
        except TelegramAPIError as exc:
            if attempt == MAX_SEND_RETRIES:
                logger.error(
                    "Telegram send failed (%s); check chat/topic/permissions",
                    type(exc).__name__,
                )
                return False
            # Never silently post in a different topic after an error.
            await asyncio.sleep(min(2**attempt, 10))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Telegram send failed (%s)", type(exc).__name__)
            return False
    return False


async def check_group(
    group: list[dict], name: str, *, dry_run: bool = False
) -> list[dict]:
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
                logger.debug(
                    "Check failed for %s (%s)", proxy.get("ip"), type(exc).__name__
                )
                return None

    logger.info("Checking %s: %d candidates", name, len(group))
    results = await asyncio.gather(*(one(proxy) for proxy in group))
    working = dedup([p for p in results if isinstance(p, dict)])
    if not dry_run:
        working_ids = {state.proxy_identity(item) for item in working}
        # Successful but not-yet-published candidates remain available next run;
        # the seen TTL is a cooldown for failed checks, not for good reserves.
        state.mark_seen_many(
            [proxy for proxy in group if state.proxy_identity(proxy) not in working_ids]
        )
        groups: dict[str, list[dict]] = defaultdict(list)
        for proxy in group:
            groups[str(proxy.get("source", "unknown"))].append(proxy)
        for source, items in groups.items():
            count = sum(state.proxy_identity(item) in working_ids for item in items)
            state.record_source_stats(source, len(items), count)
    logger.info("%s: %d/%d passed repeated checks", name, len(working), len(group))
    return working


def _sort_key(proxy: dict) -> tuple[int, int]:
    try:
        return -int(proxy.get("score", 0)), int(proxy.get("ping", 99999))
    except (TypeError, ValueError):
        return 0, 99999


def select_proxies(working: list[dict]) -> list[dict]:
    pools: dict[str, list[dict]] = {protocol: [] for protocol in TARGETS}
    for proxy in working:
        protocol = str(proxy.get("protocol", "")).upper()
        if protocol in pools:
            pools[protocol].append(proxy)
    for pool in pools.values():
        pool.sort(key=_sort_key)
    selected: list[dict] = []
    used: set[str] = set()
    ips: Counter = Counter()

    def add(proxy: dict) -> bool:
        identity = state.proxy_identity(proxy)
        ip = str(proxy.get("resolved_ip") or proxy.get("ip", ""))
        if identity in used or (MAX_PER_IP and ips[ip] >= MAX_PER_IP):
            return False
        if len(selected) >= PUBLISH_COUNT:
            return False
        selected.append(proxy)
        used.add(identity)
        ips[ip] += 1
        return True

    for protocol, target in TARGETS.items():
        count = 0
        for proxy in pools[protocol]:
            if count >= target or len(selected) >= PUBLISH_COUNT:
                break
            if add(proxy):
                count += 1
    for proxy in sorted(working, key=_sort_key):
        if len(selected) >= PUBLISH_COUNT:
            break
        add(proxy)
    return selected


async def run(
    bot: Bot | None,
    chat_id: int | None = None,
    topic_id: int | None = None,
    *,
    dry_run: bool = False,
) -> list[dict]:
    location = await detect_egress_country()
    country = str(location.get("country_code", "")).upper()
    if REQUIRE_RU_CHECK and country != "RU":
        raise RuntimeError(
            f"Публикация остановлена: страна исходящего IPv4 — {country or 'не определена'}, "
            "а REQUIRE_RU_CHECK=1. Запустите проверку из сети РФ."
        )
    logger.info(
        "Checker IPv4 egress country: %s (%s)",
        country or "unknown",
        location.get("provider") or "unavailable",
    )
    if country != "RU":
        logger.warning("This run does not establish availability from Russia")
    if not dry_run:
        if bot is None or chat_id is None:
            raise ValueError("bot and chat_id are required for publication")
        state.init_db()
        state.cleanup()
    raw = dedup(await fetch_all_proxies())
    if not raw:
        logger.warning("No proxy candidates returned by the configured sources")
        if not dry_run and SEND_STATUS:
            await send_message(
                bot, chat_id, topic_id, "⚠️ Веб-источники не вернули прокси."
            )
        return []
    if not dry_run:
        raw = state.filter_unseen(state.filter_unpublished(raw))
    groups = {protocol: [] for protocol in TARGETS}
    for proxy in raw:
        protocol = str(proxy.get("protocol", "")).upper()
        if protocol in groups:
            groups[protocol].append(proxy)
    logger.info("Fresh candidates: %s", {k: len(v) for k, v in groups.items()})
    working: list[dict] = []
    for protocol, group in groups.items():
        candidates = sample_fair(group, MAX_CHECK[protocol])
        working.extend(await check_group(candidates, protocol, dry_run=dry_run))
    working = dedup(working)
    final = select_proxies(working)
    if not final:
        logger.info("No new proxies passed the checks")
        if not dry_run and SEND_STATUS:
            await send_message(
                bot, chat_id, topic_id, "💤 Новых прокси, прошедших проверку, нет."
            )
        return []

    # A VPN or route may have changed while the batch was running. Never label
    # such a batch as checked from Russia; in strict mode stop completely.
    current_location = await detect_egress_country()
    current_country = str(current_location.get("country_code", "")).upper()
    changed = current_country != country or (
        location.get("ip") and current_location.get("ip") != location["ip"]
    )
    if changed:
        if REQUIRE_RU_CHECK:
            raise RuntimeError(
                "Исходящий IP или страна проверки изменились; публикация остановлена."
            )
        logger.warning("Egress changed during checks; the check country is now unknown")
        country = ""

    # Prefer the protocol quotas first, then backfill from other checked proxies
    # if a candidate dies at the last-moment recheck.
    first_ids = {state.proxy_identity(p) for p in final}
    candidates = final + sorted(
        (p for p in working if state.proxy_identity(p) not in first_ids), key=_sort_key
    )
    confirmed: list[dict] = []
    published_ips: Counter = Counter()
    attempted = 0
    for proxy in candidates:
        if len(confirmed) >= PUBLISH_COUNT:
            break
        candidate_ip = str(proxy.get("resolved_ip") or proxy.get("ip", ""))
        if MAX_PER_IP and published_ips[candidate_ip] >= MAX_PER_IP:
            continue
        attempted += 1
        fresh = await recheck_proxy(proxy)
        if not fresh:
            logger.info("Skipped stale proxy %s", proxy.get("id", "?"))
            if not dry_run:
                state.mark_seen(proxy)
            continue
        fresh["check_country"] = country
        if dry_run:
            logger.info(
                "DRY RUN: %s %s:%s, %s ms, checked from %s",
                fresh["protocol"],
                fresh["ip"],
                fresh["port"],
                fresh["ping"],
                country or "unknown",
            )
        elif await send_message(
            bot, chat_id, topic_id, format_message(fresh), proxy=fresh
        ):
            state.mark_published(fresh)
        else:
            raise RuntimeError(
                "Не удалось отправить сообщение в Telegram; публикация остановлена."
            )
        confirmed.append(fresh)
        published_ips[candidate_ip] += 1
        if not dry_run and SEND_DELAY:
            await asyncio.sleep(SEND_DELAY)
    logger.info(
        "%s %d/%d proxies (rechecked: %d)",
        "Would publish" if dry_run else "Published",
        len(confirmed),
        PUBLISH_COUNT,
        attempted,
    )
    return confirmed


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect, test and publish Telegram proxies"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Check without credentials, sending or changing state",
    )
    args = parser.parse_args()
    if args.dry_run:
        await run(None, dry_run=True)
        return
    token = _required("BOT_TOKEN")
    chat_id = int(_required("CHAT_ID"))
    topic_id = int(os.getenv("TOPIC_ID", "0") or 0) or None
    # Publication may use an outbound proxy; checks and country detection never do.
    publish_proxy = os.getenv("BOT_PROXY_URL", "").strip() or None
    session = AiohttpSession(proxy=publish_proxy)
    bot = Bot(
        token, session=session, default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    try:
        await run(bot, chat_id, topic_id)
    finally:
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (ValueError, RuntimeError) as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from exc
