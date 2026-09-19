"""
Telegram Proxy Bot 2026.
- Публикация в конкретную тему (Topic) Telegram-группы
- Последовательная проверка: MTProto → WEB → SOCKS5
- Умная сортировка: probe_resistant → MTProto → WEB → SOCKS5
"""

import asyncio
import logging
import os
import random

from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramRetryAfter, TelegramAPIError
from aiogram.types import LinkPreviewOptions

from sources import fetch_all_proxies
from checker import process_proxy, close_http_session
from formatter import format_message, build_keyboard
import state

# ═══════════════════════════════════════════════════════════════════════
# Логирование
# ═══════════════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    force=True,
)

for noisy in (
    "telethon", "telethon.network", "telethon.client",
    "telethon.network.mtprotosender", "telethon.network.connection",
    "asyncio", "aiogram.event",
):
    logging.getLogger(noisy).setLevel(logging.CRITICAL)

logger = logging.getLogger("bot")

# ═══════════════════════════════════════════════════════════════════════
# Конфигурация (всё из GitHub Secrets)
# ═══════════════════════════════════════════════════════════════════════
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])

# TOPIC_ID — ID темы. Для темы "Proxy TG" в группе Internet Кормилица = 250
_topic_raw = os.environ.get("TOPIC_ID", "").strip()
TOPIC_ID = int(_topic_raw) if _topic_raw else None

PUBLISH_COUNT = 6
MAX_SOCKS5_PUBLISH = 6
MAX_WEB_PUBLISH = 6
SEND_DELAY = 3
MAX_SEND_RETRIES = 3
CONCURRENCY = 20
MAX_MT_CHECK = 200
MAX_WEB_CHECK = 100
MAX_SOCKS5_CHECK = 100


# ═══════════════════════════════════════════════════════════════════════
# Дедупликация
# ═══════════════════════════════════════════════════════════════════════
def dedup_by_ip_port(proxies: list) -> list:
    best = {}
    for p in proxies:
        key = (p["ip"], p["port"])
        if key not in best or p.get("score", 0) > best[key].get("score", 0):
            best[key] = p
    return list(best.values())


# ═══════════════════════════════════════════════════════════════════════
# Проверка одного прокси
# ═══════════════════════════════════════════════════════════════════════
async def check_with_semaphore(sem: asyncio.Semaphore, raw: dict):
    async with sem:
        try:
            result = await process_proxy(raw)
            if result is not None:
                state.mark_seen(result)
            return result
        except Exception as e:
            logger.debug("check error: %s", e)
            return None


# ═══════════════════════════════════════════════════════════════════════
# Отправка с retry и поддержкой тем
# ═══════════════════════════════════════════════════════════════════════
async def send_with_retry(bot: Bot, p: dict) -> bool:
    for attempt in range(1, MAX_SEND_RETRIES + 1):
        try:
            send_kwargs = {
                "chat_id": CHAT_ID,
                "text": format_message(p),
                "reply_markup": build_keyboard(p),
                "link_preview_options": LinkPreviewOptions(is_disabled=True),
            }
            if TOPIC_ID is not None:
                send_kwargs["message_thread_id"] = TOPIC_ID

            await bot.send_message(**send_kwargs)
            probe_mark = "🛡 PROBE" if p.get("probe_resistant") else ""
            logger.info(
                "✅ Опубликован %s %s:%s ping=%sms %s",
                p["protocol"], p["ip"], p["port"],
                p.get("ping", "?"), probe_mark,
            )
            return True
        except TelegramRetryAfter as e:
            logger.warning("Flood control, ждём %ss", e.retry_after)
            await asyncio.sleep(e.retry_after + 1)
        except TelegramAPIError as e:
            logger.error("Ошибка публикации %s: %s", p.get("id"), e)
            return False
        except Exception as e:
            logger.error("Неожиданная ошибка: %s", e)
            return False
    return False


# ═══════════════════════════════════════════════════════════════════════
# Проверка группы прокси
# ═══════════════════════════════════════════════════════════════════════
async def check_group(group: list, name: str) -> list:
    if not group:
        return []

    fresh = state.filter_unseen(group)
    if not fresh:
        logger.info("%s: все уже просканированы", name)
        return []

    logger.info("%s: проверяем %s прокси", name, len(fresh))

    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(
        *[check_with_semaphore(sem, r) for r in fresh]
    )
    working = [r for r in results if r]
    working = dedup_by_ip_port(working)

    probe_count = sum(1 for p in working if p.get("probe_resistant"))
    logger.info(
        "%s: рабочих=%s (probe_resistant=%s)",
        name, len(working), probe_count,
    )
    return working


# ═══════════════════════════════════════════════════════════════════════
# Основной цикл
# ═══════════════════════════════════════════════════════════════════════
async def run(bot: Bot):
    logger.info("🚀 Запуск прокси-бота...")
    logger.info("📢 Публикация: chat_id=%s, topic_id=%s", CHAT_ID, TOPIC_ID)

    state.init_db()
    state.cleanup()

    raw_list = await fetch_all_proxies()
    if not raw_list:
        logger.warning("Источники пусты")
        return

    raw_list = dedup_by_ip_port(raw_list)

    mtproto = [r for r in raw_list if r.get("protocol") == "MTPROTO"]
    web = [r for r in raw_list if r.get("protocol") == "WEB"]
    socks5 = [r for r in raw_list if r.get("protocol") == "SOCKS5"]

    logger.info(
        "Собрано: MTProto=%s WEB=%s SOCKS5=%s | всего=%s",
        len(mtproto), len(web), len(socks5), len(raw_list),
    )

    all_working = []

    random.shuffle(mtproto)
    mt_proxies = await check_group(mtproto[:MAX_MT_CHECK], "MTProto")
    all_working.extend(mt_proxies)

    if web:
        random.shuffle(web)
        web_proxies = await check_group(web[:MAX_WEB_CHECK], "WEB")
        all_working.extend(web_proxies)

    if socks5:
        random.shuffle(socks5)
        socks_proxies = await check_group(socks5[:MAX_SOCKS5_CHECK], "SOCKS5")
        all_working.extend(socks_proxies)

    if not all_working:
        logger.info("Ни один прокси не прошёл проверку")
        return

    all_working = state.filter_unpublished(all_working)
    all_working = dedup_by_ip_port(all_working)

    logger.info("Неопубликованных: %s", len(all_working))
    if not all_working:
        logger.info("Все рабочие прокси уже публиковались")
        return

    def sort_key(p):
        proto = p["protocol"]
        probe = p.get("probe_resistant", False)
        ping = p.get("ping", 99999)
        if proto == "MTPROTO" and probe:
            group = 0
        elif proto == "MTPROTO":
            group = 1
        elif proto == "WEB":
            group = 2
        else:
            group = 3
        return (group, ping)

    all_working.sort(key=sort_key)

    logger.info("🏆 Топ-10 по качеству:")
    for p in all_working[:10]:
        probe_mark = "🛡 PROBE" if p.get("probe_resistant") else ""
        logger.info(
            "  %s %s:%s ping=%sms score=%s %s",
            p["protocol"], p["ip"], p["port"],
            p.get("ping", "?"), p.get("score", "?"), probe_mark,
        )

    probe_mt = [p for p in all_working
                if p["protocol"] == "MTPROTO" and p.get("probe_resistant")]
    normal_mt = [p for p in all_working
                 if p["protocol"] == "MTPROTO" and not p.get("probe_resistant")]
    web_ok = [p for p in all_working if p["protocol"] == "WEB"]
    socks_ok = [p for p in all_working if p["protocol"] == "SOCKS5"]

    final = []
    final.extend(probe_mt[:PUBLISH_COUNT])
    remaining = PUBLISH_COUNT - len(final)

    if remaining > 0:
        final.extend(normal_mt[:remaining])
        remaining = PUBLISH_COUNT - len(final)

    if remaining > 0 and web_ok:
        final.extend(web_ok[:min(remaining, MAX_WEB_PUBLISH)])
        remaining = PUBLISH_COUNT - len(final)

    if remaining > 0 and socks_ok:
        final.extend(socks_ok[:min(remaining, MAX_SOCKS5_PUBLISH)])

    final = dedup_by_ip_port(final)

    if not final:
        logger.info("Нет прокси для публикации")
        return

    logger.info("Публикуем %s прокси", len(final))
    published_ips = set()
    published_ok = 0

    for p in final:
        key = (p["ip"], p["port"])
        if key in published_ips:
            continue

        ok = await send_with_retry(bot, p)
        if ok:
            published_ok += 1
            published_ips.add(key)
            state.mark_published(p)
        await asyncio.sleep(SEND_DELAY)

    logger.info("✅ Успешно опубликовано: %s", published_ok)


async def main():
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    try:
        await run(bot)
    finally:
        await close_http_session()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
