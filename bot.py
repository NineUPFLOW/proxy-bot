"""
Telegram Proxy Bot 2026.
- Публикация в конкретную тему (Topic) Telegram-группы
- Последовательная проверка: MTProto → WEB → SOCKS5
- Выборка: 8 MTProto + 5 SOCKS5 + 2 WEB (добираем MTProto)
- Умная сортировка: probe_resistant → MTProto → WEB → SOCKS5
- В seen пишутся ВСЕ проверенные прокси (включая мёртвые)
- Уведомления в чат при пустых исходах
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
# Конфигурация
# ═══════════════════════════════════════════════════════════════════════
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])

_topic_raw = os.environ.get("TOPIC_ID", "").strip()
TOPIC_ID = int(_topic_raw) if _topic_raw else None

# ─── Публикация ───
PUBLISH_COUNT = 6
TARGET_MT = 3
TARGET_SOCKS5 = 3
TARGET_WEB = 3

SEND_DELAY = 3
MAX_SEND_RETRIES = 3

# ─── Проверка ───
CONCURRENCY = 20

# ─── Лимиты на проверку ───
MAX_MT_CHECK = 500
MAX_WEB_CHECK = 50
MAX_SOCKS5_CHECK = 150


def dedup_by_ip_port(proxies: list) -> list:
    best = {}
    for p in proxies:
        key = (p["ip"], p["port"])
        if key not in best or p.get("score", 0) > best[key].get("score", 0):
            best[key] = p
    return list(best.values())


async def send_status(bot: Bot, text: str) -> bool:
    """Отправляет уведомление-статус в чат (без клавиатуры)."""
    for attempt in range(1, MAX_SEND_RETRIES + 1):
        try:
            send_kwargs = {
                "chat_id": CHAT_ID,
                "text": text,
                "link_preview_options": LinkPreviewOptions(is_disabled=True),
            }
            if TOPIC_ID is not None:
                send_kwargs["message_thread_id"] = TOPIC_ID

            await bot.send_message(**send_kwargs)
            logger.info("📨 Отправлен статус: %s", text.replace("\n", " | ")[:80])
            return True
        except TelegramRetryAfter as e:
            await asyncio.sleep(e.retry_after + 1)
        except Exception as e:
            logger.error("Не удалось отправить статус: %s", e)
            return False
    return False


async def check_with_semaphore(sem: asyncio.Semaphore, raw: dict):
    async with sem:
        try:
            result = await process_proxy(raw)
            try:
                state.mark_seen(raw)
            except Exception as e:
                logger.debug("mark_seen failed: %s", e)
            return result
        except Exception as e:
            logger.debug("check error: %s", e)
            return None


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
            logger.warning("Flood control, ждём %ss (попытка %s/%s)",
                           e.retry_after, attempt, MAX_SEND_RETRIES)
            await asyncio.sleep(e.retry_after + 1)
        except TelegramAPIError as e:
            logger.error("Ошибка публикации %s: %s", p.get("id"), e)
            return False
        except Exception as e:
            logger.error("Неожиданная ошибка: %s", e)
            return False
    return False


async def check_group(group: list, name: str) -> list:
    if not group:
        return []

    logger.info("%s: проверяем %s прокси", name, len(group))

    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(
        *[check_with_semaphore(sem, r) for r in group]
    )
    working = [r for r in results if r]
    working = dedup_by_ip_port(working)

    probe_count = sum(1 for p in working if p.get("probe_resistant"))
    logger.info(
        "%s: рабочих=%s (probe_resistant=%s)",
        name, len(working), probe_count,
    )
    return working


async def run(bot: Bot):
    logger.info("🚀 Запуск прокси-бота...")
    logger.info("📢 Публикация: chat_id=%s, topic_id=%s", CHAT_ID, TOPIC_ID)
    logger.info("📊 Цели: %s прокси (%s MT + %s SOCKS5 + %s WEB)",
                PUBLISH_COUNT, TARGET_MT, TARGET_SOCKS5, TARGET_WEB)

    state.init_db()
    state.cleanup()

    # ─── 1. Сбор ───
    raw_list = await fetch_all_proxies()
    if not raw_list:
        logger.warning("Источники пусты")
        await send_status(
            bot,
            "⚠️ Источники пусты\n\n"
            "Не удалось собрать ни одного прокси из Telegram-каналов."
        )
        return

    raw_list = dedup_by_ip_port(raw_list)

    mtproto = [r for r in raw_list if r.get("protocol") == "MTPROTO"]
    web = [r for r in raw_list if r.get("protocol") == "WEB"]
    socks5 = [r for r in raw_list if r.get("protocol") == "SOCKS5"]

    logger.info(
        "Собрано: MTProto=%s WEB=%s SOCKS5=%s | всего=%s",
        len(mtproto), len(web), len(socks5), len(raw_list),
    )

    # ─── 2. Проверка ───
    all_working = []

    random.shuffle(mtproto)
    fresh_mt = state.filter_unseen(mtproto)
    logger.info("MTProto: свежих=%s из %s", len(fresh_mt), len(mtproto))
    mt_proxies = await check_group(fresh_mt[:MAX_MT_CHECK], "MTProto")
    all_working.extend(mt_proxies)

    fresh_web = []
    if web:
        random.shuffle(web)
        fresh_web = state.filter_unseen(web)
        logger.info("WEB: свежих=%s из %s", len(fresh_web), len(web))
        web_proxies = await check_group(fresh_web[:MAX_WEB_CHECK], "WEB")
        all_working.extend(web_proxies)

    fresh_socks = []
    if socks5:
        random.shuffle(socks5)
        fresh_socks = state.filter_unseen(socks5)
        logger.info("SOCKS5: свежих=%s из %s", len(fresh_socks), len(socks5))
        socks_proxies = await check_group(fresh_socks[:MAX_SOCKS5_CHECK], "SOCKS5")
        all_working.extend(socks_proxies)

    if not all_working:
        logger.info("Ни один прокси не прошёл проверку")
        await send_status(
            bot,
            "⚠️ Ни один прокси не прошёл проверку\n\n"
            f"Проверено: MTProto={len(fresh_mt[:MAX_MT_CHECK])}, "
            f"WEB={len(fresh_web[:MAX_WEB_CHECK])}, "
            f"SOCKS5={len(fresh_socks[:MAX_SOCKS5_CHECK])}\n\n"
            "Попробую в следующем запуске."
        )
        return

    # ─── 3. Фильтрация опубликованных ───
    before_filter = len(all_working)
    all_working = state.filter_unpublished(all_working)
    all_working = dedup_by_ip_port(all_working)
    after_filter = len(all_working)

    logger.info("Неопубликованных: %s (из %s рабочих)", after_filter, before_filter)

    if not all_working:
        logger.info("Все рабочие прокси уже публиковались")
        await send_status(
            bot,
            "💤 Все рабочие прокси уже публиковались\n\n"
            f"Проверено рабочих: {before_filter}\n"
            "Все они были опубликованы недавно.\n\n"
            "Жду появления новых прокси в источниках."
        )
        return

    # ─── 4. Сортировка ───
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

    # ─── 5. Формирование выборки ───
    probe_mt = [p for p in all_working
                if p["protocol"] == "MTPROTO" and p.get("probe_resistant")]
    normal_mt = [p for p in all_working
                 if p["protocol"] == "MTPROTO" and not p.get("probe_resistant")]
    web_ok = [p for p in all_working if p["protocol"] == "WEB"]
    socks_ok = [p for p in all_working if p["protocol"] == "SOCKS5"]

    mt_pool = probe_mt + normal_mt

    picked_mt = mt_pool[:TARGET_MT]
    picked_socks = socks_ok[:TARGET_SOCKS5]
    picked_web = web_ok[:TARGET_WEB]

    final = picked_mt + picked_socks + picked_web

    if len(final) < PUBLISH_COUNT:
        used_keys = {(p["ip"], p["port"]) for p in final}
        for p in mt_pool:
            key = (p["ip"], p["port"])
            if key in used_keys:
                continue
            final.append(p)
            used_keys.add(key)
            if len(final) >= PUBLISH_COUNT:
                break

    if len(final) < PUBLISH_COUNT:
        used_keys = {(p["ip"], p["port"]) for p in final}
        for p in socks_ok:
            key = (p["ip"], p["port"])
            if key in used_keys:
                continue
            final.append(p)
            used_keys.add(key)
            if len(final) >= PUBLISH_COUNT:
                break

    if len(final) < PUBLISH_COUNT:
        used_keys = {(p["ip"], p["port"]) for p in final}
        for p in web_ok:
            key = (p["ip"], p["port"])
            if key in used_keys:
                continue
            final.append(p)
            used_keys.add(key)
            if len(final) >= PUBLISH_COUNT:
                break

    final = dedup_by_ip_port(final)

    logger.info(
        "Выборка: MTProto=%s SOCKS5=%s WEB=%s | всего=%s",
        sum(1 for p in final if p["protocol"] == "MTPROTO"),
        sum(1 for p in final if p["protocol"] == "SOCKS5"),
        sum(1 for p in final if p["protocol"] == "WEB"),
        len(final),
    )

    if not final:
        logger.info("Нет прокси для публикации")
        await send_status(
            bot,
            "⚠️ Нет прокси для публикации\n\n"
            "После фильтрации не осталось подходящих."
        )
        return

    # ─── 6. Публикация ───
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
