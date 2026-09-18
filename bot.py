"""
Telegram Proxy Bot 2026.
Работает ТОЛЬКО через GitHub Secrets.
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

# ─── Публикация ───
PUBLISH_COUNT = 6
MAX_SOCKS5_PUBLISH = 1
MAX_WEB_PUBLISH = 3
SEND_DELAY = 3
MAX_SEND_RETRIES = 3          # ← исправлено: константа определена

# ─── Проверка ───
CONCURRENCY = 20

# ─── Лимиты на проверку за один запуск ───
MAX_MT_CHECK = 200
MAX_WEB_CHECK = 50
MAX_SOCKS5_CHECK = 20


def dedup_by_ip_port(proxies: list) -> list:
    """Убирает дубликаты по IP:port, оставляя лучший по score."""
    best = {}
    for p in proxies:
        key = (p["ip"], p["port"])
        if key not in best or p.get("score", 0) > best[key].get("score", 0):
            best[key] = p
    return list(best.values())


async def check_with_semaphore(sem: asyncio.Semaphore, raw: dict):
    """Проверка одного прокси с ограничением параллелизма."""
    async with sem:
        try:
            result = await process_proxy(raw)
            if result is not None:
                state.mark_seen(result)
            return result
        except Exception as e:
            logger.debug("check error: %s", e)
            return None


async def send_with_retry(bot: Bot, p: dict) -> bool:
    """Отправка сообщения с обработкой flood-control."""
    for attempt in range(1, MAX_SEND_RETRIES + 1):
        try:
            await bot.send_message(
                chat_id=CHAT_ID,
                text=format_message(p),
                reply_markup=build_keyboard(p),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            logger.info("✅ Опубликован %s #%s", p["protocol"], p["id"])
            return True
        except TelegramRetryAfter as e:
            logger.warning("Flood control, ждём %ss (попытка %s/%s)",
                           e.retry_after, attempt, MAX_SEND_RETRIES)
            await asyncio.sleep(e.retry_after + 1)
        except TelegramAPIError as e:
            logger.error("Ошибка публикации %s #%s: %s",
                         p["protocol"], p.get("id"), e)
            return False
        except Exception as e:
            logger.error("Неожиданная ошибка: %s", e)
            return False

    logger.error("Не удалось отправить после %s попыток", MAX_SEND_RETRIES)
    return False


async def run(bot: Bot):
    logger.info("🚀 Запуск прокси-бота...")
    state.init_db()
    state.cleanup()

    # ─── 1. Сбор ───
    raw_list = await fetch_all_proxies()
    if not raw_list:
        logger.warning("Источники пусты")
        return

    # ─── 2. Дедупликация ───
    raw_list = dedup_by_ip_port(raw_list)

    # ─── 3. Лимиты по протоколам ───
    mtproto = [r for r in raw_list if r.get("protocol") == "MTPROTO"]
    socks5 = [r for r in raw_list if r.get("protocol") == "SOCKS5"]
    web = [r for r in raw_list if r.get("protocol") == "WEB"]

    logger.info("Собрано: MTProto=%s WEB=%s SOCKS5=%s | всего=%s",
                len(mtproto), len(web), len(socks5), len(raw_list))

    random.shuffle(mtproto)
    random.shuffle(socks5)
    random.shuffle(web)

    selected = (
        mtproto[:MAX_MT_CHECK]
        + web[:MAX_WEB_CHECK]
        + socks5[:MAX_SOCKS5_CHECK]
    )
    random.shuffle(selected)

    # ─── 4. Фильтрация уже просканированных ───
    fresh = state.filter_unseen(selected)
    logger.info("Новых для проверки: %s (пропущено: %s)",
                len(fresh), len(selected) - len(fresh))
    if not fresh:
        logger.info("Нет новых прокси")
        return

    # ─── 5. Проверка ───
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(
        *[check_with_semaphore(sem, r) for r in fresh]
    )
    working = [r for r in results if r]

    mt_ok = [p for p in working if p["protocol"] == "MTPROTO"]
    web_ok = [p for p in working if p["protocol"] == "WEB"]
    socks_ok = [p for p in working if p["protocol"] == "SOCKS5"]

    logger.info("Рабочих: MTPROTO=%s WEB=%s SOCKS5=%s | всего=%s",
                len(mt_ok), len(web_ok), len(socks_ok), len(working))

    if not working:
        logger.info("Ни один прокси не прошёл проверку")
        return

    # ─── 6. Фильтрация опубликованных ───
    working = state.filter_unpublished(working)
    logger.info("Неопубликованных: %s", len(working))
    if not working:
        logger.info("Все рабочие прокси уже публиковались")
        return

    # ─── 7. Сортировка по score ───
    working.sort(key=lambda p: p.get("score", 0), reverse=True)

    logger.info("🏆 Топ-10 по качеству:")
    for p in working[:10]:
        logger.info("  %s %s:%s ping=%sms score=%s",
                    p["protocol"], p["ip"], p["port"],
                    p.get("ping", "?"), p.get("score", "?"))

    # ─── 8. Формирование выборки ───
    mt_sorted = [p for p in working if p["protocol"] == "MTPROTO"]
    web_sorted = [p for p in working if p["protocol"] == "WEB"]
    socks_sorted = [p for p in working if p["protocol"] == "SOCKS5"]

    final = mt_sorted[:PUBLISH_COUNT]

    remaining = PUBLISH_COUNT - len(final)
    if remaining > 0 and web_sorted:
        final.extend(web_sorted[:min(remaining, MAX_WEB_PUBLISH)])
        remaining = PUBLISH_COUNT - len(final)

    if remaining > 0 and socks_sorted:
        final.extend(socks_sorted[:min(remaining, MAX_SOCKS5_PUBLISH)])

    if not final:
        logger.info("Нет прокси для публикации")
        return

    # ─── 9. Публикация ───
    logger.info("Публикуем %s прокси", len(final))
    published_ok = []
    for p in final:
        ok = await send_with_retry(bot, p)
        if ok:
            published_ok.append(p)
            state.mark_published(p)
        await asyncio.sleep(SEND_DELAY)

    logger.info("✅ Успешно опубликовано: %s", len(published_ok))


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
