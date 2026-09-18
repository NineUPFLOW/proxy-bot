""" Точка входа. Полный цикл: сбор → дедуп → фильтр → проверка →
фильтр опубликованных → сортировка → публикация топ-6. """

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
    "telethon",
    "telethon.network",
    "telethon.client",
    "telethon.network.mtprotosender",
    "telethon.network.connection",
    "asyncio",
    "aiogram.event",
):
    logging.getLogger(noisy).setLevel(logging.CRITICAL)

logger = logging.getLogger("bot")

# ═══════════════════════════════════════════════════════════════════════
# Конфигурация
# ═══════════════════════════════════════════════════════════════════════
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = os.environ["CHAT_ID"]

PUBLISH_COUNT = 6
MAX_SOCKS5_PUBLISH = 1
MAX_WEB_PUBLISH = 3
SEND_DELAY = 3
MAX_SEND_RETRIES = 3
CONCURRENCY = 20


# ═══════════════════════════════════════════════════════════════════════
# Проверка одного прокси
# ═══════════════════════════════════════════════════════════════════════
async def check_with_semaphore(sem: asyncio.Semaphore, raw: dict):
    async with sem:
        try:
            result = await process_proxy(raw)
        except Exception as e:
            logger.debug("check error: %s", e)
            result = None
        # Помечаем как просмотренный в любом случае — чтобы не проверять мёртвые повторно
        try:
            state.mark_seen(raw)
        except Exception as e:
            logger.debug("mark_seen error: %s", e)
        return result


# ═══════════════════════════════════════════════════════════════════════
# Отправка с retry
# ═══════════════════════════════════════════════════════════════════════
async def send_with_retry(bot: Bot, p: dict) -> bool:
    for attempt in range(1, MAX_SEND_RETRIES + 1):
        try:
            await bot.send_message(
                chat_id=CHAT_ID,
                text=format_message(p),
                reply_markup=build_keyboard(p),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            logger.info("Опубликован %s #%s", p["protocol"], p.get("id"))
            return True
        except TelegramRetryAfter as e:
            logger.warning(
                "Flood control, ждём %ss (попытка %s/%s)",
                e.retry_after, attempt, MAX_SEND_RETRIES,
            )
            await asyncio.sleep(e.retry_after + 1)
        except TelegramAPIError as e:
            logger.error(
                "Ошибка публикации %s #%s: %s",
                p["protocol"], p.get("id"), e,
            )
            return False
        except Exception as e:
            logger.error("Неожиданная ошибка публикации: %s", e)
            return False
    logger.error("Не удалось отправить %s #%s", p["protocol"], p.get("id"))
    return False


# ═══════════════════════════════════════════════════════════════════════
# Основной цикл
# ═══════════════════════════════════════════════════════════════════════
async def run(bot: Bot):
    # ─── 0. Инициализация ───
    logger.info("Инициализация состояния...")
    state.init_db()
    state.cleanup()

    # ─── 1. Сбор ───
    logger.info("Сбор прокси из источников...")
    raw_list = await fetch_all_proxies()
    if not raw_list:
        logger.warning("Источники пусты")
        return

    # ─── 2. Дедупликация внутри батча ───
    seen_in_batch = set()
    unique_raw = []
    for r in raw_list:
        key = f"{r.get('protocol')}:{r.get('ip')}:{r.get('port')}"
        if key not in seen_in_batch:
            seen_in_batch.add(key)
            unique_raw.append(r)

    logger.info("Собрано: %s, уникальных: %s", len(raw_list), len(unique_raw))

    mtproto_cnt = sum(1 for r in unique_raw if r.get("protocol") == "MTPROTO")
    web_cnt = sum(1 for r in unique_raw if r.get("protocol") == "WEB")
    socks5_cnt = sum(1 for r in unique_raw if r.get("protocol") == "SOCKS5")
    logger.info(
        "По протоколам: MTProto=%s WEB=%s SOCKS5=%s",
        mtproto_cnt, web_cnt, socks5_cnt,
    )
    random.shuffle(unique_raw)

    # ─── 3. Фильтрация уже проверенных ───
    fresh_raw = state.filter_unseen(unique_raw)
    logger.info(
        "Новых для сканирования: %s (пропущено: %s)",
        len(fresh_raw), len(unique_raw) - len(fresh_raw),
    )
    if not fresh_raw:
        logger.info("Нет новых прокси для проверки")
        return

    # ─── 4. Проверка ───
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(
        *[check_with_semaphore(sem, r) for r in fresh_raw]
    )
    working = [r for r in results if r]

    mtproto_ok = [p for p in working if p["protocol"] == "MTPROTO"]
    web_ok = [p for p in working if p["protocol"] == "WEB"]
    socks5_ok = [p for p in working if p["protocol"] == "SOCKS5"]
    logger.info(
        "Рабочих: MTPROTO=%s WEB=%s SOCKS5=%s | всего=%s",
        len(mtproto_ok), len(web_ok), len(socks5_ok), len(working),
    )
    if not working:
        logger.info("Ни один прокси не прошёл проверку")
        return

    # ─── 5. Фильтрация опубликованных ───
    working = state.filter_unpublished(working)
    logger.info("Неопубликованных: %s", len(working))
    if not working:
        logger.info("Все рабочие прокси уже публиковались")
        return

    # ─── 6. Сортировка по score ───
    working.sort(key=lambda p: p.get("score", 0), reverse=True)
    logger.info("Топ-10 по качеству:")
    for p in working[:10]:
        logger.info(
            "  %s %s:%s ping=%sms score=%s",
            p["protocol"], p["ip"], p["port"],
            p.get("ping", "?"), p.get("score", "?"),
        )

    # ─── 7. Отбор ───
    mtproto_sorted = [p for p in working if p["protocol"] == "MTPROTO"]
    web_sorted = [p for p in working if p["protocol"] == "WEB"]
    socks5_sorted = [p for p in working if p["protocol"] == "SOCKS5"]

    selected = []
    selected.extend(mtproto_sorted[:PUBLISH_COUNT])

    remaining = PUBLISH_COUNT - len(selected)
    if remaining > 0 and web_sorted:
        selected.extend(web_sorted[:min(remaining, MAX_WEB_PUBLISH)])

    remaining = PUBLISH_COUNT - len(selected)
    if remaining > 0 and socks5_sorted:
        selected.extend(socks5_sorted[:min(remaining, MAX_SOCKS5_PUBLISH)])

    if not selected:
        logger.info("Нет прокси для публикации")
        return

    # ─── 8. Публикация ───
    logger.info("Публикуем %s прокси", len(selected))
    published_ok = 0
    for idx, p in enumerate(selected, start=1):
        p["id"] = idx
        ok = await send_with_retry(bot, p)
        if ok:
            published_ok += 1
            state.mark_published(p)
        await asyncio.sleep(SEND_DELAY)
    logger.info("Успешно опубликовано: %s", published_ok)


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
