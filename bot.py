"""
Точка входа. Запускает полный цикл:
1. Сбор прокси из Telegram-источников (MTProto + SOCKS5 + WEB)
2. Дедупликация в батче
3. Лимит на сканирование за один запуск
4. Фильтрация уже просканированных (seen)
5. Проверка новых
6. Фильтрация уже опубликованных
7. Сортировка по score (протокол + пинг) — публикуем ЛУЧШИЕ
8. Публикация топ-6 прокси
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
CHAT_ID = os.environ["CHAT_ID"]

# ─── Публикация ───
PUBLISH_COUNT = 6                # публикуем 6 прокси за раз
MAX_SOCKS5_PUBLISH = 1           # максимум 1 SOCKS5 из публикуемых
MAX_WEB_PUBLISH = 3              # максимум 3 WEB из публикуемых
SEND_DELAY = 3
MAX_SEND_RETRIES = 3

# ─── Проверка ───
CONCURRENCY = 20

# ─── Лимиты на сканирование за один запуск ───
MAX_MT_CHECK = 200
MAX_SOCKS5_CHECK = 20
MAX_WEB_CHECK = 50


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
            logger.info("Опубликован %s #%s", p["protocol"], p["id"])
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

    logger.error(
        "Не удалось отправить %s #%s после %s попыток",
        p["protocol"], p.get("id"), MAX_SEND_RETRIES,
    )
    return False


# ═══════════════════════════════════════════════════════════════════════
# Основной цикл
# ═══════════════════════════════════════════════════════════════════════
async def run(bot: Bot):
    # ─── 0. Инициализация состояния ───
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

    # ─── 3. Лимит на проверку за один запуск ───
    mtproto_all = [r for r in unique_raw if r.get("protocol") == "MTPROTO"]
    socks5_all = [r for r in unique_raw if r.get("protocol") == "SOCKS5"]
    web_all = [r for r in unique_raw if r.get("protocol") == "WEB"]

    random.shuffle(mtproto_all)
    random.shuffle(socks5_all)
    random.shuffle(web_all)

    mtproto_pick = mtproto_all[:MAX_MT_CHECK]
    socks5_pick = socks5_all[:MAX_SOCKS5_CHECK]
    web_pick = web_all[:MAX_WEB_CHECK]

    unique_raw = mtproto_pick + web_pick + socks5_pick
    random.shuffle(unique_raw)

    logger.info(
        "Лимит на проверку: MTProto=%s WEB=%s SOCKS5=%s | всего=%s",
        len(mtproto_pick), len(web_pick), len(socks5_pick), len(unique_raw),
    )

    # ─── 4. Фильтрация уже просканированных ───
    fresh_raw = state.filter_unseen(unique_raw)
    logger.info(
        "Новых для сканирования: %s (пропущено: %s)",
        len(fresh_raw), len(unique_raw) - len(fresh_raw),
    )
    if not fresh_raw:
        logger.info("Нет новых прокси для проверки")
        return

    # ─── 5. Проверка ───
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(
        *[check_with_semaphore(sem, r) for r in fresh_raw]
    )
    working = [r for r in results if r]

    # ─── Статистика ───
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

    # ─── 6. Фильтрация уже опубликованных ───
    working = state.filter_unpublished(working)
    logger.info("Неопубликованных: %s", len(working))
    if not working:
        logger.info("Все рабочие прокси уже публиковались")
        return

    # ─── 7. Сортировка по score (ЛУЧШИЕ сверху) ───
    working.sort(key=lambda p: p.get("score", 0), reverse=True)

    logger.info("Топ-10 по качеству:")
    for p in working[:10]:
        logger.info(
            "  %s %s:%s ping=%sms score=%s",
            p["protocol"], p["ip"], p["port"],
            p.get("ping", "?"), p.get("score", "?"),
        )

    # ─── 7.5. Ограничения по протоколам ───
    mtproto_sorted = [p for p in working if p["protocol"] == "MTPROTO"]
    web_sorted = [p for p in working if p["protocol"] == "WEB"]
    socks5_sorted = [p for p in working if p["protocol"] == "SOCKS5"]

    selected = []

    # MTProto — приоритет
    selected.extend(mtproto_sorted[:PUBLISH_COUNT])

    # WEB — если осталось место
    remaining = PUBLISH_COUNT - len(selected)
    if remaining > 0 and web_sorted:
        selected.extend(web_sorted[:min(remaining, MAX_WEB_PUBLISH)])
        remaining = PUBLISH_COUNT - len(selected)

    # SOCKS5 — только если совсем мало
    if remaining > 0 and socks5_sorted:
        selected.extend(socks5_sorted[:min(remaining, MAX_SOCKS5_PUBLISH)])

    if not selected:
        logger.info("Нет прокси для публикации")
        return

    # ─── 8. Публикация ───
    logger.info("Публикуем %s прокси", len(selected))
    published_ok = []
    for p in selected:
        ok = await send_with_retry(bot, p)
        if ok:
            published_ok.append(p)
            state.mark_published(p)
        await asyncio.sleep(SEND_DELAY)

    logger.info("Успешно опубликовано: %s", len(published_ok))


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
