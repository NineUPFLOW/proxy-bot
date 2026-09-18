"""
Точка входа. Запускает полный цикл:
1. Сбор прокси из источников (MTProto + SOCKS5)
2. Фильтрация уже просканированных
3. Проверка новых
4. Фильтрация уже опубликованных
5. Публикация лучших

WEB-прокси временно отключены: нет рабочих источников.
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
#  Логирование
# ═══════════════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    force=True,
)
logger = logging.getLogger("bot")


# ═══════════════════════════════════════════════════════════════════════
#  Конфигурация
# ═══════════════════════════════════════════════════════════════════════
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = os.environ["CHAT_ID"]

# Публикация
PUBLISH_COUNT = 5               # сколько прокси публиковать за цикл
CONCURRENCY = 10                # параллельных проверок
MAX_SOCKS5_RATIO = 0.4          # максимум SOCKS5 в публикации (40%)
SEND_DELAY = 3                  # пауза между сообщениями (сек)
MAX_SEND_RETRIES = 3            # попыток отправки при ошибке


# ═══════════════════════════════════════════════════════════════════════
#  Проверка прокси с ограничением параллелизма
# ═══════════════════════════════════════════════════════════════════════
async def check_with_semaphore(sem: asyncio.Semaphore, raw: dict):
    async with sem:
        try:
            return await process_proxy(raw)
        except Exception as e:
            logger.debug("check error: %s", e)
            return None


# ═══════════════════════════════════════════════════════════════════════
#  Отправка с retry
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
#  Основной цикл
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
        key = f"{r.get('ip')}:{r.get('port')}:{r.get('protocol')}"
        if key not in seen_in_batch:
            seen_in_batch.add(key)
            unique_raw.append(r)
    logger.info("Собрано: %s, уникальных: %s", len(raw_list), len(unique_raw))

    # ─── 3. Фильтрация уже просканированных ───
    fresh_raw = state.filter_unseen(unique_raw)
    logger.info(
        "Новых для сканирования: %s (пропущено: %s)",
        len(fresh_raw), len(unique_raw) - len(fresh_raw),
    )

    if not fresh_raw:
        logger.info("Нет новых прокси для проверки")
        return

    # ─── 4. Проверка ───
    random.shuffle(fresh_raw)
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(
        *[check_with_semaphore(sem, r) for r in fresh_raw]
    )

    working = [r for r in results if r]
    for p in working:
        state.mark_seen(p)
    logger.info("Рабочих прокси: %s", len(working))

    # ─── 5. Фильтрация уже опубликованных ───
    working = state.filter_unpublished(working)
    logger.info("Неопубликованных: %s", len(working))

    if not working:
        logger.info("Все рабочие прокси уже публиковались")
        return

    # ─── 6. Разделение по типам ───
    mtproto = [p for p in working if p["protocol"] == "MTPROTO"]
    socks5 = [p for p in working if p["protocol"] == "SOCKS5"]

    max_socks5 = max(1, int(PUBLISH_COUNT * MAX_SOCKS5_RATIO))
    socks5 = socks5[:max_socks5]

    # ─── 7. Формирование выборки с приоритетом MTProto ───
    selected = []
    selected.extend(mtproto[:PUBLISH_COUNT])
    remaining = PUBLISH_COUNT - len(selected)

    if remaining > 0:
        pool = socks5[:]
        random.shuffle(pool)
        selected.extend(pool[:remaining])

    if not selected:
        logger.info("Нет прокси для публикации")
        return

    # ─── 8. Публикация ───
    logger.info("Публикуем %s прокси", len(selected))
    for p in selected:
        ok = await send_with_retry(bot, p)
        if ok:
            state.mark_published(p)
        await asyncio.sleep(SEND_DELAY)

    # ─── 9. Закрытие ресурсов ───
    await close_http_session()
    logger.info("Цикл завершён")


# ═══════════════════════════════════════════════════════════════════════
#  Точка входа
# ═══════════════════════════════════════════════════════════════════════
async def main():
    logger.info("═══ Запуск Proxy Bot ═══")

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )

    try:
        await run(bot)
    except Exception as e:
        logger.exception("Критическая ошибка в run(): %s", e)
        raise
    finally:
        await bot.session.close()
        logger.info("═══ Завершение Proxy Bot ═══")


if __name__ == "__main__":
    asyncio.run(main())
