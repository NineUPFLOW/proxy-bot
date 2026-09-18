"""
Точка входа. Полный цикл:
1. Сбор прокси из Telegram-источников
2. Дедупликация в батче (по ip:port)
3. Проверка ВСЕХ новых (оптимизировано)
4. Дедупликация рабочих (по ip:port)
5. Фильтрация уже опубликованных (published)
6. Сортировка по score
7. Публикация ВСЕХ рабочих
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

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = os.environ["CHAT_ID"]

# ─── Публикация ───
MT_PUBLISH_MAX = 15          # максимум MTProto в одной публикации
MAX_WEB_PUBLISH = 3          # максимум WEB
MAX_SOCKS5_PUBLISH = 1       # максимум SOCKS5
SEND_DELAY = 3
MAX_SEND_RETRIES = 3
CONCURRENCY = 20


def dedup_by_ip_port(proxies: list) -> list:
    """Жёсткая дедупликация по ip:port с приоритетом по score."""
    best = {}
    for p in proxies:
        key = (p["ip"], p["port"])
        if key not in best or p.get("score", 0) > best[key].get("score", 0):
            best[key] = p
    return list(best.values())


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


async def run(bot: Bot):
    # ─── 0. Инициализация состояния ───
    logger.info("Инициализация состояния...")
    state.init_db()
    state.cleanup()

    seen_count = state.count_seen()
    pub_count = state.count_published()
    logger.info(
        "Состояние при старте: seen=%s published=%s",
        seen_count, pub_count,
    )

    # ─── 1. Сбор ───
    logger.info("Сбор прокси из источников...")
    raw_list = await fetch_all_proxies()
    if not raw_list:
        logger.warning("Источники пусты")
        return

    # ─── 2. Дедупликация по ip:port ───
    raw_list = dedup_by_ip_port(raw_list)
    logger.info("После дедупликации по ip:port: %s", len(raw_list))

    # ─── 3. Оптимизированная проверка ВСЕХ (без жёстких лимитов) ───
    mtproto_all = [r for r in raw_list if r.get("protocol") == "MTPROTO"]
    socks5_all = [r for r in raw_list if r.get("protocol") == "SOCKS5"]
    web_all = [r for r in raw_list if r.get("protocol") == "WEB"]

    random.shuffle(mtproto_all)
    random.shuffle(socks5_all)
    random.shuffle(web_all)

    # Приоритет: 70% MTProto, 20% SOCKS5, 10% WEB
    total = len(mtproto_all) + len(socks5_all) + len(web_all)
    priority_mt = int(total * 0.70)
    priority_socks = int(total * 0.20)
    priority_web = total - priority_mt - priority_socks

    mtproto_pick = mtproto_all[:priority_mt]
    socks5_pick = socks5_all[:priority_socks]
    web_pick = web_all[:priority_web]

    raw_list = mtproto_pick + socks5_pick + web_pick
    random.shuffle(raw_list)

    logger.info(
        "Проверка: MTProto=%s SOCKS5=%s WEB=%s | всего=%s",
        len(mtproto_pick), len(socks5_pick), len(web_pick), len(raw_list),
    )

    logger.info(
        "По протоколам (приоритет): MTProto=%s SOCKS5=%s WEB=%s",
        len(mtproto_pick), len(socks5_pick), len(web_pick),
    )

    # ─── 4. Фильтрация уже просканированных ───
    fresh_raw = state.filter_unseen(raw_list)
    logger.info(
        "Новых для сканирования: %s (пропущено: %s)",
        len(fresh_raw), len(raw_list) - len(fresh_raw),
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

    # ─── Дедупликация рабочих ───
    before = len(working)
    working = dedup_by_ip_port(working)
    if before != len(working):
        logger.info(
            "Рабочих после дедупликации: %s (убрано %s)",
            len(working), before - len(working),
        )

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
    before_filter = len(working)
    working = state.filter_unpublished(working)
    skipped = before_filter - len(working)
    logger.info(
        "После фильтра опубликованных: %s (отсеяно %s)",
        len(working), skipped,
    )

    if not working:
        logger.info("Все рабочие прокси уже публиковались — публиковать нечего")
        return

    # ─── 7. Сортировка по score ───
    working.sort(key=lambda p: p.get("score", 0), reverse=True)

    logger.info("Топ-10 по качеству:")
    for p in working[:10]:
        logger.info(
            "  %s %s:%s ping=%sms score=%s",
            p["protocol"], p["ip"], p["port"],
            p.get("ping", "?"), p.get("score", "?"),
        )

    # ─── 8. Формирование выборки (публикуем ВСЕ рабочие) ───
    mtproto_sorted = [p for p in working if p["protocol"] == "MTPROTO"]
    web_sorted = [p for p in working if p["protocol"] == "WEB"]
    socks5_sorted = [p for p in working if p["protocol"] == "SOCKS5"]

    selected = []
    selected.extend(mtproto_sorted[:MT_PUBLISH_MAX])

    if web_sorted:
        selected.extend(web_sorted[:MAX_WEB_PUBLISH])

    if socks5_sorted:
        selected.extend(socks5_sorted[:MAX_SOCKS5_PUBLISH])

    # Финальная дедупликация
    selected = dedup_by_ip_port(selected)

    if not selected:
        logger.info("Нет прокси для публикации")
        return

    logger.info(
        "Публикуем %s прокси (из %s доступных)",
        len(selected), len(working),
    )

    # ─── 9. Публикация ───
    published_ok = []
    published_keys = set()
    for p in selected:
        key = (p["ip"], p["port"])
        if key in published_keys:
            logger.warning("Пропуск дубликата %s:%s", p["ip"], p["port"])
            continue
        published_keys.add(key)
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
    logger.info("✅ Бот успешно завершил цикл публикации прокси!")
