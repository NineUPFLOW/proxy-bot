"""
Telegram Proxy Bot 2026 — полностью переписан с нуля
Работает ТОЛЬКО через GitHub Secrets
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

for noisy in ("telethon", "telethon.network", "telethon.client", "asyncio", "aiogram"):
    logging.getLogger(noisy).setLevel(logging.CRITICAL)

logger = logging.getLogger("bot")

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])


def dedup_by_ip_port(proxies: list) -> list:
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
            logger.info("✅ Опубликован %s #%s", p["protocol"], p["id"])
            return True
        except TelegramRetryAfter as e:
            logger.warning("Flood control, ждём %ss", e.retry_after)
            await asyncio.sleep(e.retry_after + 1)
        except TelegramAPIError as e:
            logger.error("Ошибка публикации %s #%s: %s", p["protocol"], p.get("id"), e)
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

    raw_list = await fetch_all_proxies()
    raw_list = dedup_by_ip_port(raw_list)

    mtproto = [r for r in raw_list if r.get("protocol") == "MTPROTO"]
    socks5 = [r for r in raw_list if r.get("protocol") == "SOCKS5"]
    web = [r for r in raw_list if r.get("protocol") == "WEB"]

    random.shuffle(mtproto)
    random.shuffle(socks5)
    random.shuffle(web)

    total = len(mtproto) + len(socks5) + len(web)
    pick_mt = int(total * 0.70)
    pick_socks = int(total * 0.20)
    pick_web = total - pick_mt - pick_socks

    selected = mtproto[:pick_mt] + socks5[:pick_socks] + web[:pick_web]
    random.shuffle(selected)

    fresh = state.filter_unseen(selected)
    logger.info("Новых для проверки: %s", len(fresh))

    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(*[check_with_semaphore(sem, r) for r in fresh])
    working = [r for r in results if r]

    working = dedup_by_ip_port(working)
    working = state.filter_unpublished(working)

    if not working:
        logger.info("Нет новых рабочих прокси для публикации")
        return

    working.sort(key=lambda p: p.get("score", 0), reverse=True)

    mtproto_ok = [p for p in working if p["protocol"] == "MTPROTO"]
    web_ok = [p for p in working if p["protocol"] == "WEB"]
    socks5_ok = [p for p in working if p["protocol"] == "SOCKS5"]

    logger.info("Рабочие для публикации: MTPROTO=%s | WEB=%s | SOCKS5=%s", len(mtproto_ok), len(web_ok), len(socks5_ok))

    selected = []
    selected.extend(mtproto_ok[:MT_PUBLISH_MAX])
    selected.extend(web_ok[:MAX_WEB_PUBLISH])
    selected.extend(socks5_ok[:MAX_SOCKS5_PUBLISH])

    selected = dedup_by_ip_port(selected)

    for p in selected:
        await send_with_retry(bot, p)
        await asyncio.sleep(SEND_DELAY)

    logger.info("✅ Публикация завершена")


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
    logger.info("✅ Бот успешно завершил цикл!")
