import asyncio
import logging
import os
import random

from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import LinkPreviewOptions

from sources import fetch_all_proxies
from checker import process_proxy
from formatter import format_message, build_keyboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = os.environ["CHAT_ID"]

PUBLISH_COUNT = 5
CONCURRENCY = 10

# Максимальная доля SOCKS5 среди публикуемых (в РФ работают нестабильно)
SOCKS5_MAX_RATIO = 0.3  # 30%


async def check_with_semaphore(sem, raw):
    async with sem:
        try:
            return await process_proxy(raw)
        except Exception as e:
            logger.debug(f"check error: {e}")
            return None


async def main():
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )

    raw_list = await fetch_all_proxies()
    if not raw_list:
        logger.warning("Источники пусты")
        await bot.session.close()
        return

    random.shuffle(raw_list)

    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [check_with_semaphore(sem, r) for r in raw_list]
    results = await asyncio.gather(*tasks)

    working = [r for r in results if r]
    logger.info(f"Рабочих прокси: {len(working)}")

    # ─── ПРИОРИТИЗАЦИЯ ────────────────────────────────────────────────
    # 1. Белые IP (любой протокол)
    # 2. MTProto с fake TLS (ee)
    # 3. WEB (dd)
    # 4. SOCKS5
    white = [p for p in working if p["is_white"]]
    mtproto = [p for p in working if p["protocol"] == "MTPROTO" and not p["is_white"]]
    web = [p for p in working if p["protocol"] == "WEB" and not p["is_white"]]
    socks5 = [p for p in working if p["protocol"] == "SOCKS5" and not p["is_white"]]

    # Ограничиваем SOCKS5
    max_socks5 = max(1, int(PUBLISH_COUNT * SOCKS5_MAX_RATIO))
    socks5 = socks5[:max_socks5]

    # Собираем итоговый список
    seen = set()
    final = []
    for p in white + mtproto + web + socks5:
        key = (p["ip"], p["port"])
        if key in seen:
            continue
        seen.add(key)
        final.append(p)
        if len(final) >= PUBLISH_COUNT:
            break

    if not final:
        logger.warning("Нет рабочих прокси для публикации")
        await bot.session.close()
        return

    for p in final:
        try:
            await bot.send_message(
                chat_id=CHAT_ID,
                text=format_message(p),
                reply_markup=build_keyboard(p),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            logger.info(f"Опубликован {p['protocol']} #{p['id']}")
            await asyncio.sleep(3)
        except Exception as e:
            logger.error(f"Ошибка публикации: {e}")

    await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
