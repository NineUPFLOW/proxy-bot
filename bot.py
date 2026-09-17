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

PUBLISH_COUNT = 5      # сколько прокси публиковать за один запуск
CONCURRENCY = 10       # сколько прокси проверять параллельно


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

    # Приоритет: сначала белые IP
    white = [p for p in working if p["is_white"]]
    normal = [p for p in working if not p["is_white"]]

    # Убираем дубликаты
    seen = set()
    final = []
    for p in white + normal:
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
