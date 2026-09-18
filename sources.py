"""
Сбор прокси из открытых источников + парсинг Telegram-каналов.
Все ссылки проверены на 2026-09-18.
"""

import asyncio
import logging
from collections import Counter
from urllib.parse import urlparse, parse_qs

import aiohttp
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.errors import FloodWaitError, ChannelPrivateError

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# ─── MTProto из tg:// ссылок ───────────────────────────────────────────
MTPROTO_URLS = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
]

# ─── SOCKS5 ────────────────────────────────────────────────────────────
SOCKS5_URLS = [
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
]

# ─── Telegram-каналы с MTProto-прокси ──────────────────────────────────
# Без @, только username. Telethon сам подпишется через JoinChannelRequest.
TELEGRAM_CHANNELS = [
    "ProxyMTProto",
    "mtproto_poc",
    "mtprotoproxylist",
    "ProxyBaza",
    "freeproxylistru",
]

# Сколько последних сообщений читать из каждого канала
CHANNEL_MESSAGES_LIMIT = 100

# Таймаут на парсинг одного канала
CHANNEL_TIMEOUT = 30

# API-данные для Telethon
API_ID = None
API_HASH = None
TG_SESSION = None


def _init_telegram_env():
    """Ленивая инициализация env для Telethon."""
    global API_ID, API_HASH, TG_SESSION
    import os
    if API_ID is None:
        API_ID = int(os.environ["API_ID"])
        API_HASH = os.environ["API_HASH"]
        TG_SESSION = os.environ.get("TG_SESSION")


# ─── ЗАГРУЗЧИКИ ────────────────────────────────────────────────────────
async def _get_text(session, url):
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=20), headers=HEADERS
        ) as r:
            if r.status == 200:
                text = await r.text()
                return [l.strip() for l in text.splitlines() if l.strip()]
            logger.warning("Text fetch %s: HTTP %s", url, r.status)
    except Exception as e:
        logger.warning("Text fetch failed %s: %s", url, e)
    return []


# ─── ПАРСЕРЫ ───────────────────────────────────────────────────────────
def _parse_tg_link(line: str):
    """Парсит tg://proxy (ee) и tg://webproxy (dd) ссылки."""
    try:
        parsed = urlparse(line)
        params = parse_qs(parsed.query)
        server = params.get("server", [None])[0]
        secret = params.get("secret", [None])[0]
        if not server or not secret:
            return None

        if "tg://proxy?" in line or "t.me/proxy?" in line:
            port = params.get("port", [None])[0]
            if not port:
                return None
            if not secret.startswith("ee"):
                return None
            return {
                "protocol": "MTPROTO",
                "ip": server,
                "port": int(port),
                "secret": secret,
                "raw": line,
            }

        if "tg://webproxy?" in line or "t.me/webproxy?" in line:
            return {
                "protocol": "WEB",
                "ip": server,
                "port": 443,
                "secret": secret,
                "raw": line,
            }
    except Exception:
        return None
    return None


def _parse_socks5_line(line: str):
    if ":" not in line:
        return None
    try:
        host_part = line.rsplit("@", 1)[-1] if "@" in line else line
        ip, port = host_part.rsplit(":", 1)
        return {
            "protocol": "SOCKS5",
            "ip": ip.strip(),
            "port": int(port.strip()),
            "raw": line,
        }
    except ValueError:
        return None


def _extract_proxies_from_text(text: str) -> list:
    """Извлекает все tg://proxy ссылки из произвольного текста."""
    result = []
    for line in text.splitlines():
        line = line.strip()
        # Убираем markdown-обёртки: `tg://...`, [текст](tg://...), <a>...</a>
        line = line.replace("`", "").replace("</a>", "")
        if "(" in line and ")" in line and "tg://" in line:
            # Markdown-ссылка: [text](tg://proxy?...)
            for part in line.split("("):
                if "tg://proxy" in part or "tg://webproxy" in part:
                    part = part.split(")")[0].strip()
                    p = _parse_tg_link(part)
                    if p:
                        result.append(p)
            continue
        if "tg://proxy" in line or "t.me/proxy" in line or "tg://webproxy" in line:
            p = _parse_tg_link(line)
            if p:
                result.append(p)
    return result


# ─── ПАРСИНГ TELEGRAM-КАНАЛОВ ──────────────────────────────────────────
async def _fetch_from_channel(client: TelegramClient, channel: str) -> list:
    """Читает последние сообщения из канала и извлекает прокси."""
    result = []
    try:
        # Пробуем подписаться (для публичных каналов это безопасно)
        try:
            await client(JoinChannelRequest(channel))
        except ChannelPrivateError:
            logger.debug("Канал %s приватный, пропускаем", channel)
            return result
        except Exception:
            pass  # уже подписаны

        messages = await asyncio.wait_for(
            client.get_messages(channel, limit=CHANNEL_MESSAGES_LIMIT),
            timeout=CHANNEL_TIMEOUT,
        )

        for msg in messages:
            text = msg.message or ""
            if not text:
                continue
            proxies = _extract_proxies_from_text(text)
            result.extend(proxies)

        logger.info(
            "Telegram @%s: %s сообщений → %s прокси",
            channel, len(messages), len(result),
        )
    except FloodWaitError as e:
        logger.warning("FloodWait для @%s: %ss", channel, e.seconds)
        await asyncio.sleep(min(e.seconds, 60))
    except asyncio.TimeoutError:
        logger.warning("Таймаут при чтении @%s", channel)
    except Exception as e:
        logger.warning("Ошибка чтения @%s: %s", channel, e)
    return result


async def fetch_from_telegram_channels() -> list:
    """
    Парсит MTProto-прокси из публичных Telegram-каналов через userbot.
    Возвращает список словарей в том же формате, что и sources.
    """
    _init_telegram_env()

    if not TG_SESSION:
        logger.warning("TG_SESSION не задан, парсинг Telegram-каналов пропущен")
        return []

    result = []
    client = None
    try:
        client = TelegramClient(
            StringSession(TG_SESSION),
            API_ID,
            API_HASH,
            timeout=15,
            connection_retries=0,
            auto_reconnect=False,
        )
        await client.connect()

        if not await client.is_user_authorized():
            logger.warning("TG_SESSION не авторизована, парсинг каналов пропущен")
            return []

        for channel in TELEGRAM_CHANNELS:
            proxies = await _fetch_from_channel(client, channel)
            result.extend(proxies)
            # Пауза между каналами (антифлуд)
            await asyncio.sleep(2)

    except Exception as e:
        logger.warning("Ошибка userbot-парсера: %s", e)
    finally:
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                pass

    logger.info("Из Telegram-каналов собрано: %s прокси", len(result))
    return result


# ─── ГЛАВНАЯ ФУНКЦИЯ ───────────────────────────────────────────────────
async def fetch_all_proxies() -> list:
    result = []
    seen = set()

    def add(p):
        key = (p["protocol"], p["ip"], p["port"])
        if key not in seen:
            seen.add(key)
            result.append(p)

    # ─── 1. GitHub-источники ───
    async with aiohttp.ClientSession(headers=HEADERS) as s:
        for url in MTPROTO_URLS:
            lines = await _get_text(s, url)
            added = 0
            for line in lines:
                p = _parse_tg_link(line)
                if p:
                    add(p)
                    added += 1
            logger.info("MTProto %s: %s → %s", url.split("/")[-2], len(lines), added)

        for url in SOCKS5_URLS:
            lines = await _get_text(s, url)
            added = 0
            for line in lines:
                p = _parse_socks5_line(line)
                if p:
                    add(p)
                    added += 1
            logger.info("SOCKS5 %s: %s → %s", url.split("/")[-2], len(lines), added)

    # ─── 2. Telegram-каналы (userbot) ───
    tg_proxies = await fetch_from_telegram_channels()
    for p in tg_proxies:
        add(p)

    stats = Counter(p["protocol"] for p in result)
    logger.info("Всего собрано: %s | %s", len(result), dict(stats))
    return result
