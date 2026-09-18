"""
Сбор прокси из Telegram-источников.
Читает и текст сообщений, и inline-кнопки (в каналах, группах, супергруппах).
"""
import asyncio
import logging
from collections import Counter
from urllib.parse import urlparse, parse_qs

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.errors import FloodWaitError, ChannelPrivateError

logger = logging.getLogger(__name__)

# ─── ИСТОЧНИКИ ─────────────────────────────────────────────────────────
TELEGRAM_SOURCES = [
    # ── Каналы с MTProto-прокси ──
    "TProxyRU",
    "ProxyMTProto",
    "MProxyFree",
    "vnespiska",
    "Proxy_tm_unlimited",
    "KVN_ot_RKN",
    "telemt_free_proxy",
    "proxy_first_ru",
    "MTProto34",
    "mtpro_xyz",
    "proxy_telegramt",
    # ── Группы и форумы ──
    "urlsources",
    "strbypass",
    "PODVAL_MIX",
    "razlo4ka7",
    "FreeLifeForum",
    "RaViraNet",
]

MESSAGES_LIMIT = 100
SOURCE_TIMEOUT = 30
SOURCE_DELAY = 3

API_ID = None
API_HASH = None
TG_SESSION = None


def _init_telegram_env():
    global API_ID, API_HASH, TG_SESSION
    import os
    if API_ID is None:
        API_ID = int(os.environ["API_ID"])
        API_HASH = os.environ["API_HASH"]
        TG_SESSION = os.environ.get("TG_SESSION")


# ─── ПАРСЕРЫ ───────────────────────────────────────────────────────────

def _parse_tg_proxy(line: str):
    try:
        params = parse_qs(urlparse(line).query)
        server = params.get("server", [None])[0]
        port = params.get("port", [None])[0]
        secret = params.get("secret", [None])[0]
        if not all([server, port, secret]):
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
    except Exception:
        return None


def _parse_tg_socks(line: str):
    try:
        params = parse_qs(urlparse(line).query)
        server = params.get("server", [None])[0]
        port = params.get("port", [None])[0]
        if not all([server, port]):
            return None
        return {
            "protocol": "SOCKS5",
            "ip": server,
            "port": int(port),
            "raw": line,
        }
    except Exception:
        return None


def _parse_tg_webproxy(line: str):
    try:
        params = parse_qs(urlparse(line).query)
        server = params.get("server", [None])[0]
        secret = params.get("secret", [None])[0]
        port = params.get("port", ["443"])[0]
        if not all([server, secret]):
            return None
        if not secret.startswith("dd"):
            return None
        return {
            "protocol": "WEB",
            "ip": server,
            "port": int(port) if port else 443,
            "secret": secret,
            "raw": line,
        }
    except Exception:
        return None


def _parse_socks5_uri(line: str):
    try:
        parsed = urlparse(line)
        if parsed.scheme not in ("socks5", "socks"):
            return None
        host = parsed.hostname
        port = parsed.port
        if not all([host, port]):
            return None
        return {
            "protocol": "SOCKS5",
            "ip": host,
            "port": int(port),
            "raw": line,
        }
    except Exception:
        return None


def _parse_bare_socks5(line: str):
    line = line.strip()
    if line.count(":") != 1:
        return None
    try:
        ip, port = line.rsplit(":", 1)
        port = int(port)
        if not (1 <= port <= 65535):
            return None
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        for p in parts:
            if not (0 <= int(p) <= 255):
                return None
        return {
            "protocol": "SOCKS5",
            "ip": ip,
            "port": port,
            "raw": line,
        }
    except (ValueError, AttributeError):
        return None


def _extract_from_token(token: str):
    token = token.strip().strip("`<>\"'")
    if not token:
        return None
    if "tg://proxy" in token or "t.me/proxy" in token:
        return _parse_tg_proxy(token)
    if "tg://socks" in token or "t.me/socks" in token:
        return _parse_tg_socks(token)
    if "tg://webproxy" in token or "t.me/webproxy" in token:
        return _parse_tg_webproxy(token)
    if token.startswith("socks5://") or token.startswith("socks://"):
        return _parse_socks5_uri(token)
    return None


def _extract_proxies_from_text(text: str) -> list:
    if not text:
        return []
    result = []
    text = text.replace("`", "").replace("</a>", "")

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        for token in line.split():
            p = _extract_from_token(token)
            if p:
                result.append(p)

        if not any(s in line for s in ("tg://", "t.me/", "socks5://", "socks://")):
            for word in line.split():
                p = _parse_bare_socks5(word)
                if p:
                    result.append(p)

    return result


def _extract_proxies_from_markup(msg) -> list:
    """
    Извлекает прокси из inline-кнопок.
    Работает и для каналов, и для групп, и для супергрупп.
    """
    if not msg.reply_markup:
        return []
    result = []
    try:
        rows = getattr(msg.reply_markup, "rows", [])
        for row in rows:
            for button in row.buttons:
                # URL-кнопки
                url = getattr(button, "url", None)
                if url:
                    p = _extract_from_token(url)
                    if p:
                        result.append(p)
                    continue
                # Кнопки с callback_data могут содержать tg-ссылки
                data = getattr(button, "data", None)
                if data:
                    try:
                        data_str = data.decode("utf-8", errors="ignore")
                        p = _extract_from_token(data_str)
                        if p:
                            result.append(p)
                    except Exception:
                        pass
    except Exception as e:
        logger.debug("markup parse error: %s", e)
    return result


# ─── ПАРСИНГ ИСТОЧНИКОВ ────────────────────────────────────────────────

async def _fetch_from_source(client: TelegramClient, source: str) -> list:
    result = []
    try:
        try:
            await client(JoinChannelRequest(source))
        except ChannelPrivateError:
            logger.debug("Источник @%s приватный, пропускаем", source)
            return result
        except Exception:
            pass

        messages = await asyncio.wait_for(
            client.get_messages(source, limit=MESSAGES_LIMIT),
            timeout=SOURCE_TIMEOUT,
        )

        from_text = 0
        from_markup = 0

        for msg in messages:
            text_proxies = _extract_proxies_from_text(msg.message or "")
            result.extend(text_proxies)
            from_text += len(text_proxies)

            markup_proxies = _extract_proxies_from_markup(msg)
            result.extend(markup_proxies)
            from_markup += len(markup_proxies)

        logger.info(
            "Telegram @%s: %s сообщений → текст %s, кнопки %s",
            source, len(messages), from_text, from_markup,
        )
    except FloodWaitError as e:
        logger.warning("FloodWait для @%s: %ss", source, e.seconds)
        await asyncio.sleep(min(e.seconds, 60))
    except asyncio.TimeoutError:
        logger.warning("Таймаут при чтении @%s", source)
    except Exception as e:
        logger.warning("Ошибка чтения @%s: %s", source, e)
    return result


async def fetch_from_telegram_sources() -> list:
    _init_telegram_env()

    if not TG_SESSION:
        logger.warning("TG_SESSION не задан, парсинг пропущен")
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

        if not await is_user_authorized():  # <--- добавлено
            logger.warning("TG_SESSION не авторизована")
            return []

        for source in TELEGRAM_SOURCES:
            proxies = await _fetch_from_source(client, source)
            result.extend(proxies)
            await asyncio.sleep(SOURCE_DELAY)

    except Exception as e:
        logger.warning("Ошибка userbot-парсера: %s", e)
    finally:
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                pass

    logger.info("Из Telegram-источников собрано: %s", len(result))
    return result


async def is_user_authorized() -> bool:
    """Проверяет, авторизован ли пользователь в Telegram."""
    try:
        await client.get_me()
        return True
    except Exception:
        return False


# ─── ГЛАВНАЯ ФУНКЦИЯ ───────────────────────────────────────────────────

async def fetch_all_proxies() -> list:
    result = []
    seen = set()

    def add(p):
        key = (p["protocol"], p["ip"], p["port"])
        if key not in seen:
            seen.add(key)
            result.append(p)

    tg_proxies = await fetch_from_telegram_sources()
    for p in tg_proxies:
        add(p)

    stats = Counter(p["protocol"] for p in result)
    logger.info("Всего собрано: %s | %s", len(result), dict(stats))
    return result
