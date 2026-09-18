"""
Сбор прокси из Telegram-источников.
- Regex-парсинг markdown и HTML-ссылок
- Анализ Secret: извлечение домена-маски, probe_resistant
"""

import asyncio
import logging
import os
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.errors import FloodWaitError, ChannelPrivateError

logger = logging.getLogger(__name__)

# ─── ИСТОЧНИКИ ─────────────────────────────────────────────────────────
TELEGRAM_SOURCES = [
    "TProxyRU", "ProxyMTProto", "MProxyFree", "vnespiska",
    "Proxy_tm_unlimited", "KVN_ot_RKN", "telemt_free_proxy",
    "proxy_first_ru", "MTProto34", "mtpro_xyz", "proxy_telegramt",
    "urlsources", "strbypass", "PODVAL_MIX", "razlo4ka7",
    "FreeLifeForum", "RaViraNet",
]

MESSAGES_LIMIT = 100
SOURCE_TIMEOUT = 30
SOURCE_DELAY = 2

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

# ─── Regex для извлечения URL из текста ────────────────────────────────
RE_MARKDOWN = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
RE_HTML_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
RE_TG_URL = re.compile(
    r"(tg://proxy[^\s<>\"'\)\]]+|t\.me/proxy[^\s<>\"'\)\]]+"
    r"|tg://socks[^\s<>\"'\)\]]+|t\.me/socks[^\s<>\"'\)\]]+"
    r"|tg://webproxy[^\s<>\"'\)\]]+|t\.me/webproxy[^\s<>\"'\)\]]+"
    r"|socks5://[^\s<>\"'\)\]]+|socks://[^\s<>\"'\)\]]+)"
)


# ═══════════════════════════════════════════════════════════════════════
#  АНАЛИЗ SECRET
# ═══════════════════════════════════════════════════════════════════════

HEX_CHARS = set("0123456789abcdefABCDEF")


def _extract_domain_from_secret(secret: str) -> str | None:
    """Извлекает домен-маску из ee-секрета. Возвращает None при ошибке."""
    if not secret.startswith("ee") or len(secret) < 36:
        return None

    rest = secret[2:]
    if len(rest) < 34:
        return None

    domain_hex = rest[32:]
    if not domain_hex or len(domain_hex) % 2 != 0:
        return None
    if not all(c in HEX_CHARS for c in domain_hex):
        return None

    try:
        domain_bytes = bytes.fromhex(domain_hex)
        domain = domain_bytes.decode("ascii", errors="ignore").strip("\x00")
        if "." in domain and 3 < len(domain) < 100 and " " not in domain:
            return domain
    except (ValueError, UnicodeDecodeError):
        pass
    return None


def analyze_secret(proxy: dict):
    """Анализирует secret MTProto: маска домена, fake TLS, probe_resistant."""
    secret = proxy.get("secret", "")
    proxy["mask_domain"] = None
    proxy["has_fake_tls"] = secret.startswith("ee")
    proxy["probe_resistant"] = False

    if proxy["has_fake_tls"]:
        domain = _extract_domain_from_secret(secret)
        if domain:
            proxy["mask_domain"] = domain
            proxy["probe_resistant"] = True  # уточнится в checker


# ═══════════════════════════════════════════════════════════════════════
#  ПАРСЕРЫ
# ═══════════════════════════════════════════════════════════════════════

def _parse_qs_safe(query: str) -> dict:
    """parse_qs с защитой base64-плюсов и без превращения в пробел."""
    return parse_qs(query.replace("+", "%2B"))


def _parse_tg_proxy(line: str):
    try:
        params = _parse_qs_safe(urlparse(line).query)
        server = params.get("server", [None])[0]
        port = params.get("port", [None])[0]
        secret = params.get("secret", [None])[0]
        if not all([server, port, secret]):
            return None
        if secret.startswith("dd"):
            return None
        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                return None
        except ValueError:
            return None

        proxy = {
            "protocol": "MTPROTO",
            "ip": server,
            "port": port_int,
            "secret": secret,
            "raw": line,
        }
        analyze_secret(proxy)
        return proxy
    except Exception:
        return None


def _parse_tg_socks(line: str):
    try:
        params = _parse_qs_safe(urlparse(line).query)
        server = params.get("server", [None])[0]
        port = params.get("port", [None])[0]
        if not all([server, port]):
            return None
        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                return None
        except ValueError:
            return None
        return {
            "protocol": "SOCKS5",
            "ip": server,
            "port": port_int,
            "raw": line,
        }
    except Exception:
        return None


def _parse_tg_webproxy(line: str):
    try:
        params = _parse_qs_safe(urlparse(line).query)
        server = params.get("server", [None])[0]
        secret = params.get("secret", [None])[0]
        if not all([server, secret]) or not secret.startswith("dd"):
            return None
        port_raw = params.get("port", ["443"])[0]
        try:
            port = int(port_raw) if port_raw else 443
        except ValueError:
            port = 443
        return {
            "protocol": "WEB",
            "ip": server,
            "port": port,
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
        port_int = int(port)
        if not (1 <= port_int <= 65535):
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
            "port": port_int,
            "raw": line,
        }
    except (ValueError, AttributeError):
        return None


def _extract_from_token(token: str):
    """Извлекает прокси из одного токена."""
    token = token.strip().strip("`<>\"'()[]{}")
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
    """
    Извлекает все прокси из текста через regex.
    Обрабатывает: markdown [t](url), html <a href>, обычные ссылки.
    """
    if not text:
        return []

    result = []
    seen_urls = set()

    # 1. Markdown-ссылки [text](url)
    for match in RE_MARKDOWN.finditer(text):
        url = match.group(2).strip()
        if url not in seen_urls:
            seen_urls.add(url)
            p = _extract_from_token(url)
            if p:
                result.append(p)

    # 2. HTML href
    for match in RE_HTML_HREF.finditer(text):
        url = match.group(1).strip()
        if url not in seen_urls:
            seen_urls.add(url)
            p = _extract_from_token(url)
            if p:
                result.append(p)

    # 3. Голые ссылки
    for match in RE_TG_URL.finditer(text):
        url = match.group(1).strip()
        if url not in seen_urls:
            seen_urls.add(url)
            p = _extract_from_token(url)
            if p:
                result.append(p)

    # 4. Fallback: ip:port (без ссылок)
    if not result:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if any(s in line for s in ("tg://", "t.me/", "socks5://", "socks://")):
                continue
            for word in line.split():
                p = _parse_bare_socks5(word.strip("`<>\"'()[]{}"))
                if p:
                    result.append(p)

    return result


def _extract_proxies_from_markup(msg) -> list:
    """Извлекает прокси из inline-кнопок сообщения."""
    if not msg.reply_markup:
        return []
    result = []
    try:
        rows = getattr(msg.reply_markup, "rows", [])
        for row in rows:
            for button in row.buttons:
                url = getattr(button, "url", None)
                if not url:
                    continue
                p = _extract_from_token(url)
                if p:
                    result.append(p)
    except Exception as e:
        logger.debug("markup parse error: %s", e)
    return result


# ═══════════════════════════════════════════════════════════════════════
#  ПАРСИНГ ИСТОЧНИКОВ
# ═══════════════════════════════════════════════════════════════════════

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

        try:
            messages = await asyncio.wait_for(
                client.get_messages(source, limit=MESSAGES_LIMIT),
                timeout=SOURCE_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning("Таймаут при чтении @%s", source)
            return result

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
    except Exception as e:
        logger.warning("Ошибка чтения @%s: %s", source, e)
    return result


async def fetch_from_telegram_sources() -> list:
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

        try:
            authorized = await asyncio.wait_for(
                client.is_user_authorized(), timeout=15
            )
        except asyncio.TimeoutError:
            logger.warning("Таймаут is_user_authorized")
            return []

        if not authorized:
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


# ═══════════════════════════════════════════════════════════════════════
#  ГЛАВНАЯ ФУНКЦИЯ
# ═══════════════════════════════════════════════════════════════════════

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
