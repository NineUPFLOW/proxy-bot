""" Проверка прокси: MTProto, WEB (через MTProto-туннель), SOCKS5. """

import asyncio
import logging
import time
import os

import aiohttp
from aiohttp_socks import ProxyConnector

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.help import GetConfigRequest
from telethon.network import ConnectionTcpMTProxyRandomizedIntermediate

logger = logging.getLogger("checker")

# ═══════════════════════════════════════════════════════════════════════
# Конфигурация
# ═══════════════════════════════════════════════════════════════════════
API_ID = int(os.environ.get("API_ID", "0") or "0")
API_HASH = os.environ.get("API_HASH", "")
TG_SESSION = os.environ.get("TG_SESSION", "")

CHECK_TIMEOUT = 8
SOCKS_TIMEOUT = 8

_session: aiohttp.ClientSession | None = None


async def _get_session() -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession()
    return _session


async def close_http_session():
    global _session
    if _session and not _session.closed:
        await _session.close()
        _session = None


# ═══════════════════════════════════════════════════════════════════════
# MTProto
# ═══════════════════════════════════════════════════════════════════════
async def _one_mtproto_attempt(ip: str, port: int, secret: str) -> int | None:
    client = None
    try:
        if not TG_SESSION or not API_ID or not API_HASH:
            logger.warning("TG_SESSION / API_ID / API_HASH не заданы — MTProto пропущен")
            return None
        client = TelegramClient(
            StringSession(TG_SESSION),
            API_ID,
            API_HASH,
            connection=ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=(ip, port, secret),
            timeout=CHECK_TIMEOUT,
            connection_retries=0,
            retry_delay=0,
            auto_reconnect=False,
        )
        t0 = time.monotonic()
        await asyncio.wait_for(client.connect(), timeout=CHECK_TIMEOUT)
        if not client.is_connected():
            return None
        await asyncio.wait_for(client(GetConfigRequest()), timeout=CHECK_TIMEOUT)
        return int((time.monotonic() - t0) * 1000)
    except (asyncio.TimeoutError, asyncio.CancelledError, ConnectionError, OSError):
        return None
    except Exception as e:
        logger.debug("mtproto %s:%s — %s", ip, port, e)
        return None
    finally:
        if client is not None:
            try:
                await asyncio.wait_for(client.disconnect(), timeout=2)
            except Exception:
                pass


async def check_mtproto(proxy: dict) -> dict | None:
    ip = proxy["ip"]
    port = int(proxy["port"])
    secret = proxy.get("secret", "")
    if not secret:
        return None

    ping = await _one_mtproto_attempt(ip, port, secret)
    if ping is None:
        return None

    result = dict(proxy)
    result["ping"] = ping
    result["score"] = _score("MTPROTO", ping)
    result.update(_geo_stub(ip))
    return result


# ═══════════════════════════════════════════════════════════════════════
# WEB
# ═══════════════════════════════════════════════════════════════════════
async def check_web(proxy: dict) -> dict | None:
    """
    WEB-прокси проверяем через тот же MTProto-туннель (Telegram использует
    такой же транспорт для web-прокси, отличие только в префиксе secret).
    """
    ip = proxy["ip"]
    port = int(proxy["port"])
    secret = proxy.get("secret", "")
    if not secret.startswith("dd"):
        return None

    # Telegram-клиент принимает secret как есть, префикс dd обрабатывается
    # самим Telegram, поэтому можно использовать тот же код.
    ping = await _one_mtproto_attempt(ip, port, secret)
    if ping is None:
        return None

    result = dict(proxy)
    result["ping"] = ping
    result["score"] = _score("WEB", ping)
    result.update(_geo_stub(ip))
    return result


# ═══════════════════════════════════════════════════════════════════════
# SOCKS5
# ═══════════════════════════════════════════════════════════════════════
async def check_socks5(proxy: dict) -> dict | None:
    ip = proxy["ip"]
    port = int(proxy["port"])
    url = f"socks5://{ip}:{port}"
    t0 = time.monotonic()
    try:
        connector = ProxyConnector.from_url(url)
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.get(
                "https://api.ipify.org?format=json",
                timeout=aiohttp.ClientTimeout(total=SOCKS_TIMEOUT),
            ) as r:
                if r.status != 200:
                    return None
                await r.json()
        ping = int((time.monotonic() - t0) * 1000)
    except Exception as e:
        logger.debug("socks5 %s:%s — %s", ip, port, e)
        return None

    result = dict(proxy)
    result["ping"] = ping
    result["score"] = _score("SOCKS5", ping)
    result.update(_geo_stub(ip))
    return result


# ═══════════════════════════════════════════════════════════════════════
# Вспомогательные
# ═══════════════════════════════════════════════════════════════════════
def _score(proto: str, ping: int) -> float:
    base = {"MTPROTO": 100.0, "WEB": 80.0, "SOCKS5": 60.0}.get(proto, 0.0)
    return base - ping / 100.0


_GEO_CACHE: dict[str, dict] = {}


def _geo_stub(ip: str) -> dict:
    """ Заглушка: страна/город/провайдер. При желании можно подключить GeoIP. """
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    info = {
        "country": "Unknown",
        "city": "Unknown",
        "provider": "Unknown",
        "flag": "🏳️",
    }
    _GEO_CACHE[ip] = info
    return info


# ═══════════════════════════════════════════════════════════════════════
# Точка входа
# ═══════════════════════════════════════════════════════════════════════
async def process_proxy(raw: dict) -> dict | None:
    proto = raw.get("protocol", "").upper()
    try:
        if proto == "MTPROTO":
            if not raw.get("secret", "").startswith("ee"):
                return None
            return await check_mtproto(raw)
        if proto == "WEB":
            return await check_web(raw)
        if proto == "SOCKS5":
            return await check_socks5(raw)
    except Exception as e:
        logger.debug("process_proxy %s — %s", raw, e)
    return None
