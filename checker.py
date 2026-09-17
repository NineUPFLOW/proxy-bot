"""
Проверка прокси с учётом РУ-сегмента.
Дополнительные проверки для обхода ТСПУ и глушилок.
"""
import asyncio
import hashlib
import ipaddress
import logging
import socket
import os
import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.help import GetConfigRequest
from telethon.network.connection import ConnectionTcpMTProxyRandomizedIntermediate

# ─── Глушим логи Telethon ──────────────────────────────────────────────
for name in (
    "telethon",
    "telethon.network",
    "telethon.client",
    "telethon.network.mtprotosender",
    "telethon.network.connection",
):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

# ─── Лимиты ────────────────────────────────────────────────────────────
MAX_PING_MS = 5000
MAX_PING_WEB_MS = 3000
CHECK_TIMEOUT = 6
WEB_CHECK_TIMEOUT = 8

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

# ─── URL для проверок ──────────────────────────────────────────────────
TEST_URL_TG = "https://api.telegram.org"
TEST_URL_RU = "https://ya.ru"
TEST_URL_RU_ALT = "https://vk.com"  # дополнительный тест для РУ-сегмента

# ─── Общая HTTP-сессия ─────────────────────────────────────────────────
_http_session: aiohttp.ClientSession | None = None
_geo_semaphore = asyncio.Semaphore(5)


def _get_http_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession()
    return _http_session


async def close_http_session():
    global _http_session
    if _http_session is not None and not _http_session.closed:
        await _http_session.close()
    _http_session = None


# ─── Утилиты ───────────────────────────────────────────────────────────
def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _stable_id(ip: str, port: int) -> int:
    digest = hashlib.md5(f"{ip}:{port}".encode()).hexdigest()
    return int(digest, 16) % 10_000_000


async def geolocate(ip: str) -> dict:
    async with _geo_semaphore:
        session = _get_http_session()
        try:
            async with session.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,query",
                timeout=aiohttp.ClientTimeout(total=8),
            ) as r:
                if r.status == 429:
                    logger.warning("ip-api.com: превышен лимит запросов (429)")
                    return {}
                if r.status == 200:
                    data = await r.json()
                    if data.get("status") == "success":
                        return data
        except Exception as e:
            logger.debug("geolocate(%s) failed: %s", ip, e)
    return {}


# ─── Проверка MTProto ──────────────────────────────────────────────────
async def check_mtproto(proxy: dict) -> dict | None:
    """Проверка MTProto с 3 handshake (нужно 2)."""
    try:
        ip = proxy["ip"]
        port = proxy["port"]
        secret = proxy["secret"]

        # Если IP — домен, резолвим
        if not _is_ip(ip):
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.getaddrinfo(ip, port)[0][4][0]
            except Exception:
                return None

        client = TelegramClient(
            StringSession(TG_SESSION),
            API_ID,
            API_HASH,
            connection=ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=(ip, port, secret),
            timeout=CHECK_TIMEOUT,
            connection_retries=1,
            retry_delay=0,
            auto_reconnect=False,
        )

        start = asyncio.get_event_loop().time()
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            return None

        # 3 handshake
        success = 0
        for _ in range(3):
            try:
                await client(GetConfigRequest())
                success += 1
            except Exception:
                pass

        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        await client.disconnect()

        if success < 2 or elapsed > MAX_PING_MS:
            return None

        geo = await geolocate(ip)
        proxy.update({
            "ip": ip,
            "ping": int(elapsed),
            "id": _stable_id(ip, port),
            "country": geo.get("country", "Unknown"),
            "countryCode": geo.get("countryCode", ""),
            "city": geo.get("city", "Unknown"),
            "provider": geo.get("isp", "Unknown"),
            "flag": _country_flag(geo.get("countryCode", "")),
        })
        return proxy

    except Exception as e:
        logger.debug("MTProto check failed: %s", e)
        return None


# ─── Проверка SOCKS5 ───────────────────────────────────────────────────
async def check_socks5(proxy: dict) -> dict | None:
    """Строгая проверка SOCKS5: Telegram + ya.ru + vk.com."""
    try:
        ip = proxy["ip"]
        port = proxy["port"]

        if not _is_ip(ip):
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.getaddrinfo(ip, port)[0][4][0]
            except Exception:
                return None

        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5,
            host=ip,
            port=port,
            rdns=True,
        )

        start = asyncio.get_event_loop().time()
        async with aiohttp.ClientSession(connector=connector) as session:
            # Проверка Telegram
            async with session.get(
                TEST_URL_TG,
                timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
            ) as r:
                if r.status != 200 and r.status != 404:
                    return None

            # Проверка ya.ru
            async with session.get(
                TEST_URL_RU,
                timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
            ) as r:
                if r.status != 200:
                    return None

            # Дополнительная проверка для РУ-сегмента
            try:
                async with session.get(
                    TEST_URL_RU_ALT,
                    timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                ) as r:
                    if r.status not in (200, 301, 302):
                        pass  # не критично
            except Exception:
                pass

        elapsed = (asyncio.get_event_loop().time() - start) * 1000

        if elapsed > MAX_PING_MS:
            return None

        geo = await geolocate(ip)
        proxy.update({
            "ip": ip,
            "ping": int(elapsed),
            "id": _stable_id(ip, port),
            "country": geo.get("country", "Unknown"),
            "countryCode": geo.get("countryCode", ""),
            "city": geo.get("city", "Unknown"),
            "provider": geo.get("isp", "Unknown"),
            "flag": _country_flag(geo.get("countryCode", "")),
        })
        return proxy

    except Exception as e:
        logger.debug("SOCKS5 check failed: %s", e)
        return None


# ─── Проверка WEB ──────────────────────────────────────────────────────
async def check_web(proxy: dict) -> dict | None:
    """Проверка WEB (TgWebProxy) — 2 handshake."""
    try:
        ip = proxy["ip"]
        port = proxy.get("port", 443)
        secret = proxy["secret"]

        if not _is_ip(ip):
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.getaddrinfo(ip, port)[0][4][0]
            except Exception:
                return None

        client = TelegramClient(
            StringSession(TG_SESSION),
            API_ID,
            API_HASH,
            connection=ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=(ip, port, secret),
            timeout=WEB_CHECK_TIMEOUT,
            connection_retries=1,
            retry_delay=0,
            auto_reconnect=False,
        )

        start = asyncio.get_event_loop().time()
        await client.connect()

        success = 0
        for _ in range(2):
            try:
                await client(GetConfigRequest())
                success += 1
            except Exception:
                pass

        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        await client.disconnect()

        if success < 2 or elapsed > MAX_PING_WEB_MS:
            return None

        geo = await geolocate(ip)
        proxy.update({
            "ip": ip,
            "ping": int(elapsed),
            "id": _stable_id(ip, port),
            "country": geo.get("country", "Unknown"),
            "countryCode": geo.get("countryCode", ""),
            "city": geo.get("city", "Unknown"),
            "provider": geo.get("isp", "Unknown"),
            "flag": _country_flag(geo.get("countryCode", "")),
        })
        return proxy

    except Exception as e:
        logger.debug("WEB check failed: %s", e)
        return None


# ─── Диспетчер ─────────────────────────────────────────────────────────
async def process_proxy(proxy: dict) -> dict | None:
    """Маршрутизирует проверку по типу протокола."""
    proto = proxy.get("protocol", "").upper()

    if proto == "MTPROTO":
        return await check_mtproto(proxy)
    if proto == "SOCKS5":
        return await check_socks5(proxy)
    if proto == "WEB":
        return await check_web(proxy)

    return None


# ─── Флаги стран ───────────────────────────────────────────────────────
def _country_flag(code: str) -> str:
    """Преобразует код страны в emoji-флаг."""
    if not code or len(code) != 2:
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())
