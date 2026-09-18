"""
Проверка прокси с учётом РУ-сегмента.
Дополнительные проверки для обхода ТСПУ и глушилок.
Кэш геолокации, retry при 429, HEADERS для HTTP-запросов.
"""

import asyncio
import hashlib
import ipaddress
import logging
import os
import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.help import GetConfigRequest
from telethon.network.connection import ConnectionTcpMTProxyRandomizedIntermediate

# ─── Глушим логи Telethon ──────────────────────────────────────────────
for name in (
    "telethon", "telethon.network", "telethon.client",
    "telethon.network.mtprotosender", "telethon.network.connection",
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
TEST_URL_RU_ALT = "https://vk.com"

# ─── Общая HTTP-сессия + кэш геолокации ────────────────────────────────
_http_session: aiohttp.ClientSession | None = None
_geo_cache: dict[str, dict] = {}
_geo_semaphore = asyncio.Semaphore(5)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def _get_http_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(headers=HEADERS)
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


def _country_flag(code: str) -> str:
    """Преобразует код страны в emoji-флаг."""
    if not code or len(code) != 2:
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


async def geolocate(ip: str) -> dict:
    """Геолокация с кэшем и retry при 429."""
    if ip in _geo_cache:
        return _geo_cache[ip]

    async with _geo_semaphore:
        session = _get_http_session()
        for attempt in range(3):
            try:
                async with session.get(
                    f"http://ip-api.com/json/{ip}"
                    "?fields=status,country,countryCode,city,isp,query",
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as r:
                    if r.status == 429:
                        await asyncio.sleep(2 * (attempt + 1))
                        continue
                    if r.status == 200:
                        data = await r.json()
                        if data.get("status") == "success":
                            _geo_cache[ip] = data
                            return data
                        return {}
            except Exception as e:
                logger.debug("geolocate(%s) attempt %s failed: %s", ip, attempt + 1, e)
                await asyncio.sleep(1)
    return {}


# ─── Проверка MTProto ──────────────────────────────────────────────────
async def check_mtproto(proxy: dict) -> dict | None:
    """Проверка MTProto с 3 handshake (нужно 2)."""
    try:
        ip = proxy["ip"]
        port = proxy["port"]
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
            timeout=CHECK_TIMEOUT,
            connection_retries=0,          # ← быстрее отсеиваем мёртвые
            retry_delay=0,
            auto_reconnect=False,
        )

        start = asyncio.get_event_loop().time()
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            return None

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
        async with aiohttp.ClientSession(connector=connector, connector_owner=False) as session:
            try:
                async with session.get(
                    TEST_URL_TG,
                    timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                ) as r:
                    if r.status >= 500:
                        return None
            except Exception:
                return None

            async with session.get(
                TEST_URL_RU,
                timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
            ) as r:
                if r.status != 200:
                    return None

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
    finally:
        try:
            await connector.close()
        except Exception:
            pass


# ─── Главная функция ───────────────────────────────────────────────────
async def process_proxy(raw: dict) -> dict | None:
    proto = raw["protocol"].upper()

    if proto == "MTPROTO":
        if not raw.get("secret", "").startswith("ee"):
            return None
        return await check_mtproto(raw)

    if proto == "SOCKS5":
        return await check_socks5(raw)

    if proto == "WEB":
        # WEB-прокси временно отключены
        return None

    return None
