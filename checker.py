"""
Проверка прокси. Приоритет — MTProto для РФ.
"""
import asyncio
import logging
import ipaddress
import socket
import hashlib
from urllib.parse import urlparse, parse_qs

import aiohttp
import aiohttp_socks
from aiogram import Bot

logger = logging.getLogger(__name__)

# ─── Глобальные ─────────────────────────────────────────────────────────
MAX_CHECK_TIMEOUT = 10
WEB_CHECK_TIMEOUT = 5
SOCKS5_CHECK_TIMEOUT = 8

_http_session: aiohttp.ClientSession | None = None
_geo_cache: dict[str, dict] = {}
_geo_semaphore = asyncio.Semaphore(5)

# ─── Логирование шумных библиотек ─────────────────────────────────────
logging.getLogger("telethon").setLevel(logging.CRITICAL)
logging.getLogger("telethon.network").setLevel(logging.CRITICAL)


def _get_http_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            timeout=aiohttp.ClientTimeout(total=5),
        )
    return _http_session


async def close_http_session():
    global _http_session
    if _http_session is not None and not _http_session.closed:
        await _http_session.close()
    _http_session = None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


async def _resolve(host: str) -> str | None:
    if _is_ip(host):
        return host
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception as e:
        logger.debug("resolve(%s) failed: %s", host, e)
    return None


def _stable_id(ip: str, port: int) -> int:
    digest = hashlib.md5(f"{ip}:{port}".encode()).hexdigest()
    return int(digest, 16) % 10_000_000


def _country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


async def geolocate(ip: str) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]
    async with _geo_semaphore:
        try:
            async with _get_http_session().get(
                f"https://ipinfo.io/{ip}/json",
                timeout=5,
            ) as resp:
                if resp.status != 200:
                    raise Exception("HTTP error")
                data = await resp.json()
            country = data.get("country", "Unknown")
            city = data.get("city", "Unknown")
            provider = data.get("org", "Unknown")
            flag = _country_flag(country)
            geo = {"flag": flag, "country": country, "city": city, "provider": provider}
            _geo_cache[ip] = geo
            return geo
        except Exception as e:
            logger.debug("geolocate(%s) failed: %s", ip, e)
            return {"flag": "🏳️", "country": "Unknown", "city": "Unknown", "provider": "Unknown"}


async def check_mtproto(raw: dict) -> dict | None:
    ip = raw["ip"]
    port = raw["port"]
    secret = raw["secret"]
    try:
        client = TelegramClient(
            StringSession(),
            API_ID,
            API_HASH,
            timeout=15,
            connection_retries=0,
            auto_reconnect=False,
        )
        await client.connect()
        proxy = await client.get_proxy(ip, port, secret=secret, timeout=MAX_CHECK_TIMEOUT)
        if proxy:
            await client.disconnect()
            return proxy
        await client.disconnect()
    except Exception as e:
        logger.debug("MTProto %s:%s failed: %s", ip, port, e)
    return None


async def check_socks5(raw: dict) -> dict | None:
    ip = raw["ip"]
    port = raw["port"]
    try:
        async with aiohttp_socks.ProxyConnector.from_url(
            f"socks5://{ip}:{port}",
            ssl=False,
            limit=1,
        ) as connector:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    TEST_URL_RU, timeout=SOCKS5_CHECK_TIMEOUT
                ) as resp:
                    if resp.status == 200:
                        return raw
    except Exception as e:
        logger.debug("SOCKS5 %s:%s failed: %s", ip, port, e)
    return None


async def check_web(raw: dict) -> dict | None:
    ip = raw["ip"]
    port = raw["port"]
    secret = raw["secret"]
    try:
        async with aiohttp.ClientSession() as session:
            url = f"http://{ip}:{port}"
            if port != 443:
                url = f"http://{ip}:{port}"
            async with session.get(
                url, timeout=WEB_CHECK_TIMEOUT, ssl=False
            ) as resp:
                if resp.status == 200:
                    return raw
    except Exception as e:
        logger.debug("WEB %s:%s failed: %s", ip, port, e)
    return None


# ─── Скоринг ───────────────────────────────────────────────────────────
def compute_score(proxy: dict) -> int:
    proto = proxy.get("protocol", "").upper()
    ping = proxy.get("ping", 0)
    base = {"MTPROTO": 10000, "WEB": 5000, "SOCKS5": 0}.get(proto, 0)
    return base - min(ping, 5000)


# ─── Проверка одного прокси ────────────────────────────────────────────
async def process_proxy(raw: dict) -> dict | None:
    proto = raw.get("protocol", "").upper()
    if proto == "MTPROTO":
        if not raw.get("secret", "").startswith("ee"):
            return None
        return await check_mtproto(raw)
    if proto == "WEB":
        if not raw.get("secret", "").startswith("dd"):
            return None
        return await check_web(raw)
    if proto == "SOCKS5":
        return await check_socks5(raw)
    return None
