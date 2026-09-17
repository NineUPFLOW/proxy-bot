import asyncio
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

logger = logging.getLogger(__name__)

MAX_PING_MS = 5000
CHECK_TIMEOUT = 8
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

TEST_URL = "https://api.ipify.org?format=json"


# ─── УТИЛИТЫ ────────────────────────────────────────────────────────────

def is_white_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split(":")[0])
        return not (addr.is_private or addr.is_loopback
                    or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


async def geolocate(ip: str) -> dict:
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"http://ip-api.com/json/{ip}"
                "?fields=status,country,countryCode,city,isp,query",
                timeout=aiohttp.ClientTimeout(total=8),
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    if data.get("status") == "success":
                        return data
        except Exception:
            pass
    return {}


def country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🏳️"
    return (chr(0x1F1E6 + ord(code[0].upper()) - 65)
            + chr(0x1F1E6 + ord(code[1].upper()) - 65))


# ─── ПРОВЕРКА MTProto / WEB (через Telethon) ────────────────────────────

async def check_telegram_proxy(host: str, port: int, secret: str):
    """
    Проверяет MTProto или WEB прокси через реальный handshake Telethon.
    Возвращает пинг в мс или None, если прокси не работает.
    """
    client = TelegramClient(
        StringSession(TG_SESSION) if TG_SESSION else None,
        API_ID, API_HASH,
        connection=ConnectionTcpMTProxyRandomizedIntermediate,
        proxy=(host, int(port), secret),
        timeout=CHECK_TIMEOUT,
        connection_retries=1,
    )
    try:
        t0 = asyncio.get_event_loop().time()
        await client.connect()
        if not client.is_connected():
            return None
        await client(GetConfigRequest())
        ping = int((asyncio.get_event_loop().time() - t0) * 1000)
        await client.disconnect()
        return ping if ping < MAX_PING_MS else None
    except Exception as e:
        logger.debug(f"Telethon proxy check failed {host}:{port}: {e}")
        try:
            await client.disconnect()
        except Exception:
            pass
        return None


# ─── ПРОВЕРКА SOCKS5 / HTTP ─────────────────────────────────────────────

async def check_socks5(host: str, port: int):
    """Проверяет SOCKS5-прокси реальным HTTP-запросом через него."""
    try:
        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5,
            host=host,
            port=int(port),
            rdns=True,
        )
        t0 = asyncio.get_event_loop().time()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                TEST_URL, timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT)
            ) as resp:
                if resp.status == 200:
                    ping = round((asyncio.get_event_loop().time() - t0) * 1000, 1)
                    return ping if ping < MAX_PING_MS else None
    except Exception as e:
        logger.debug(f"SOCKS5 check failed {host}:{port}: {e}")
    return None


async def check_http(host: str, port: int):
    """Проверяет HTTP-прокси реальным HTTP-запросом через него."""
    try:
        proxy_url = f"http://{host}:{port}"
        t0 = asyncio.get_event_loop().time()
        async with aiohttp.ClientSession() as session:
            async with session.get(
                TEST_URL,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
            ) as resp:
                if resp.status == 200:
                    ping = round((asyncio.get_event_loop().time() - t0) * 1000, 1)
                    return ping if ping < MAX_PING_MS else None
    except Exception as e:
        logger.debug(f"HTTP check failed {host}:{port}: {e}")
    return None


# ─── ГЛАВНАЯ ФУНКЦИЯ ───────────────────────────────────────────────────

async def process_proxy(raw: dict):
    """
    Полный цикл: реальная проверка -> геолокация -> белый IP.
    Возвращает обогащённый словарь или None, если прокси не работает.
    """
    proto = raw["protocol"].upper()
    ip = raw["ip"]
    port = raw["port"]

    # 1. Реальная проверка
    if proto in ("MTPROTO", "WEB"):
        ping = await check_telegram_proxy(ip, port, raw["secret"])
    elif proto == "SOCKS5":
        ping = await check_socks5(ip, port)
    elif proto == "HTTP":
        ping = await check_http(ip, port)
    else:
        return None

    if ping is None:
        return None

    # 2. Геолокация (для WEB — резолвим домен)
    lookup_ip = ip
    if proto == "WEB" and not is_white_ip(ip):
        try:
            lookup_ip = socket.gethostbyname(ip)
        except Exception:
            return None

    geo = await geolocate(lookup_ip)
    if not geo:
        return None

    # 3. Белый IP (для WEB всегда False)
    white = is_white_ip(lookup_ip) and proto != "WEB"

    raw.update({
        "ping": f"{ping} ms",
        "country": geo.get("country", "Unknown"),
        "countryCode": geo.get("countryCode", ""),
        "city": geo.get("city", "Unknown"),
        "provider": geo.get("isp", "Unknown"),
        "flag": country_flag(geo.get("countryCode", "")),
        "is_white": white,
        "id": abs(hash(f"{ip}:{port}")) % 10_000_000,
    })
    return raw
