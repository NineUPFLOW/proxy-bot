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

# ─── ГЛУШИМ ЛОГИ TELETHON ──────────────────────────────────────────────
for name in ("telethon", "telethon.network", "telethon.client",
             "telethon.network.mtprotosender", "telethon.network.connection"):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

MAX_PING_MS = 5000
CHECK_TIMEOUT = 5
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

TEST_URL = "https://api.ipify.org?format=json"


# ─── ГЛУШИМ ШУМНЫЕ ИСКЛЮЧЕНИЯ ASYNCIO ОТ TELETHON ──────────────────────

def _silence_telethon_futures(loop, context):
    """Игнорирует 'Future exception was never retrieved' от Telethon."""
    msg = context.get("message", "")
    if "Future exception was never retrieved" in msg:
        return
    loop.default_exception_handler(context)


# ─── УТИЛИТЫ ───────────────────────────────────────────────────────────

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


# ─── ПРОВЕРКА MTProto / WEB ────────────────────────────────────────────

async def check_telegram_proxy(host: str, port: int, secret: str):
    """Проверяет MTProto/WEB прокси через реальный handshake Telethon."""
    # Глушим шумные исключения Telethon
    try:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(_silence_telethon_futures)
    except RuntimeError:
        pass

    client = None
    try:
        client = TelegramClient(
            StringSession(TG_SESSION) if TG_SESSION else None,
            API_ID, API_HASH,
            connection=ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=(host, int(port), secret),
            timeout=CHECK_TIMEOUT,
            connection_retries=0,
            retry_delay=0,
            auto_reconnect=False,
            request_retries=1,
        )
        t0 = asyncio.get_event_loop().time()

        await asyncio.wait_for(client.connect(), timeout=CHECK_TIMEOUT)
        if not client.is_connected():
            return None

        await asyncio.wait_for(client(GetConfigRequest()), timeout=CHECK_TIMEOUT)
        ping = int((asyncio.get_event_loop().time() - t0) * 1000)

        try:
            await asyncio.wait_for(client.disconnect(), timeout=3)
        except Exception:
            pass

        return ping if ping < MAX_PING_MS else None

    except (asyncio.TimeoutError, asyncio.CancelledError):
        pass
    except Exception:
        pass
    finally:
        if client:
            try:
                await asyncio.wait_for(client.disconnect(), timeout=2)
            except Exception:
                pass
    return None


# ─── ПРОВЕРКА SOCKS5 / HTTP ────────────────────────────────────────────

async def check_socks5(host: str, port: int):
    try:
        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5,
            host=host, port=int(port), rdns=True,
        )
        t0 = asyncio.get_event_loop().time()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                TEST_URL, timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT)
            ) as resp:
                if resp.status == 200:
                    ping = round((asyncio.get_event_loop().time() - t0) * 1000, 1)
                    return ping if ping < MAX_PING_MS else None
    except Exception:
        pass
    return None


async def check_http(host: str, port: int):
    try:
        proxy_url = f"http://{host}:{port}"
        t0 = asyncio.get_event_loop().time()
        async with aiohttp.ClientSession() as session:
            async with session.get(
                TEST_URL, proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
            ) as resp:
                if resp.status == 200:
                    ping = round((asyncio.get_event_loop().time() - t0) * 1000, 1)
                    return ping if ping < MAX_PING_MS else None
    except Exception:
        pass
    return None


# ─── ГЛАВНАЯ ФУНКЦИЯ ───────────────────────────────────────────────────

async def process_proxy(raw: dict):
    proto = raw["protocol"].upper()
    ip = raw["ip"]
    port = raw["port"]

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

    lookup_ip = ip
    if proto == "WEB" and not is_white_ip(ip):
        try:
            lookup_ip = socket.gethostbyname(ip)
        except Exception:
            return None

    geo = await geolocate(lookup_ip)
    if not geo:
        return None

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
