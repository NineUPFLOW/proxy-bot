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

for name in ("telethon", "telethon.network", "telethon.client",
             "telethon.network.mtprotosender", "telethon.network.connection"):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

# Разные лимиты пинга для разных протоколов
MAX_PING_MS = 5000          # для MTProto и SOCKS5
MAX_PING_WEB_MS = 2000      # для WEB — строже
CHECK_TIMEOUT = 6
WEB_CHECK_TIMEOUT = 8
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

# URL для проверки SOCKS5
TEST_URL_TG = "https://api.telegram.org"
TEST_URL_RU = "https://ya.ru"


# ─── ГЛУШИМ ШУМНЫЕ ИСКЛЮЧЕНИЯ ──────────────────────────────────────────

def _silence_telethon_futures(loop, context):
    msg = context.get("message", "")
    if "Future exception was never retrieved" in msg:
        return
    loop.default_exception_handler(context)


# ─── УТИЛИТЫ ───────────────────────────────────────────────────────────

def _is_ip(s: str) -> bool:
    """Проверяет, является ли строка IP-адресом (IPv4 или IPv6)."""
    try:
        ipaddress.ip_address(s)
        return True
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


# ─── MTProto / WEB ─────────────────────────────────────────────────────

async def _one_mtproto_handshake(host, port, secret, timeout):
    """Одна попытка подключения. Возвращает пинг в мс или None."""
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
            timeout=timeout,
            connection_retries=0,
            retry_delay=0,
            auto_reconnect=False,
            request_retries=1,
        )
        t0 = asyncio.get_event_loop().time()
        await asyncio.wait_for(client.connect(), timeout=timeout)
        if not client.is_connected():
            return None
        await asyncio.wait_for(client(GetConfigRequest()), timeout=timeout)
        ping = int((asyncio.get_event_loop().time() - t0) * 1000)
        try:
            await asyncio.wait_for(client.disconnect(), timeout=3)
        except Exception:
            pass
        return ping
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


async def check_telegram_proxy(host: str, port: int, secret: str, is_web: bool = False):
    """
    Проверка MTProto/WEB.
    Для WEB — двойная проверка (handshake дважды с паузой).
    """
    timeout = WEB_CHECK_TIMEOUT if is_web else CHECK_TIMEOUT

    ping1 = await _one_mtproto_handshake(host, port, secret, timeout)
    if ping1 is None:
        return None

    if not is_web:
        return ping1 if ping1 < MAX_PING_MS else None

    # WEB: двойная проверка
    await asyncio.sleep(1)
    ping2 = await _one_mtproto_handshake(host, port, secret, timeout)
    if ping2 is None:
        return None

    avg_ping = (ping1 + ping2) / 2
    if avg_ping > MAX_PING_WEB_MS:
        return None

    return int(avg_ping)


# ─── SOCKS5 (двойная проверка: Telegram + ya.ru) ──────────────────────

async def _socks5_get(connector, url: str, timeout: float):
    """Один GET-запрос через SOCKS5. Возвращает статус или None."""
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as resp:
                return resp.status
    except Exception:
        return None


async def check_socks5(host: str, port: int):
    """
    Проверяет SOCKS5 по двум URL:
      - api.telegram.org — реальная доступность Telegram
      - ya.ru — косвенная проверка, что не заблокирован в РФ
    Публикуем только если прошли ОБА теста.
    Возвращает пинг или None.
    """
    try:
        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5,
            host=host, port=int(port), rdns=True,
        )
        t0 = asyncio.get_event_loop().time()

        # 1. Telegram
        tg_status = await _socks5_get(connector, TEST_URL_TG, CHECK_TIMEOUT)
        if tg_status is None or tg_status >= 500:
            return None

        # 2. ya.ru
        ru_status = await _socks5_get(connector, TEST_URL_RU, CHECK_TIMEOUT)
        if ru_status is None or ru_status >= 500:
            return None

        ping = round((asyncio.get_event_loop().time() - t0) * 1000, 1)
        return ping if ping < MAX_PING_MS else None
    except Exception:
        return None


# ─── ГЛАВНАЯ ФУНКЦИЯ ───────────────────────────────────────────────────

async def process_proxy(raw: dict):
    proto = raw["protocol"].upper()
    ip = raw["ip"]
    port = raw["port"]

    if proto == "MTPROTO":
        ping = await check_telegram_proxy(ip, port, raw["secret"], is_web=False)
    elif proto == "WEB":
        ping = await check_telegram_proxy(ip, port, raw["secret"], is_web=True)
    elif proto == "SOCKS5":
        ping = await check_socks5(ip, port)
    else:
        return None

    if ping is None:
        return None

    lookup_ip = ip
    if proto == "WEB" and not _is_ip(ip):
        try:
            lookup_ip = socket.gethostbyname(ip)
        except Exception:
            return None

    geo = await geolocate(lookup_ip)
    if not geo:
        return None

    raw.update({
        "ping": f"{ping} ms",
        "country": geo.get("country", "Unknown"),
        "countryCode": geo.get("countryCode", ""),
        "city": geo.get("city", "Unknown"),
        "provider": geo.get("isp", "Unknown"),
        "flag": country_flag(geo.get("countryCode", "")),
        "id": abs(hash(f"{ip}:{port}")) % 10_000_000,
    })
    return raw
