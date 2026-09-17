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

# ─── ГЛУШИМ ЛОГИ TELETHON ──────────────────────────────────────────────
for name in ("telethon", "telethon.network", "telethon.client",
             "telethon.network.mtprotosender", "telethon.network.connection"):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

# ─── ЛИМИТЫ ────────────────────────────────────────────────────────────
MAX_PING_MS = 5000          # для MTProto и SOCKS5
MAX_PING_WEB_MS = 3000      # для WEB — строже
CHECK_TIMEOUT = 6
WEB_CHECK_TIMEOUT = 8

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

# URL для строгой проверки SOCKS5
TEST_URL_TG = "https://api.telegram.org"
TEST_URL_RU = "https://ya.ru"

# ─── КЭШ ГЕОЛОКАЦИИ (чтобы не долбить ip-api.com повторно) ─────────────
_geo_cache: dict = {}
_geo_lock = asyncio.Lock()


# ─── ГЛУШИМ ШУМНЫЕ ИСКЛЮЧЕНИЯ ASYNCIO ──────────────────────────────────
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


def make_id(ip: str, port) -> int:
    """
    Детерминированный ID прокси.
    ВАЖНО: встроенный hash() для строк рандомизируется PYTHONHASHSEED
    на каждый запуск процесса — одинаковый прокси получал бы разный id
    от запуска к запуску. Используем md5, чтобы id был стабилен.
    """
    digest = hashlib.md5(f"{ip}:{port}".encode()).hexdigest()
    return int(digest, 16) % 10_000_000


async def geolocate(ip: str) -> dict:
    """Геолокация через ip-api.com с кэшем и retry при 429 (rate limit)."""
    async with _geo_lock:
        cached = _geo_cache.get(ip)
    if cached is not None:
        return cached

    result = {}
    async with aiohttp.ClientSession() as s:
        for attempt in range(3):
            try:
                async with s.get(
                    f"http://ip-api.com/json/{ip}"
                    "?fields=status,country,countryCode,city,isp,query",
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as r:
                    if r.status == 429:
                        # уперлись в лимит free-плана — подождём и повторим
                        await asyncio.sleep(1.5 * (attempt + 1))
                        continue
                    if r.status == 200:
                        data = await r.json()
                        if data.get("status") == "success":
                            result = data
                    break
            except Exception as e:
                logger.debug(f"geolocate error {ip}: {e}")
                break

    async with _geo_lock:
        _geo_cache[ip] = result
    return result


def country_flag(code: str) -> str:
    """'DE' -> '🇩🇪'"""
    if not code or len(code) != 2:
        return "🏳️"
    return (chr(0x1F1E6 + ord(code[0].upper()) - 65)
            + chr(0x1F1E6 + ord(code[1].upper()) - 65))


# ─── MTProto / WEB (через Telethon) ────────────────────────────────────
async def _one_mtproto_handshake(host, port, secret, timeout):
    """Одна попытка handshake. Возвращает пинг в мс или None."""
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
        t0 = asyncio.get_running_loop().time()
        await asyncio.wait_for(client.connect(), timeout=timeout)
        if not client.is_connected():
            return None
        await asyncio.wait_for(client(GetConfigRequest()), timeout=timeout)
        ping = int((asyncio.get_running_loop().time() - t0) * 1000)
        try:
            await asyncio.wait_for(client.disconnect(), timeout=3)
        except Exception:
            pass
        return ping
    except (asyncio.TimeoutError, asyncio.CancelledError):
        return None
    except Exception as e:
        logger.debug(f"mtproto handshake {host}:{port} failed: {e}")
        return None
    finally:
        if client:
            try:
                await asyncio.wait_for(client.disconnect(), timeout=2)
            except Exception:
                pass


async def check_telegram_proxy(host: str, port: int, secret: str, is_web: bool = False):
    """
    Проверка MTProto/WEB через реальный handshake Telethon.
    Для MTProto — 3 последовательные попытки. Если хотя бы одна провалилась,
    прокси считается нестабильным и отсеивается.
    Для WEB — 2 попытки (WEB и так нестабильны, слишком строго не нужно).
    """
    timeout = WEB_CHECK_TIMEOUT if is_web else CHECK_TIMEOUT
    attempts = 2 if is_web else 3
    pings = []
    for i in range(attempts):
        ping = await _one_mtproto_handshake(host, port, secret, timeout)
        if ping is None:
            return None
        pings.append(ping)
        if i < attempts - 1:
            await asyncio.sleep(0.5)

    avg_ping = sum(pings) / len(pings)
    limit = MAX_PING_WEB_MS if is_web else MAX_PING_MS
    return int(avg_ping) if avg_ping < limit else None


# ─── SOCKS5 (СТРОГАЯ ПРОВЕРКА: Telegram + ya.ru) ───────────────────────
async def check_socks5(host: str, port: int):
    """
    Строгая проверка SOCKS5:
    - обязательный доступ к api.telegram.org
    - обязательный доступ к ya.ru
    Публикуем только если пройдены ОБА теста.

    ВАЖНО: оба запроса выполняются через ОДНУ и ту же ClientSession.
    Раньше на каждый запрос создавалась новая ClientSession с тем же
    connector — а connector_owner=True по умолчанию закрывает connector
    при выходе из первой сессии, из-за чего второй запрос падал с
    "Connector is closed" и check_socks5 ВСЕГДА возвращал None.
    """
    connector = ProxyConnector(
        proxy_type=ProxyType.SOCKS5,
        host=host, port=int(port), rdns=True,
    )
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            t0 = asyncio.get_running_loop().time()

            try:
                async with session.get(
                    TEST_URL_TG,
                    timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                    allow_redirects=False,
                ) as resp:
                    tg_status = resp.status
            except Exception:
                tg_status = None
            if tg_status is None or tg_status >= 500:
                return None

            try:
                async with session.get(
                    TEST_URL_RU,
                    timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                    allow_redirects=False,
                ) as resp:
                    ru_status = resp.status
            except Exception:
                ru_status = None
            if ru_status is None or ru_status >= 500:
                return None

            ping = round((asyncio.get_running_loop().time() - t0) * 1000, 1)
            return ping if ping < MAX_PING_MS else None
    except Exception as e:
        logger.debug(f"socks5 check {host}:{port} failed: {e}")
        return None


# ─── ГЛАВНАЯ ФУНКЦИЯ ───────────────────────────────────────────────────
async def process_proxy(raw: dict):
    """
    Полный цикл проверки одного прокси:
    1) Проверка работоспособности (по протоколу)
    2) Геолокация
    3) Обогащение данными (ping, страна, город, провайдер)
    Возвращает обогащённый словарь или None, если прокси не работает.
    """
    proto = raw["protocol"].upper()
    ip = raw["ip"]
    port = raw["port"]

    # ─── 1. Проверка по протоколу ───
    if proto == "MTPROTO":
        if not raw.get("secret", "").startswith("ee"):
            return None
        ping = await check_telegram_proxy(ip, port, raw["secret"], is_web=False)
    elif proto == "WEB":
        ping = await check_telegram_proxy(ip, port, raw["secret"], is_web=True)
    elif proto == "SOCKS5":
        ping = await check_socks5(ip, port)
    else:
        return None

    if ping is None:
        return None

    # ─── 2. Резолв домена для WEB ───
    lookup_ip = ip
    if proto == "WEB" and not _is_ip(ip):
        try:
            lookup_ip = socket.gethostbyname(ip)
        except Exception:
            return None

    # ─── 3. Геолокация ───
    geo = await geolocate(lookup_ip)
    if not geo:
        return None

    # ─── 4. Обогащение данными ───
    raw.update({
        "ping": f"{ping} ms",
        "country": geo.get("country", "Unknown"),
        "countryCode": geo.get("countryCode", ""),
        "city": geo.get("city", "Unknown"),
        "provider": geo.get("isp", "Unknown"),
        "flag": country_flag(geo.get("countryCode", "")),
        "id": make_id(ip, port),
    })
    return raw
