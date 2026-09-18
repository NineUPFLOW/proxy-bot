"""
Проверка прокси с анализом probe_resistant.
Оптимизировано: быстрая probe-проверка, кэш с лимитом.
"""

import asyncio
import hashlib
import ipaddress
import logging
import os
import socket

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.help import GetConfigRequest
from telethon.network.connection import ConnectionTcpMTProxyRandomizedIntermediate

for name in (
    "telethon", "telethon.network", "telethon.client",
    "telethon.network.mtprotosender", "telethon.network.connection",
    "asyncio",
):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

# ─── Лимиты ────────────────────────────────────────────────────────────
MAX_PING_MS = 8000
MAX_PING_WEB_MS = 6000
CHECK_TIMEOUT = 8
WEB_CHECK_TIMEOUT = 10
PROBE_TIMEOUT = 5

MT_ATTEMPTS = 3
MT_REQUIRED = 2

# ─── Скоринг ───────────────────────────────────────────────────────────
def compute_score(proxy: dict) -> int:
    proto = proxy.get("protocol", "").upper()
    ping = proxy.get("ping", 0)
    probe = proxy.get("probe_resistant", False)
    secret = proxy.get("secret", "")

    base = 0
    if proto == "MTPROTO":
        base = 10000
        if secret.startswith("ee"):
            base += 3000
        if probe:
            base += 5000  # максимальный приоритет
    elif proto == "WEB":
        base = 5000

    return base - min(ping, 8000)


ALLOWED_COUNTRIES = {
    "RU", "BY", "KZ", "UA", "MD", "UZ", "KG", "TJ", "AM", "AZ", "GE",
    "DE", "NL", "FI", "SE", "NO", "DK", "EE", "LV", "LT", "IS",
    "PL", "CZ", "SK", "AT", "CH", "FR", "BE", "GB", "IE", "LU",
    "IT", "ES", "PT", "RO", "BG", "RS", "HU", "HR", "SI", "GR", "CY", "MT",
    "TR", "US", "CA", "JP", "KR", "SG", "HK",
}

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

TEST_URL_TG = "https://api.telegram.org"
TEST_URL_RU = "https://ya.ru"

_http_session: aiohttp.ClientSession | None = None
_geo_cache: dict[str, dict] = {}
_probe_cache: dict[str, bool] = {}
_geo_semaphore = asyncio.Semaphore(5)

PROBE_CACHE_LIMIT = 5000

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
                logger.debug("geolocate(%s) #%s: %s", ip, attempt + 1, e)
                await asyncio.sleep(1)
    return {}


# ═══════════════════════════════════════════════════════════════════════
#  PROBE RESISTANCE TEST
# ═══════════════════════════════════════════════════════════════════════

async def check_probe_resistant(domain: str) -> bool:
    """Проверяет, что домен-маска отдаёт реальный ответ (любой < 500)."""
    if not domain:
        return False
    if domain in _probe_cache:
        return _probe_cache[domain]

    session = _get_http_session()
    try:
        async with session.get(
            f"https://{domain}/",
            timeout=aiohttp.ClientTimeout(total=PROBE_TIMEOUT),
            allow_redirects=False,
            ssl=False,
        ) as r:
            is_real = r.status < 500
    except Exception as e:
        logger.debug("probe %s failed: %s", domain, e)
        is_real = False

    # Ограничиваем размер кэша
    if len(_probe_cache) >= PROBE_CACHE_LIMIT:
        _probe_cache.clear()

    _probe_cache[domain] = is_real
    return is_real


# ═══════════════════════════════════════════════════════════════════════
#  ENRICH
# ═══════════════════════════════════════════════════════════════════════

def _enrich(proxy: dict, ip: str, ping: int, geo: dict, probe_ok: bool) -> dict | None:
    country_code = geo.get("countryCode", "")
    if country_code and country_code not in ALLOWED_COUNTRIES:
        logger.debug("Отсев по стране: %s (%s)", ip, country_code)
        return None

    proxy.update({
        "ip": ip,
        "ping": ping,
        "id": _stable_id(ip, proxy["port"]),
        "country": geo.get("country", "Unknown"),
        "countryCode": country_code,
        "city": geo.get("city", "Unknown"),
        "provider": geo.get("isp", "Unknown"),
        "flag": _country_flag(country_code),
        "probe_resistant": probe_ok,
    })
    proxy["score"] = compute_score(proxy)
    return proxy


# ═══════════════════════════════════════════════════════════════════════
#  MTProto / WEB
# ═══════════════════════════════════════════════════════════════════════

async def _one_mtproto_attempt(ip: str, port: int, secret: str) -> int | None:
    client = None
    try:
        client = TelegramClient(
            StringSession(TG_SESSION),
            API_ID, API_HASH,
            connection=ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=(ip, port, secret),
            timeout=CHECK_TIMEOUT,
            connection_retries=0,
            retry_delay=0,
            auto_reconnect=False,
        )
        t0 = asyncio.get_running_loop().time()

        await asyncio.wait_for(client.connect(), timeout=CHECK_TIMEOUT)
        if not client.is_connected():
            return None

        await asyncio.wait_for(
            client(GetConfigRequest()), timeout=CHECK_TIMEOUT
        )
        return int((asyncio.get_running_loop().time() - t0) * 1000)
    except (asyncio.TimeoutError, asyncio.CancelledError, ConnectionError, OSError):
        return None
    except Exception as e:
        logger.debug("mtproto attempt %s:%s — %s", ip, port, e)
        return None
    finally:
        if client is not None:
            try:
                await asyncio.wait_for(client.disconnect(), timeout=2)
            except Exception:
                pass


async def check_mtproto(proxy: dict) -> dict | None:
    host = proxy["ip"]
    port = int(proxy["port"])
    secret = proxy["secret"]

    ip = await _resolve(host)
    if not ip:
        return None

    pings: list[int] = []
    for attempt in range(MT_ATTEMPTS):
        ping = await _one_mtproto_attempt(ip, port, secret)
        if ping is not None:
            pings.append(ping)
            if len(pings) >= MT_REQUIRED:
                break
        if attempt < MT_ATTEMPTS - 1:
            await asyncio.sleep(0.3)

    if len(pings) < MT_REQUIRED:
        return None

    avg_ping = sum(pings) // len(pings)

    is_web = proxy["protocol"].upper() == "WEB"
    limit = MAX_PING_WEB_MS if is_web else MAX_PING_MS
    if avg_ping > limit:
        return None

    # probe resistance — только для MTProto с доменом-маской
    probe_ok = False
    if not is_web and proxy.get("mask_domain"):
        probe_ok = await check_probe_resistant(proxy["mask_domain"])

    geo = await geolocate(ip)
    return _enrich(proxy, ip, avg_ping, geo, probe_ok)


# ═══════════════════════════════════════════════════════════════════════
#  SOCKS5
# ═══════════════════════════════════════════════════════════════════════

async def check_socks5(proxy: dict) -> dict | None:
    host = proxy["ip"]
    port = int(proxy["port"])

    ip = await _resolve(host)
    if not ip:
        return None

    connector = ProxyConnector(
        proxy_type=ProxyType.SOCKS5,
        host=ip,
        port=port,
        rdns=True,
    )
    try:
        t0 = asyncio.get_running_loop().time()
        async with aiohttp.ClientSession(
            connector=connector, connector_owner=False
        ) as session:
            try:
                async with session.get(
                    TEST_URL_TG,
                    timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                    allow_redirects=False,
                ) as r:
                    if r.status >= 500:
                        return None
            except Exception:
                return None

            try:
                async with session.get(
                    TEST_URL_RU,
                    timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                    allow_redirects=False,
                ) as r:
                    if r.status >= 500:
                        return None
            except Exception:
                return None

        ping = int((asyncio.get_running_loop().time() - t0) * 1000)
        if ping > MAX_PING_MS:
            return None

        geo = await geolocate(ip)
        return _enrich(proxy, ip, ping, geo, probe_ok=False)
    except Exception as e:
        logger.debug("socks5 %s:%s — %s", ip, port, e)
        return None
    finally:
        try:
            await connector.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════
#  ГЛАВНАЯ ФУНКЦИЯ
# ═══════════════════════════════════════════════════════════════════════

async def process_proxy(raw: dict) -> dict | None:
    proto = raw.get("protocol", "").upper()

    if proto == "MTPROTO":
        if not raw.get("secret"):
            return None
        return await check_mtproto(raw)

    if proto == "WEB":
        if not raw.get("secret", "").startswith("dd"):
            return None
        return await check_mtproto(raw)

    if proto == "SOCKS5":
        return await check_socks5(raw)

    return None
