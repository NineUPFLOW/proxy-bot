"""
Проверка прокси.
- MTProto/WEB: handshake через Telethon (MT_ATTEMPTS попыток, нужно MT_REQUIRED)
- SOCKS5: только api.telegram.org (без ya.ru — для Telegram он избыточен)
- Probe Resistance Test для MTProto с маской домена
"""
import asyncio
import base64
import binascii
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

# ─── Уровень логирования через env ─────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

for name in (
    "telethon",
    "telethon.network",
    "telethon.client",
    "telethon.network.mtprotosender",
    "telethon.network.connection",
    "asyncio",
):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

# ─── Лимиты ────────────────────────────────────────────────────────────
MAX_PING_MS = 5000
MAX_PING_WEB_MS = 4000
CHECK_TIMEOUT = 8
WEB_CHECK_TIMEOUT = 10
PROBE_TIMEOUT = 5
MT_ATTEMPTS = 3
MT_REQUIRED = 1


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
            base += 5000
    elif proto == "WEB":
        base = 5000
    return base - min(ping, 5000)


ALLOWED_COUNTRIES = {
    "RU", "BY", "KZ", "UA", "MD", "UZ", "KG", "TJ", "AM", "AZ", "GE",
    "DE", "NL", "FI", "SE", "NO", "DK", "EE", "LV", "LT", "IS", "PL",
    "CZ", "SK", "AT", "CH", "FR", "BE", "GB", "IE", "LU", "IT", "ES",
    "PT", "RO", "BG", "RS", "HU", "HR", "SI", "GR", "CY", "MT", "TR",
    "US", "CA", "JP", "KR", "SG", "HK",
}

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

TEST_URL_TG = "https://api.telegram.org"

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
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        if not infos:
            return None
        return infos[0][4][0]
    except Exception:
        return None


def _stable_id(ip: str, port: int) -> str:
    raw = f"{ip}:{port}".encode()
    return hashlib.sha256(raw).hexdigest()[:12]


def _country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🏴"
    return chr(0x1F1E6 + ord(code[0]) - 65) + chr(0x1F1E6 + ord(code[1]) - 65)


async def geolocate(ip: str) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]
    async with _geo_semaphore:
        if ip in _geo_cache:
            return _geo_cache[ip]
        try:
            session = _get_http_session()
            async with session.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,city,isp"},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as r:
                data = await r.json()
                if data.get("status") == "success":
                    _geo_cache[ip] = data
                    return data
        except Exception:
            pass
    _geo_cache[ip] = {}
    return {}


async def check_probe_resistant(domain: str) -> bool:
    if domain in _probe_cache:
        return _probe_cache[domain]
    if len(_probe_cache) > PROBE_CACHE_LIMIT:
        _probe_cache.clear()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443), timeout=PROBE_TIMEOUT
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        _probe_cache[domain] = True
        return True
    except Exception:
        _probe_cache[domain] = False
        return False


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
# MTProto / WEB
# ═══════════════════════════════════════════════════════════════════════

_HEX = set("0123456789abcdef")


def _decode_secret(s: str) -> bytes | None:
    """
    Декодирует секрет MTProxy из hex или base64url.
    Возвращает bytes длиной 16 или 17 (с dd/ee-префиксом) или None.
    """
    if not s:
        return None
    s = s.strip()

    # 1) hex
    s_low = s.lower()
    if s_low and all(c in _HEX for c in s_low) and len(s_low) % 2 == 0:
        try:
            b = bytes.fromhex(s_low)
            if len(b) in (16, 17):
                return b
        except ValueError:
            pass

    # 2) base64url (с добавлением паддинга)
    try:
        pad = (-len(s)) % 4
        b = base64.urlsafe_b64decode(s + "=" * pad)
        if len(b) in (16, 17):
            return b
    except (binascii.Error, ValueError):
        pass

    return None


def _normalize_secret(secret: str) -> str | None:
    """
    Приводит секрет к 32-символьному hex, который точно примет Telethon.

    - 16-byte hex/base64           → 32 hex
    - dd + 16-byte hex/base64      → 32 hex (dd отрезается)
    - ee + 16-byte + domain (FakeTLS) → None (Telethon 1.36 не умеет)
    - всё остальное                → None
    """
    b = _decode_secret(secret)
    if b is None:
        return None
    if len(b) == 17:
        if b[0] == 0xdd:
            b = b[1:]
        else:
            return None
    return b.hex()


async def _one_mtproto_attempt(ip: str, port: int, secret: str, is_web: bool = False) -> int | None:
    client = None
    timeout = WEB_CHECK_TIMEOUT if is_web else CHECK_TIMEOUT
    raw_secret = _normalize_secret(secret)
    if not raw_secret:
        # DEBUG: подробности по каждому отсеянному прокси
        logger.debug(
            "mtproto skip %s:%s — invalid secret %r",
            ip, port, (secret[:10] + "…") if secret else "",
        )
        return None
    try:
        client = TelegramClient(
            StringSession(TG_SESSION), API_ID, API_HASH,
            connection=ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=(ip, port, raw_secret),
            timeout=timeout,
            connection_retries=0,
            retry_delay=0,
            auto_reconnect=False,
        )
        t0 = asyncio.get_running_loop().time()
        await asyncio.wait_for(client.connect(), timeout=timeout)
        if not client.is_connected():
            return None
        await asyncio.wait_for(client(GetConfigRequest()), timeout=timeout)
        return int((asyncio.get_running_loop().time() - t0) * 1000)
    except asyncio.CancelledError:
        raise
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return None
    except Exception as e:
        # DEBUG: технические детали падений handshake
        logger.debug("mtproto attempt %s:%s — %s: %s", ip, port, type(e).__name__, e)
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
    is_web = proxy["protocol"].upper() == "WEB"
    ip = await _resolve(host)
    if not ip:
        return None
    pings: list[int] = []
    for attempt in range(MT_ATTEMPTS):
        ping = await _one_mtproto_attempt(ip, port, secret, is_web=is_web)
        if ping is not None:
            pings.append(ping)
            if len(pings) >= MT_REQUIRED:
                break
        if attempt < MT_ATTEMPTS - 1:
            await asyncio.sleep(0.3)
    if len(pings) < MT_REQUIRED:
        return None
    avg_ping = sum(pings) // len(pings)
    limit = MAX_PING_WEB_MS if is_web else MAX_PING_MS
    if avg_ping > limit:
        return None
    probe_ok = False
    if not is_web and proxy.get("mask_domain"):
        probe_ok = await check_probe_resistant(proxy["mask_domain"])
    geo = await geolocate(ip)
    return _enrich(proxy, ip, avg_ping, geo, probe_ok)


# ═══════════════════════════════════════════════════════════════════════
# SOCKS5 (только Telegram)
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
        ping = int((asyncio.get_running_loop().time() - t0) * 1000)
        if ping > MAX_PING_MS:
            return None
        geo = await geolocate(ip)
        return _enrich(proxy, ip, ping, geo, probe_ok=False)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.debug("socks5 %s:%s — %s", ip, port, e)
        return None
    finally:
        try:
            await connector.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════
# ГЛАВНАЯ ФУНКЦИЯ
# ═══════════════════════════════════════════════════════════════════════

async def process_proxy(raw: dict) -> dict | None:
    proto = raw.get("protocol", "").upper()
    if proto == "MTPROTO":
        if not raw.get("secret"):
            return None
        return await check_mtproto(raw)
    if proto == "WEB":
        if not raw.get("secret"):
            return None
        return await check_mtproto(raw)
    if proto == "SOCKS5":
        return await check_socks5(raw)
    return None
