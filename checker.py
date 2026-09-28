"""Async proxy checks for MTProto, Telegram WEB Proxy and SOCKS5."""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import ipaddress
import logging
import os
import socket
from typing import Optional

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType
from telethon import TelegramClient, connection
from telethon.sessions import StringSession
from telethon.tl.functions.help import GetConfigRequest

try:
    from telethon_webproxy import ConnectionWebProxy
except ImportError:  # pragma: no cover
    ConnectionWebProxy = None

# ─── Подавление шума от telethon при handshake ───
# "Unexpected exception in the receive loop" / readexactly errors
# появляются на каждой мёртвой MTProxy и не несут ценности.
for name in (
    "telethon",
    "telethon.network",
    "telethon.client",
    "telethon.network.mtprotosender",
    "telethon.network.connection",
):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
CHECK_TIMEOUT = float(os.getenv("CHECK_TIMEOUT", "8"))
WEB_CHECK_TIMEOUT = float(os.getenv("WEB_CHECK_TIMEOUT", "15"))
SOCKS_CHECK_TIMEOUT = float(os.getenv("SOCKS_CHECK_TIMEOUT", "10"))
MAX_PING_MS = int(os.getenv("MAX_PING_MS", "5000"))
MAX_WEB_PING_MS = int(os.getenv("MAX_WEB_PING_MS", "10000"))
MAX_GEO_CONCURRENCY = max(1, int(os.getenv("MAX_GEO_CONCURRENCY", "5")))
GEO_TIMEOUT = float(os.getenv("GEO_TIMEOUT", "5"))
TEST_URL = os.getenv("SOCKS_TEST_URL", "https://api.telegram.org")
HEADERS = {"User-Agent": "proxy-bot/2.1"}

ALLOWED_COUNTRIES = {
    "RU", "BY", "KZ", "UA", "MD", "UZ", "KG", "TJ", "AM", "AZ", "GE",
    "DE", "NL", "FI", "SE", "NO", "DK", "EE", "LV", "LT", "IS", "PL",
    "CZ", "SK", "AT", "CH", "FR", "BE", "GB", "IE", "LU", "IT", "ES",
    "PT", "RO", "BG", "RS", "HU", "HR", "SI", "GR", "CY", "MT", "TR",
    "US", "CA", "JP", "KR", "SG", "HK",
}

_http_session: Optional[aiohttp.ClientSession] = None
_geo_cache: dict[str, dict] = {}
_geo_sem = asyncio.Semaphore(MAX_GEO_CONCURRENCY)


def _session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(headers=HEADERS)
    return _http_session


async def close_http_session() -> None:
    global _http_session
    if _http_session is not None and not _http_session.closed:
        await _http_session.close()
    _http_session = None


def _resolve_sync(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    except OSError:
        return None


async def resolve(host: str) -> str | None:
    return await asyncio.to_thread(_resolve_sync, host)


def _decode_secret(secret: str) -> bytes | None:
    value = str(secret or "").strip()
    if not value:
        return None
    low = value.lower()
    try:
        if low.startswith(("dd", "ee")) and len(low) >= 34 and all(c in "0123456789abcdef" for c in low):
            raw = bytes.fromhex(low)
            return raw
        if len(low) % 2 == 0 and all(c in "0123456789abcdef" for c in low):
            return bytes.fromhex(low)
    except ValueError:
        pass
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        return None


def normalize_mt_secret(secret: str) -> str | None:
    """Return a secret accepted by Telethon's MTProxy connector.

    Standard secrets are 16 bytes. dd-secrets are 17 bytes and must retain the
    dd prefix when used with ConnectionTcpMTProxyRandomizedIntermediate.
    EE/Fake-TLS secrets are intentionally not checked by native Telethon.
    """
    raw = _decode_secret(secret)
    if raw is None:
        return None
    low = str(secret).strip().lower()
    if low.startswith("ee"):
        return None
    if raw.startswith(b"\xdd"):
        if len(raw) != 17:
            return None
        return raw.hex()
    if len(raw) != 16:
        return None
    return raw.hex()


def _flag(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🏴"
    return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))


async def geolocate(ip: str) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]
    async with _geo_sem:
        if ip in _geo_cache:
            return _geo_cache[ip]
        try:
            async with _session().get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,city,isp"},
                timeout=aiohttp.ClientTimeout(total=GEO_TIMEOUT),
            ) as response:
                data = await response.json(content_type=None)
                if data.get("status") == "success":
                    _geo_cache[ip] = data
                    return data
        except Exception:
            logger.debug("Geo lookup failed for %s", ip, exc_info=True)
        _geo_cache[ip] = {}
        return {}


def enrich(proxy: dict, ip: str, ping: int, geo: dict, probe: bool = False) -> dict | None:
    country_code = str(geo.get("countryCode", "")).upper()
    if country_code and country_code not in ALLOWED_COUNTRIES:
        return None
    result = dict(proxy)
    result.update({
        "ip": ip,
        "ping": int(ping),
        "country": geo.get("country", "Unknown"),
        "countryCode": country_code,
        "city": geo.get("city", "Unknown"),
        "provider": geo.get("isp", "Unknown"),
        "flag": _flag(country_code),
        "probe_resistant": bool(probe),
    })
    raw_id = f"{result.get('protocol')}|{ip}|{result.get('port')}|{result.get('secret', '')}"
    result["id"] = hashlib.sha256(raw_id.encode()).hexdigest()[:12]
    result["score"] = compute_score(result)
    return result


def compute_score(proxy: dict) -> int:
    proto = str(proxy.get("protocol", "")).upper()
    try:
        ping = max(0, int(proxy.get("ping", 99999)))
    except (TypeError, ValueError):
        ping = 99999
    score = {"MTPROTO": 10000, "WEB": 7000, "SOCKS5": 5000}.get(proto, 0)
    secret = str(proxy.get("secret", "")).lower()
    if proto == "MTPROTO" and secret.startswith("dd"):
        score += 1500
    if proxy.get("probe_resistant"):
        score += 2000
    return score - min(ping, 10000)


def _mt_connection(secret: str):
    normalized = normalize_mt_secret(secret)
    if normalized is None:
        return None, None
    if normalized.startswith("dd"):
        return connection.ConnectionTcpMTProxyRandomizedIntermediate, normalized
    return connection.ConnectionTcpMTProxyIntermediate, normalized


async def _mt_attempt(host: str, port: int, secret: str) -> int | None:
    conn_cls, normalized = _mt_connection(secret)
    if conn_cls is None:
        return None
    client = TelegramClient(
        StringSession(""), API_ID, API_HASH,
        connection=conn_cls,
        proxy=(host, port, normalized),
        timeout=CHECK_TIMEOUT,
        connection_retries=0,
        retry_delay=0,
        auto_reconnect=False,
    )
    started = asyncio.get_running_loop().time()
    try:
        await asyncio.wait_for(client.connect(), CHECK_TIMEOUT)
        if not client.is_connected():
            return None
        await asyncio.wait_for(client(GetConfigRequest()), CHECK_TIMEOUT)
        return int((asyncio.get_running_loop().time() - started) * 1000)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.debug("MTProto check failed for %s:%s (%s)", host, port, type(exc).__name__)
        return None
    finally:
        try:
            await asyncio.wait_for(client.disconnect(), 2)
        except Exception:
            pass


async def check_mtproto(proxy: dict) -> dict | None:
    host = str(proxy.get("ip", "")).strip()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        return None
    if not host or not 1 <= port <= 65535:
        return None
    ip = await resolve(host)
    if not ip:
        return None
    secret = str(proxy.get("secret", ""))
    if secret.lower().startswith("ee"):
        # Native Telethon 1.45 does not implement Fake-TLS/EE.
        return None
    for attempt in range(2):
        ping = await _mt_attempt(ip, port, secret)
        if ping is not None and ping <= MAX_PING_MS:
            geo = await geolocate(ip)
            return enrich(proxy, ip, ping, geo, secret.lower().startswith("dd"))
        if attempt == 0:
            await asyncio.sleep(0.2)
    return None


async def check_web(proxy: dict) -> dict | None:
    if ConnectionWebProxy is None:
        logger.error("telethon-webproxy is not installed")
        return None
    host = str(proxy.get("ip", "")).strip().lower()
    secret = str(proxy.get("secret", "")).strip()
    if not host or not secret:
        return None
    normalized = normalize_mt_secret(secret)
    if normalized is None:
        return None
    if not normalized.startswith("dd"):
        normalized = "dd" + normalized
    client = TelegramClient(
        StringSession(""), API_ID, API_HASH,
        connection=ConnectionWebProxy,
        proxy=(host, normalized, {"mode": os.getenv("WEB_PROXY_MODE", "websocket-lanes")}),
        timeout=WEB_CHECK_TIMEOUT,
        connection_retries=0,
        retry_delay=0,
        auto_reconnect=False,
    )
    started = asyncio.get_running_loop().time()
    try:
        await asyncio.wait_for(client.connect(), WEB_CHECK_TIMEOUT)
        if not client.is_connected():
            return None
        await asyncio.wait_for(client(GetConfigRequest()), WEB_CHECK_TIMEOUT)
        ping = int((asyncio.get_running_loop().time() - started) * 1000)
        if ping > MAX_WEB_PING_MS:
            return None
        ip = await resolve(host) or host
        geo = await geolocate(ip) if ip and _is_ip(ip) else {}
        return enrich(proxy, ip, ping, geo, False)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.debug("WEB proxy check failed for %s (%s)", host, type(exc).__name__)
        return None
    finally:
        try:
            await asyncio.wait_for(client.disconnect(), 3)
        except Exception:
            pass


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def check_socks5(proxy: dict) -> dict | None:
    host = str(proxy.get("ip", "")).strip()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        return None
    if not host or not 1 <= port <= 65535:
        return None
    ip = await resolve(host)
    if not ip:
        return None

    # ─── Аутентификация, если прокси её требует ───
    user = str(proxy.get("user", "") or "").strip() or None
    password = str(proxy.get("pass", "") or "").strip() or None

    # ─── Передаём уже разрезолвленный IP: многие публичные SOCKS5
    # не поддерживают remote DNS, и запрос с доменом отваливается.
    connector = ProxyConnector(
        proxy_type=ProxyType.SOCKS5,
        host=ip,
        port=port,
        username=user,
        password=password,
        rdns=False,
    )
    started = asyncio.get_running_loop().time()
    try:
        timeout = aiohttp.ClientTimeout(total=SOCKS_CHECK_TIMEOUT)
        async with aiohttp.ClientSession(
            connector=connector,
            connector_owner=True,
            headers=HEADERS,
        ) as session:
            async with session.get(TEST_URL, timeout=timeout, allow_redirects=False) as response:
                await response.read(64 * 1024)
                # 4xx тоже означает "прокси не пропускает трафик" — отсеиваем.
                if response.status >= 400:
                    return None
        ping = int((asyncio.get_running_loop().time() - started) * 1000)
        if ping > MAX_PING_MS:
            return None
        geo = await geolocate(ip)
        return enrich(proxy, ip, ping, geo, False)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.debug("SOCKS5 check failed for %s:%s (%s)", host, port, type(exc).__name__)
        return None
    finally:
        if not connector.closed:
            try:
                await connector.close()
            except Exception:
                pass


async def process_proxy(proxy: dict) -> dict | None:
    proto = str(proxy.get("protocol", "")).upper()
    if proto == "MTPROTO":
        return await check_mtproto(proxy)
    if proto == "WEB":
        return await check_web(proxy)
    if proto == "SOCKS5":
        return await check_socks5(proxy)
    return None
