"""Asynchronous proxy checks for MTProto, WEB Proxy and SOCKS5."""

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
except ImportError:
    ConnectionWebProxy = None

logger = logging.getLogger(__name__)

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]

CHECK_TIMEOUT = float(
    os.getenv("CHECK_TIMEOUT", "8")
)

WEB_CHECK_TIMEOUT = float(
    os.getenv("WEB_CHECK_TIMEOUT", "15")
)

SOCKS_CHECK_TIMEOUT = float(
    os.getenv("SOCKS_CHECK_TIMEOUT", "8")
)

MAX_PING_MS = int(
    os.getenv("MAX_PING_MS", "5000")
)

MAX_WEB_PING_MS = int(
    os.getenv("MAX_WEB_PING_MS", "10000")
)

MAX_GEO_CONCURRENCY = max(
    1,
    int(os.getenv("MAX_GEO_CONCURRENCY", "5")),
)

GEO_TIMEOUT = float(
    os.getenv("GEO_TIMEOUT", "5")
)

TEST_URL = os.getenv(
    "SOCKS_TEST_URL",
    "https://api.telegram.org",
)

HEADERS = {
    "User-Agent": "proxy-bot/4.0"
}

ALLOWED_COUNTRIES = {
    "RU",
    "BY",
    "KZ",
    "UA",
    "MD",
    "UZ",
    "KG",
    "TJ",
    "AM",
    "AZ",
    "GE",

    "DE",
    "NL",
    "FI",
    "SE",
    "NO",
    "DK",
    "EE",
    "LV",
    "LT",
    "IS",
    "PL",
    "CZ",
    "SK",
    "AT",
    "CH",
    "FR",
    "BE",
    "GB",
    "IE",
    "LU",
    "IT",
    "ES",
    "PT",
    "RO",
    "BG",
    "RS",
    "HU",
    "HR",
    "SI",
    "GR",
    "CY",
    "MT",
    "TR",

    "US",
    "CA",
    "JP",
    "KR",
    "SG",
    "HK",
}

_http_session: Optional[aiohttp.ClientSession] = None

_geo_cache: dict[str, dict] = {}

_geo_sem = asyncio.Semaphore(
    MAX_GEO_CONCURRENCY
)

def _session() -> aiohttp.ClientSession:
    global _http_session

    if (
        _http_session is None
        or _http_session.closed
    ):
        _http_session = aiohttp.ClientSession(
            headers=HEADERS
        )

    return _http_session

async def close_http_session() -> None:
    global _http_session

    if (
        _http_session is not None
        and not _http_session.closed
    ):
        await _http_session.close()

    _http_session = None

def _resolve_sync(
    host: str,
) -> str | None:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM,
        )

        return (
            infos[0][4][0]
            if infos
            else None
        )

    except OSError:
        return None

async def resolve(
    host: str,
) -> str | None:
    return await asyncio.to_thread(
        _resolve_sync,
        host,
    )

def _decode_secret(
    secret: str,
) -> bytes | None:
    value = str(secret or "").strip()

    if not value:
        return None

    low = value.lower()

    if (
        len(low) % 2 == 0
        and all(
            char in "0123456789abcdef"
            for char in low
        )
    ):
        try:
            raw = bytes.fromhex(low)

            if len(raw) >= 16:
                return raw

        except ValueError:
            pass

    try:
        raw = base64.urlsafe_b64decode(
            value
            + "=" * (-len(value) % 4)
        )

        if len(raw) >= 16:
            return raw

    except (
        ValueError,
        binascii.Error,
    ):
        pass

    return None

def normalize_mt_secret(
    secret: str,
) -> str | None:
    """
    Normalize a regular MTProto secret.

    FakeTLS secrets are intentionally excluded from
    this checker because their handling is different
    from the regular MTProto transport.
    """

    raw = _decode_secret(secret)

    if raw is None:
        return None

    if (
        raw.startswith(b"\xee")
        or str(secret)
        .strip()
        .lower()
        .startswith("ee")
    ):
        return None

    if raw.startswith(b"\xdd"):
        if len(raw) != 17:
            return None

        raw = raw[1:]

    if len(raw) != 16:
        return None

    return raw.hex()

def _flag(code: str) -> str:
    code = (code or "").upper()

    if (
        len(code) != 2
        or not code.isalpha()
        or not code.isascii()
    ):
        return "🏴"

    return (
        chr(127397 + ord(code[0]))
        + chr(127397 + ord(code[1]))
    )

async def geolocate(
    ip: str,
) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]

    async with _geo_sem:
        if ip in _geo_cache:
            return _geo_cache[ip]

        try:
            async with _session().get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": (
                        "status,"
                        "country,"
                        "countryCode,"
                        "city,"
                        "isp"
                    )
                },
                timeout=aiohttp.ClientTimeout(
                    total=GEO_TIMEOUT
                ),
            ) as response:

                if response.status != 200:
                    raise RuntimeError(
                        f"geo HTTP {response.status}"
                    )

                data = await response.json(
                    content_type=None
                )

                if data.get("status") == "success":
                    _geo_cache[ip] = data
                    return data

        except Exception:
            logger.debug(
                "Geolocation failed for %s",
                ip,
                exc_info=True,
            )

        _geo_cache[ip] = {}
        return {}

def compute_score(
    proxy: dict,
) -> int:
    proto = str(
        proxy.get("protocol", "")
    ).upper()

    ping = max(
        0,
        min(
            int(
                proxy.get(
                    "ping",
                    99999,
                )
            ),
            99999,
        ),
    )

    base_score = {
        "MTPROTO": 10000,
        "WEB": 7000,
        "SOCKS5": 5000,
    }.get(proto, 0)

    secret = str(
        proxy.get("secret", "")
    ).lower()

    if (
        proto == "MTPROTO"
        and secret.startswith("dd")
    ):
        base_score += 1500

    country = str(
        proxy.get(
            "countryCode",
            "",
        )
    ).upper()

    if country == "RU":
        base_score += 250

    return (
        base_score
        - min(ping, 10000)
    )

def enrich(
    proxy: dict,
    ip: str,
    ping: int,
    geo: dict,
) -> dict | None:

    country_code = str(
        geo.get(
            "countryCode",
            "",
        )
    ).upper()

    if (
        country_code
        and country_code not in ALLOWED_COUNTRIES
    ):
        return None

    result = dict(proxy)

    result.update(
        {
            "resolved_ip": ip,
            "ping": int(ping),
            "ping_ms": int(ping),

            "country": geo.get(
                "country",
                "Unknown",
            ),

            "countryCode": country_code,

            "city": geo.get(
                "city",
                "Unknown",
            ),

            "provider": geo.get(
                "isp",
                "Unknown",
            ),

            "flag": _flag(
                country_code
            ),

            "check_origin": "github-runner",
        }
    )

    raw_id = (
        f"{result.get('protocol')}"
        f"|{result.get('ip')}"
        f"|{result.get('port')}"
        f"|{result.get('secret', '')}"
    )

    result["id"] = hashlib.sha256(
        raw_id.encode("utf-8")
    ).hexdigest()[:12]

    result["score"] = compute_score(
        result
    )

    return result

async def _mt_attempt(
    host: str,
    port: int,
    secret: str,
) -> int | None:

    normalized = normalize_mt_secret(
        secret
    )

    if normalized is None:
        return None

    client = TelegramClient(
        StringSession(""),
        API_ID,
        API_HASH,
        connection=(
            connection
            .ConnectionTcpMTProxyRandomizedIntermediate
        ),
        proxy=(
            host,
            port,
            normalized,
        ),
        timeout=CHECK_TIMEOUT,
        connection_retries=0,
        retry_delay=0,
        auto_reconnect=False,
    )

    started = (
        asyncio
        .get_running_loop()
        .time()
    )

    try:
        await asyncio.wait_for(
            client.connect(),
            CHECK_TIMEOUT,
        )

        if not client.is_connected():
            return None

        await asyncio.wait_for(
            client(
                GetConfigRequest()
            ),
            CHECK_TIMEOUT,
        )

        elapsed = (
            asyncio
            .get_running_loop()
            .time()
            - started
        )

        return int(
            elapsed * 1000
        )

    except asyncio.CancelledError:
        raise

    except Exception:
        logger.debug(
            "MTProto check failed "
            "for %s:%s",
            host,
            port,
            exc_info=True,
        )
        return None

    finally:
        try:
            await asyncio.wait_for(
                client.disconnect(),
                2,
            )
        except Exception:
            pass

async def check_mtproto(
    proxy: dict,
) -> dict | None:

    host = str(
        proxy.get("ip", "")
    ).strip()

    try:
        port = int(
            proxy.get(
                "port",
                0,
            )
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    if (
        not host
        or not 1 <= port <= 65535
    ):
        return None

    ip = await resolve(host)

    if not ip:
        return None

    for attempt in range(2):

        ping = await _mt_attempt(
            ip,
            port,
            str(
                proxy.get(
                    "secret",
                    "",
                )
            ),
        )

        if ping is not None:

            if ping > MAX_PING_MS:
                return None

            geo = await geolocate(ip)

            return enrich(
                proxy,
                ip,
                ping,
                geo,
            )

        if attempt == 0:
            await asyncio.sleep(0.2)

    return None

async def check_web(
    proxy: dict,
) -> dict | None:

    if ConnectionWebProxy is None:
        logger.error(
            "telethon-webproxy is not installed"
        )
        return None

    host = str(
        proxy.get("ip", "")
    ).strip().lower()

    # ИСПРАВЛЕНО: используем _decode_secret вместо normalize_mt_secret,
    # чтобы разрешить FakeTLS (ee) секреты, и передаем оригинальный секрет в прокси.
    secret = str(proxy.get("secret", "")).strip()

    if not host or _decode_secret(secret) is None:
        return None

    client = TelegramClient(
        StringSession(""),
        API_ID,
        API_HASH,
        connection=ConnectionWebProxy,
        proxy=(
            host,
            secret,
            {
                "mode": os.getenv(
                    "WEB_PROXY_MODE",
                    "websocket-lanes",
                )
            },
        ),
        timeout=WEB_CHECK_TIMEOUT,
        connection_retries=0,
        retry_delay=0,
        auto_reconnect=False,
    )

    started = (
        asyncio
        .get_running_loop()
        .time()
    )

    try:
        await asyncio.wait_for(
            client.connect(),
            WEB_CHECK_TIMEOUT,
        )

        if not client.is_connected():
            return None

        await asyncio.wait_for(
            client(
                GetConfigRequest()
            ),
            WEB_CHECK_TIMEOUT,
        )

        ping = int(
            (
                asyncio
                .get_running_loop()
                .time()
                - started
            )
            * 1000
        )

        if ping > MAX_WEB_PING_MS:
            return None

        ip = await resolve(host)

        if not ip:
            return None

        geo = await geolocate(ip)

        return enrich(
            proxy,
            ip,
            ping,
            geo,
        )

    except asyncio.CancelledError:
        raise

    except Exception:
        logger.debug(
            "WEB proxy check failed "
            "for %s",
            host,
            exc_info=True,
        )
        return None

    finally:
        try:
            await asyncio.wait_for(
                client.disconnect(),
                3,
            )
        except Exception:
            pass

async def check_socks5(
    proxy: dict,
) -> dict | None:

    host = str(
        proxy.get("ip", "")
    ).strip()

    try:
        port = int(
            proxy.get(
                "port",
                0,
            )
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    if (
        not host
        or not 1 <= port <= 65535
    ):
        return None

    ip = await resolve(host)

    if not ip:
        return None

    connector = ProxyConnector(
        proxy_type=ProxyType.SOCKS5,
        host=host,
        port=port,
        rdns=True,
    )

    started = (
        asyncio
        .get_running_loop()
        .time()
    )

    try:
        timeout = aiohttp.ClientTimeout(
            total=SOCKS_CHECK_TIMEOUT
        )

        async with aiohttp.ClientSession(
            connector=connector,
            connector_owner=True,
            headers=HEADERS,
        ) as session:

            async with session.get(
                TEST_URL,
                timeout=timeout,
                allow_redirects=False,
            ) as response:

                await response.read(
                    64 * 1024
                )

                if response.status >= 500:
                    return None

        ping = int(
            (
                asyncio
                .get_running_loop()
                .time()
                - started
            )
            * 1000
        )

        if ping > MAX_PING_MS:
            return None

        geo = await geolocate(ip)

        return enrich(
            proxy,
            ip,
            ping,
            geo,
        )

    except asyncio.CancelledError:
        raise

    except Exception:
        logger.debug(
            "SOCKS5 check failed "
            "for %s:%s",
            host,
            port,
            exc_info=True,
        )
        return None

    finally:
        try:
            connector.close()
        except Exception:
            pass

async def process_proxy(
    proxy: dict,
) -> dict | None:

    proto = str(
        proxy.get(
            "protocol",
            "",
        )
    ).upper()

    if proto == "MTPROTO":
        return await check_mtproto(
            proxy
        )

    if proto == "WEB":
        return await check_web(
            proxy
        )

    if proto == "SOCKS5":
        return await check_socks5(
            proxy
        )

    return None
