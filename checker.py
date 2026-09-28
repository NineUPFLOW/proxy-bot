«Проверка асинхронных прокси для MTProto, Telegram WEB Proxy и SOCKS5».
from __future__ import annotations

import asyncio
импорт base64
импорт binascii
импорт hashlib
импорт IP-адреса
импорт логирования
импорт os
импорт сокета
из набора текста импорт Необязательный

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType
from telethon import TelegramClient, connection
from telethon.sessions import StringSession
from telethon.tl.functions.help import GetConfigRequest

пытаться:
    from telethon_webproxy import ConnectionWebProxy
except ImportError: # pragma: no cover - dependency is pinned
    ConnectionWebProxy = None

logger = logging.getLogger(__name__)
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION", "")

CHECK_TIMEOUT = float(os.getenv("CHECK_TIMEOUT", "8"))
WEB_CHECK_TIMEOUT = float(os.getenv("WEB_CHECK_TIMEOUT", "15"))
SOCKS_CHECK_TIMEOUT = float(os.getenv("SOCKS_CHECK_TIMEOUT", "8"))
MAX_PING_MS = int(os.getenv("MAX_PING_MS", "5000"))
MAX_WEB_PING_MS = int(os.getenv("MAX_WEB_PING_MS", "10000"))
MAX_GEO_CONCURRENCY = int(os.getenv("MAX_GEO_CONCURRENCY", "5"))

TEST_URL = os.getenv("SOCKS_TEST_URL", "https://api.telegram.org")
HEADERS = {"User-Agent": "proxy-bot/2.0"}

ALLOWED_COUNTRIES = {
    "RU", "BY", "KZ", "UA", "MD", "UZ", "KG", "TJ", "AM", "AZ", "GE",
    "DE", "NL", "FI", "SE", "NO", "DK", "EE", "LV", "LT", "IS", "PL",
    "CZ", "SK", "AT", "CH", "FR", "BE", "GB", "IE", "LU", "IT", "ES",
    «PT», «RO», «BG», «RS», «HU», «HR», «SI», «GR», «CY», «MT», «TR»,
    "США", "Канада", "Япония", "Корея", "Сингапур", "Гонконг",
}

_http_session: Optional[aiohttp.ClientSession] = None
_geo_cache: dict[str, dict] = {}
_geo_sem = asyncio.Semaphore(MAX_GEO_CONCURRENCY)


def _session() -> aiohttp.ClientSession:
    глобальная _http_сессия
    если _http_session равно None или _http_session.closed:
        _http_session = aiohttp.ClientSession(headers=HEADERS)
    return _http_session


async def close_http_session() -> None:
    глобальная _http_сессия
    если _http_session не равен None и не равен _http_session.closed:
        await _http_session.close()
    _http_session = None


def _resolve_sync(host: str) -> str | None:
    пытаться:
        ipaddress.ip_address(host)
        возврат хоста
    except ValueError:
        проходить
    пытаться:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    за исключением OSError:
        вернуть None


async def resolve(host: str) -> str | None:
    return asyncio.to_thread(_resolve_sync, host)


def _decode_secret(secret: str) -> bytes | None:
    s = str(secret or "").strip()
    если не s:
        вернуть None
    низкий = s.lower()
    if len(low) % 2 == 0 and all(c in "0123456789abcdef" for c in low):
        пытаться:
            raw = bytes.fromhex(low)
            return raw if len(raw) in (16, 17) or len(raw) >= 18 else None
        except ValueError:
            проходить
    пытаться:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        return raw if len(raw) in (16, 17) else None
    кроме (ValueError, binascii.Error):
        вернуть None


def normalize_mt_secret(secret: str) -> str | None:
    """Возвращает канонический 16-байтовый секрет в шестнадцатеричном формате. FakeTLS (ee) отклоняется."""
    raw = _decode_secret(secret)
    если raw равно None:
        вернуть None
    if raw.startswith(b"\xee") or str(secret).lower().startswith("ee"):
        вернуть None
    if raw.startswith(b"\xdd"):
        если len(raw) != 17:
            вернуть None
        raw = raw[1:]
    если len(raw) != 16:
        вернуть None
    return raw.hex()


def _flag(code: str) -> str:
    код = (код или "").upper()
    if len(code) != 2 or not code.isalpha():
        вернуть "🏴"
    return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))


async def geolocate(ip: str) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]
    асинхронно с _geo_sem:
        if ip in _geo_cache:
            return _geo_cache[ip]
        пытаться:
            async with _session().get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,city,isp"},
                timeout=aiohttp.ClientTimeout(total=4),
            ) в ответ:
                data = await response.json(content_type=None)
                if data.get("status") == "success":
                    _geo_cache[ip] = data
                    возвращаемые данные
        за исключением исключения:
            logger.debug("Ошибка поиска местоположения для %s", ip, exc_info=True)
        _geo_cache[ip] = {}
        возвращаться {}


def enrich(proxy: dict, ip: str, ping: int, geo: dict, probe: bool = False) -> dict | None:
    country_code = str(geo.get("countryCode", "")).upper()
    если country_code и country_code не входят в ALLOWED_COUNTRIES:
        вернуть None
    результат = dict(proxy)
    результат.обновление({
        "ip": ip,
        "ping": int(ping),
        "страна": geo.get("страна", "Неизвестно"),
        "countryCode": country_code,
        "city": geo.get("city", "Unknown"),
        "provider": geo.get("isp", "Unknown"),
        "флаг": _флаг(код_страны),
        "probe_resistant": bool(probe),
    })
    raw_id = f"{result.get('protocol')}|{ip}|{result.get('port')}|{result.get('secret', '')}"
    result["id"] = hashlib.sha256(raw_id.encode()).hexdigest()[:12]
    result["score"] = compute_score(result)
    вернуть результат


def compute_score(proxy: dict) -> int:
    proto = str(proxy.get("protocol", "")).upper()
    ping = max(0, min(int(proxy.get("ping", 99999)), 99999))
    score = {"MTPROTO": 10000, "WEB": 7000, "SOCKS5": 5000}.get(proto, 0)
    secret = str(proxy.get("secret", "")).lower()
    if proto == "MTPROTO" and secret.startswith("dd"):
        оценка += 1500
    if proxy.get("probe_resistant"):
        оценка += 2000
    return score - min(ping, 10000)


async def _mt_attempt(host: str, port: int, secret: str) -> int | None:
    normalized = normalize_mt_secret(secret)
    если не нормализовано:
        вернуть None
    клиент = TelegramClient(
        StringSession(""), API_ID, API_HASH,
        connection=connection.ConnectionTcpMTProxyRandomizedIntermediate,
        proxy=(host, port, normalized),
        timeout=CHECK_TIMEOUT,
        connection_retries=0,
        retry_delay=0,
        auto_reconnect=False,
    )
    started = asyncio.get_running_loop().time()
    пытаться:
        await asyncio.wait_for(client.connect(), CHECK_TIMEOUT)
        if not client.is_connected():
            вернуть None
        await asyncio.wait_for(client(GetConfigRequest()), CHECK_TIMEOUT)
        return int((asyncio.get_running_loop().time() - started) * 1000)
    except asyncio.CancelledError:
        поднимать
    за исключением исключения:
        logger.debug("Проверка MTProto не удалась для %s:%s", host, port, exc_info=True)
        вернуть None
    окончательно:
        пытаться:
            await asyncio.wait_for(client.disconnect(), 2)
        за исключением исключения:
            проходить


async def check_mtproto(proxy: dict) -> dict | None:
    host = str(proxy.get("ip", "")).strip()
    порт = int(proxy.get("порт", 0))
    если не хост или не (1 <= порт <= 65535):
        вернуть None
    ip = await resolve(host)
    если не IP-адрес:
        вернуть None
    пинги = []
    для попытки в диапазоне(2):
        value = await _mt_attempt(ip, port, proxy.get("secret", ""))
        если значение не равно None:
            pings.append(value)
            перерыв
        если попытка == 0:
            await asyncio.sleep(0.2)
    if not pings or pings[0] > MAX_PING_MS:
        вернуть None
    geo = await geolocate(ip)
    return enrich(proxy, ip, pings[0], geo, bool(proxy.get("probe_resistant")))


async def check_web(proxy: dict) -> dict | None:
    если ConnectionWebProxy равен None:
        logger.error("telethon-webproxy не установлен")
        вернуть None
    host = str(proxy.get("ip", "")).strip().lower()
    secret = str(proxy.get("secret", "")).strip()
    if not host or not normalize_mt_secret(secret):
        вернуть None
    клиент = TelegramClient(
        StringSession(""), API_ID, API_HASH,
        connection=ConnectionWebProxy,
        proxy=(host, secret, {"mode": os.getenv("WEB_PROXY_MODE", "websocket-lanes")}),
        timeout=WEB_CHECK_TIMEOUT,
        connection_retries=0,
        retry_delay=0,
        auto_reconnect=False,
    )
    started = asyncio.get_running_loop().time()
    пытаться:
        await asyncio.wait_for(client.connect(), WEB_CHECK_TIMEOUT)
        if not client.is_connected():
            вернуть None
        await asyncio.wait_for(client(GetConfigRequest()), WEB_CHECK_TIMEOUT)
        ping = int((asyncio.get_running_loop().time() - started) * 1000)
        если ping > MAX_WEB_PING_MS:
            вернуть None
        geo = await geolocate(host)
        # Веб-хост — это публичный домен ретрансляции; его DNS/IP-адрес полезен для диагностики.
        ip = await resolve(host) or host
        return enrich(proxy, ip, ping, geo, False)
    except asyncio.CancelledError:
        поднимать
    за исключением исключения:
        logger.debug("Проверка веб-прокси для %s не удалась", host, exc_info=True)
        вернуть None
    окончательно:
        пытаться:
            await asyncio.wait_for(client.disconnect(), 3)
        за исключением исключения:
            проходить


async def check_socks5(proxy: dict) -> dict | None:
    host = str(proxy.get("ip", "")).strip()
    порт = int(proxy.get("порт", 0))
    если не хост или не (1 <= порт <= 65535):
        вернуть None
    ip = await resolve(host)
    если не IP-адрес:
        вернуть None
    connector = ProxyConnector(proxy_type=ProxyType.SOCKS5, host=host, port=port, rdns=True)
    started = asyncio.get_running_loop().time()
    пытаться:
        timeout = aiohttp.ClientTimeout(total=SOCKS_CHECK_TIMEOUT)
        async with aiohttp.ClientSession(connector=connector, connector_owner=True, headers=HEADERS) as session:
            async with session.get(TEST_URL, timeout=timeout, allow_redirects=False) as response:
                await response.read(64 * 1024)
                если response.status >= 500:
                    вернуть None
        ping = int((asyncio.get_running_loop().time() - started) * 1000)
        если ping > MAX_PING_MS:
            вернуть None
        geo = await geolocate(ip)
        return enrich(proxy, ip, ping, geo, False)
    except asyncio.CancelledError:
        поднимать
    за исключением исключения:
        logger.debug("Проверка SOCKS5 не удалась для %s:%s", host, port, exc_info=True)
        вернуть None
    окончательно:
        пытаться:
            connector.close()
        за исключением исключения:
            проходить


async def process_proxy(proxy: dict) -> dict | None:
    proto = str(proxy.get("protocol", "")).upper()
    если proto == "MTPROTO":
        return await check_mtproto(proxy)
    если proto == "WEB":
        return await check_web(proxy)
    если proto == "SOCKS5":
        return await check_socks5(proxy)
    вернуть None
