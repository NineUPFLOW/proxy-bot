import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import random
import socket
from collections import Counter
from datetime import datetime, timezone, timedelta
from html import escape
from urllib.parse import urlparse, parse_qs

import aiohttp
from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramRetryAfter
from aiogram.types import (
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    LinkPreviewOptions,
)
from aiohttp_socks import ProxyConnector, ProxyType
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.help import GetConfigRequest
from telethon.network.connection import ConnectionTcpMTProxyRandomizedIntermediate

# ─── НАСТРОЙКИ ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
for name in ("telethon", "telethon.network", "telethon.client",
             "telethon.network.mtprotosender", "telethon.network.connection"):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = os.environ["CHAT_ID"]
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

PUBLISH_COUNT = 5
CONCURRENCY = 10
MAX_SOCKS5_RATIO = 0.4
MAX_WEB_COUNT = 2

MAX_PING_MS = 5000
MAX_PING_WEB_MS = 3000
CHECK_TIMEOUT = 6
WEB_CHECK_TIMEOUT = 8

TEST_URL_TG = "https://api.telegram.org"
TEST_URL_RU = "https://ya.ru"

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

SEEN_FILE = "seen.json"
SEEN_TTL_HOURS = 24

# ─── ИСТОЧНИКИ ─────────────────────────────────────────────────────────
MTPROTO_URLS = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
]
RU_MTPROTO_URL = "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt"
SOCKS5_URL = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"
SOCKS5_FALLBACK = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"
WEB_PROXY_URL = "https://mtpro.xyz/api/?type=webproxy"
LONEKING_MT_URL = "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/mtproto.json"

# ─── ОБЩАЯ HTTP-СЕССИЯ ─────────────────────────────────────────────────
_http_session: aiohttp.ClientSession | None = None
_geo_cache: dict = {}
_geo_semaphore = asyncio.Semaphore(5)


async def get_http_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(headers=HEADERS)
    return _http_session


async def close_http_session():
    global _http_session
    if _http_session and not _http_session.closed:
        await _http_session.close()


# ─── ГЛУШИМ ШУМНЫЕ ИСКЛЮЧЕНИЯ ASYNCIO ──────────────────────────────────
def _silence_telethon_futures(loop, context):
    msg = context.get("message", "")
    if "Future exception was never retrieved" in msg:
        return
    loop.default_exception_handler(context)


# ═══════════════════════════════════════════════════════════════════════
#  ИСТОРИЯ ОПУБЛИКОВАННЫХ ПРОКСИ
# ═══════════════════════════════════════════════════════════════════════

def load_seen() -> dict:
    """Загружает список уже опубликованных прокси, удаляя старые (>24ч)."""
    try:
        with open(SEEN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(hours=SEEN_TTL_HOURS)).isoformat()
        return {k: v for k, v in data.items() if isinstance(v, str) and v > cutoff}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_seen(seen: dict):
    """Сохраняет историю опубликованных прокси в файл."""
    try:
        with open(SEEN_FILE, "w", encoding="utf-8") as f:
            json.dump(seen, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Не удалось сохранить {SEEN_FILE}: {e}")


def proxy_key(p: dict) -> str:
    """Уникальный ключ прокси для дедупликации."""
    return f"{p['protocol']}:{p['ip']}:{p['port']}"


# ═══════════════════════════════════════════════════════════════════════
#  SOURCES — сбор прокси
# ═══════════════════════════════════════════════════════════════════════

async def _get_text(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200:
                text = await r.text()
                return [l.strip() for l in text.splitlines() if l.strip()]
            logger.warning(f"Text fetch {url}: HTTP {r.status}")
    except Exception as e:
        logger.warning(f"Text fetch failed {url}: {e}")
    return []


async def _get_json(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200:
                return await r.json()
            logger.warning(f"JSON fetch {url}: HTTP {r.status}")
    except Exception as e:
        logger.warning(f"JSON fetch failed {url}: {e}")
    return []


def _parse_tg_link(line: str):
    """
    Парсит tg://proxy и tg://webproxy ссылки.

    - tg://proxy?secret=ee...    → MTProto (Fake TLS)
    - tg://proxy?secret=dd...    → пропускаем
    - tg://webproxy?secret=dd... → WEB (TgWebProxy)
    """
    try:
        parsed = urlparse(line)
        params = parse_qs(parsed.query)
        server = params.get("server", [None])[0]
        secret = params.get("secret", [None])[0]
        if not server or not secret:
            return None

        if "tg://proxy?" in line or "t.me/proxy?" in line:
            port = params.get("port", [None])[0]
            if not port:
                return None
            if not secret.startswith("ee"):
                return None
            return {
                "protocol": "MTPROTO",
                "ip": server,
                "port": int(port),
                "secret": secret,
                "raw": line,
            }

        if "tg://webproxy?" in line or "t.me/webproxy?" in line:
            return {
                "protocol": "WEB",
                "ip": server,
                "port": 443,
                "secret": secret,
                "raw": line,
            }
    except Exception:
        return None
    return None


def _parse_socks5_line(line: str):
    if ":" not in line:
        return None
    try:
        host_part = line.rsplit("@", 1)[-1] if "@" in line else line
        ip, port = host_part.rsplit(":", 1)
        return {
            "protocol": "SOCKS5",
            "ip": ip.strip(),
            "port": int(port.strip()),
            "raw": line,
        }
    except ValueError:
        return None


def _parse_loneking_json(item: dict):
    try:
        if item.get("protocol") == "mtproto" and item.get("secret"):
            secret = item["secret"]
            if not secret.startswith("ee"):
                return None
            return {
                "protocol": "MTPROTO",
                "ip": item["server"],
                "port": int(item["port"]),
                "secret": secret,
                "raw": item.get("link", ""),
            }
    except Exception:
        return None


async def fetch_all_proxies() -> list:
    result = []
    seen = set()

    def add(p):
        key = (p["protocol"], p["ip"], p["port"])
        if key not in seen:
            seen.add(key)
            result.append(p)

    session = await get_http_session()

    for url in MTPROTO_URLS:
        lines = await _get_text(session, url)
        for line in lines:
            p = _parse_tg_link(line)
            if p:
                add(p)

    ru_lines = await _get_text(session, RU_MTPROTO_URL)
    for line in ru_lines:
        p = _parse_tg_link(line)
        if p:
            add(p)

    web_data = await _get_json(session, WEB_PROXY_URL)
    if web_data:
        items = web_data if isinstance(web_data, list) else web_data.get("proxies", [])
        for item in items:
            if isinstance(item, dict) and "server" in item and "secret" in item:
                add({
                    "protocol": "WEB",
                    "ip": item["server"],
                    "port": int(item.get("port", 443)),
                    "secret": item["secret"],
                    "raw": item.get("link", ""),
                })

    json_data = await _get_json(session, LONEKING_MT_URL)
    if json_data:
        items = json_data if isinstance(json_data, list) else json_data.get("proxies", [])
        for item in items:
            p = _parse_loneking_json(item)
            if p:
                add(p)

    for line in await _get_text(session, SOCKS5_URL):
        p = _parse_socks5_line(line)
        if p:
            add(p)

    if len([p for p in result if p["protocol"] == "SOCKS5"]) < 50:
        for line in await _get_text(session, SOCKS5_FALLBACK):
            p = _parse_socks5_line(line)
            if p:
                add(p)

    stats = Counter(p["protocol"] for p in result)
    logger.info(f"Итого: {dict(stats)}")
    return result


# ═══════════════════════════════════════════════════════════════════════
#  CHECKER — проверка и геолокация
# ═══════════════════════════════════════════════════════════════════════

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def deterministic_id(ip: str, port: int) -> int:
    h = hashlib.md5(f"{ip}:{port}".encode()).hexdigest()
    return int(h, 16) % 10_000_000


async def geolocate(ip: str) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]

    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,country,countryCode,city,isp,query"
    )
    session = await get_http_session()

    async with _geo_semaphore:
        for attempt in range(3):
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
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
                logger.debug(f"geolocate {ip} attempt {attempt+1}: {e}")
                await asyncio.sleep(1)
    return {}


def country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🏳️"
    return (chr(0x1F1E6 + ord(code[0].upper()) - 65)
            + chr(0x1F1E6 + ord(code[1].upper()) - 65))


async def _one_mtproto_handshake(host, port, secret, timeout):
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
    except Exception as e:
        logger.debug(f"mtproto handshake {host}:{port}: {e}")
    finally:
        if client:
            try:
                await asyncio.wait_for(client.disconnect(), timeout=2)
            except Exception:
                pass
    return None


async def check_telegram_proxy(host: str, port: int, secret: str, is_web: bool = False):
    timeout = WEB_CHECK_TIMEOUT if is_web else CHECK_TIMEOUT
    attempts = 2 if is_web else 3
    required = attempts if is_web else 2

    pings = []
    for i in range(attempts):
        ping = await _one_mtproto_handshake(host, port, secret, timeout)
        if ping is not None:
            pings.append(ping)
        if i < attempts - 1:
            await asyncio.sleep(0.5)

    if len(pings) < required:
        return None

    avg_ping = sum(pings) / len(pings)
    if is_web:
        return int(avg_ping) if avg_ping < MAX_PING_WEB_MS else None
    return int(avg_ping) if avg_ping < MAX_PING_MS else None


async def check_socks5(host: str, port: int):
    connector = ProxyConnector(
        proxy_type=ProxyType.SOCKS5,
        host=host, port=int(port), rdns=True,
    )
    try:
        t0 = asyncio.get_event_loop().time()
        async with aiohttp.ClientSession(
            connector=connector, connector_owner=False
        ) as session:
            try:
                async with session.get(
                    TEST_URL_TG,
                    timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                    allow_redirects=False,
                ) as resp:
                    if resp.status >= 500:
                        return None
            except Exception as e:
                logger.debug(f"socks5 telegram {host}:{port}: {e}")
                return None

            try:
                async with session.get(
                    TEST_URL_RU,
                    timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT),
                    allow_redirects=False,
                ) as resp:
                    if resp.status >= 500:
                        return None
            except Exception as e:
                logger.debug(f"socks5 ya.ru {host}:{port}: {e}")
                return None

        ping = round((asyncio.get_event_loop().time() - t0) * 1000, 1)
        return ping if ping < MAX_PING_MS else None
    except Exception as e:
        logger.debug(f"socks5 check {host}:{port}: {e}")
        return None
    finally:
        try:
            await connector.close()
        except Exception:
            pass


async def process_proxy(raw: dict):
    proto = raw["protocol"].upper()
    ip = raw["ip"]
    port = raw["port"]

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
        "id": deterministic_id(ip, port),
    })
    return raw


# ═══════════════════════════════════════════════════════════════════════
#  FORMATTER — сообщения
# ═══════════════════════════════════════════════════════════════════════

PROTO_ICON = {"MTPROTO": "🔐", "SOCKS5": "🧦", "WEB": "🌐"}
PROTO_LABEL = {"MTPROTO": "MTProto", "SOCKS5": "SOCKS5", "WEB": "WEB (TgWebProxy)"}


def build_connect_link(p: dict) -> str:
    proto = p["protocol"].upper()
    ip, port = p["ip"], p["port"]

    if proto == "MTPROTO":
        return f"tg://proxy?server={ip}&port={port}&secret={p['secret']}"
    if proto == "SOCKS5":
        return f"tg://socks?server={ip}&port={port}"
    if proto == "WEB":
        if port == 443:
            return f"tg://webproxy?server={ip}&secret={p['secret']}"
        return f"tg://webproxy?server={ip}&port={port}&secret={p['secret']}"
    return ""


def _build_label(p: dict) -> str:
    proto = p["protocol"].upper()
    label = PROTO_LABEL.get(proto, proto)
    if proto == "MTPROTO" and p.get("secret", "").startswith("ee"):
        label += " · 🛡 Fake TLS"
    if proto == "WEB":
        label += " · ⚠️ нестабильный"
    return label


def format_message(p: dict) -> str:
    proto = p["protocol"].upper()
    flag = p.get("flag", "🏳️")
    country = escape(p.get("country", "Unknown"))
    city = escape(p.get("city", "Unknown"))
    provider = escape(p.get("provider", "Unknown"))
    ping = escape(p.get("ping", "N/A"))
    ip = escape(p.get("ip", ""))

    icon = PROTO_ICON.get(proto, "🔗")
    label = _build_label(p)
    ip_label = "🌐 Домен" if proto == "WEB" else "📍 IP"

    body = (
        f"{flag} <b>{country}</b>  ·  <code>#{p['id']}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"\n"
        f"┌ {icon} <b>{label}</b>\n"
        f"├ 🌐 <b>Пинг:</b> <code>{ping}</code>\n"
        f"├ 🏳️ <b>Страна:</b> {flag} {country}\n"
        f"├ 🏙 <b>Город:</b> {city}\n"
        f"├ 🏢 <b>Провайдер:</b> {provider}\n"
        f"└ {ip_label}: <code>{ip}</code>\n"
    )

    footer_parts = []
    if proto == "SOCKS5":
        footer_parts.append("✅ Строгая проверка: Telegram + ya.ru пройдены")
    if proto == "WEB":
        footer_parts.append("⚠️ WEB-прокси работают нестабильно")
    if proto == "MTPROTO":
        footer_parts.append("⚠️ MTProto могут блокироваться ТСПУ")

    if footer_parts:
        body += "\n" + "\n".join(footer_parts)
    return body


def build_keyboard(p: dict):
    proto = p["protocol"].upper()
    link = build_connect_link(p)
    if proto == "WEB":
        label = "🌐 Подключить WEB-прокси"
    elif proto == "SOCKS5":
        label = "🧦 Подключить SOCKS5"
    elif proto == "MTPROTO":
        label = "🔐 Подключить MTProto"
    else:
        label = "🔑 Подключить прокси"
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=label, url=link)
    ]])


# ═══════════════════════════════════════════════════════════════════════
#  BOT — главная логика
# ═══════════════════════════════════════════════════════════════════════

async def check_with_semaphore(sem, raw):
    async with sem:
        try:
            return await process_proxy(raw)
        except Exception as e:
            logger.debug(f"check error: {e}")
            return None


async def send_with_retry(bot: Bot, chat_id, text: str, keyboard=None, max_retries=3):
    for attempt in range(max_retries):
        try:
            await bot.send_message(
                chat_id=chat_id,
                text=text,
                reply_markup=keyboard,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return True
        except TelegramRetryAfter as e:
            wait = e.retry_after + 1
            logger.warning(f"Flood control, ждём {wait} сек...")
            await asyncio.sleep(wait)
        except Exception as e:
            logger.error(f"Ошибка публикации: {e}")
            return False
    return False


async def run():
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    try:
        raw_list = await fetch_all_proxies()
        if not raw_list:
            logger.warning("Источники пусты")
            return

        random.shuffle(raw_list)

        sem = asyncio.Semaphore(CONCURRENCY)
        results = await asyncio.gather(
            *[check_with_semaphore(sem, r) for r in raw_list]
        )
        working = [r for r in results if r]

        mtproto = [p for p in working if p["protocol"] == "MTPROTO"]
        web = [p for p in working if p["protocol"] == "WEB"]
        socks5 = [p for p in working if p["protocol"] == "SOCKS5"]

        logger.info(
            f"Рабочих прокси: {len(working)} | "
            f"MTPROTO={len(mtproto)} WEB={len(web)} SOCKS5={len(socks5)}"
        )

        # ── Дедупликация: загружаем историю ──
        published = load_seen()
        logger.info(f"В истории уже {len(published)} прокси")

        web = web[:MAX_WEB_COUNT]
        max_socks5 = max(1, int(PUBLISH_COUNT * MAX_SOCKS5_RATIO))
        socks5 = socks5[:max_socks5]

        seen_in_run = set()
        final = []
        for p in mtproto + web + socks5:
            key = proxy_key(p)
            if key in published or key in seen_in_run:
                continue
            seen_in_run.add(key)
            final.append(p)
            if len(final) >= PUBLISH_COUNT:
                break

        if not final:
            logger.warning("Нет новых прокси для публикации (все уже были)")
            return

        # ── Публикация ──
        published_ok = []
        for p in final:
            ok = await send_with_retry(
                bot, CHAT_ID, format_message(p), build_keyboard(p)
            )
            if ok:
                logger.info(f"Опубликован {p['protocol']} #{p['id']}")
                published_ok.append(p)
            await asyncio.sleep(3)

        # ── Сохраняем историю ──
        if published_ok:
            now_iso = datetime.now(timezone.utc).isoformat()
            for p in published_ok:
                published[proxy_key(p)] = now_iso
            save_seen(published)
            logger.info(f"История обновлена: {len(published)} записей")
    finally:
        await bot.session.close()


async def main():
    try:
        await run()
    finally:
        await close_http_session()


if __name__ == "__main__":
    asyncio.run(main())
