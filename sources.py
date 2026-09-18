"""
Сбор прокси из открытых источников.
Все ссылки проверены на 2026-09-18.
"""

import logging
from collections import Counter
from urllib.parse import urlparse, parse_qs

import aiohttp

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# ─── MTProto из tg:// ссылок ───────────────────────────────────────────
MTPROTO_URLS = [
    # SoliSpirit — эталонный источник, обновление каждые 12 часов
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    # Grim1313 — форк SoliSpirit, удобные форматы
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    # ALIILAPRO — ежедневное обновление
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
]

# ─── RU-специфичный источник (Fake-TLS под Yandex, VK, Gosuslugi) ──────
RU_MTPROTO_URL = (
    "https://raw.githubusercontent.com/kort0881/"
    "telegram-proxy-collector/main/proxy_ru.txt"
)

# ─── SOCKS5 (проверенные, автоматически обновляемые) ───────────────────
SOCKS5_URLS = [
    # monosans — обновление каждый час, сортировка по скорости
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    # proxifly — обновление каждые 5 минут, тысячи прокси
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
]


# ─── ЗАГРУЗЧИКИ ────────────────────────────────────────────────────────
async def _get_text(session, url):
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=20), headers=HEADERS
        ) as r:
            if r.status == 200:
                text = await r.text()
                return [l.strip() for l in text.splitlines() if l.strip()]
            logger.warning("Text fetch %s: HTTP %s", url, r.status)
    except Exception as e:
        logger.warning("Text fetch failed %s: %s", url, e)
    return []


async def _get_json(session, url):
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=20), headers=HEADERS
        ) as r:
            if r.status == 200:
                return await r.json()
            logger.warning("JSON fetch %s: HTTP %s", url, r.status)
    except Exception as e:
        logger.warning("JSON fetch failed %s: %s", url, e)
    return None


# ─── ПАРСЕРЫ ───────────────────────────────────────────────────────────
def _parse_tg_link(line: str):
    """Парсит tg://proxy (ee) и tg://webproxy (dd) ссылки."""
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


# ─── ГЛАВНАЯ ФУНКЦИЯ ───────────────────────────────────────────────────
async def fetch_all_proxies() -> list:
    result = []
    seen = set()

    def add(p):
        key = (p["protocol"], p["ip"], p["port"])
        if key not in seen:
            seen.add(key)
            result.append(p)

    async with aiohttp.ClientSession(headers=HEADERS) as s:
        # 1. MTProto из tg:// ссылок
        for url in MTPROTO_URLS:
            lines = await _get_text(s, url)
            added = 0
            for line in lines:
                p = _parse_tg_link(line)
                if p:
                    add(p)
                    added += 1
            logger.info("MTProto %s: %s → %s", url.split("/")[-2], len(lines), added)

        # 2. RU MTProto (Fake-TLS под российские сервисы)
        ru_lines = await _get_text(s, RU_MTPROTO_URL)
        added = 0
        for line in ru_lines:
            p = _parse_tg_link(line)
            if p:
                add(p)
                added += 1
        logger.info("RU MTProto: %s → %s", len(ru_lines), added)

        # 3. SOCKS5
        for url in SOCKS5_URLS:
            lines = await _get_text(s, url)
            added = 0
            for line in lines:
                p = _parse_socks5_line(line)
                if p:
                    add(p)
                    added += 1
            logger.info("SOCKS5 %s: %s → %s", url.split("/")[-2], len(lines), added)

    stats = Counter(p["protocol"] for p in result)
    logger.info("Всего собрано: %s | %s", len(result), dict(stats))
    return result
