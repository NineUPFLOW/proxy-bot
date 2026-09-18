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
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
]

# RU-сегмент (маскировка под российские сервисы)
# Правильный URL: https://github.com/kort0881/telegram-proxy-collector
RU_MTPROTO_URL = (
    "https://raw.githubusercontent.com/kort0881/"
    "telegram-proxy-collector/main/proxy_ru.txt"
)

# ─── SOCKS5 ────────────────────────────────────────────────────────────
SOCKS5_URLS = [
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",
]

# ─── JSON-источники MTProto ───────────────────────────────────────────
# Правильный URL: https://github.com/Yagami200/free-mtproto-proxies
YAGAMI_JSON = (
    "https://raw.githubusercontent.com/Yagami200/"
    "free-mtproto-proxies/main/data/proxies.json"
)

# Правильный URL: https://github.com/Chumbayoumba/free-telegram-proxy-russia-2026
CHUMBAYOUMBA_JSON = (
    "https://raw.githubusercontent.com/Chumbayoumba/"
    "free-telegram-proxy-russia-2026/main/mtproto.json"
)


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


def _parse_yagami_json(items: list) -> list:
    """Парсит ответ Yagami200/free-mtproto-proxies."""
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        host = item.get("host") or item.get("server")
        port = item.get("port")
        secret = item.get("secret")
        if not all([host, port, secret]):
            continue
        if not secret.startswith("ee"):
            continue
        result.append({
            "protocol": "MTPROTO",
            "ip": host,
            "port": int(port),
            "secret": secret,
            "raw": f"tg://proxy?server={host}&port={port}&secret={secret}",
        })
    return result


def _parse_chumbayoumba_json(items: list) -> list:
    """Парсит ответ Chumbayoumba/free-telegram-proxy-russia-2026."""
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        host = item.get("server") or item.get("host")
        port = item.get("port")
        secret = item.get("secret")
        if not all([host, port, secret]):
            continue
        if not secret.startswith("ee"):
            continue
        result.append({
            "protocol": "MTPROTO",
            "ip": host,
            "port": int(port),
            "secret": secret,
            "raw": f"tg://proxy?server={host}&port={port}&secret={secret}",
        })
    return result


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

        # 2. RU MTProto
        ru_lines = await _get_text(s, RU_MTPROTO_URL)
        added = 0
        for line in ru_lines:
            p = _parse_tg_link(line)
            if p:
                add(p)
                added += 1
        logger.info("RU MTProto: %s → %s", len(ru_lines), added)

        # 3. Yagami200 JSON
        yagami_data = await _get_json(s, YAGAMI_JSON)
        if isinstance(yagami_data, list):
            added = 0
            for p in _parse_yagami_json(yagami_data):
                add(p)
                added += 1
            logger.info("Yagami200 JSON: %s → %s", len(yagami_data), added)

        # 4. Chumbayoumba JSON
        chumb_data = await _get_json(s, CHUMBAYOUMBA_JSON)
        if isinstance(chumb_data, list):
            added = 0
            for p in _parse_chumbayoumba_json(chumb_data):
                add(p)
                added += 1
            logger.info("Chumbayoumba JSON: %s → %s", len(chumb_data), added)

        # 5. SOCKS5
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
