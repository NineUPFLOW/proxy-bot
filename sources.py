import logging
from collections import Counter
from urllib.parse import urlparse, parse_qs

import aiohttp

logger = logging.getLogger(__name__)

# ─── ИСТОЧНИКИ (с добавлением RU-сегмента) ───────────────────────────────

# MTProto: SoliSpirit — обновляется каждые 12 часов, авто-проверка
MTPROTO_URLS = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
]

# MTProto для России (маскировка под Yandex, VK и др.)
RU_MTPROTO_URL = "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt"

# SOCKS5 (строгая проверка)
SOCKS5_URL = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"
SOCKS5_FALLBACK = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"

# WEB-прокси
WEB_PROXY_URL = "https://mtpro.xyz/api/?type=webproxy"

# MTProto из JSON (LoneKingCode)
LONEKING_MT_URL = "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/mtproto.json"


# ─── ЗАГРУЗЧИКИ ─────────────────────────────────────────────────────────
async def _get_text(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200:
                text = await r.text()
                return [l.strip() for l in text.splitlines() if l.strip()]
            logger.warning(f"{url}: HTTP {r.status}")
    except Exception as e:
        logger.warning(f"Text fetch failed {url}: {e}")
    return []


async def _get_json(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200:
                return await r.json()
            logger.warning(f"{url}: HTTP {r.status}")
    except Exception as e:
        logger.warning(f"JSON fetch failed {url}: {e}")
    return []


# ─── ПАРСЕРЫ ───────────────────────────────────────────────────────────
def _parse_tg_link(line: str):
    """
    Парсит tg://proxy ссылку. Оставляет только Fake TLS (ee) и WEB (dd).
    Используем urlparse/parse_qs вместо ручного split("="), чтобы
    параметры корректно URL-декодировались (раньше secret/server могли
    прийти в "сыром" percent-encoded виде и ломать прокси).
    """
    if "tg://proxy?" not in line and "t.me/proxy?" not in line:
        return None
    try:
        query = urlparse(line).query
        params = parse_qs(query)
        server = params.get("server", [None])[0]
        port = params.get("port", [None])[0]
        secret = params.get("secret", [None])[0]
        if not all([server, port, secret]):
            return None
        if not (secret.startswith("ee") or secret.startswith("dd")):
            return None
        proto = "WEB" if secret.startswith("dd") else "MTPROTO"
        return {
            "protocol": proto,
            "ip": server,
            "port": int(port),
            "secret": secret,
            "raw": line,
        }
    except Exception:
        return None


def _parse_socks5_line(line: str):
    """
    Парсит 'ip:port' и 'user:pass@ip:port'.
    Раньше поддерживался только 'ip:port' — строка вида
    'user:pass@1.2.3.4:1080' ломала парсер (rsplit по ':' отдавал
    кусок 'user:pass@1.2.3.4' как "ip").
    """
    line = line.strip()
    if not line:
        return None

    hostport = line.rpartition("@")[2] if "@" in line else line
    if ":" not in hostport:
        return None

    ip, _, port = hostport.rpartition(":")
    if not ip or not port:
        return None

    try:
        return {"protocol": "SOCKS5", "ip": ip.strip(),
                "port": int(port.strip()), "raw": line}
    except ValueError:
        return None


def _parse_loneking_json(item: dict):
    """Парсит MTProto из JSON LoneKingCode."""
    try:
        if item.get("protocol") == "mtproto" and item.get("secret"):
            secret = item["secret"]
            if not (secret.startswith("ee") or secret.startswith("dd")):
                return None
            proto = "WEB" if secret.startswith("dd") else "MTPROTO"
            return {
                "protocol": proto,
                "ip": item["server"],
                "port": int(item["port"]),
                "secret": secret,
                "raw": item.get("link", ""),
            }
    except Exception:
        return None
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

    async with aiohttp.ClientSession() as s:
        # MTProto / WEB из tg:// ссылок
        for url in MTPROTO_URLS:
            lines = await _get_text(s, url)
            for line in lines:
                p = _parse_tg_link(line)
                if p:
                    add(p)
            logger.info(f"{url.split('/')[-2]}: загружено {len(lines)} строк")

        # RU MTProto (маскировка под российские сервисы)
        ru_lines = await _get_text(s, RU_MTPROTO_URL)
        for line in ru_lines:
            p = _parse_tg_link(line)
            if p:
                add(p)
        logger.info(f"RU MTProto: загружено {len(ru_lines)} строк")

        # WEB из mtpro.xyz
        web_data = await _get_json(s, WEB_PROXY_URL)
        if web_data:
            items = web_data if isinstance(web_data, list) else web_data.get("proxies", [])
            for item in items:
                if isinstance(item, dict) and "server" in item and "secret" in item:
                    add({
                        "protocol": "WEB",
                        "ip": item["server"],
                        "port": int(item.get("port", 443)),
                        "secret": item["secret"],
                        "raw": "",
                    })
            logger.info(f"mtpro.xyz webproxy: {len(items)} записей")

        # MTProto из JSON LoneKingCode
        json_data = await _get_json(s, LONEKING_MT_URL)
        if json_data:
            items = json_data if isinstance(json_data, list) else json_data.get("proxies", [])
            for item in items:
                p = _parse_loneking_json(item)
                if p:
                    add(p)
            logger.info(f"LoneKing MTProto: {len(items)} записей")

        # SOCKS5
        for line in await _get_text(s, SOCKS5_URL):
            p = _parse_socks5_line(line)
            if p:
                add(p)

    # Резервный SOCKS5
    if len([p for p in result if p["protocol"] == "SOCKS5"]) < 50:
        async with aiohttp.ClientSession() as s:
            for line in await _get_text(s, SOCKS5_FALLBACK):
                p = _parse_socks5_line(line)
                if p:
                    add(p)

    stats = Counter(p["protocol"] for p in result)
    logger.info(f"Итого: {dict(stats)}")
    return result
