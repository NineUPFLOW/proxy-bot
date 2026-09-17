import aiohttp
import logging
from collections import Counter
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

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


# ─── ЗАГРУЗЧИКИ ────────────────────────────────────────────────────────

async def _get_text(session, url):
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=20), headers=HEADERS
        ) as r:
            if r.status == 200:
                text = await r.text()
                return [l.strip() for l in text.splitlines() if l.strip()]
            logger.warning(f"Text fetch {url}: HTTP {r.status}")
    except Exception as e:
        logger.warning(f"Text fetch failed {url}: {e}")
    return []


async def _get_json(session, url):
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=20), headers=HEADERS
        ) as r:
            if r.status == 200:
                return await r.json()
            logger.warning(f"JSON fetch {url}: HTTP {r.status}")
    except Exception as e:
        logger.warning(f"JSON fetch failed {url}: {e}")
    return []


# ─── ПАРСЕРЫ ───────────────────────────────────────────────────────────

def _parse_tg_link(line: str):
    """
    Парсит tg://proxy и tg://webproxy ссылки.

    - tg://proxy?secret=ee...    → MTProto (Fake TLS)
    - tg://proxy?secret=dd...    → пропускаем (обычный MTProto, нестабилен)
    - tg://webproxy?secret=dd... → WEB (TgWebProxy)
    """
    try:
        parsed = urlparse(line)
        params = parse_qs(parsed.query)
        server = params.get("server", [None])[0]
        secret = params.get("secret", [None])[0]
        if not server or not secret:
            return None

        # ── MTProto (tg://proxy или t.me/proxy) ──
        if "tg://proxy?" in line or "t.me/proxy?" in line:
            port = params.get("port", [None])[0]
            if not port:
                return None
            # Только Fake TLS (ee) — dd-секреты нестабильны и не поддерживаются
            if not secret.startswith("ee"):
                return None
            return {
                "protocol": "MTPROTO",
                "ip": server,
                "port": int(port),
                "secret": secret,
                "raw": line,
            }

        # ── WEB (tg://webproxy или t.me/webproxy) ──
        if "tg://webproxy?" in line or "t.me/webproxy?" in line:
            return {
                "protocol": "WEB",
                "ip": server,
                "port": 443,  # всегда 443
                "secret": secret,
                "raw": line,
            }
    except Exception:
        return None
    return None


def _parse_socks5_line(line: str):
    """Поддерживает форматы ip:port и user:pass@ip:port."""
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
    """Парсит MTProto из JSON LoneKingCode. Оставляет только ee (Fake TLS)."""
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
        # ── MTProto / WEB из tg:// ссылок ──
        for url in MTPROTO_URLS:
            lines = await _get_text(s, url)
            for line in lines:
                p = _parse_tg_link(line)
                if p:
                    add(p)
            logger.info(f"{url.split('/')[-2]}: загружено {len(lines)} строк")

        # ── RU MTProto (маскировка под российские сервисы) ──
        ru_lines = await _get_text(s, RU_MTPROTO_URL)
        for line in ru_lines:
            p = _parse_tg_link(line)
            if p:
                add(p)
        logger.info(f"RU MTProto: загружено {len(ru_lines)} строк")

        # ── WEB из mtpro.xyz ──
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
                        "raw": item.get("link", ""),
                    })
            logger.info(f"mtpro.xyz webproxy: {len(items)} записей")

        # ── MTProto из JSON LoneKingCode ──
        json_data = await _get_json(s, LONEKING_MT_URL)
        if json_data:
            items = json_data if isinstance(json_data, list) else json_data.get("proxies", [])
            for item in items:
                p = _parse_loneking_json(item)
                if p:
                    add(p)
            logger.info(f"LoneKing MTProto: {len(items)} записей")

        # ── SOCKS5 ──
        for line in await _get_text(s, SOCKS5_URL):
            p = _parse_socks5_line(line)
            if p:
                add(p)

    # ── Резервный SOCKS5, если основных мало ──
    if len([p for p in result if p["protocol"] == "SOCKS5"]) < 50:
        async with aiohttp.ClientSession(headers=HEADERS) as s:
            for line in await _get_text(s, SOCKS5_FALLBACK):
                p = _parse_socks5_line(line)
                if p:
                    add(p)

    stats = Counter(p["protocol"] for p in result)
    logger.info(f"Итого: {dict(stats)}")
    return result
