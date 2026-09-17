import aiohttp
import logging

logger = logging.getLogger(__name__)

# ─── ИСТОЧНИКИ (проверены на сентябрь 2026) ────────────────────────────

# MTProto: SoliSpirit — обновляется каждые 12 часов, авто-проверка
MTPROTO_URLS = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
]

# SOCKS5 / HTTP: обновляются ежечасно с авто-проверкой
SOCKS5_URL = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"
HTTP_URL = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"

# Резервные источники SOCKS5/HTTP
SOCKS5_FALLBACK = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"
HTTP_FALLBACK = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"

# WEB-прокси: агрегатор mtpro.xyz (парсит Telegram-каналы)
WEB_PROXY_URL = "https://mtpro.xyz/api/?type=webproxy"


# ─── ЗАГРУЗЧИКИ ────────────────────────────────────────────────────────

async def _get_text(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200:
                text = await r.text()
                return [l.strip() for l in text.splitlines() if l.strip()]
    except Exception as e:
        logger.warning(f"Text fetch failed {url}: {e}")
    return []


async def _get_json(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200:
                return await r.json()
    except Exception as e:
        logger.warning(f"JSON fetch failed {url}: {e}")
    return []


# ─── ПАРСЕРЫ ───────────────────────────────────────────────────────────

def _parse_tg_link(line: str):
    """Парсит строку вида tg://proxy?server=...&port=...&secret=..."""
    if "tg://proxy?" not in line and "t.me/proxy?" not in line:
        return None
    try:
        query = line.split("?", 1)[1]
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        server = params.get("server")
        port = params.get("port")
        secret = params.get("secret")
        if not all([server, port, secret]):
            return None

        # Определяем тип по secret: dd = WEB, ee = MTProto
        proto = "WEB" if secret.startswith("dd") else "MTPROTO"
        return {
            "protocol": proto,
            "ip": server,
            "port": int(port),
            "secret": secret,
        }
    except Exception:
        return None


def _parse_socks5_line(line: str):
    if ":" not in line:
        return None
    ip, port = line.rsplit(":", 1)
    try:
        return {"protocol": "SOCKS5", "ip": ip.strip(), "port": int(port.strip())}
    except ValueError:
        return None


def _parse_http_line(line: str):
    if ":" not in line:
        return None
    ip, port = line.rsplit(":", 1)
    try:
        return {"protocol": "HTTP", "ip": ip.strip(), "port": int(port.strip())}
    except ValueError:
        return None


# ─── ГЛАВНАЯ ФУНКЦИЯ ───────────────────────────────────────────────────

async def fetch_all_proxies() -> list:
    """
    Собирает прокси из всех источников.
    Возвращает список словарей: protocol, ip, port [, secret].
    """
    result = []
    seen = set()

    def add(p):
        key = (p["protocol"], p["ip"], p["port"])
        if key not in seen:
            seen.add(key)
            result.append(p)

    async with aiohttp.ClientSession() as s:
        # ── MTProto / WEB (из tg:// ссылок) ──
        for url in MTPROTO_URLS:
            lines = await _get_text(s, url)
            for line in lines:
                p = _parse_tg_link(line)
                if p:
                    add(p)
            logger.info(f"{url.split('/')[-2]}: загружено {len(lines)} строк")

        # ── WEB-прокси из mtpro.xyz ──
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
                    })
            logger.info(f"mtpro.xyz webproxy: {len(items)} записей")

        # ── SOCKS5 ──
        lines = await _get_text(s, SOCKS5_URL)
        for line in lines:
            p = _parse_socks5_line(line)
            if p:
                add(p)

        # ── HTTP ──
        lines = await _get_text(s, HTTP_URL)
        for line in lines:
            p = _parse_http_line(line)
            if p:
                add(p)

    # Если основных источников мало — добираем из резервных
    if len([p for p in result if p["protocol"] in ("SOCKS5", "HTTP")]) < 50:
        async with aiohttp.ClientSession() as s:
            for line in await _get_text(s, SOCKS5_FALLBACK):
                p = _parse_socks5_line(line)
                if p:
                    add(p)
            for line in await _get_text(s, HTTP_FALLBACK):
                p = _parse_http_line(line)
                if p:
                    add(p)

    from collections import Counter
    stats = Counter(p["protocol"] for p in result)
    logger.info(f"Итого: {dict(stats)}")
    return result
