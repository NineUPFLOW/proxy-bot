"""
Сбор прокси из источников с учётом статистики.
Автоматически отключает источники с низким success rate.
"""
import aiohttp
import logging
from urllib.parse import urlparse, parse_qs
import state

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# ─── Источники ─────────────────────────────────────────────────────────
MTPROTO_URLS = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
]

RU_MTPROTO_URL = "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt"

SOCKS5_URLS = [
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
]

WEB_PROXY_URL = "https://mtpro.xyz/api/?type=webproxy"
LONEKING_MT_URL = "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/mtproto.json"


# ─── Загрузчики ────────────────────────────────────────────────────────
async def _get_text(session, url):
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=20),
            headers=HEADERS,
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
            url,
            timeout=aiohttp.ClientTimeout(total=20),
            headers=HEADERS,
        ) as r:
            if r.status == 200:
                return await r.json()
            logger.warning("JSON fetch %s: HTTP %s", url, r.status)
    except Exception as e:
        logger.warning("JSON fetch failed %s: %s", url, e)
    return []


# ─── Парсеры ───────────────────────────────────────────────────────────
def _parse_tg_link(line: str):
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
        pass
    return None


def _parse_socks5_line(line: str):
    try:
        parts = line.strip().split(":")
        if len(parts) == 2:
            ip, port = parts
            return {
                "protocol": "SOCKS5",
                "ip": ip,
                "port": int(port),
                "secret": "",
                "raw": line,
            }
    except Exception:
        pass
    return None


# ─── Основная функция ──────────────────────────────────────────────────
async def fetch_all_proxies():
    """Собирает прокси из всех источников с учётом статистики."""
    working_sources = state.get_working_sources(min_success_rate=0.005)
    if not working_sources:
        working_sources = (
            MTPROTO_URLS + [RU_MTPROTO_URL] + SOCKS5_URLS
            + [WEB_PROXY_URL, LONEKING_MT_URL]
        )

    all_proxies = []

    async with aiohttp.ClientSession() as session:
        # ─── MTProto ───
        for url in MTPROTO_URLS + [RU_MTPROTO_URL]:
            if working_sources and url not in working_sources:
                continue
            lines = await _get_text(session, url)
            if not lines:
                state.record_source_failure(url)
                continue
            parsed = [p for p in (_parse_tg_link(l) for l in lines) if p]
            state.update_source_stats(url, len(lines), len(parsed))
            all_proxies.extend(parsed)
            logger.info(
                "MTProto %s: %s → %s",
                url.split("/")[-1], len(lines), len(parsed),
            )

        # ─── SOCKS5 ───
        for url in SOCKS5_URLS:
            if working_sources and url not in working_sources:
                continue
            lines = await _get_text(session, url)
            if not lines:
                state.record_source_failure(url)
                continue
            parsed = [p for p in (_parse_socks5_line(l) for l in lines) if p]
            state.update_source_stats(url, len(lines), len(parsed))
            all_proxies.extend(parsed)
            logger.info(
                "SOCKS5 %s: %s → %s",
                url.split("/")[-1], len(lines), len(parsed),
            )

        # ─── WEB ───
        if not working_sources or WEB_PROXY_URL in working_sources:
            data = await _get_json(session, WEB_PROXY_URL)
            if data:
                parsed = []
                items = data if isinstance(data, list) else data.get("proxies", [])
                for item in items:
                    raw = item.get("link") or item.get("url") or ""
                    p = _parse_tg_link(raw)
                    if p:
                        parsed.append(p)
                state.update_source_stats(WEB_PROXY_URL, len(items), len(parsed))
                all_proxies.extend(parsed)
                logger.info("WEB: %s → %s", len(items), len(parsed))

        # ─── LoneKing MTProto (JSON) ───
        if not working_sources or LONEKING_MT_URL in working_sources:
            data = await _get_json(session, LONEKING_MT_URL)
            if data:
                parsed = []
                items = data if isinstance(data, list) else []
                for item in items:
                    raw = item.get("link") or item.get("url") or ""
                    p = _parse_tg_link(raw)
                    if p:
                        parsed.append(p)
                state.update_source_stats(LONEKING_MT_URL, len(items), len(parsed))
                all_proxies.extend(parsed)
                logger.info("LoneKing: %s → %s", len(items), len(parsed))

    logger.info("Всего собрано: %s", len(all_proxies))
    return all_proxies
