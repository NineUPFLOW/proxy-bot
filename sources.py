"""
Сбор прокси из источников с учётом статистики.
Автоматически отключает источники с низким success rate.

WEB-прокси временно отключены: публичный API mtpro.xyz приостановлен,
а других стабильных источников для TgWebProxy сейчас нет.
"""
import aiohttp
import logging
from urllib.parse import urlparse, parse_qs
import state

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


# ═══════════════════════════════════════════════════════════════════════
#  Источники
# ═══════════════════════════════════════════════════════════════════════

# MTProto (глобальные)
MTPROTO_URLS = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
]

# MTProto (РУ-сегмент — приоритетные)
RU_MTPROTO_URLS = [
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt",
]

# MTProto (EU)
EU_MTPROTO_URLS = [
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt",
]

# SOCKS5 — единственный актуальный источник (kort0881)
SOCKS5_URLS = [
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/socks5.txt",
]

# WEB-прокси — ОТКЛЮЧЕНО (нет рабочих источников)
# Ранее использовался https://mtpro.xyz/api/?type=webproxy —
# приостановлен с 1 марта 2026 года.
WEB_PROXY_URLS = []


# ═══════════════════════════════════════════════════════════════════════
#  Загрузчики
# ═══════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════
#  Парсеры
# ═══════════════════════════════════════════════════════════════════════

def _parse_tg_link(line: str):
    """Парсит tg://proxy и tg://webproxy ссылки."""
    try:
        parsed = urlparse(line)
        params = parse_qs(parsed.query)
        server = params.get("server", [None])[0]
        secret = params.get("secret", [None])[0]
        if not server or not secret:
            return None

        # MTProto
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

        # WEB (на случай, если когда-то вернём источник)
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
    """Парсит строки формата ip:port и socks5://ip:port."""
    try:
        s = line.strip()

        # Убираем возможный префикс
        if s.startswith("socks5://"):
            s = s[len("socks5://"):]

        parts = s.split(":")
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


# ═══════════════════════════════════════════════════════════════════════
#  Основная функция
# ═══════════════════════════════════════════════════════════════════════

async def fetch_all_proxies():
    """Собирает прокси из всех источников с учётом статистики."""
    working_sources = state.get_working_sources(min_success_rate=0.005)
    if not working_sources:
        working_sources = (
            MTPROTO_URLS + RU_MTPROTO_URLS + EU_MTPROTO_URLS
            + SOCKS5_URLS + WEB_PROXY_URLS
        )

    all_proxies = []

    async with aiohttp.ClientSession() as session:
        # ─── MTProto (глобальные) ───
        for url in MTPROTO_URLS:
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

        # ─── MTProto (РУ-сегмент — приоритет) ───
        for url in RU_MTPROTO_URLS:
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
                "RU-MTProto %s: %s → %s",
                url.split("/")[-1], len(lines), len(parsed),
            )

        # ─── MTProto (EU) ───
        for url in EU_MTPROTO_URLS:
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
                "EU-MTProto %s: %s → %s",
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

        # ─── WEB — отключено ───
        # Когда появится новый источник, раскомментировать блок ниже
        # и заполнить WEB_PROXY_URLS.
        #
        # for url in WEB_PROXY_URLS:
        #     if working_sources and url not in working_sources:
        #         continue
        #     data = await _get_json(session, url)
        #     if not data:
        #         state.record_source_failure(url)
        #         continue
        #     items = data if isinstance(data, list) else data.get("proxies", [])
        #     parsed = []
        #     for item in items:
        #         raw = item.get("link") or item.get("url") or ""
        #         p = _parse_tg_link(raw)
        #         if p:
        #             parsed.append(p)
        #     state.update_source_stats(url, len(items), len(parsed))
        #     all_proxies.extend(parsed)
        #     logger.info("WEB %s: %s → %s", url, len(items), len(parsed))

    logger.info("Всего собрано: %s", len(all_proxies))
    return all_proxies
