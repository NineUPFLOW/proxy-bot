"""Collect and parse Telegram proxy links from configured Telegram channels."""
from __future__ import annotations

import asyncio
import logging
import os
import re
from collections import Counter
from urllib.parse import parse_qs, unquote, urlparse

from telethon import TelegramClient
from telethon.errors import FloodWaitError
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.tl.types import MessageEntityCode, MessageEntityPre

logger = logging.getLogger(__name__)
API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION", "")

DEFAULT_SOURCES = """urlsources
DESKVPN_RUSSIA
FREEVPN444
File_vpn_2
FluxVPNOff
FreeSubVPN
HalavaHappkeys
Holost_Vpn
KeyVless
LowiKForum
RaViraNet
Unblock_Tech
VLESSdo
VlESSdoo
WSVPN_KEYS_chat
bypassInterne
forumYamVPN
forumhappcluchi
halyava_vpnx
halyava_vpnz
kfwlforum
majetahapp
niyakwi
Razlo4ka7
russia_vp
shadbobr1
shadowsocks_phs
slashvpnfree
v2raytunkeys
vlessrus
vpn4everyone
whitetunnelru
wildVF"""
TELEGRAM_SOURCES = [x.strip().lstrip("@") for x in os.getenv("TELEGRAM_SOURCES", DEFAULT_SOURCES).splitlines() if x.strip()]
MESSAGES_LIMIT = int(os.getenv("MESSAGES_LIMIT", "200"))
THREAD_LIMIT = int(os.getenv("THREAD_LIMIT", "80"))
SOURCE_TIMEOUT = float(os.getenv("SOURCE_TIMEOUT", "30"))
SOURCE_DELAY = float(os.getenv("SOURCE_DELAY", "1.0"))

RE_MARKDOWN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
RE_HTML_HREF = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)
RE_URL = re.compile(r"(?:tg://(?:proxy|socks|webproxy)\?[^\s<>\"']+|(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/(?:proxy|socks|webproxy)\?[^\s<>\"']+|socks5?://[^\s<>\"']+)", re.I)


def _clean_url(value: str) -> str:
    return value.strip().strip("`<>\"'()[]{}.,;")


def _qs(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query, keep_blank_values=True).items() if v}


def _valid_port(value: object) -> int | None:
    try:
        p = int(value)
        return p if 1 <= p <= 65535 else None
    except (TypeError, ValueError):
        return None


def _valid_host(host: str) -> bool:
    host = host.strip().lower()
    return bool(host) and len(host) <= 253 and " " not in host and "/" not in host and "?" not in host


def _valid_secret(secret: str) -> bool:
    s = secret.strip().lower()
    if re.fullmatch(r"(?:dd)?[0-9a-f]{32}", s):
        return True
    # URL-safe base64 for 16 or 17 bytes.
    if re.fullmatch(r"[A-Za-z0-9_-]{22,24}", s):
        return True
    return False


def analyze_secret(proxy: dict) -> None:
    secret = str(proxy.get("secret", "")).lower()
    proxy["has_fake_tls"] = secret.startswith("ee")
    proxy["mask_domain"] = None
    # ee secrets are intentionally kept out of the working list: Telethon's
    # normal MTProxy connector cannot perform the FakeTLS layer correctly.
    if secret.startswith("ee") and len(secret) >= 36:
        try:
            domain_hex = secret[34:]
            domain = bytes.fromhex(domain_hex).decode("ascii", "ignore").strip("\x00")
            if "." in domain and " " not in domain:
                proxy["mask_domain"] = domain
        except (ValueError, UnicodeDecodeError):
            pass


def _parse_proxy(url: str) -> dict | None:
    url = _clean_url(url)
    low = url.lower()
    try:
        if low.startswith("tg://proxy") or "/proxy?" in low:
            q = _qs(url)
            host = unquote(q.get("server", "")).strip()
            port = _valid_port(q.get("port"))
            secret = unquote(q.get("secret", "")).strip()
            if _valid_host(host) and port and _valid_secret(secret):
                p = {"protocol": "MTPROTO", "ip": host, "port": port, "secret": secret, "raw": url}
                analyze_secret(p)
                return p
        if low.startswith("tg://socks") or "/socks?" in low:
            q = _qs(url)
            host = unquote(q.get("server", "")).strip()
            port = _valid_port(q.get("port"))
            if _valid_host(host) and port:
                return {"protocol": "SOCKS5", "ip": host, "port": port, "raw": url}
        if low.startswith("tg://webproxy") or "/webproxy?" in low:
            q = _qs(url)
            host = unquote(q.get("server", q.get("host", ""))).strip().lower()
            secret = unquote(q.get("secret", "")).strip()
            if _valid_host(host) and _valid_secret(secret):
                return {"protocol": "WEB", "ip": host, "port": 443, "secret": secret, "raw": url}
        if low.startswith("socks5://") or low.startswith("socks://"):
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port
            if _valid_host(host) and _valid_port(port):
                return {"protocol": "SOCKS5", "ip": host, "port": int(port), "raw": url}
    except (ValueError, TypeError):
        return None
    return None


def _parse_bare_socks(token: str) -> dict | None:
    token = _clean_url(token)
    if token.count(":") != 1:
        return None
    host, port = token.rsplit(":", 1)
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) and _valid_port(port):
        if all(0 <= int(x) <= 255 for x in host.split(".")):
            return {"protocol": "SOCKS5", "ip": host, "port": int(port), "raw": token}
    return None


def extract_from_text(text: str) -> list[dict]:
    if not text:
        return []
    result = []
    seen = set()
    candidates = []
    candidates.extend(m.group(1) for m in RE_MARKDOWN.finditer(text))
    candidates.extend(m.group(1) for m in RE_HTML_HREF.finditer(text))
    candidates.extend(m.group(0) for m in RE_URL.finditer(text))
    for line in text.splitlines():
        candidates.extend(line.split())
    for token in candidates:
        token = _clean_url(token)
        if not token or token in seen:
            continue
        seen.add(token)
        parsed = _parse_proxy(token) or _parse_bare_socks(token)
        if parsed:
            result.append(parsed)
    return result


def extract_from_message(message) -> list[dict]:
    result = []
    text = getattr(message, "message", None) or getattr(message, "text", None) or ""
    result.extend(extract_from_text(text))
    for entity in getattr(message, "entities", None) or []:
        if isinstance(entity, (MessageEntityCode, MessageEntityPre)):
            try:
                result.extend(extract_from_text(text[entity.offset:entity.offset + entity.length]))
            except Exception:
                pass
    markup = getattr(message, "reply_markup", None)
    for row in getattr(markup, "rows", []) or []:
        for button in getattr(row, "buttons", []) or []:
            url = getattr(button, "url", None)
            if url:
                p = _parse_proxy(url)
                if p:
                    result.append(p)
    return result


def _dedup(proxies: list[dict]) -> list[dict]:
    result = []
    seen = set()
    for p in proxies:
        key = (p.get("protocol"), str(p.get("ip", "")).lower(), int(p.get("port", 0)), str(p.get("secret", "")).lower())
        if key not in seen:
            seen.add(key)
            result.append(p)
    return result


async def _fetch_source(client: TelegramClient, source: str) -> list[dict]:
    result = []
    try:
        try:
            await client(JoinChannelRequest(source))
        except Exception:
            pass
        entity = await client.get_entity(source)
        topic_ids = set()
        async for msg in client.iter_messages(entity, limit=min(MESSAGES_LIMIT, 100)):
            reply_to = getattr(msg, "reply_to", None)
            top = getattr(reply_to, "reply_to_top_id", None) if reply_to else None
            if top:
                topic_ids.add(top)
            result.extend(extract_from_message(msg))
        for topic_id in list(topic_ids)[:THREAD_LIMIT]:
            try:
                messages = await asyncio.wait_for(
                    client.get_messages(entity, limit=50, reply_to=topic_id), SOURCE_TIMEOUT
                )
                for msg in messages or []:
                    result.extend(extract_from_message(msg))
            except Exception:
                logger.debug("Topic %s failed in @%s", topic_id, source, exc_info=True)
        logger.info("@%s -> %d proxy links", source, len(result))
    except FloodWaitError as exc:
        delay = min(int(exc.seconds), 120)
        logger.warning("FloodWait @%s: sleeping %ss", source, delay)
        await asyncio.sleep(delay)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.warning("Source failed @%s", source, exc_info=True)
    return _dedup(result)


async def fetch_from_telegram_sources() -> list[dict]:
    if not TG_SESSION:
        logger.error("TG_SESSION is empty; cannot read Telegram sources")
        return []
    client = TelegramClient(
        StringSession(TG_SESSION), API_ID, API_HASH,
        timeout=15, connection_retries=1, retry_delay=1, auto_reconnect=False,
    )
    result = []
    try:
        await client.connect()
        if not await asyncio.wait_for(client.is_user_authorized(), 15):
            logger.error("TG_SESSION is not authorized")
            return []
        for source in TELEGRAM_SOURCES:
            if not client.is_connected():
                try:
                    await client.connect()
                except Exception:
                    logger.error("Telegram reconnect failed; stopping source scan")
                    break
            result.extend(await _fetch_source(client, source))
            await asyncio.sleep(SOURCE_DELAY)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Telegram source collector failed")
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
    return _dedup(result)


async def fetch_all_proxies() -> list[dict]:
    result = await fetch_from_telegram_sources()
    stats = Counter(p["protocol"] for p in result)
    logger.info("Collected %d unique proxies: %s", len(result), dict(stats))
    return result
