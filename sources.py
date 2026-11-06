"""Collect proxy links from HTTPS feeds and local files, never Telegram channels."""

from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import logging
import os
import re
import socket
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

import aiohttp

import state
from network import PublicIPv4Resolver, read_limited, safe_https_url
from proxy_utils import canonical_secret_hex, secret_kind, valid_hostname

logger = logging.getLogger(__name__)
SOURCES_FILE = Path(
    os.getenv("SOURCES_FILE") or Path(__file__).with_name("sources.json")
)
SOURCE_TIMEOUT = max(1.0, float(os.getenv("SOURCE_TIMEOUT", "20")))
SOURCE_CONCURRENCY = max(1, int(os.getenv("SOURCE_CONCURRENCY", "4")))
MAX_SOURCE_BYTES = max(1024, int(os.getenv("MAX_SOURCE_BYTES", str(2 * 1024 * 1024))))
MAX_PER_SOURCE = max(1, int(os.getenv("MAX_PER_SOURCE", "10000")))

RE_MARKDOWN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
RE_HTML_HREF = re.compile(r"href=['\"]([^'\"]+)['\"]", re.I)
RE_URL = re.compile(
    r"(?:tg://(?:proxy|socks|webproxy)\?[^\s<>\"']+"
    r"|(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/(?:proxy|socks|webproxy)\?[^\s<>\"']+"
    r"|socks5?://[^\s<>\"']+)",
    re.I,
)
RE_BARE_SOCKS = re.compile(r"(?<![\w.@/])((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})(?![\w.])")
RE_SOCKS_CONTEXT = re.compile(r"\bsocks5?\b", re.I)


def _clean_url(value: str) -> str:
    return value.strip().strip("`<>\"'()[]{}.,;")


def _qs(url: str) -> dict[str, str]:
    """Percent-decode once; a literal plus is part of standard base64."""
    query: dict[str, str] = {}
    for pair in urlsplit(url).query.split("&"):
        if pair:
            key, _, value = pair.partition("=")
            query.setdefault(unquote(key), unquote(value))
    return query


def _valid_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _valid_host(host: str) -> bool:
    return valid_hostname(host)


def _valid_web_host(host: str) -> bool:
    return valid_hostname(host, domain_only=True)


def _valid_secret(secret: str) -> bool:
    return secret_kind(secret) != "invalid"


def analyze_secret(proxy: dict) -> None:
    from proxy_utils import decode_secret

    kind = secret_kind(str(proxy.get("secret", "")))
    proxy["has_fake_tls"] = kind == "fake_tls"
    raw = decode_secret(str(proxy.get("secret", "")))
    proxy["mask_domain"] = (
        raw[17:].decode("ascii") if kind == "fake_tls" and raw else None
    )


def _parse_proxy(url: str) -> dict | None:
    url = _clean_url(html.unescape(url))
    if not url:
        return None
    if re.match(r"^(?:t\.me|telegram\.me|telegram\.dog)/", url, re.I):
        url = "https://" + url
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host_of_link = (parsed.hostname or "").lower()
        if scheme == "tg":
            kind = host_of_link
        elif scheme in {"http", "https"} and host_of_link in {
            "t.me",
            "telegram.me",
            "telegram.dog",
        }:
            kind = parsed.path.strip("/").lower()
        elif scheme in {"socks", "socks5"}:
            host = (parsed.hostname or "").rstrip(".").lower()
            port = _valid_port(parsed.port)
            if not _valid_host(host) or not port:
                return None
            proxy = {"protocol": "SOCKS5", "ip": host, "port": port}
            if parsed.username is not None:
                proxy["user"] = unquote(parsed.username)
            if parsed.password is not None:
                proxy["pass"] = unquote(parsed.password)
            return proxy
        else:
            return None
        if kind not in {"proxy", "socks", "webproxy"}:
            return None
        query = _qs(url)
        host = (
            query.get("server", query.get("host", ""))
            .strip()
            .strip("[]")
            .rstrip(".")
            .lower()
        )
        if kind == "webproxy":
            secret = canonical_secret_hex(query.get("secret", ""))
            if not _valid_web_host(host) or secret_kind(secret) not in {"plain", "dd"}:
                return None
            return {"protocol": "WEB", "ip": host, "port": 443, "secret": secret}
        port = _valid_port(query.get("port"))
        if not _valid_host(host) or not port:
            return None
        if kind == "socks":
            proxy = {"protocol": "SOCKS5", "ip": host, "port": port}
            if "user" in query:
                proxy["user"] = query["user"]
            if "pass" in query:
                proxy["pass"] = query["pass"]
            return proxy
        secret = canonical_secret_hex(query.get("secret", ""))
        if not secret:
            return None
        proxy = {"protocol": "MTPROTO", "ip": host, "port": port, "secret": secret}
        analyze_secret(proxy)
        return proxy
    except (TypeError, ValueError):
        return None


def _parse_bare_socks(token: str) -> dict | None:
    try:
        host, port_text = _clean_url(token).rsplit(":", 1)
        ipaddress.IPv4Address(host)
        port = _valid_port(port_text)
    except (ValueError, TypeError):
        return None
    return {"protocol": "SOCKS5", "ip": host, "port": port} if port else None


def _dedup(proxies: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result = []
    for proxy in proxies:
        key = state.proxy_identity(proxy)
        if key not in seen:
            seen.add(key)
            result.append(proxy)
    return result


def extract_from_text(text: str, *, default_protocol: str = "") -> list[dict]:
    """Extract links from TXT, HTML, Markdown or string values in JSON.

    Bare IP:port is interpreted as SOCKS5 only for a declared SOCKS5 feed, or
    on a line that explicitly mentions SOCKS; it is not inferred elsewhere.
    """
    if not text:
        return []
    texts = [html.unescape(text)]
    if text.lstrip().startswith(("{", "[")):
        try:
            stack = [json.loads(text)]
            while stack:
                item = stack.pop()
                if isinstance(item, str):
                    texts.append(html.unescape(item))
                elif isinstance(item, dict):
                    stack.extend(item.values())
                elif isinstance(item, list):
                    stack.extend(item)
        except (ValueError, RecursionError):
            pass
    candidates: list[str] = []
    for value in texts:
        candidates.extend(m.group(1) for m in RE_MARKDOWN.finditer(value))
        candidates.extend(m.group(1) for m in RE_HTML_HREF.finditer(value))
        candidates.extend(m.group(0) for m in RE_URL.finditer(value))
        for line in value.splitlines():
            if default_protocol.upper() == "SOCKS5" or RE_SOCKS_CONTEXT.search(line):
                candidates.extend(m.group(1) for m in RE_BARE_SOCKS.finditer(line))
    return _dedup(
        [
            proxy
            for token in candidates
            if (proxy := (_parse_proxy(token) or _parse_bare_socks(token)))
        ]
    )


def load_sources(path: Path | None = None) -> list[dict]:
    path = path or SOURCES_FILE
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read sources configuration: {path}") from exc
    rows = document.get("sources") if isinstance(document, dict) else None
    if not isinstance(rows, list) or not rows or len(rows) > 100:
        raise ValueError(
            "sources.json must contain a non-empty 'sources' list (max 100)"
        )
    result, names = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Each source must be an object")
        name = row.get("name", "")
        fmt = str(row.get("format", "links")).lower()
        url, file_path = row.get("url"), row.get("path")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name)
            or name in names
        ):
            raise ValueError(
                "Source names must be unique and contain only letters, digits, . _ -"
            )
        if fmt not in {"links", "socks5"} or bool(url) == bool(file_path):
            raise ValueError(
                f"Source {name}: set format and exactly one of url or path"
            )
        if url and (
            not isinstance(url, str) or not safe_https_url(url, forbid_telegram=True)
        ):
            raise ValueError(f"Source {name}: only non-Telegram HTTPS URLs are allowed")
        if file_path and not isinstance(file_path, str):
            raise ValueError(f"Source {name}: path must be a string")
        names.add(name)
        result.append(
            {
                "name": name,
                "format": fmt,
                "url": url,
                "path": (path.parent / file_path).resolve() if file_path else None,
            }
        )
    return result


def _read_local(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("local source exceeds size limit")
    return data


async def _download(session: aiohttp.ClientSession, url: str) -> bytes:
    for _ in range(4):
        if not safe_https_url(url, forbid_telegram=True):
            raise ValueError("unsafe or Telegram source URL")
        async with session.get(url, allow_redirects=False) as response:
            if response.status in {301, 302, 303, 307, 308}:
                location = response.headers.get("Location")
                if not location:
                    raise ValueError("redirect without Location")
                url = urljoin(url, location)
                continue
            response.raise_for_status()
            return await read_limited(response, MAX_SOURCE_BYTES)
    raise ValueError("too many redirects")


async def fetch_all_proxies(path: Path | None = None) -> list[dict]:
    config = load_sources(path)
    semaphore = asyncio.Semaphore(SOURCE_CONCURRENCY)
    connector = aiohttp.TCPConnector(
        resolver=PublicIPv4Resolver(), family=socket.AF_INET
    )
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=SOURCE_TIMEOUT),
        trust_env=False,
        headers={"User-Agent": "Mozilla/5.0 proxy-bot/3.0"},
    ) as session:

        async def fetch_one(source: dict) -> list[dict]:
            async with semaphore:
                try:
                    if source["path"]:
                        data = await asyncio.to_thread(_read_local, source["path"])
                    else:
                        data = await _download(session, source["url"])
                    proxies = extract_from_text(
                        data.decode("utf-8-sig", errors="replace"),
                        default_protocol="SOCKS5"
                        if source["format"] == "socks5"
                        else "",
                    )[:MAX_PER_SOURCE]
                    for proxy in proxies:
                        proxy["source"] = source["name"]
                    logger.info(
                        "Source %s: %d candidates", source["name"], len(proxies)
                    )
                    return proxies
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, OSError, TimeoutError, ValueError) as exc:
                    # Do not log URLs: local configuration may contain API keys.
                    logger.warning(
                        "Source %s failed (%s)", source["name"], type(exc).__name__
                    )
                    return []

        results = await asyncio.gather(*(fetch_one(source) for source in config))
    proxies = _dedup([proxy for result in results for proxy in result])
    stats = Counter(p["protocol"] for p in proxies)
    logger.info("Collected %d unique candidates: %s", len(proxies), dict(stats))
    return proxies
