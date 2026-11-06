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
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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


def _parse_mtproto_fields(host: object, port: object, secret: object) -> dict | None:
    """Build an MTProto candidate with the same validation as a Telegram link.

    This only parses syntax. Public IPv4 resolution is still enforced by the
    checker before making a connection, including for structured JSON records.
    """
    if not isinstance(host, str) or not isinstance(secret, str):
        return None
    if isinstance(port, bool) or not isinstance(port, (str, int)):
        return None
    host = host.strip().strip("[]").rstrip(".").lower()
    parsed_port = _valid_port(port)
    canonical = canonical_secret_hex(secret.strip())
    if not _valid_host(host) or not parsed_port or not canonical:
        return None
    proxy = {
        "protocol": "MTPROTO",
        "ip": host,
        "port": parsed_port,
        "secret": canonical,
    }
    analyze_secret(proxy)
    return proxy


def _parse_bare_mtproto(line: str) -> dict | None:
    # The format is intentionally IPv4/domain only; an arbitrary IP:port line
    # must never be silently treated as MTProto or SOCKS5.
    line = line.partition("#")[0].strip()
    parts = line.split(":")
    if len(parts) != 3:
        return None
    return _parse_mtproto_fields(parts[0], parts[1], parts[2])


def _parse_mtproto_object(item: dict) -> dict | None:
    # Only consume separate JSON fields in a source explicitly declared mtproto.
    # An explicit different protocol/type must not be reinterpreted as MTProto.
    for key in ("protocol", "type"):
        if key in item and str(item[key]).lower() not in {"mtproto", "mtproxy"}:
            return None
    host = item.get("server", item.get("host", item.get("ip")))
    return _parse_mtproto_fields(host, item.get("port"), item.get("secret"))


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

    Bare IPv4:port is SOCKS5 only in a declared SOCKS5 feed or on a line that
    explicitly mentions SOCKS. Bare host:port:secret and separate JSON fields
    are interpreted as MTProto only for a declared MTProto feed.
    """
    if not text:
        return []
    declared = default_protocol.upper()
    texts = [html.unescape(text)]
    structured: list[dict] = []
    if text.lstrip().startswith(("{", "[")):
        try:
            stack = [json.loads(text)]
            while stack:
                item = stack.pop()
                if isinstance(item, str):
                    texts.append(html.unescape(item))
                elif isinstance(item, dict):
                    if declared == "MTPROTO" and (proxy := _parse_mtproto_object(item)):
                        structured.append(proxy)
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
            if declared == "MTPROTO" and (proxy := _parse_bare_mtproto(line)):
                structured.append(proxy)
            if declared == "SOCKS5" or RE_SOCKS_CONTEXT.search(line):
                candidates.extend(m.group(1) for m in RE_BARE_SOCKS.finditer(line))
    return _dedup(
        structured
        + [
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
        if fmt not in {"links", "socks5", "mtproto"} or bool(url) == bool(file_path):
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


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _http_date(value: str | None) -> str | None:
    """Return a parsed server-provided date; never mistake it for proxy freshness."""
    if not value:
        return None
    try:
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return date.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    except (TypeError, ValueError, OverflowError, IndexError):
        return None


async def _download(
    session: aiohttp.ClientSession, url: str, *, metadata: dict | None = None
) -> bytes:
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
            data = await read_limited(response, MAX_SOURCE_BYTES)
            if metadata is not None:
                metadata["last_modified"] = _http_date(
                    response.headers.get("Last-Modified")
                )
            return data
    raise ValueError("too many redirects")


async def fetch_source_results(path: Path | None = None) -> list[dict]:
    """Fetch each configured source once; retain separate counts for audits.

    Candidate details are internal. Consumers publishing reports must remove
    the proxies list: it can contain secrets and source-specific credentials.
    """
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

        async def fetch_one(source: dict) -> dict:
            report = {
                "name": source["name"],
                "status": "error",
                "retrieved_at": None,
                "last_modified": None,
                "candidate_counts": {},
                "proxies": [],
            }
            async with semaphore:
                try:
                    if source["path"]:
                        data = await asyncio.to_thread(_read_local, source["path"])
                        try:
                            report["last_modified"] = (
                                datetime.fromtimestamp(
                                    source["path"].stat().st_mtime, timezone.utc
                                )
                                .replace(microsecond=0)
                                .isoformat()
                            )
                        except (OSError, OverflowError, ValueError):
                            pass
                    else:
                        data = await _download(session, source["url"], metadata=report)
                    proxies = extract_from_text(
                        data.decode("utf-8-sig", errors="replace"),
                        default_protocol=source["format"].upper(),
                    )[:MAX_PER_SOURCE]
                    for proxy in proxies:
                        proxy["source"] = source["name"]
                    report["status"] = "candidates" if proxies else "empty"
                    report["retrieved_at"] = _utc_now()
                    report["candidate_counts"] = dict(
                        Counter(p["protocol"] for p in proxies)
                    )
                    report["proxies"] = proxies
                    logger.info(
                        "Source %s: %d candidates", source["name"], len(proxies)
                    )
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, OSError, TimeoutError, ValueError) as exc:
                    # Never log the URL, path or exception message: these may contain keys.
                    report["error_type"] = type(exc).__name__
                    if isinstance(exc, aiohttp.ClientResponseError):
                        report["http_status"] = exc.status
                    logger.warning(
                        "Source %s failed (%s)", source["name"], type(exc).__name__
                    )
                return report

        return await asyncio.gather(*(fetch_one(source) for source in config))


async def fetch_all_proxies(path: Path | None = None) -> list[dict]:
    results = await fetch_source_results(path)
    proxies = _dedup([proxy for result in results for proxy in result["proxies"]])
    stats = Counter(p["protocol"] for p in proxies)
    logger.info("Collected %d unique candidates: %s", len(proxies), dict(stats))
    return proxies
