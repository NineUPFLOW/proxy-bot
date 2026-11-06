"""IPv4 safety, pinned DNS and an honest estimate of the checker egress country."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

logger = logging.getLogger(__name__)
DNS_TIMEOUT = 5.0


def public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        isinstance(ip, ipaddress.IPv4Address)
        and ip.is_global
        and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    )


async def resolve_public_ipv4(host: str, *, preferred: str | None = None) -> str | None:
    """Refuse mixed DNS answers; keep the tested IP if still in the answer set."""
    host = str(host or "").strip().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host if public_ipv4(host) else None
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
            ),
            timeout=DNS_TIMEOUT,
        )
    except (OSError, TimeoutError):
        return None
    addresses = {info[4][0] for info in infos}
    if not addresses or not all(public_ipv4(address) for address in addresses):
        return None
    if preferred in addresses:
        return preferred
    return min(addresses, key=lambda ip: int(ipaddress.IPv4Address(ip)))


class PublicIPv4Resolver(AbstractResolver):
    """aiohttp resolver that never returns an internal or non-IPv4 address."""

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        ip = await resolve_public_ipv4(host)
        if ip is None:
            raise OSError("Host does not resolve exclusively to public IPv4")
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": socket.AF_INET,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    async def close(self) -> None:
        pass


class PinnedIPv4Resolver(AbstractResolver):
    """Pin WEB relay connections to the address that was validated for the check."""

    def __init__(self, hostname: str, address: str):
        if not public_ipv4(address):
            raise ValueError("WEB relay address is not public IPv4")
        self.hostname = hostname.lower().rstrip(".")
        self.address = address

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        if host.lower().rstrip(".") != self.hostname:
            raise OSError("WEB relay attempted to resolve a different hostname")
        return [
            {
                "hostname": host,
                "host": self.address,
                "port": port,
                "family": socket.AF_INET,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    async def close(self) -> None:
        pass


def safe_https_url(url: str, *, forbid_telegram: bool = False) -> bool:
    """Disallow credentials, Telegram source hosts, private IPs and non-HTTPS."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return False
    if (
        parts.scheme.lower() != "https"
        or not host
        or parts.username is not None
        or parts.password is not None
        or (port is not None and not 1 <= port <= 65535)
    ):
        return False
    if forbid_telegram and any(
        host == suffix or host.endswith("." + suffix)
        for suffix in ("t.me", "telegram.me", "telegram.dog", "telegram.org")
    ):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        from proxy_utils import valid_hostname

        return valid_hostname(host, domain_only=True)
    return public_ipv4(host)


async def read_limited(response: aiohttp.ClientResponse, limit: int) -> bytes:
    if response.content_length is not None and response.content_length > limit:
        raise ValueError("response exceeds size limit")
    data = bytearray()
    async for chunk in response.content.iter_chunked(64 * 1024):
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("response exceeds size limit")
    return bytes(data)


async def detect_egress_country() -> dict:
    """Estimate direct IPv4 egress location, never via BOT_PROXY_URL.

    The result is evidence about this runner, not a guarantee about every route,
    ISP or client in Russia. Failures return an unknown country.
    """
    endpoints = (
        ("ipwho.is", "https://ipwho.is/"),
        ("ipapi.co", "https://ipapi.co/json/"),
    )
    timeout = aiohttp.ClientTimeout(total=8)
    connector = aiohttp.TCPConnector(
        resolver=PublicIPv4Resolver(), family=socket.AF_INET
    )
    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        trust_env=False,
        headers={"User-Agent": "proxy-bot/3.0"},
    ) as session:
        for provider, url in endpoints:
            try:
                async with session.get(url, allow_redirects=False) as response:
                    if response.status != 200:
                        continue
                    data = json.loads(
                        (await read_limited(response, 64 * 1024)).decode()
                    )
                if not isinstance(data, dict) or data.get("success") is False:
                    continue
                ip = str(data.get("ip", ""))
                country = str(data.get("country_code", "")).upper()
                if (
                    public_ipv4(ip)
                    and len(country) == 2
                    and country.isascii()
                    and country.isalpha()
                ):
                    return {"country_code": country, "ip": ip, "provider": provider}
            except (
                aiohttp.ClientError,
                TimeoutError,
                OSError,
                ValueError,
                UnicodeError,
            ):
                logger.warning("Egress country lookup failed: %s", provider)
    return {"country_code": "", "ip": "", "provider": ""}
