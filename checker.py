"""Check a real Telegram MTProto request through each candidate, asynchronously.

Checks originate from this process's network. The server's country is not the
same thing as the check location. No Telegram account/session is needed.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import statistics
import struct
from contextlib import suppress
from datetime import datetime, timezone

import aiohttp
from mtproxy_checker import Mode
from mtproxy_checker.faketls import (
    FAKETLS_APP_DATA_PREFIX,
    FAKETLS_CCS,
    FAKETLS_MAX_APP_DATA,
    make_faketls_client_hello,
    validate_faketls_server_response,
)
from mtproxy_checker.protocol import (
    frame_message,
    make_obfuscated2_handshake,
    make_unencrypted_req_pq_multi,
    parse_res_pq,
)
from python_socks import ProxyType
from python_socks.async_.asyncio import Proxy
from telethon_webproxy import HTTPSCarrier, WebSocketCarrier, WebSocketLanesCarrier
from telethon_webproxy.carrier_base import bootstrap_session

from network import (
    PinnedIPv4Resolver,
    PublicIPv4Resolver,
    read_limited,
    resolve_public_ipv4,
)
from proxy_utils import (
    canonical_secret_hex,
    secret_kind,
)
from proxy_utils import (
    decode_secret as _decode_secret,
)
from proxy_utils import (
    is_dd_secret as is_dd_secret,
)
from proxy_utils import (
    normalize_mt_secret as normalize_mt_secret,
)

logger = logging.getLogger(__name__)
CHECK_TIMEOUT = max(1.0, float(os.getenv("CHECK_TIMEOUT", "8")))
WEB_CHECK_TIMEOUT = max(1.0, float(os.getenv("WEB_CHECK_TIMEOUT", "12")))
SOCKS_CHECK_TIMEOUT = max(1.0, float(os.getenv("SOCKS_CHECK_TIMEOUT", "8")))
MAX_PING_MS = max(1, int(os.getenv("MAX_PING_MS", "5000")))
MAX_WEB_PING_MS = max(1, int(os.getenv("MAX_WEB_PING_MS", "10000")))
CHECK_ATTEMPTS = int(os.getenv("CHECK_ATTEMPTS", "3"))
CHECK_REQUIRED = int(os.getenv("CHECK_REQUIRED", "2"))
CHECK_RETRY_DELAY = max(0.0, float(os.getenv("CHECK_RETRY_DELAY", "0.2")))
if not (1 <= CHECK_REQUIRED <= CHECK_ATTEMPTS <= 10):
    raise ValueError(
        "CHECK_REQUIRED and CHECK_ATTEMPTS must satisfy 1 <= required <= attempts <= 10"
    )
GEO_ENABLED = os.getenv("GEO_ENABLED", "0").lower() in {"1", "true", "yes"}
GEO_TIMEOUT = max(1.0, float(os.getenv("GEO_TIMEOUT", "5")))
MAX_GEO_CONCURRENCY = max(1, int(os.getenv("MAX_GEO_CONCURRENCY", "5")))
WEB_PROXY_MODE = os.getenv("WEB_PROXY_MODE", "auto")
# A real production Telegram DC; SOCKS must relay MTProto, not merely open a port.
TELEGRAM_DC_IP = "149.154.167.51"
TELEGRAM_DC_PORT = 443
MAX_FRAME = 256 * 1024
MAX_WEB_RESPONSE = 256 * 1024
MAX_WEB_FRAMES = 1024

_geo_cache: dict[str, dict] = {}
_geo_sem = asyncio.Semaphore(MAX_GEO_CONCURRENCY)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _flag(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isascii() or not code.isalpha():
        return "🏴"
    return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))


async def geolocate(ip: str) -> dict:
    """Optional server geolocation; failure never makes a proxy look verified."""
    if not GEO_ENABLED:
        return {}
    if ip in _geo_cache:
        return _geo_cache[ip]
    async with _geo_sem:
        if ip in _geo_cache:
            return _geo_cache[ip]
        try:
            connector = aiohttp.TCPConnector(
                resolver=PublicIPv4Resolver(), family=socket.AF_INET
            )
            async with (
                aiohttp.ClientSession(
                    connector=connector,
                    trust_env=False,
                    timeout=aiohttp.ClientTimeout(total=GEO_TIMEOUT),
                    headers={"User-Agent": "proxy-bot/3.0"},
                ) as session,
                session.get(
                    f"https://ipwho.is/{ip}", allow_redirects=False
                ) as response,
            ):
                if response.status != 200:
                    raise ValueError("geo lookup failed")
                import json

                data = json.loads((await read_limited(response, 64 * 1024)).decode())
                if not isinstance(data, dict) or not data.get("success"):
                    raise ValueError("geo lookup failed")
                info = {
                    "country": data.get("country", ""),
                    "countryCode": data.get("country_code", ""),
                    "city": data.get("city", ""),
                    "isp": (data.get("connection") or {}).get("isp", ""),
                }
                _geo_cache[ip] = info
                return info
        except (
            aiohttp.ClientError,
            OSError,
            TimeoutError,
            ValueError,
            UnicodeError,
            AttributeError,
        ):
            logger.debug("Geo lookup failed for %s", ip)
        _geo_cache[ip] = {}
        return {}


def compute_score(proxy: dict) -> int:
    """Prefer the observed success ratio, then latency; no protocol bonuses.

    A few recent checks are a weak sample, not a long-term reliability model.
    The multiplier preserves the priority of a one-unit ratio difference over
    the full bounded latency range.
    """
    try:
        ping = max(0, int(proxy.get("ping", 99999)))
    except (TypeError, ValueError, OverflowError):
        ping = 99999
    try:
        successes = int(proxy.get("check_successes", 0))
        total = int(proxy.get("check_total", 0))
    except (TypeError, ValueError, OverflowError):
        successes = total = 0
    ratio = successes * 10000 // total if 0 <= successes <= total and total > 0 else 0
    return ratio * 10001 - min(ping, 10000)


def enrich(
    proxy: dict, ip: str, ping: int, geo: dict, successes: int, total: int
) -> dict:
    import hashlib

    from state import proxy_identity

    result = dict(proxy)
    country = str(geo.get("countryCode", "")).upper()
    result.update(
        {
            # Preserve the original hostname: it is the address the Telegram client uses.
            "resolved_ip": ip,
            "ping": int(ping),
            "country": geo.get("country", ""),
            "countryCode": country,
            "city": geo.get("city", ""),
            "provider": geo.get("isp", ""),
            "flag": _flag(country),
            "check_successes": successes,
            "check_total": total,
            "checked_at": _now(),
        }
    )
    result["id"] = hashlib.sha256(proxy_identity(result).encode()).hexdigest()[:12]
    result["score"] = compute_score(result)
    return result


class _TCPStream:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader, self.writer = reader, writer

    async def write(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def readexactly(self, n: int) -> bytes:
        return await self.reader.readexactly(n)


class _FakeTLSStream(_TCPStream):
    """Fake-TLS records, with authenticated ServerHello and bounded reads."""

    def __init__(self, reader, writer, key: bytes, domain: str):
        super().__init__(reader, writer)
        self.key, self.domain = key, domain
        self.buffer = bytearray()
        self.first_write = True

    async def _record(self) -> tuple[bytes, bytes]:
        header = await self.reader.readexactly(5)
        if header[1:3] not in {b"\x03\x01", b"\x03\x03"}:
            raise ValueError("invalid FakeTLS record version")
        size = int.from_bytes(header[3:5], "big")
        if size > 65535:
            raise ValueError("FakeTLS record too large")
        return header, await self.reader.readexactly(size)

    async def handshake(self) -> None:
        hello, client_random = make_faketls_client_hello(self.key, self.domain)
        self.writer.write(hello)
        await self.writer.drain()
        first_header, first_body = await self._record()
        if first_header[0] != 0x16:
            raise ValueError("missing FakeTLS ServerHello")
        ccs = await self.reader.readexactly(len(FAKETLS_CCS))
        if ccs != FAKETLS_CCS:
            raise ValueError("missing FakeTLS ChangeCipherSpec")
        app_header, app_body = await self._record()
        if app_header[0] != 0x17:
            raise ValueError("missing FakeTLS application record")
        validate_faketls_server_response(
            self.key,
            client_random,
            first_header + first_body + ccs + app_header + app_body,
        )

    async def write(self, data: bytes) -> None:
        packet = bytearray()
        if self.first_write:
            packet.extend(FAKETLS_CCS)
            self.first_write = False
        for offset in range(0, len(data), FAKETLS_MAX_APP_DATA):
            chunk = data[offset : offset + FAKETLS_MAX_APP_DATA]
            packet.extend(
                FAKETLS_APP_DATA_PREFIX + struct.pack(">H", len(chunk)) + chunk
            )
        self.writer.write(packet)
        await self.writer.drain()

    async def readexactly(self, n: int) -> bytes:
        while len(self.buffer) < n:
            header, payload = await self._record()
            if header[0] == 0x14 and payload == b"\x01":
                continue
            if header[0] != 0x17 or not payload:
                raise ValueError("invalid FakeTLS application data")
            self.buffer.extend(payload)
            if len(self.buffer) > MAX_FRAME + 65535:
                raise ValueError("FakeTLS buffer too large")
        result = bytes(self.buffer[:n])
        del self.buffer[:n]
        return result


class _CarrierStream:
    def __init__(self, carrier, stream_id: int):
        self.carrier, self.stream_id = carrier, stream_id
        self.buffer = bytearray()

    async def write(self, data: bytes) -> None:
        await self.carrier.send_data(self.stream_id, data)

    async def readexactly(self, n: int) -> bytes:
        while len(self.buffer) < n:
            chunk = await self.carrier.recv_data(self.stream_id)
            if not chunk:
                raise ConnectionError("WEB relay closed stream")
            self.buffer.extend(chunk)
            if len(self.buffer) > MAX_FRAME + 65535:
                raise ValueError("WEB relay response too large")
        result = bytes(self.buffer[:n])
        del self.buffer[:n]
        return result


async def _read_frame(stream, decrypt, mode: Mode) -> bytes:
    if mode == Mode.ABRIDGED:
        first = decrypt(await stream.readexactly(1))[0]
        if first == 127:
            length = int.from_bytes(decrypt(await stream.readexactly(3)), "little") * 4
        elif first < 127:
            length = first * 4
        else:
            raise ValueError("invalid abridged frame header")
    else:
        length = struct.unpack("<I", decrypt(await stream.readexactly(4)))[0]
        length &= 0x7FFFFFFF
    if not 1 <= length <= MAX_FRAME:
        raise ValueError("invalid MTProto frame length")
    return decrypt(await stream.readexactly(length))


async def _exchange_mtproxy(stream, key: bytes, mode: Mode) -> None:
    header, encrypt, decrypt = make_obfuscated2_handshake(key, mode, 2)
    await stream.write(header)
    nonce, request = make_unencrypted_req_pq_multi()
    await stream.write(encrypt.update(frame_message(request, mode)))
    response = await _read_frame(stream, decrypt.update, mode)
    parse_res_pq(response, nonce)


async def _close_writer(writer) -> None:
    if writer is not None:
        writer.close()
        with suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 2)


async def _mt_attempt(ip: str, port: int, secret: str) -> int | None:
    raw = _decode_secret(secret)
    kind = secret_kind(secret)
    if not raw or kind == "invalid":
        return None
    key = raw if kind == "plain" else raw[1:17]
    mode = Mode.ABRIDGED if kind == "plain" else Mode.SECURE
    writer = None
    started = asyncio.get_running_loop().time()
    try:
        async with asyncio.timeout(CHECK_TIMEOUT):
            reader, writer = await asyncio.open_connection(
                ip, port, family=socket.AF_INET
            )
            if kind == "fake_tls":
                stream = _FakeTLSStream(reader, writer, key, raw[17:].decode("ascii"))
                await stream.handshake()
            else:
                stream = _TCPStream(reader, writer)
            await _exchange_mtproxy(stream, key, mode)
            return max(1, int((asyncio.get_running_loop().time() - started) * 1000))
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.debug(
            "MTProto check failed for %s:%s (%s)", ip, port, type(exc).__name__
        )
        return None
    finally:
        await _close_writer(writer)


async def _socks_attempt(
    ip: str, port: int, user: str | None, password: str | None
) -> int | None:
    writer = sock = None
    started = asyncio.get_running_loop().time()
    try:
        async with asyncio.timeout(SOCKS_CHECK_TIMEOUT):
            proxy = Proxy(
                ProxyType.SOCKS5,
                host=ip,
                port=port,
                username=user,
                password=password,
                rdns=False,
            )
            sock = await proxy.connect(
                TELEGRAM_DC_IP, TELEGRAM_DC_PORT, timeout=SOCKS_CHECK_TIMEOUT
            )
            reader, writer = await asyncio.open_connection(sock=sock)
            sock = None  # writer owns the socket now
            stream = _TCPStream(reader, writer)
            nonce, request = make_unencrypted_req_pq_multi()
            await stream.write(b"\xef" + frame_message(request, Mode.ABRIDGED))
            response = await _read_frame(stream, lambda data: data, Mode.ABRIDGED)
            parse_res_pq(response, nonce)
            return max(1, int((asyncio.get_running_loop().time() - started) * 1000))
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.debug("SOCKS5 check failed for %s:%s (%s)", ip, port, type(exc).__name__)
        return None
    finally:
        await _close_writer(writer)
        if sock is not None:
            sock.close()


class _BoundedResponse(aiohttp.ClientResponse):
    async def read(self) -> bytes:
        if self._body is None:
            self._body = await read_limited(self, MAX_WEB_RESPONSE)
        return self._body


class _BoundedWebSession:
    """Keep the pinned session, but cap the library's larger WebSocket limit."""

    def __init__(self, session: aiohttp.ClientSession):
        self._session = session

    def ws_connect(self, *args, **kwargs):
        requested = kwargs.get("max_msg_size", MAX_WEB_RESPONSE)
        if not isinstance(requested, int) or requested <= 0:
            requested = MAX_WEB_RESPONSE  # aiohttp treats 0 as unlimited
        kwargs["max_msg_size"] = min(requested, MAX_WEB_RESPONSE)
        return self._session.ws_connect(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._session, name)


def _limit_web_frames(carrier) -> None:
    """Bound all relay frames before the library can enqueue their payloads."""
    dispatch = carrier._dispatch_frame
    total_bytes = 0
    total_frames = 0

    def limited_dispatch(frame_type, stream_id, payload):
        nonlocal total_bytes, total_frames
        total_frames += 1
        total_bytes += 8 + len(payload)  # include the relay frame header
        if total_frames > MAX_WEB_FRAMES or total_bytes > MAX_WEB_RESPONSE:
            raise ValueError("WEB relay frame budget exceeded")
        return dispatch(frame_type, stream_id, payload)

    carrier._dispatch_frame = limited_dispatch


def _web_trace(host: str) -> aiohttp.TraceConfig:
    trace = aiohttp.TraceConfig()

    async def guard(_session, _ctx, params):
        url = params.url
        if url.scheme not in {"https", "wss"} or url.host != host or url.port != 443:
            raise ValueError("WEB relay attempted a request outside its pinned host")

    async def reject_redirect(_session, _ctx, _params):
        raise ValueError("WEB relay redirects are not allowed")

    trace.on_request_start.append(guard)
    trace.on_request_redirect.append(reject_redirect)
    return trace


async def _web_attempt(host: str, ip: str, secret: str) -> int | None:
    """Check WEB via the exact hostname and secret, pinning DNS and forbidding redirects."""
    raw = _decode_secret(secret)
    if not raw or secret_kind(secret) not in {"plain", "dd"}:
        return None
    carrier_types = {
        "websocket-lanes": WebSocketLanesCarrier,
        "websocket": WebSocketCarrier,
        "https": HTTPSCarrier,
        "https-lanes": HTTPSCarrier,
    }
    if WEB_PROXY_MODE != "auto" and WEB_PROXY_MODE not in carrier_types:
        logger.error("Unsupported WEB_PROXY_MODE")
        return None
    carrier = None
    session = None
    started = asyncio.get_running_loop().time()
    try:
        async with asyncio.timeout(WEB_CHECK_TIMEOUT):
            resolver = PinnedIPv4Resolver(host, ip)
            connector = aiohttp.TCPConnector(resolver=resolver, family=socket.AF_INET)
            session = aiohttp.ClientSession(
                connector=connector,
                trust_env=False,
                response_class=_BoundedResponse,
                trace_configs=[_web_trace(host)],
                timeout=aiohttp.ClientTimeout(total=WEB_CHECK_TIMEOUT),
            )
            canonical = canonical_secret_hex(secret)
            info = await bootstrap_session(host, canonical, session, None)
            mode = info.carrier_mode if WEB_PROXY_MODE == "auto" else WEB_PROXY_MODE
            carrier_type = carrier_types.get(mode)
            if carrier_type is None:
                raise ValueError("Unsupported WEB carrier advertised by relay")
            carrier = carrier_type(host, canonical)
            # The pinned library uses private carrier fields here. Limit each
            # WebSocket message and the total frames before they enter its queue.
            _limit_web_frames(carrier)
            carrier._http = _BoundedWebSession(session)
            carrier._session_info = info
            await carrier._start_transport()
            carrier._connected = True
            stream_id = await carrier.open_stream()
            stream = _CarrierStream(carrier, stream_id)
            key = raw if len(raw) == 16 else raw[1:]
            await _exchange_mtproxy(stream, key, Mode.SECURE)
            return max(1, int((asyncio.get_running_loop().time() - started) * 1000))
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.debug("WEB check failed for %s (%s)", host, type(exc).__name__)
        return None
    finally:
        if carrier is not None:
            with suppress(Exception):
                await asyncio.wait_for(carrier.disconnect(), 2)
        if session is not None and not session.closed:
            await session.close()


async def _attempt(proxy: dict, ip: str) -> int | None:
    protocol = str(proxy.get("protocol", "")).upper()
    port = int(proxy["port"])
    if protocol == "MTPROTO":
        return await _mt_attempt(ip, port, str(proxy.get("secret", "")))
    if protocol == "SOCKS5":
        return await _socks_attempt(
            ip, port, proxy.get("user") or None, proxy.get("pass") or None
        )
    if protocol == "WEB":
        return await _web_attempt(str(proxy["ip"]), ip, str(proxy.get("secret", "")))
    return None


def _ping_limit(proxy: dict) -> int:
    return MAX_WEB_PING_MS if proxy.get("protocol") == "WEB" else MAX_PING_MS


async def process_proxy(proxy: dict) -> dict | None:
    """A proxy is eligible only after CHECK_REQUIRED real successful exchanges."""
    host = str(proxy.get("ip", "")).strip()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        return None
    if not host or not 1 <= port <= 65535:
        return None
    ip = await resolve_public_ipv4(host)
    if not ip:
        return None
    times = []
    performed = 0
    for index in range(CHECK_ATTEMPTS):
        performed += 1
        ping = await _attempt(proxy, ip)
        if ping is not None and ping <= _ping_limit(proxy):
            times.append(ping)
        if len(times) + CHECK_ATTEMPTS - performed < CHECK_REQUIRED:
            return None
        if index + 1 < CHECK_ATTEMPTS and CHECK_RETRY_DELAY:
            await asyncio.sleep(CHECK_RETRY_DELAY)
    if len(times) < CHECK_REQUIRED:
        return None
    geo = await geolocate(ip)
    return enrich(proxy, ip, int(statistics.median(times)), geo, len(times), performed)


async def recheck_proxy(proxy: dict) -> dict | None:
    """One fresh round immediately before publication; reject a DNS change."""
    ip = await resolve_public_ipv4(
        str(proxy.get("ip", "")), preferred=proxy.get("resolved_ip")
    )
    if not ip or ip != proxy.get("resolved_ip"):
        return None
    ping = await _attempt(proxy, ip)
    if ping is None or ping > _ping_limit(proxy):
        return None
    result = dict(proxy)
    result["checked_at"] = _now()
    result["confirmation_ping_ms"] = ping
    return result
