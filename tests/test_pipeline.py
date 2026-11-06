"""Offline regression and local-protocol tests for the publication pipeline."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from aiogram.exceptions import TelegramBadRequest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from mtproxy_checker import Mode
from mtproxy_checker.faketls import FAKETLS_CCS
from mtproxy_checker.protocol import frame_message
from yarl import URL

import bot
import checker
import formatter
import network
import sources
import state

PLAIN = "ab" * 16
FAKETLS = "ee" + "12" * 16 + "example.com".encode().hex()


class ParserAndConfigTests(unittest.TestCase):
    def test_imports_without_telegram_credentials(self):
        env = os.environ.copy()
        for key in ("API_ID", "API_HASH", "TG_SESSION", "BOT_TOKEN", "CHAT_ID"):
            env.pop(key, None)
        result = subprocess.run(
            [sys.executable, "-c", "import bot, checker, sources; print('ok')"],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")

    def test_secret_base64_fake_tls_and_dedup(self):
        encoded = base64.urlsafe_b64encode(bytes.fromhex(FAKETLS)).decode().rstrip("=")
        text = (
            f"tg://proxy?server=proxy.example.com&port=443&secret={FAKETLS}\n"
            f"https://t.me/proxy?server=PROXY.example.com.&port=443&secret={encoded}"
        )
        parsed = sources.extract_from_text(text)
        self.assertEqual(len(parsed), 1)
        self.assertTrue(parsed[0]["has_fake_tls"])
        self.assertEqual(parsed[0]["mask_domain"], "example.com")
        self.assertEqual(parsed[0]["secret"], FAKETLS)

    def test_base64_that_looks_like_hex_is_not_misdecoded(self):
        spelling = "a" * 22
        expected = base64.b64decode(spelling + "==").hex()
        self.assertEqual(checker.canonical_secret_hex(spelling), expected)
        self.assertEqual(checker.secret_kind(spelling), "plain")

    def test_bad_fake_tls_domains_and_garbage_rejected(self):
        for value in (
            "ee" + "11" * 16,
            "ee" + "11" * 16 + "0a6578616d706c652e636f6d",
            "ee" + "11" * 16 + "ffff",
            "dd" + "11" * 17,
            "a" * 22 + "!!!",
        ):
            self.assertEqual(checker.secret_kind(value), "invalid", value)

    def test_html_and_json_links(self):
        link = f"https://t.me/proxy?server=example.com&port=443&secret={PLAIN}"
        html = f'<a href="{link.replace("&", "&amp;")}">add</a>'
        json_text = json.dumps({"proxies": [{"link": link}]})
        self.assertEqual(len(sources.extract_from_text(html)), 1)
        self.assertEqual(len(sources.extract_from_text(json_text)), 1)

    def test_bare_ip_only_in_socks_feeds(self):
        text = "8.8.8.8:1080\n1.1.1.1:99999\n999.1.1.1:42"
        self.assertEqual(sources.extract_from_text(text), [])
        parsed = sources.extract_from_text(text, default_protocol="SOCKS5")
        self.assertEqual([(x["ip"], x["port"]) for x in parsed], [("8.8.8.8", 1080)])

    def test_socks_auth_does_not_create_an_unauthenticated_duplicate(self):
        items = sources.extract_from_text("socks5://alice:pa%3Ass@8.8.8.8:1080")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["user"], "alice")
        self.assertEqual(items[0]["pass"], "pa:ss")
        self.assertIn("pass=pa%3Ass", formatter.build_connect_link(items[0]))

    def test_public_sources_are_https_not_telegram_channels(self):
        configured = sources.load_sources()
        self.assertGreaterEqual(len(configured), 3)
        for source in configured:
            self.assertTrue(network.safe_https_url(source["url"], forbid_telegram=True))

    def test_invalid_config_does_not_silently_fall_back_to_channels(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sources.json"
            for url in (
                "https://t.me/s/somechannel",
                "https://api.telegram.org/foo",
                "http://example.com/",
                "https://127.0.0.1/",
                "https://u:p@example.com/",
            ):
                path.write_text(json.dumps({"sources": [{"name": "a", "url": url}]}))
                with self.assertRaises(ValueError, msg=url):
                    sources.load_sources(path)

    def test_identity_normalizes_secret_and_preserves_socks_pairs(self):
        b64 = base64.urlsafe_b64encode(bytes.fromhex(PLAIN)).decode().rstrip("=")
        a = {"protocol": "MTPROTO", "ip": "example.com", "port": 443, "secret": PLAIN}
        b = {**a, "secret": b64}
        self.assertEqual(state.proxy_identity(a), state.proxy_identity(b))
        c = {
            "protocol": "SOCKS5",
            "ip": "8.8.8.8",
            "port": 1080,
            "user": "a:b",
            "pass": "c",
        }
        d = {**c, "user": "a", "pass": "b:c"}
        self.assertNotEqual(state.proxy_identity(c), state.proxy_identity(d))

    def test_message_labels_where_test_ran_and_escapes(self):
        proxy = {
            "protocol": "MTPROTO",
            "ip": "8.8.8.8",
            "port": 443,
            "secret": FAKETLS,
            "ping": 123,
            "check_successes": 2,
            "check_total": 3,
            "check_country": "US",
            "country": "<RU>",
            "checked_at": "2026-11-06T17:00:00+00:00",
        }
        text = formatter.format_message(proxy)
        self.assertIn("Fake TLS", text)
        self.assertIn("Точка проверки:</b> US", text)
        self.assertIn("&lt;RU&gt;", text)
        self.assertIn("2/3", text)
        self.assertIn("17:00:00 UTC", text)


class LocalSourcesAndNetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_feeds_and_one_missing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one.txt").write_text(
                f"tg://proxy?server=8.8.8.8&port=443&secret={PLAIN}\n"
            )
            (root / "two.txt").write_text("1.1.1.1:1080\n")
            cfg = {
                "sources": [
                    {"name": "one", "path": "one.txt", "format": "links"},
                    {"name": "missing", "path": "missing.txt", "format": "links"},
                    {"name": "two", "path": "two.txt", "format": "socks5"},
                ]
            }
            path = root / "sources.json"
            path.write_text(json.dumps(cfg))
            result = await sources.fetch_all_proxies(path)
            self.assertEqual({p["protocol"] for p in result}, {"MTPROTO", "SOCKS5"})
            self.assertEqual({p["source"] for p in result}, {"one", "two"})

    async def test_redirect_to_telegram_is_not_followed(self):
        class Response:
            status = 302
            headers = {"Location": "https://t.me/s/channel"}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                pass

        session = Mock()
        session.get.return_value = Response()
        with self.assertRaises(ValueError):
            await sources._download(session, "https://example.com/list")
        self.assertEqual(session.get.call_count, 1)

    async def test_public_resolver_rejects_mixed_private_answers(self):
        infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=infos)):
            self.assertIsNone(await network.resolve_public_ipv4("example.com"))
        self.assertIsNone(await network.resolve_public_ipv4("169.254.169.254"))
        self.assertIsNone(await network.resolve_public_ipv4("::1"))
        self.assertEqual(await network.resolve_public_ipv4("8.8.8.8"), "8.8.8.8")

    async def test_dns_rotation_keeps_the_previously_tested_ip(self):
        infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
        ]
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=infos)):
            self.assertEqual(
                await network.resolve_public_ipv4("example.com"), "1.1.1.1"
            )
            self.assertEqual(
                await network.resolve_public_ipv4("example.com", preferred="8.8.8.8"),
                "8.8.8.8",
            )

    async def test_web_resolver_is_pinned_and_refuses_private_ips(self):
        with self.assertRaises(ValueError):
            network.PinnedIPv4Resolver("example.com", "127.0.0.1")
        resolver = network.PinnedIPv4Resolver("example.com", "8.8.8.8")
        self.assertEqual(
            (await resolver.resolve("example.com", 443))[0]["host"], "8.8.8.8"
        )
        with self.assertRaises(OSError):
            await resolver.resolve("other.example.com", 443)

    async def test_web_trace_disallows_redirects_and_other_hosts(self):
        trace = checker._web_trace("example.com")
        await trace.on_request_start[0](
            None, None, SimpleNamespace(url=URL("https://example.com/x"))
        )
        with self.assertRaises(ValueError):
            await trace.on_request_start[0](
                None, None, SimpleNamespace(url=URL("https://127.0.0.1/"))
            )
        with self.assertRaises(ValueError):
            await trace.on_request_redirect[0](None, None, None)


# Local fake endpoints exercise actual SOCKS, MTProto AES framing and FakeTLS.
def _response(nonce: bytes, *, wrong_nonce: bool = False) -> bytes:
    nonce = b"X" * 16 if wrong_nonce else nonce
    body = struct.pack("<I", 0x05162463) + nonce + b"S" * 16
    return b"\x00" * 8 + struct.pack("<Q", 4) + struct.pack("<I", len(body)) + body


async def _read_abridged(reader):
    first = (await reader.readexactly(1))[0]
    length = (
        int.from_bytes(await reader.readexactly(3), "little") if first == 127 else first
    )
    return await reader.readexactly(length * 4)


class ProtocolIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def _server(self, callback):
        server = await asyncio.start_server(callback, "127.0.0.1", 0)
        self.addAsyncCleanup(self._close_server, server)
        return server.sockets[0].getsockname()[1]

    async def _close_server(self, server):
        server.close()
        await server.wait_closed()

    async def test_socks_checks_real_dc_request_and_validates_nonce(self):
        targets = []

        async def handler(reader, writer):
            try:
                greeting = await reader.readexactly(2)
                await reader.readexactly(greeting[1])
                writer.write(b"\x05\x00")
                await writer.drain()
                head = await reader.readexactly(4)
                self.assertEqual(head[:3], b"\x05\x01\x00")
                self.assertEqual(head[3], 1)
                ip = socket.inet_ntoa(await reader.readexactly(4))
                port = int.from_bytes(await reader.readexactly(2), "big")
                targets.append((ip, port))
                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                self.assertEqual(await reader.readexactly(1), b"\xef")
                request = await _read_abridged(reader)
                writer.write(frame_message(_response(request[24:40]), Mode.ABRIDGED))
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        port = await self._server(handler)
        self.assertIsNotNone(
            await checker._socks_attempt("127.0.0.1", port, None, None)
        )
        self.assertEqual(targets, [(checker.TELEGRAM_DC_IP, checker.TELEGRAM_DC_PORT)])

    async def test_socks_rejects_a_wrong_nonce(self):
        async def handler(reader, writer):
            try:
                greeting = await reader.readexactly(2)
                await reader.readexactly(greeting[1])
                writer.write(b"\x05\x00")
                await writer.drain()
                await reader.readexactly(10)
                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                await reader.readexactly(1)
                req = await _read_abridged(reader)
                writer.write(
                    frame_message(
                        _response(req[24:40], wrong_nonce=True), Mode.ABRIDGED
                    )
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        port = await self._server(handler)
        self.assertIsNone(await checker._socks_attempt("127.0.0.1", port, None, None))

    async def _mt_server(self, secret: str, wrong_nonce: bool = False):
        raw = bytes.fromhex(secret)
        kind = checker.secret_kind(secret)
        key = raw if kind == "plain" else raw[1:17]
        mode = Mode.ABRIDGED if kind == "plain" else Mode.SECURE

        async def handler(reader, writer):
            buffer = bytearray()

            async def read_data(n):
                if kind != "fake_tls":
                    return await reader.readexactly(n)
                while len(buffer) < n:
                    head = await reader.readexactly(5)
                    data = await reader.readexactly(int.from_bytes(head[3:5], "big"))
                    if head[0] == 0x14:
                        continue
                    self.assertEqual(head[0], 0x17)
                    buffer.extend(data)
                out = bytes(buffer[:n])
                del buffer[:n]
                return out

            try:
                if kind == "fake_tls":
                    hello = await reader.readexactly(517)
                    client_random = hello[11:43]
                    response = bytearray(
                        b"\x16\x03\x03\x00\x26"
                        + b"\x00" * 38
                        + FAKETLS_CCS
                        + b"\x17\x03\x03\x00\x01x"
                    )
                    response[11:43] = hmac.new(
                        key, client_random + bytes(response), hashlib.sha256
                    ).digest()
                    writer.write(response)
                    await writer.drain()
                header = await read_data(64)
                client_key = hashlib.sha256(header[8:40] + key).digest()
                client_iv = header[40:56]
                decr = Cipher(
                    algorithms.AES(client_key), modes.CTR(client_iv)
                ).encryptor()
                decr.update(b"\x00" * 64)  # client consumed 64 bytes for its header
                rev = header[55:7:-1]
                server_key = hashlib.sha256(rev[:32] + key).digest()
                server_iv = rev[32:48]
                encr = Cipher(
                    algorithms.AES(server_key), modes.CTR(server_iv)
                ).encryptor()
                if mode == Mode.ABRIDGED:
                    first = decr.update(await read_data(1))[0]
                    length = first * 4
                else:
                    length = struct.unpack("<I", decr.update(await read_data(4)))[0]
                request = decr.update(await read_data(length))
                response = encr.update(
                    frame_message(
                        _response(request[24:40], wrong_nonce=wrong_nonce), mode
                    )
                )
                if kind == "fake_tls":
                    response = (
                        b"\x17\x03\x03" + struct.pack(">H", len(response)) + response
                    )
                writer.write(response)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        return await self._server(handler)

    async def test_plain_and_dd_full_exchange(self):
        for secret in (PLAIN, "dd" + "12" * 16, "dd" + "12" * 15):
            with self.subTest(secret=secret[:2], length=len(secret)):
                port = await self._mt_server(secret)
                self.assertIsNotNone(
                    await checker._mt_attempt("127.0.0.1", port, secret)
                )

    async def test_faketls_hmac_and_full_exchange(self):
        port = await self._mt_server(FAKETLS)
        self.assertIsNotNone(await checker._mt_attempt("127.0.0.1", port, FAKETLS))

    async def test_faketls_wrong_nonce_rejected(self):
        port = await self._mt_server(FAKETLS, wrong_nonce=True)
        self.assertIsNone(await checker._mt_attempt("127.0.0.1", port, FAKETLS))

    async def test_faketls_rejects_invalid_server_hmac(self):
        async def handler(reader, writer):
            try:
                await reader.readexactly(517)
                # Structurally plausible records, but no valid ServerHello HMAC.
                response = (
                    b"\x16\x03\x03\x00\x26"
                    + b"\x00" * 38
                    + FAKETLS_CCS
                    + b"\x17\x03\x03\x00\x01x"
                )
                writer.write(response)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        port = await self._server(handler)
        self.assertIsNone(await checker._mt_attempt("127.0.0.1", port, FAKETLS))

    async def test_web_uses_exact_plain_secret_and_requires_exchange(self):
        instances = []

        class FakeCarrier:
            def __init__(self, host, secret):
                self.host, self.secret = host, secret
                instances.append(self)

            async def _start_transport(self):
                pass

            async def open_stream(self):
                return 1

            async def disconnect(self):
                pass

        info = SimpleNamespace(carrier_mode="websocket-lanes")
        with (
            patch.object(checker, "WebSocketLanesCarrier", FakeCarrier),
            patch.object(checker, "WEB_PROXY_MODE", "auto"),
            patch.object(checker, "bootstrap_session", AsyncMock(return_value=info)),
            patch.object(checker, "_exchange_mtproxy", AsyncMock()) as exchange,
        ):
            self.assertIsNotNone(
                await checker._web_attempt("example.com", "8.8.8.8", PLAIN)
            )
            self.assertEqual(instances[0].secret, PLAIN)
            self.assertEqual(exchange.await_args.args[1], bytes.fromhex(PLAIN))
            self.assertEqual(exchange.await_args.args[2], Mode.SECURE)


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    def proxy(self):
        return {
            "protocol": "MTPROTO",
            "ip": "example.com",
            "port": 443,
            "secret": FAKETLS,
            "source": "feed",
        }

    async def test_two_of_three_successes_and_dns_preserved(self):
        with (
            patch.object(
                checker, "resolve_public_ipv4", AsyncMock(return_value="8.8.8.8")
            ),
            patch.object(checker, "_attempt", AsyncMock(side_effect=[100, None, 300])),
            patch.object(checker, "geolocate", AsyncMock(return_value={})),
            patch.object(checker, "CHECK_ATTEMPTS", 3),
            patch.object(checker, "CHECK_REQUIRED", 2),
            patch.object(checker, "CHECK_RETRY_DELAY", 0),
        ):
            result = await checker.process_proxy(self.proxy())
        self.assertEqual(result["ip"], "example.com")
        self.assertEqual(result["resolved_ip"], "8.8.8.8")
        self.assertEqual(result["ping"], 200)
        self.assertEqual((result["check_successes"], result["check_total"]), (2, 3))

    async def test_not_enough_successes_never_publish(self):
        with (
            patch.object(
                checker, "resolve_public_ipv4", AsyncMock(return_value="8.8.8.8")
            ),
            patch.object(checker, "_attempt", AsyncMock(side_effect=[100, None, None])),
            patch.object(checker, "CHECK_ATTEMPTS", 3),
            patch.object(checker, "CHECK_REQUIRED", 2),
            patch.object(checker, "CHECK_RETRY_DELAY", 0),
        ):
            self.assertIsNone(await checker.process_proxy(self.proxy()))

    async def test_recheck_rejects_dns_change(self):
        proxy = {**self.proxy(), "resolved_ip": "8.8.8.8"}
        with (
            patch.object(
                checker, "resolve_public_ipv4", AsyncMock(return_value="1.1.1.1")
            ),
            patch.object(checker, "_attempt", AsyncMock()) as attempt,
        ):
            self.assertIsNone(await checker.recheck_proxy(proxy))
            attempt.assert_not_awaited()

    async def test_strict_country_guard_fails_closed(self):
        for country in ("US", ""):
            with (
                self.subTest(country=country),
                patch.object(bot, "REQUIRE_RU_CHECK", True),
                patch.object(
                    bot,
                    "detect_egress_country",
                    AsyncMock(return_value={"country_code": country}),
                ),
                patch.object(bot, "fetch_all_proxies", AsyncMock()) as fetch,
            ):
                with self.assertRaises(RuntimeError):
                    await bot.run(None, dry_run=True)
                fetch.assert_not_awaited()

    async def test_dry_run_does_not_change_state_or_send(self):
        proxy = {
            **self.proxy(),
            "resolved_ip": "8.8.8.8",
            "score": 100,
            "ping": 100,
            "id": "one",
            "check_successes": 3,
            "check_total": 3,
        }
        with (
            patch.object(bot, "REQUIRE_RU_CHECK", False),
            patch.object(
                bot,
                "detect_egress_country",
                AsyncMock(return_value={"country_code": "US"}),
            ),
            patch.object(
                bot, "fetch_all_proxies", AsyncMock(return_value=[self.proxy()])
            ),
            patch.object(bot, "check_group", AsyncMock(side_effect=[[proxy], [], []])),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=proxy)),
            patch.object(bot.state, "init_db") as init,
            patch.object(bot.state, "mark_published") as mark,
            patch.object(bot, "send_message", AsyncMock()) as send,
        ):
            result = await bot.run(None, dry_run=True)
        self.assertEqual(result[0]["check_country"], "US")
        init.assert_not_called()
        mark.assert_not_called()
        send.assert_not_awaited()

    async def test_strict_run_stops_if_egress_changes_during_batch(self):
        proxy = {**self.proxy(), "resolved_ip": "8.8.8.8", "score": 100, "ping": 100}
        locations = [
            {"country_code": "RU", "ip": "1.1.1.1"},
            {"country_code": "RU", "ip": "8.8.8.8"},
        ]
        with (
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(
                bot, "detect_egress_country", AsyncMock(side_effect=locations)
            ),
            patch.object(
                bot, "fetch_all_proxies", AsyncMock(return_value=[self.proxy()])
            ),
            patch.object(bot, "check_group", AsyncMock(side_effect=[[proxy], [], []])),
            patch.object(bot, "recheck_proxy", AsyncMock()) as recheck,
        ):
            with self.assertRaises(RuntimeError):
                await bot.run(None, dry_run=True)
            recheck.assert_not_awaited()

    async def test_failed_final_check_is_backfilled(self):
        first = {
            **self.proxy(),
            "ip": "one.example",
            "resolved_ip": "1.1.1.1",
            "score": 100,
            "ping": 100,
        }
        second = {
            **self.proxy(),
            "ip": "two.example",
            "resolved_ip": "8.8.8.8",
            "score": 90,
            "ping": 120,
        }
        with (
            patch.object(bot, "REQUIRE_RU_CHECK", False),
            patch.object(bot, "PUBLISH_COUNT", 1),
            patch.object(
                bot,
                "detect_egress_country",
                AsyncMock(return_value={"country_code": "US"}),
            ),
            patch.object(
                bot, "fetch_all_proxies", AsyncMock(return_value=[first, second])
            ),
            patch.object(
                bot, "check_group", AsyncMock(side_effect=[[first, second], [], []])
            ),
            patch.object(bot, "recheck_proxy", AsyncMock(side_effect=[None, second])),
        ):
            result = await bot.run(None, dry_run=True)
        self.assertEqual([p["ip"] for p in result], ["two.example"])

    async def test_recheck_failure_blocks_publication(self):
        proxy = {
            **self.proxy(),
            "resolved_ip": "8.8.8.8",
            "score": 100,
            "ping": 100,
            "id": "one",
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(
                bot,
                "detect_egress_country",
                AsyncMock(return_value={"country_code": "RU"}),
            ),
            patch.object(
                bot, "fetch_all_proxies", AsyncMock(return_value=[self.proxy()])
            ),
            patch.object(bot, "check_group", AsyncMock(side_effect=[[proxy], [], []])),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=None)),
            patch.object(bot, "send_message", AsyncMock()) as send,
            patch.object(state, "mark_published") as mark,
        ):
            self.assertEqual(await bot.run(Mock(), 123), [])
            send.assert_not_awaited()
            mark.assert_not_called()

    async def test_successful_send_is_recorded_only_after_publication(self):
        proxy = {
            **self.proxy(),
            "resolved_ip": "8.8.8.8",
            "score": 100,
            "ping": 100,
            "id": "one",
            "check_successes": 3,
            "check_total": 3,
            "checked_at": "2026-11-06T17:00:00+00:00",
        }
        tg_bot = Mock()
        tg_bot.send_message = AsyncMock()
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(bot, "SEND_DELAY", 0),
            patch.object(
                bot,
                "detect_egress_country",
                AsyncMock(return_value={"country_code": "RU", "ip": "1.1.1.1"}),
            ),
            patch.object(
                bot, "fetch_all_proxies", AsyncMock(return_value=[self.proxy()])
            ),
            patch.object(bot, "check_group", AsyncMock(side_effect=[[proxy], [], []])),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=proxy)),
        ):
            result = await bot.run(tg_bot, 123, 42)
            self.assertEqual(len(result), 1)
            self.assertEqual(state.count_published(), 1)
            self.assertEqual(state.filter_unpublished([self.proxy()]), [])
            self.assertEqual(
                tg_bot.send_message.await_args.kwargs["message_thread_id"], 42
            )
            self.assertIn(
                "Точка проверки:</b> RU", tg_bot.send_message.await_args.kwargs["text"]
            )

    async def test_failed_send_is_not_marked_published(self):
        proxy = {
            **self.proxy(),
            "resolved_ip": "8.8.8.8",
            "score": 100,
            "ping": 100,
            "id": "one",
            "check_successes": 3,
            "check_total": 3,
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(
                bot,
                "detect_egress_country",
                AsyncMock(return_value={"country_code": "RU", "ip": "1.1.1.1"}),
            ),
            patch.object(
                bot, "fetch_all_proxies", AsyncMock(return_value=[self.proxy()])
            ),
            patch.object(bot, "check_group", AsyncMock(side_effect=[[proxy], [], []])),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=proxy)),
            patch.object(bot, "send_message", AsyncMock(return_value=False)),
        ):
            with self.assertRaises(RuntimeError):
                await bot.run(Mock(), 123)
            self.assertEqual(state.count_published(), 0)
            self.assertEqual(state.filter_unpublished([self.proxy()]), [self.proxy()])

    async def test_failed_topic_never_falls_back_to_other_topic(self):
        mocked_bot = Mock()
        mocked_bot.send_message = AsyncMock(
            side_effect=TelegramBadRequest(method=Mock(), message="bad topic")
        )
        with (
            patch.object(bot, "MAX_SEND_RETRIES", 2),
            patch.object(bot.asyncio, "sleep", AsyncMock()),
        ):
            self.assertFalse(await bot.send_message(mocked_bot, 1, 42, "text"))
        self.assertEqual(mocked_bot.send_message.await_count, 2)
        self.assertTrue(
            all(
                call.kwargs["message_thread_id"] == 42
                for call in mocked_bot.send_message.await_args_list
            )
        )

    def test_fair_sampling_and_diversity(self):
        many = [{"source": "large", "ip": str(i)} for i in range(100)]
        few = [{"source": "small", "ip": "small" + str(i)} for i in range(2)]
        with patch.object(bot.random, "shuffle", lambda _: None):
            chosen = bot.sample_fair(many + few, 4)
        self.assertEqual(
            [p["source"] for p in chosen], ["large", "small", "large", "small"]
        )
        p1 = {
            **self.proxy(),
            "ip": "one.example",
            "resolved_ip": "8.8.8.8",
            "score": 100,
        }
        p2 = {**p1, "ip": "two.example", "score": 99}
        p3 = {**p1, "ip": "three.example", "resolved_ip": "1.1.1.1", "score": 98}
        with patch.object(bot, "MAX_PER_IP", 1):
            selected = bot.select_proxies([p1, p2, p3])
        self.assertEqual(len(selected), 2)
        self.assertEqual({p["resolved_ip"] for p in selected}, {"8.8.8.8", "1.1.1.1"})

    async def test_only_failed_candidates_enter_cooldown(self):
        good = self.proxy()
        bad = {**good, "ip": "bad.example"}

        async def check(proxy):
            return proxy if proxy["ip"] == good["ip"] else None

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "process_proxy", AsyncMock(side_effect=check)),
        ):
            state.init_db()
            result = await bot.check_group([good, bad], "MTPROTO")
            self.assertEqual(result, [good])
            self.assertEqual(state.filter_unseen([good, bad]), [good])

    async def test_seen_ttl_filter(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
        ):
            state.init_db()
            p = self.proxy()
            self.assertEqual(state.filter_unseen([p]), [p])
            state.mark_seen(p)
            self.assertEqual(state.filter_unseen([p]), [])


if __name__ == "__main__":
    unittest.main()
