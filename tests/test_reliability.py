"""Regression coverage for state safety and final-candidate selection."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import aiohttp
from aiohttp import web
from telethon_webproxy.protocol import FrameType

import bot
import checker
import state

PLAIN = "ab" * 16


class StateSafetyTests(unittest.IsolatedAsyncioTestCase):
    def candidate(self):
        return {
            "protocol": "MTPROTO",
            "ip": "proxy.example.com",
            "port": 443,
            "secret": PLAIN,
            "source": "test-feed",
        }

    async def test_changed_egress_does_not_cool_down_or_record_failed_checks(self):
        candidate = self.candidate()
        locations = [
            {"country_code": "RU", "ip": "1.1.1.1"},
            {"country_code": "US", "ip": "8.8.8.8"},
        ]
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(bot, "SEND_STATUS", True),
            patch.object(
                bot, "detect_egress_country", AsyncMock(side_effect=locations)
            ),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[candidate])),
            patch.object(bot, "process_proxy", AsyncMock(return_value=None)),
            patch.object(bot, "send_message", AsyncMock()) as send,
        ):
            with self.assertRaises(RuntimeError):
                await bot.run(Mock(), 123)
            self.assertEqual(state.filter_unseen([candidate]), [candidate])
            with state._connect() as conn:
                count = conn.execute("SELECT COUNT(*) FROM source_stats").fetchone()[0]
            self.assertEqual(count, 0)
            send.assert_not_awaited()

    async def test_stable_egress_still_cools_down_a_failed_candidate(self):
        candidate = self.candidate()
        location = {"country_code": "RU", "ip": "1.1.1.1"}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(bot, "SEND_STATUS", False),
            patch.object(
                bot, "detect_egress_country", AsyncMock(return_value=location)
            ),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[candidate])),
            patch.object(bot, "process_proxy", AsyncMock(return_value=None)),
        ):
            self.assertEqual(await bot.run(Mock(), 123), [])
            self.assertEqual(state.filter_unseen([candidate]), [])
            with state._connect() as conn:
                row = conn.execute(
                    "SELECT total_fetched, total_working FROM source_stats"
                ).fetchone()
            self.assertEqual(row, (1, 0))

    async def test_same_country_but_changed_ip_is_rejected_before_state_writes(self):
        candidate = self.candidate()
        locations = [
            {"country_code": "RU", "ip": "1.1.1.1"},
            {"country_code": "RU", "ip": "8.8.8.8"},
        ]
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(
                bot, "detect_egress_country", AsyncMock(side_effect=locations)
            ),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[candidate])),
            patch.object(bot, "process_proxy", AsyncMock(return_value=None)),
        ):
            with self.assertRaises(RuntimeError):
                await bot.run(Mock(), 123)
            self.assertEqual(state.filter_unseen([candidate]), [candidate])

    async def test_non_strict_change_discards_even_final_recheck_failure(self):
        candidate = self.candidate()
        working = {**candidate, "resolved_ip": "8.8.4.4", "score": 100, "ping": 100}
        locations = [
            {"country_code": "RU", "ip": "1.1.1.1"},
            {"country_code": "US", "ip": "8.8.8.8"},
        ]
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", False),
            patch.object(
                bot, "detect_egress_country", AsyncMock(side_effect=locations)
            ),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[candidate])),
            patch.object(bot, "process_proxy", AsyncMock(return_value=working)),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=None)),
        ):
            self.assertEqual(await bot.run(Mock(), 123), [])
            self.assertEqual(state.filter_unseen([candidate]), [candidate])
            with state._connect() as conn:
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM source_stats").fetchone()[0], 0
                )


class PublicationLockTests(unittest.IsolatedAsyncioTestCase):
    async def test_parallel_run_is_rejected_before_fetch_and_lock_is_released(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "detect_egress_country", AsyncMock()) as detect,
            patch.object(bot, "fetch_all_proxies", AsyncMock()) as fetch,
        ):
            with state.publication_lock():
                with self.assertRaisesRegex(RuntimeError, "уже"):
                    await bot.run(Mock(), 123)
                script = """
import state, sys
try:
    with state.publication_lock():
        pass
except RuntimeError:
    sys.exit(42)
"""
                probe = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-c",
                    script,
                    env={**os.environ, "STATE_DB": str(Path(tmp) / "state.db")},
                )
                self.assertEqual(await asyncio.wait_for(probe.wait(), 10), 42)
            detect.assert_not_awaited()
            fetch.assert_not_awaited()
            with state.publication_lock():
                pass  # closing the first connection releases the lock

    async def test_process_crash_releases_lock_for_next_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "state.db"
            env = {**os.environ, "STATE_DB": str(db_path)}
            script = (
                "import state, time; "
                "lock=state.publication_lock(); lock.__enter__(); "
                "print('ready', flush=True); time.sleep(120)"
            )
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                script,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                self.assertEqual(
                    await asyncio.wait_for(process.stdout.readline(), 10), b"ready\n"
                )
                with patch.object(state, "DB_PATH", db_path):
                    with self.assertRaises(RuntimeError):
                        with state.publication_lock():
                            pass
                    process.kill()
                    await asyncio.wait_for(process.wait(), 10)
                    with state.publication_lock():
                        pass
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()

    async def test_cancelling_run_releases_the_lock(self):
        entered = asyncio.Event()

        async def waiting_for_location():
            entered.set()
            await asyncio.Event().wait()

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(
                bot,
                "detect_egress_country",
                AsyncMock(side_effect=waiting_for_location),
            ),
        ):
            task = asyncio.create_task(bot.run(Mock(), 123))
            try:
                await asyncio.wait_for(entered.wait(), 5)
                with self.assertRaises(RuntimeError):
                    await bot.run(Mock(), 123)
            finally:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            with state.publication_lock():
                pass

    async def test_dry_run_does_not_create_database_or_lock(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", False),
            patch.object(bot, "detect_egress_country", AsyncMock(return_value={})),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[])),
        ):
            self.assertEqual(await bot.run(None, dry_run=True), [])
            self.assertEqual(list(Path(tmp).iterdir()), [])


class QuotaRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_final_recheck_prefers_reserve_of_missing_protocol(self):
        def candidate(protocol, label, address, score):
            return {
                "protocol": protocol,
                "ip": f"{label}.example.com",
                "port": 443 if protocol != "SOCKS5" else 1080,
                "secret": PLAIN,
                "source": "test-feed",
                "resolved_ip": address,
                "score": score,
                "ping": 100,
                "id": label,
            }

        mt = candidate("MTPROTO", "mt-best", "8.8.8.1", 100)
        mt_extra = candidate("MTPROTO", "mt-extra", "8.8.8.2", 99)
        socks_dead = candidate("SOCKS5", "socks-dead", "8.8.8.3", 70)
        socks_reserve = candidate("SOCKS5", "socks-reserve", "8.8.8.4", 30)
        web = candidate("WEB", "web", "8.8.8.5", 40)
        checked = [mt, mt_extra, socks_dead, socks_reserve, web]

        async def recheck(proxy):
            return None if proxy["id"] == "socks-dead" else dict(proxy)

        with (
            patch.object(bot, "REQUIRE_RU_CHECK", False),
            patch.object(bot, "PUBLISH_COUNT", 3),
            patch.object(bot, "TARGETS", {"MTPROTO": 1, "SOCKS5": 1, "WEB": 1}),
            patch.object(bot, "MAX_PER_IP", 1),
            patch.object(
                bot,
                "detect_egress_country",
                AsyncMock(return_value={"country_code": "US", "ip": "1.1.1.1"}),
            ),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=checked)),
            patch.object(
                bot,
                "check_group",
                AsyncMock(
                    side_effect=[[mt, mt_extra], [socks_dead, socks_reserve], [web]]
                ),
            ),
            patch.object(bot, "recheck_proxy", AsyncMock(side_effect=recheck)),
        ):
            result = await bot.run(None, dry_run=True)
        self.assertEqual({p["protocol"] for p in result}, {"MTPROTO", "SOCKS5", "WEB"})
        self.assertIn("socks-reserve", [p["id"] for p in result])
        self.assertNotIn("mt-extra", [p["id"] for p in result])

    def test_replacements_respect_ips_and_already_filled_protocols(self):
        confirmed = {
            "protocol": "MTPROTO",
            "ip": "mt.example.com",
            "port": 443,
            "secret": PLAIN,
            "resolved_ip": "8.8.8.8",
            "score": 100,
        }
        same_ip = {
            "protocol": "SOCKS5",
            "ip": "one.example.com",
            "port": 1080,
            "resolved_ip": "8.8.8.8",
            "score": 99,
        }
        distinct = {
            "protocol": "SOCKS5",
            "ip": "two.example.com",
            "port": 1080,
            "resolved_ip": "1.1.1.1",
            "score": 30,
        }
        another_mt = {**confirmed, "ip": "extra.example.com", "resolved_ip": "9.9.9.9"}
        with (
            patch.object(bot, "PUBLISH_COUNT", 2),
            patch.object(bot, "TARGETS", {"MTPROTO": 1, "SOCKS5": 1, "WEB": 0}),
            patch.object(bot, "MAX_PER_IP", 1),
        ):
            self.assertEqual(
                bot.select_proxies(
                    [same_ip, distinct, another_mt], already_selected=[confirmed]
                ),
                [distinct],
            )


class WebResourceLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_websocket_transport_enforces_message_limit(self):
        async def oversized(request):
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            await ws.send_bytes(b"X" * (checker.MAX_WEB_RESPONSE + 1))
            await ws.close()
            return ws

        app = web.Application()
        app.router.add_get("/", oversized)
        runner = web.AppRunner(app)
        await runner.setup()
        self.addAsyncCleanup(runner.cleanup)
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        async with aiohttp.ClientSession() as session:
            bounded = checker._BoundedWebSession(session)
            ws = await bounded.ws_connect(
                f"http://127.0.0.1:{port}/", max_msg_size=4 * 1024 * 1024
            )
            self.addAsyncCleanup(ws.close)
            message = await ws.receive(timeout=3)
            self.assertEqual(message.type, aiohttp.WSMsgType.ERROR)
            self.assertEqual(message.data.code, aiohttp.WSCloseCode.MESSAGE_TOO_BIG)

    async def test_web_attempt_installs_both_limits(self):
        carriers = []

        class FakeCarrier:
            def __init__(self, host, secret):
                self.received = []
                carriers.append(self)

            def _dispatch_frame(self, frame_type, stream_id, payload):
                self.received.append(payload)

            async def _start_transport(self):
                assert isinstance(self._http, checker._BoundedWebSession)

            async def open_stream(self):
                return 1

            async def disconnect(self):
                pass

        async def excessive_exchange(stream, _key, _mode):
            chunk = b"x" * (checker.MAX_WEB_RESPONSE // 2)
            stream.carrier._dispatch_frame(FrameType.DATA, 1, chunk)
            stream.carrier._dispatch_frame(FrameType.DATA, 1, chunk)

        with (
            patch.object(checker, "WebSocketLanesCarrier", FakeCarrier),
            patch.object(checker, "WEB_PROXY_MODE", "auto"),
            patch.object(
                checker,
                "bootstrap_session",
                AsyncMock(return_value=SimpleNamespace(carrier_mode="websocket-lanes")),
            ),
            patch.object(
                checker, "_exchange_mtproxy", AsyncMock(side_effect=excessive_exchange)
            ),
        ):
            self.assertIsNone(
                await checker._web_attempt("example.com", "8.8.8.8", PLAIN)
            )
        self.assertEqual(len(carriers[0].received), 1)
        self.assertTrue(carriers[0]._http.closed)

    async def test_websocket_limit_never_increases_a_smaller_limit(self):
        session = Mock()
        bounded = checker._BoundedWebSession(session)
        bounded.ws_connect("wss://example.com", max_msg_size=2048)
        self.assertEqual(session.ws_connect.call_args.kwargs["max_msg_size"], 2048)
        bounded.ws_connect("wss://example.com", max_msg_size=0)
        self.assertEqual(
            session.ws_connect.call_args.kwargs["max_msg_size"],
            checker.MAX_WEB_RESPONSE,
        )

    async def test_carrier_frame_budget_caps_total_queued_data(self):
        class Carrier:
            def __init__(self):
                self.received = []

            def _dispatch_frame(self, frame_type, sid, payload):
                self.received.append(payload)

        carrier = Carrier()
        checker._limit_web_frames(carrier)
        chunk = b"x" * (checker.MAX_WEB_RESPONSE // 2)
        carrier._dispatch_frame(FrameType.DATA, 1, chunk)
        with self.assertRaises(ValueError):
            carrier._dispatch_frame(FrameType.DATA, 1, chunk)
        self.assertEqual(len(carrier.received), 1)

    async def test_carrier_frame_budget_caps_empty_frame_flood(self):
        carrier = Mock()
        checker._limit_web_frames(carrier)
        for _ in range(checker.MAX_WEB_FRAMES):
            carrier._dispatch_frame(FrameType.PING, 0, b"")
        with self.assertRaises(ValueError):
            carrier._dispatch_frame(FrameType.PING, 0, b"")


class SourceParsingSafetyTests(unittest.TestCase):
    def test_malformed_markdown_cannot_stall_the_parser(self):
        # An untrusted source can be as large as 2 MiB. Repeated unmatched
        # delimiters previously made the Markdown regex take quadratic time.
        script = r"""
import sources
assert sources.extract_from_text("[" * 200_000) == []
assert sources.extract_from_text("[]( " * 50_000) == []
text = "[proxy](tg://proxy?server=8.8.8.8&port=443&secret=" + "ab" * 16 + ")"
result = sources.extract_from_text(text)
assert len(result) == 1 and result[0]["ip"] == "8.8.8.8"
"""
        subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            timeout=6,
        )


if __name__ == "__main__":
    unittest.main()
