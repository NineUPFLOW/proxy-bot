"""Regression tests for added feed formats, source preservation and auditing."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import audit_sources
import checker
import sources

PLAIN = "ab" * 16
FAKETLS = "ee" + "12" * 16 + "example.com".encode().hex()


class MTProtoFeedTests(unittest.TestCase):
    def test_bare_feed_requires_explicit_format(self):
        text = f"# comments\nProxy.Example.com:443:{PLAIN}\n8.8.8.8:1080\n"
        self.assertEqual(sources.extract_from_text(text), [])
        parsed = sources.extract_from_text(text, default_protocol="MTPROTO")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["ip"], "proxy.example.com")
        self.assertEqual(parsed[0]["port"], 443)
        self.assertEqual(parsed[0]["secret"], PLAIN)
        self.assertEqual(parsed[0]["protocol"], "MTPROTO")

    def test_bare_secret_encodings_and_comments(self):
        encoded = base64.urlsafe_b64encode(bytes.fromhex(FAKETLS)).decode().rstrip("=")
        text = f"p.example.com:443:{FAKETLS} # label\np.example.com:443:{encoded}"
        parsed = sources.extract_from_text(text, default_protocol="MTPROTO")
        self.assertEqual(len(parsed), 1)
        self.assertTrue(parsed[0]["has_fake_tls"])
        self.assertEqual(parsed[0]["mask_domain"], "example.com")

    def test_bare_invalid_candidates_are_rejected(self):
        bad = [
            f"proxy.example.com:0:{PLAIN}",
            f"proxy.example.com:99999:{PLAIN}",
            "proxy.example.com:443:short",
            f"localhost:443:{PLAIN}",
            f"[::1]:443:{PLAIN}",
            f"proxy.example.com:443:{PLAIN}:suffix",
            f"proxy.example.com:443.5:{PLAIN}",
        ]
        for text in bad:
            with self.subTest(text=text):
                self.assertEqual(
                    sources.extract_from_text(text, default_protocol="MTPROTO"), []
                )

    def test_structured_json_only_with_mtproto_format(self):
        data = json.dumps(
            {"nested": [{"server": "proxy.example.com", "port": 443, "secret": PLAIN}]}
        )
        self.assertEqual(sources.extract_from_text(data), [])
        proxies = sources.extract_from_text(data, default_protocol="MTPROTO")
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["secret"], PLAIN)

    def test_structured_variants_and_link_dedup(self):
        link = f"tg://proxy?server=one.example.com&port=443&secret={PLAIN}"
        text = json.dumps(
            {
                "items": [
                    {
                        "server": "one.example.com",
                        "port": 443,
                        "secret": PLAIN,
                        "type": "mtproto",
                        "link": link,
                    },
                    {"host": "two.example.com", "port": "443", "secret": FAKETLS},
                    {
                        "ip": "8.8.8.8",
                        "port": 2053,
                        "secret": PLAIN,
                        "protocol": "MTPROTO",
                    },
                ]
            }
        )
        parsed = sources.extract_from_text(text, default_protocol="MTPROTO")
        self.assertEqual(
            {p["ip"] for p in parsed}, {"one.example.com", "two.example.com", "8.8.8.8"}
        )
        self.assertEqual(len(parsed), 3)

    def test_structured_wrong_types_invalid_secret_and_ports_rejected(self):
        text = json.dumps(
            [
                {
                    "server": "example.com",
                    "port": 443,
                    "secret": PLAIN,
                    "type": "socks5",
                },
                {"server": "example.com", "port": True, "secret": PLAIN},
                {"server": "example.com", "port": 443.5, "secret": PLAIN},
                {"server": "example.com", "port": 443, "secret": [PLAIN]},
                {"server": [], "port": 443, "secret": PLAIN},
                {"server": "example.com", "port": 443, "secret": "bad"},
            ]
        )
        self.assertEqual(
            sources.extract_from_text(text, default_protocol="MTPROTO"), []
        )

    def test_declared_mtproto_still_extracts_ordinary_links(self):
        link = f"https://t.me/proxy?server=8.8.8.8&port=443&secret={PLAIN}"
        self.assertEqual(
            len(sources.extract_from_text(link, default_protocol="MTPROTO")), 1
        )
        self.assertEqual(
            sources.extract_from_text("8.8.8.8:1080", default_protocol="MTPROTO"), []
        )

    def test_json_api_with_embedded_html(self):
        link = f"tg://proxy?server=8.8.8.8&port=443&secret={PLAIN}"
        payload = json.dumps(
            {"html": f'<a href="{link.replace("&", "&amp;")}">connect</a>', "total": 1}
        )
        self.assertEqual(len(sources.extract_from_text(payload)), 1)

    def test_all_five_original_sources_are_preserved(self):
        expected = {
            "ru-web-api": "https://vnespiska.win/api/proxies-ru.json",
            "web-catalog": "https://raw.githubusercontent.com/ryazhapov/tg-proxy-list/main/proxy.txt",
            "mtproto-catalog": "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
            "proxifly-socks5": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
            "speedx-socks5": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        }
        configured = sources.load_sources()
        self.assertGreaterEqual(len(configured), 25)
        actual = {item["name"]: item for item in configured}
        for name, url in expected.items():
            self.assertEqual(actual[name]["url"], url)
            self.assertEqual(
                actual[name]["format"], "socks5" if name.endswith("socks5") else "links"
            )

    def test_server_modified_date_is_only_metadata(self):
        self.assertEqual(
            sources._http_date("Fri, 06 Nov 2026 15:10:12 GMT"),
            "2026-11-06T15:10:12+00:00",
        )
        self.assertIsNone(sources._http_date(None))
        self.assertIsNone(sources._http_date("not-a-date"))


class SourceResultTests(unittest.IsolatedAsyncioTestCase):
    async def test_results_preserve_per_feed_counts_and_existing_global_dedup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one.txt").write_text(f"8.8.8.8:443:{PLAIN}\n")
            (root / "two.txt").write_text(
                f"tg://proxy?server=8.8.8.8&port=443&secret={PLAIN}\n"
            )
            (root / "empty.txt").write_text("nothing usable")
            config = {
                "sources": [
                    {"name": "one", "path": "one.txt", "format": "mtproto"},
                    {"name": "two", "path": "two.txt", "format": "links"},
                    {"name": "empty", "path": "empty.txt"},
                    {"name": "missing", "path": "missing.txt"},
                ]
            }
            path = root / "sources.json"
            path.write_text(json.dumps(config))
            results = await sources.fetch_source_results(path)
            self.assertEqual(
                [r["status"] for r in results],
                ["candidates", "candidates", "empty", "error"],
            )
            self.assertEqual(results[0]["candidate_counts"], {"MTPROTO": 1})
            self.assertEqual(results[1]["candidate_counts"], {"MTPROTO": 1})
            self.assertIsNotNone(results[0]["last_modified"])
            self.assertIsNotNone(results[2]["retrieved_at"])
            self.assertEqual(results[3]["error_type"], "FileNotFoundError")
            collected = await sources.fetch_all_proxies(path)
            self.assertEqual(len(collected), 1)
            self.assertEqual(collected[0]["source"], "one")

    async def test_private_ip_in_new_format_never_reaches_a_connection(self):
        text = f"127.0.0.1:443:{PLAIN}"
        candidate = sources.extract_from_text(text, default_protocol="MTPROTO")[0]
        with patch.object(checker, "_attempt", AsyncMock()) as attempt:
            self.assertIsNone(await checker.process_proxy(candidate))
            attempt.assert_not_awaited()

    async def test_new_format_still_rejects_telegram_source_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sources.json"
            path.write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "name": "bad",
                                "format": "mtproto",
                                "url": "https://t.me/s/channel",
                            }
                        ]
                    }
                )
            )
            with self.assertRaises(ValueError):
                await sources.fetch_source_results(path)


class AuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_report_contains_aggregates_not_candidate_details(self):
        proxy = {
            "protocol": "MTPROTO",
            "ip": "8.8.8.8",
            "port": 443,
            "secret": PLAIN,
            "source": "test",
        }
        feed = {
            "name": "test",
            "status": "candidates",
            "retrieved_at": "2026-11-06T00:00:00+00:00",
            "last_modified": None,
            "candidate_counts": {"MTPROTO": 1},
            "proxies": [proxy],
            "url": "https://example.com/?key=supersecret",
        }
        geo = {"country_code": "RU", "ip": "1.1.1.1", "provider": "test"}
        with (
            patch.object(
                sources, "fetch_source_results", AsyncMock(return_value=[feed])
            ),
            patch.object(
                audit_sources,
                "detect_egress_country",
                AsyncMock(side_effect=[geo, geo]),
            ),
            patch.object(checker, "process_proxy", AsyncMock(return_value=proxy)),
        ):
            report = await audit_sources.audit(sample_per_source=2)
        self.assertEqual(report["check_origin"]["country_code"], "RU")
        self.assertTrue(report["check_origin"]["egress_stable"])
        self.assertEqual(report["sources"][0]["sample"]["passed"], 1)
        self.assertEqual(report["unique_candidates"], 1)
        rendered = json.dumps(report)
        for secret in ("8.8.8.8", "1.1.1.1", PLAIN, "supersecret", "example.com"):
            self.assertNotIn(secret, rendered)

    async def test_changed_or_unknown_egress_never_labelled_ru(self):
        before = {"country_code": "RU", "ip": "8.8.8.8"}
        changed = {"country_code": "RU", "ip": "1.1.1.1"}
        self.assertEqual(audit_sources._origin(before, changed)["country_code"], None)
        self.assertFalse(audit_sources._origin(before, {})["egress_stable"])
        self.assertFalse(
            audit_sources._origin({"country_code": "RU"}, before)["egress_stable"]
        )

    async def test_zero_sample_has_no_country_lookup_or_proxy_check(self):
        feed = {
            "name": "empty",
            "status": "empty",
            "retrieved_at": None,
            "last_modified": None,
            "candidate_counts": {},
            "proxies": [],
        }
        with (
            patch.object(
                sources, "fetch_source_results", AsyncMock(return_value=[feed])
            ),
            patch.object(audit_sources, "detect_egress_country", AsyncMock()) as geo,
            patch.object(checker, "process_proxy", AsyncMock()) as check,
        ):
            report = await audit_sources.audit(sample_per_source=0)
        geo.assert_not_awaited()
        check.assert_not_awaited()
        self.assertIsNone(report["check_origin"]["egress_stable"])
        self.assertEqual(report["sample_checked"], 0)

    async def test_sample_failure_does_not_abort_other_sources(self):
        proxy = {"protocol": "MTPROTO", "ip": "8.8.8.8", "port": 443, "secret": PLAIN}
        feed = {
            "name": "x",
            "status": "candidates",
            "retrieved_at": None,
            "last_modified": None,
            "candidate_counts": {"MTPROTO": 1},
            "proxies": [proxy],
        }
        geo = {"country_code": "US", "ip": "1.1.1.1"}
        with (
            patch.object(
                sources, "fetch_source_results", AsyncMock(return_value=[feed])
            ),
            patch.object(
                audit_sources,
                "detect_egress_country",
                AsyncMock(side_effect=[geo, geo]),
            ),
            patch.object(
                checker, "process_proxy", AsyncMock(side_effect=RuntimeError("secret!"))
            ),
        ):
            report = await audit_sources.audit(sample_per_source=1)
        self.assertEqual(report["sample_checked"], 1)
        self.assertEqual(report["sample_passed"], 0)
        self.assertNotIn("secret!", json.dumps(report))

    async def test_sample_cancellation_is_not_swallowed(self):
        proxy = {"protocol": "MTPROTO", "ip": "8.8.8.8", "port": 443, "secret": PLAIN}
        feed = {
            "name": "x",
            "status": "candidates",
            "retrieved_at": None,
            "last_modified": None,
            "candidate_counts": {"MTPROTO": 1},
            "proxies": [proxy],
        }
        with (
            patch.object(
                sources, "fetch_source_results", AsyncMock(return_value=[feed])
            ),
            patch.object(
                audit_sources, "detect_egress_country", AsyncMock(return_value={})
            ),
            patch.object(
                checker, "process_proxy", AsyncMock(side_effect=asyncio.CancelledError)
            ),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await audit_sources.audit(sample_per_source=1)


class AuditCLITests(unittest.TestCase):
    def test_strict_ru_reports_before_returning_failure(self):
        report = {
            "check_origin": {"country_code": "US"},
            "unique_candidates": 10,
            "sample_passed": 2,
        }
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["audit_sources.py", "--require-ru"]),
            patch.object(audit_sources, "audit", new=Mock(return_value="sentinel")),
            patch.object(audit_sources.asyncio, "run", return_value=report),
            contextlib.redirect_stdout(output),
        ):
            status = audit_sources.main()
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output.getvalue()), report)

    def test_fail_if_empty_and_fail_if_no_working(self):
        for flag, report in (
            ("--fail-if-empty", {"unique_candidates": 0, "sample_passed": 0}),
            ("--fail-if-no-working", {"unique_candidates": 3, "sample_passed": 0}),
        ):
            with self.subTest(flag=flag):
                with (
                    patch.object(sys, "argv", ["audit_sources.py", flag]),
                    patch.object(
                        audit_sources, "audit", new=Mock(return_value="sentinel")
                    ),
                    patch.object(audit_sources.asyncio, "run", return_value=report),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(audit_sources.main(), 1)

    def test_require_ru_and_zero_samples_is_an_argument_error(self):
        with (
            patch.object(
                sys,
                "argv",
                ["audit_sources.py", "--sample-per-source", "0", "--require-ru"],
            ),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as exc,
        ):
            audit_sources.main()
        self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
