"""Unit tests for parsing, secret handling, formatting and state.

Run from the repository root:

    python -m unittest discover -s tests -t . -v

Only stdlib dependencies are required; network access is never used.
"""
from __future__ import annotations

import base64
import contextlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Modules read credentials at import time; provide harmless placeholders.
os.environ.setdefault("API_ID", "1")
os.environ.setdefault("API_HASH", "test")
os.environ.setdefault("BOT_TOKEN", "123456:TEST")
os.environ.setdefault("CHAT_ID", "-1000000000000")

_TMP_DIR = tempfile.mkdtemp(prefix="proxy-bot-tests-")
_TMP_DB = Path(_TMP_DIR) / "state.db"
os.environ["STATE_DB"] = str(_TMP_DB)

import checker  # noqa: E402
import formatter  # noqa: E402
import sources  # noqa: E402
import state  # noqa: E402


def tearDownModule() -> None:
    with contextlib.suppress(OSError):
        os.unlink(_TMP_DB)
    with contextlib.suppress(OSError):
        os.rmdir(_TMP_DIR)


class ExtractFromTextTests(unittest.TestCase):
    def test_tg_proxy_link(self):
        parsed = sources.extract_from_text(
            "tg://proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16
        )
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["protocol"], "MTPROTO")
        self.assertEqual(parsed[0]["ip"], "1.2.3.4")
        self.assertEqual(parsed[0]["port"], 443)

    def test_tme_proxy_link(self):
        parsed = sources.extract_from_text(
            "https://t.me/proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16
        )
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["protocol"], "MTPROTO")

    def test_padded_base64_secret(self):
        raw = bytes(range(16))
        padded = base64.b64encode(raw).decode()
        self.assertTrue(padded.endswith("=="))
        parsed = sources.extract_from_text(
            f"tg://proxy?server=1.2.3.4&port=443&secret={padded}"
        )
        self.assertEqual(len(parsed), 1, "padded base64 secret must be accepted")

    def test_socks5_url_with_auth(self):
        parsed = sources.extract_from_text("socks5://alice:pw@5.6.7.8:1080")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["protocol"], "SOCKS5")
        self.assertEqual(parsed[0]["user"], "alice")
        self.assertEqual(parsed[0]["pass"], "pw")

    def test_bare_ip_only_with_socks_context(self):
        self.assertEqual(sources.extract_from_text("server at 5.6.7.8:1080"), [])
        parsed = sources.extract_from_text("socks5 5.6.7.8:1080")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["protocol"], "SOCKS5")

    def test_invalid_port_rejected(self):
        self.assertEqual(sources.extract_from_text("socks5://1.2.3.4:99999"), [])

    def test_dedup_within_text(self):
        link = "tg://proxy?server=1.2.3.4&port=443&secret=" + "ab" * 16
        parsed = sources.extract_from_text(f"{link}\n{link}")
        self.assertEqual(len(parsed), 1)


class ValidSecretTests(unittest.TestCase):
    def test_hex_16_bytes(self):
        self.assertTrue(sources._valid_secret("ab" * 16))

    def test_dd_hex(self):
        self.assertTrue(sources._valid_secret("dd" + "ab" * 16))

    def test_base64_16_bytes(self):
        self.assertTrue(
            sources._valid_secret(base64.b64encode(bytes(16)).decode())
        )

    def test_too_short_base64_rejected(self):
        self.assertFalse(sources._valid_secret("short"))
        self.assertFalse(sources._valid_secret(""))


class SecretKindTests(unittest.TestCase):
    def test_plain_16_bytes(self):
        self.assertEqual(checker.secret_kind("11" * 16), "plain")

    def test_plain_secret_starting_with_dd_byte_is_not_dd(self):
        # 16-byte secret whose first byte is 0xdd is not a 17-byte dd secret.
        secret = "dd" + "11" * 15
        self.assertEqual(checker.secret_kind(secret), "dd")
        self.assertIsNone(checker.normalize_mt_secret(secret))

    def test_real_dd_secret(self):
        secret = "dd" + "11" * 16
        self.assertEqual(checker.secret_kind(secret), "dd")
        self.assertTrue(checker.is_dd_secret(secret))
        self.assertEqual(checker.normalize_mt_secret(secret), secret)

    def test_fake_tls_secret(self):
        secret = "ee" + "33" * 16 + "0a6578616d706c652e636f6d"
        self.assertEqual(checker.secret_kind(secret), "fake_tls")
        self.assertIsNone(checker.normalize_mt_secret(secret))


class ScoreTests(unittest.TestCase):
    def test_mtproto_beats_web_and_socks(self):
        mt = checker.compute_score({"protocol": "MTPROTO", "ping": 100})
        web = checker.compute_score({"protocol": "WEB", "ping": 100})
        socks = checker.compute_score({"protocol": "SOCKS5", "ping": 100})
        self.assertGreater(mt, web)
        self.assertGreater(web, socks)

    def test_lower_ping_scores_higher(self):
        fast = checker.compute_score({"protocol": "MTPROTO", "ping": 50})
        slow = checker.compute_score({"protocol": "MTPROTO", "ping": 900})
        self.assertGreater(fast, slow)

    def test_bad_ping_does_not_crash(self):
        self.assertIsInstance(
            checker.compute_score({"protocol": "MTPROTO", "ping": "n/a"}), int
        )


class FormatterTests(unittest.TestCase):
    def test_mtproto_link(self):
        link = formatter.build_connect_link(
            {
                "protocol": "MTPROTO",
                "ip": "1.2.3.4",
                "port": 443,
                "secret": "ab" * 16,
            }
        )
        self.assertTrue(link.startswith("tg://proxy?"))

    def test_socks_link_includes_auth(self):
        link = formatter.build_connect_link(
            {
                "protocol": "SOCKS5",
                "ip": "5.6.7.8",
                "port": 1080,
                "user": "alice",
                "pass": "p@ss word",
            }
        )
        self.assertIn("user=alice", link)
        self.assertIn("pass=p%40ss%20word", link)

    def test_socks_link_without_auth(self):
        link = formatter.build_connect_link(
            {"protocol": "SOCKS5", "ip": "5.6.7.8", "port": 1080}
        )
        self.assertEqual(link, "tg://socks?server=5.6.7.8&port=1080")

    def test_invalid_port_returns_empty(self):
        self.assertEqual(
            formatter.build_connect_link(
                {
                    "protocol": "MTPROTO",
                    "ip": "1.2.3.4",
                    "port": 0,
                    "secret": "ab" * 16,
                }
            ),
            "",
        )

    def test_format_message_escapes_html(self):
        text = formatter.format_message(
            {
                "protocol": "MTPROTO",
                "ip": "1.2.3.4",
                "port": 443,
                "ping": 42,
                "country": "<script>",
                "city": "X",
                "provider": "Y",
                "id": "abc",
            }
        )
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("42 ms", text)


class StateTests(unittest.TestCase):
    def setUp(self):
        state.init_db()
        with state._connect() as conn:
            conn.execute("DELETE FROM seen_proxies")
            conn.execute("DELETE FROM published_proxies")

    def test_identity_distinguishes_protocol_and_secret(self):
        a = {"protocol": "MTPROTO", "ip": "1.2.3.4", "port": 443, "secret": "aa" * 16}
        b = {"protocol": "MTPROTO", "ip": "1.2.3.4", "port": 443, "secret": "bb" * 16}
        c = {"protocol": "WEB", "ip": "1.2.3.4", "port": 443, "secret": "aa" * 16}
        self.assertNotEqual(state.proxy_identity(a), state.proxy_identity(b))
        self.assertNotEqual(state.proxy_identity(a), state.proxy_identity(c))

    def test_identity_distinguishes_socks_credentials(self):
        a = {"protocol": "SOCKS5", "ip": "1.2.3.4", "port": 1080, "user": "u1"}
        b = {"protocol": "SOCKS5", "ip": "1.2.3.4", "port": 1080, "user": "u2"}
        self.assertNotEqual(state.proxy_identity(a), state.proxy_identity(b))

    def test_publish_filter_round_trip(self):
        proxy = {
            "protocol": "MTPROTO",
            "ip": "1.2.3.4",
            "port": 443,
            "secret": "aa" * 16,
        }
        self.assertEqual(state.filter_unpublished([proxy]), [proxy])
        state.mark_published(proxy)
        self.assertEqual(state.filter_unpublished([proxy]), [])

    def test_mark_seen(self):
        proxy = {
            "protocol": "MTPROTO",
            "ip": "9.9.9.9",
            "port": 443,
            "secret": "aa" * 16,
        }
        before = state.count_seen()
        state.mark_seen_many([proxy, proxy])
        self.assertEqual(state.count_seen(), before + 1)


if __name__ == "__main__":
    unittest.main()
