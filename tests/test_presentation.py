"""Presentation, link safety and small-sample fairness regression tests."""

from __future__ import annotations

import unittest
from html.parser import HTMLParser
from unittest.mock import AsyncMock, Mock, patch

import bot
import formatter

PLAIN = "ab" * 16
FAKE_TLS = "ee" + "12" * 16 + b"example.com".hex()


class AllowedMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))


class PresentationTests(unittest.TestCase):
    def example(self):
        return {
            "protocol": "MTPROTO",
            "ip": "proxy.example.com",
            "port": 443,
            "secret": FAKE_TLS,
            "ping": 145,
            "confirmation_ping_ms": 151,
            "check_successes": 2,
            "check_total": 3,
            "check_country": "RU",
            "checked_at": "2026-11-06T17:00:00+00:00",
            "id": "a1b2c3d4e5f6",
        }

    def test_message_retains_key_facts_and_real_recheck(self):
        rendered = formatter.format_message(self.example())
        for expected in (
            "MTProto · Fake TLS",
            "proxy.example.com:443",
            "145 ms (медиана)",
            "2/3",
            "Финальная перепроверка:</b> 151 ms",
            "Точка проверки:</b> RU",
            "06.11.2026 17:00:00 UTC",
            "a1b2c3d4e5f6",
        ):
            self.assertIn(expected, rendered)
        self.assertNotIn(FAKE_TLS, rendered)
        self.assertLess(len(rendered), 4096)

    def test_missing_or_invalid_data_is_not_displayed_as_fake_success(self):
        p = {**self.example(), "port": "not-a-port", "ping": "n/a", "check_total": 0}
        p.pop("confirmation_ping_ms")
        text = formatter.format_message(p)
        self.assertIn("Время ответа:</b> неизвестно", text)
        self.assertIn("Успешных проверок:</b> неизвестно", text)
        self.assertNotIn("Финальная перепроверка", text)
        self.assertNotIn("0/0", text)
        self.assertIsNone(formatter.build_keyboard(p))

    def test_impossible_success_count_does_not_look_real(self):
        p = {**self.example(), "check_successes": 4, "check_total": 3}
        self.assertIn("Успешных проверок:</b> неизвестно", formatter.format_message(p))

    def test_text_escapes_untrusted_fields_and_uses_telegram_supported_tags(self):
        p = {
            **self.example(),
            "id": "<b>untrusted</b>",
            "ip": 'host</code><a href="https://evil.example">',
            "country": '<script>alert("x")</script>',
            "check_country": "<bad>",
        }
        text = formatter.format_message(p)
        parser = AllowedMarkup()
        parser.feed(text)
        self.assertTrue(parser.tags)
        self.assertTrue(
            all(tag in {"b", "code"} and not attrs for tag, attrs in parser.tags)
        )
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("Точка проверки:</b> не определена", text)
        self.assertIsNone(formatter.build_keyboard(p))

    def test_valid_long_hostname_is_not_cut_off_in_message(self):
        host = "a" * 62 + "." + "b" * 62 + ".example.com"
        p = {**self.example(), "ip": host}
        self.assertIn(host + ":443", formatter.format_message(p))
        self.assertIsNotNone(formatter.build_keyboard(p))

    def test_web_button_rejects_non_domain_and_non_443(self):
        p = {**self.example(), "protocol": "WEB", "secret": PLAIN}
        self.assertIsNone(formatter.build_keyboard({**p, "ip": "8.8.8.8"}))
        self.assertIsNone(formatter.build_keyboard({**p, "port": 8443}))
        link = formatter.build_connect_link(p)
        self.assertEqual(link, "tg://webproxy?server=proxy.example.com&secret=" + PLAIN)

    def test_link_validation_rejects_malformed_host_and_boolean_port(self):
        p = self.example()
        for host in (
            "localhost",
            "evil.example/path",
            "evil.example?x=1",
            "a b.example",
        ):
            with self.subTest(host=host):
                self.assertEqual(formatter.build_connect_link({**p, "ip": host}), "")
        self.assertEqual(formatter.build_connect_link({**p, "port": True}), "")
        self.assertEqual(formatter.build_connect_link({**p, "port": 443.5}), "")

    def test_button_keeps_auth_but_message_never_exposes_it(self):
        p = {
            **self.example(),
            "protocol": "SOCKS5",
            "user": "my-user",
            "pass": "p@ss word",
        }
        text = formatter.format_message(p)
        link = formatter.build_connect_link(p)
        self.assertNotIn("my-user", text)
        self.assertNotIn("p@ss word", text)
        self.assertIn("user=my-user", link)
        self.assertIn("pass=p%40ss%20word", link)

    def test_small_limit_does_not_always_start_with_the_first_source(self):
        proxies = [{"source": name, "ip": name} for name in ("one", "two", "three")]
        with patch.object(
            bot.random, "shuffle", side_effect=lambda items: items.reverse()
        ):
            selected = bot.sample_fair(proxies, 2)
        self.assertEqual([p["source"] for p in selected], ["three", "two"])


class SendSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_button_never_reaches_telegram(self):
        telegram = Mock()
        telegram.send_message = AsyncMock()
        p = {"protocol": "SOCKS5", "ip": "evil.example/path", "port": 1080}
        self.assertFalse(await bot.send_message(telegram, 123, None, "text", proxy=p))
        telegram.send_message.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
