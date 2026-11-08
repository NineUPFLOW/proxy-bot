"""Regression tests for publication boundaries and workflow secret exposure."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import bot
import state

PLAIN = "ab" * 16
RU = {"country_code": "RU", "ip": "1.1.1.1"}
US = {"country_code": "US", "ip": "8.8.8.8"}


class EgressAtPublicationTests(unittest.IsolatedAsyncioTestCase):
    def candidate(self):
        return {
            "protocol": "MTPROTO",
            "ip": "proxy.example.com",
            "port": 443,
            "secret": PLAIN,
            "source": "feed",
        }

    async def test_strict_guard_stops_if_ip_changes_during_final_recheck(self):
        candidate = self.candidate()
        checked = {**candidate, "resolved_ip": "8.8.4.4", "score": 100, "ping": 100}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(bot, "SEND_DELAY", 0),
            patch.object(
                bot, "detect_egress_country", AsyncMock(side_effect=[RU, RU, US])
            ),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[candidate])),
            patch.object(bot, "process_proxy", AsyncMock(return_value=checked)),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=checked)),
            patch.object(bot, "send_message", AsyncMock(return_value=True)) as send,
        ):
            with self.assertRaises(RuntimeError):
                await bot.run(Mock(), 123)
            send.assert_not_awaited()
            self.assertEqual(state.count_published(), 0)

    async def test_unavailable_egress_lookup_stops_strict_publication(self):
        candidate = self.candidate()
        checked = {**candidate, "resolved_ip": "8.8.4.4", "score": 100, "ping": 100}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(
                bot, "detect_egress_country", AsyncMock(side_effect=[RU, RU, {}])
            ),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[candidate])),
            patch.object(bot, "process_proxy", AsyncMock(return_value=checked)),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=checked)),
            patch.object(bot, "send_message", AsyncMock()) as send,
        ):
            with self.assertRaises(RuntimeError):
                await bot.run(Mock(), 123)
            send.assert_not_awaited()

    async def test_same_country_ip_change_stops_after_first_send(self):
        first = self.candidate()
        second = {**first, "ip": "another.example"}
        first_checked = {**first, "resolved_ip": "8.8.4.4", "score": 100, "ping": 100}
        second_checked = {**second, "resolved_ip": "1.0.0.1", "score": 90, "ping": 110}
        changed_ip = {"country_code": "RU", "ip": "8.8.8.8"}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(bot, "PUBLISH_COUNT", 2),
            patch.object(bot, "SEND_DELAY", 0),
            patch.object(
                bot,
                "detect_egress_country",
                AsyncMock(side_effect=[RU, RU, RU, changed_ip]),
            ),
            patch.object(
                bot, "fetch_all_proxies", AsyncMock(return_value=[first, second])
            ),
            patch.object(
                bot,
                "process_proxy",
                AsyncMock(side_effect=[first_checked, second_checked]),
            ),
            patch.object(bot, "recheck_proxy", AsyncMock(side_effect=lambda p: p)),
            patch.object(bot, "send_message", AsyncMock(return_value=True)) as send,
        ):
            with self.assertRaises(RuntimeError):
                await bot.run(Mock(), 123)
            self.assertEqual(send.await_count, 1)
            self.assertEqual(state.count_published(), 1)

    async def test_non_strict_never_labels_changed_egress_as_ru(self):
        candidate = self.candidate()
        checked = {**candidate, "resolved_ip": "8.8.4.4", "score": 100, "ping": 100}
        with (
            patch.object(bot, "REQUIRE_RU_CHECK", False),
            patch.object(
                bot, "detect_egress_country", AsyncMock(side_effect=[RU, RU, US])
            ),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[candidate])),
            patch.object(bot, "process_proxy", AsyncMock(return_value=checked)),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=checked)),
        ):
            result = await bot.run(None, dry_run=True)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["check_country"], "")

    async def test_failed_final_check_is_not_persisted_if_egress_changed(self):
        candidate = self.candidate()
        checked = {**candidate, "resolved_ip": "8.8.4.4", "score": 100, "ping": 100}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(
                bot, "detect_egress_country", AsyncMock(side_effect=[RU, RU, US])
            ),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[candidate])),
            patch.object(bot, "process_proxy", AsyncMock(return_value=checked)),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=None)),
        ):
            with self.assertRaises(RuntimeError):
                await bot.run(Mock(), 123)
            self.assertEqual(state.filter_unseen([candidate]), [candidate])

    async def test_failed_final_check_is_cooled_down_on_stable_egress(self):
        candidate = self.candidate()
        checked = {**candidate, "resolved_ip": "8.8.4.4", "score": 100, "ping": 100}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(state, "DB_PATH", Path(tmp) / "state.db"),
            patch.object(bot, "REQUIRE_RU_CHECK", True),
            patch.object(bot, "detect_egress_country", AsyncMock(return_value=RU)),
            patch.object(bot, "fetch_all_proxies", AsyncMock(return_value=[candidate])),
            patch.object(bot, "process_proxy", AsyncMock(return_value=checked)),
            patch.object(bot, "recheck_proxy", AsyncMock(return_value=None)),
        ):
            self.assertEqual(await bot.run(Mock(), 123), [])
            self.assertEqual(state.filter_unseen([candidate]), [])


class WorkflowSecretTests(unittest.TestCase):
    def test_job_environment_does_not_expose_secrets_to_install_and_tests(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/run.yml").read_text()
        job_env = workflow.split("    env:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertNotIn("secrets.", job_env)

    def test_secrets_are_limited_to_non_dry_run_publish_step(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/run.yml").read_text()
        publish = workflow.split("      - name: Check and publish\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        self.assertIn("if: ${{ !inputs.dry_run }}", publish)
        self.assertIn("secrets.BOT_TOKEN", publish)
        self.assertEqual(workflow.count("secrets."), publish.count("secrets."))
        dry_run = workflow.split("      - name: Dry run\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        self.assertIn("if: ${{ inputs.dry_run }}", dry_run)
        self.assertNotIn("secrets.", dry_run)


if __name__ == "__main__":
    unittest.main()
