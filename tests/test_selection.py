"""Selection should preserve feasible protocol diversity under per-IP limits."""

from __future__ import annotations

import itertools
import random
import unittest
from collections import Counter
from unittest.mock import patch

import bot
import state
from selection import select


def candidate(protocol: str, label: str, address: str, score: int) -> dict:
    return {
        "protocol": protocol,
        "ip": f"{label}.example",
        "resolved_ip": address,
        "port": 1080 if protocol == "SOCKS5" else 443,
        "secret": "ab" * 16,
        "score": score,
        "ping": 100,
    }


class SelectionTests(unittest.TestCase):
    def test_highest_scored_mt_must_not_block_the_only_socks_candidate(self):
        mt_best = candidate("MTPROTO", "mt-best", "1.1.1.1", 100)
        mt_alternative = candidate("MTPROTO", "mt-alt", "8.8.8.8", 90)
        socks = candidate("SOCKS5", "socks", "1.1.1.1", 80)
        with (
            patch.object(bot, "PUBLISH_COUNT", 2),
            patch.object(bot, "MAX_PER_IP", 1),
            patch.object(bot, "TARGETS", {"MTPROTO": 1, "SOCKS5": 1, "WEB": 0}),
        ):
            selected = bot.select_proxies([mt_best, mt_alternative, socks])
        self.assertEqual(
            {p["ip"] for p in selected}, {"mt-alt.example", "socks.example"}
        )

    def test_can_reassign_across_two_protocols(self):
        proxies = [
            candidate("MTPROTO", "mt-a", "1.1.1.1", 100),
            candidate("MTPROTO", "mt-b", "8.8.8.8", 90),
            candidate("SOCKS5", "socks-b", "8.8.8.8", 80),
            candidate("SOCKS5", "socks-c", "9.9.9.9", 70),
            candidate("WEB", "web-a", "1.1.1.1", 60),
        ]
        selected = select(
            proxies,
            previous=[],
            targets={"MTPROTO": 1, "SOCKS5": 1, "WEB": 1},
            max_per_ip=1,
            limit=3,
        )
        self.assertEqual(
            {p["ip"] for p in selected},
            {"mt-b.example", "socks-c.example", "web-a.example"},
        )

    def test_against_exhaustive_small_cases(self):
        # Compare to every feasible subset, including fixed previous choices.
        # This tests quota coverage and fill count, not global score optimality.
        rng = random.Random(1884)
        protocols = ("MTPROTO", "SOCKS5", "WEB")
        for case in range(300):
            proxies = [
                candidate(
                    rng.choice(protocols),
                    f"p{i}",
                    f"8.8.8.{rng.randint(1, 4)}",
                    rng.randint(1, 100),
                )
                for i in range(rng.randint(0, 8))
            ]
            cap, limit = rng.randint(0, 2), rng.randint(1, 5)
            targets = {protocol: rng.randint(0, 3) for protocol in protocols}
            previous = []
            for proxy in proxies[: rng.randint(0, 2)]:
                used_at_ip = sum(
                    p["resolved_ip"] == proxy["resolved_ip"] for p in previous
                )
                if len(previous) < limit and (not cap or used_at_ip < cap):
                    previous.append(proxy)
            available = [proxy for proxy in proxies if proxy not in previous]
            chosen = select(
                available,
                previous=previous,
                targets=targets,
                max_per_ip=cap,
                limit=limit,
            )
            result = previous + chosen
            counts = Counter(p["protocol"] for p in result)
            ips = Counter(p["resolved_ip"] for p in result)
            identities = {state.proxy_identity(p) for p in result}
            self.assertLessEqual(len(result), limit, case)
            self.assertEqual(len(result), len(identities), case)
            self.assertTrue(
                not cap or all(count <= cap for count in ips.values()), case
            )
            actual = (sum(min(counts[p], targets[p]) for p in protocols), len(result))
            best = (-1, -1)
            for size in range(min(len(available), limit - len(previous)) + 1):
                for subset in itertools.combinations(available, size):
                    trial = previous + list(subset)
                    trial_ips = Counter(p["resolved_ip"] for p in trial)
                    if cap and any(count > cap for count in trial_ips.values()):
                        continue
                    trial_counts = Counter(p["protocol"] for p in trial)
                    score = (
                        sum(min(trial_counts[p], targets[p]) for p in protocols),
                        len(trial),
                    )
                    best = max(best, score)
            self.assertEqual(actual, best, f"case={case}; targets={targets}; cap={cap}")
