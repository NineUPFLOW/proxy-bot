"""Diagnose HTTPS/local source feeds without publishing or changing state.

The JSON report contains aggregate counts only: no URLs, proxy addresses,
credentials or secrets. Optional samples use the same protocol checker as the
bot; they are evidence about this machine's network, not every network in RU.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import checker
import sources
import state
from network import detect_egress_country

# Third-party WEB transport messages can include remote details; the audit emits
# only aggregate information. The normal bot also suppresses these messages.
for _name in (
    "telethon_webproxy",
    "telethon_webproxy.carrier_base",
    "telethon_webproxy.carrier_lanes",
    "telethon_webproxy.carrier_https",
):
    logging.getLogger(_name).setLevel(logging.CRITICAL)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _origin(before: dict, after: dict) -> dict:
    country = str(before.get("country_code", "")).upper()
    stable = bool(
        before.get("ip")
        and after.get("ip") == before.get("ip")
        and country
        and country == str(after.get("country_code", "")).upper()
    )
    # No egress IP is included in the report. Inconclusive geolocation or a
    # changing route must not be labelled as a measurement from Russia.
    return {
        "country_code": country if stable else None,
        "egress_stable": stable,
        "provider": before.get("provider") if stable else None,
    }


async def audit(
    *, path: Path | None = None, sample_per_source: int = 2, concurrency: int = 20
) -> dict:
    if not 0 <= sample_per_source <= 20 or not 1 <= concurrency <= 50:
        raise ValueError("invalid audit sample or concurrency limit")
    if sample_per_source:
        results, before = await asyncio.gather(
            sources.fetch_source_results(path), detect_egress_country()
        )
    else:
        results = await sources.fetch_source_results(path)
        before = {}

    semaphore = asyncio.Semaphore(concurrency)

    async def check(proxy: dict) -> tuple[str, bool]:
        async with semaphore:
            try:
                return proxy["protocol"], bool(await checker.process_proxy(proxy))
            except asyncio.CancelledError:
                raise
            except Exception:
                # Never expose an exception string or a proxy address/secret.
                return proxy["protocol"], False

    samples = [
        random.sample(result["proxies"], min(sample_per_source, len(result["proxies"])))
        for result in results
    ]
    checked = await asyncio.gather(
        *(check(proxy) for sample in samples for proxy in sample)
    )
    after = await detect_egress_country() if sample_per_source else {}
    origin = (
        _origin(before, after)
        if sample_per_source
        else {"country_code": None, "egress_stable": None, "provider": None}
    )
    all_ids = {
        state.proxy_identity(proxy) for result in results for proxy in result["proxies"]
    }
    rows = []
    offset = 0
    for result, sample in zip(results, samples):
        # Allowlist report fields: no source URL/path, proxy IP, auth or secret.
        row = {
            key: result[key]
            for key in (
                "name",
                "status",
                "retrieved_at",
                "last_modified",
                "candidate_counts",
                "error_type",
                "http_status",
            )
            if key in result
        }
        part = checked[offset : offset + len(sample)]
        offset += len(sample)
        per_protocol = {}
        for protocol in sorted({protocol for protocol, _ in part}):
            passes = [ok for name, ok in part if name == protocol]
            per_protocol[protocol] = {"checked": len(passes), "passed": sum(passes)}
        row["sample"] = {
            "checked": len(part),
            "passed": sum(ok for _, ok in part),
            "by_protocol": per_protocol,
        }
        rows.append(row)
    return {
        "generated_at": _now(),
        "check_origin": origin,
        "sample_per_source": sample_per_source,
        "check_attempts": checker.CHECK_ATTEMPTS,
        "check_required": checker.CHECK_REQUIRED,
        "sources_by_status": dict(Counter(row["status"] for row in rows)),
        "unique_candidates": len(all_ids),
        "sample_checked": sum(row["sample"]["checked"] for row in rows),
        "sample_passed": sum(row["sample"]["passed"] for row in rows),
        "sources": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch sources and report aggregate health without publication"
    )
    parser.add_argument("--sample-per-source", type=int, default=2, metavar="0..20")
    parser.add_argument("--concurrency", type=int, default=20, metavar="1..50")
    parser.add_argument(
        "--fail-if-empty",
        action="store_true",
        help="Exit nonzero if every feed is empty",
    )
    parser.add_argument(
        "--fail-if-no-working",
        action="store_true",
        help="Exit nonzero if no sampled candidate passes; requires a nonzero sample",
    )
    parser.add_argument(
        "--require-ru",
        action="store_true",
        help="Exit nonzero if the sampled check is not from a stable Russian egress",
    )
    args = parser.parse_args()
    if not 0 <= args.sample_per_source <= 20 or not 1 <= args.concurrency <= 50:
        parser.error("sample-per-source must be 0..20 and concurrency must be 1..50")
    if (args.fail_if_no_working or args.require_ru) and args.sample_per_source == 0:
        parser.error("--fail-if-no-working and --require-ru require a nonzero sample")
    try:
        report = asyncio.run(
            audit(
                sample_per_source=args.sample_per_source, concurrency=args.concurrency
            )
        )
    except (ValueError, OSError) as exc:
        print(
            f"Audit failed ({type(exc).__name__}); check the source configuration",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.fail_if_empty and report["unique_candidates"] == 0:
        return 1
    if args.fail_if_no_working and report["sample_passed"] == 0:
        return 1
    if args.require_ru and report["check_origin"]["country_code"] != "RU":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
