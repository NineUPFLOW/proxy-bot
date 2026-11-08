"""Select protocol diversity without needlessly colliding on one IP.

This is a bounded augmenting-path search: an already chosen proxy can move to
another candidate of the same protocol to make room for a candidate that has
no other IP. Previously published candidates are fixed and are never moved.
Scores determine search order; they are not a globally optimized objective.
"""

from __future__ import annotations

from collections import Counter

from state import proxy_identity


def _rank(proxy: dict) -> tuple[int, int]:
    try:
        return -int(proxy.get("score", 0)), int(proxy.get("ping", 99999))
    except (TypeError, ValueError):
        return 0, 99999


def _protocol(proxy: dict) -> str:
    return str(proxy.get("protocol", "")).upper()


def _ip(proxy: dict) -> str:
    return str(proxy.get("resolved_ip") or proxy.get("ip", ""))


def select(
    working: list[dict],
    *,
    previous: list[dict],
    targets: dict[str, int],
    max_per_ip: int,
    limit: int,
) -> list[dict]:
    """Fill as many protocol targets as possible, then fill remaining slots.

    Both targets and the per-IP limit include `previous`. A zero per-IP limit
    means unlimited, as it does in the bot's configuration.
    """
    pools = {protocol: [] for protocol in targets}
    ranked = sorted(
        (proxy for proxy in working if _protocol(proxy) in pools), key=_rank
    )
    for proxy in ranked:
        pools[_protocol(proxy)].append(proxy)

    selected: list[dict] = []
    used = {proxy_identity(proxy) for proxy in previous}
    ips = Counter(_ip(proxy) for proxy in previous)
    counts = Counter(_protocol(proxy) for proxy in previous)

    def add(proxy: dict) -> None:
        selected.append(proxy)
        used.add(proxy_identity(proxy))
        ips[_ip(proxy)] += 1

    def try_candidate(proxy: dict, visited: set[str]) -> bool:
        identity = proxy_identity(proxy)
        address = _ip(proxy)
        if identity in used or address in visited:
            return False
        visited.add(address)
        if not max_per_ip or ips[address] < max_per_ip:
            add(proxy)
            return True

        # This address is full. Move one selected candidate to a different
        # address for the same protocol, then put the new candidate here.
        # The visited set prevents cycles. Entries in `previous` are fixed.
        for displaced in tuple(selected):
            if _ip(displaced) != address:
                continue
            if try_protocol(_protocol(displaced), visited):
                selected.remove(displaced)
                used.remove(proxy_identity(displaced))
                ips[address] -= 1
                add(proxy)
                return True
        return False

    def try_protocol(protocol: str, visited: set[str]) -> bool:
        return any(try_candidate(proxy, visited) for proxy in pools.get(protocol, []))

    for protocol, target in targets.items():
        remaining = min(
            max(0, target - counts[protocol]),
            max(0, limit - len(previous) - len(selected)),
        )
        for _ in range(remaining):
            if len(previous) + len(selected) >= limit:
                break
            if not try_protocol(protocol, set()):
                break

    # Prefer the original protocol-first order before filling extra slots.
    order = {protocol: index for index, protocol in enumerate(targets)}
    selected.sort(
        key=lambda proxy: (order.get(_protocol(proxy), len(order)), _rank(proxy))
    )

    # Extra slots still prefer score, while allowing rearrangement that avoids
    # blocking an otherwise valid candidate on a shared address.
    for proxy in ranked:
        if len(previous) + len(selected) >= limit:
            break
        try_candidate(proxy, set())
    return selected
