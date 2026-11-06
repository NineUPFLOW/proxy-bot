"""Shared parsing and identity helpers; no credentials or network at import time."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re

_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


def decode_secret(value: str) -> bytes | None:
    """Decode a Telegram secret, preserving case for base64 and rejecting junk."""
    value = str(value or "").strip()
    if not value or len(value) > 1024:
        return None
    # Telegram accepts hex as well as base64url. Hex has precedence when the
    # spelling could be both; never lowercase a base64 string.
    if len(value) % 2 == 0 and _HEX.fullmatch(value):
        try:
            raw_hex = bytes.fromhex(value)
        except ValueError:
            return None
        # A base64url spelling can coincidentally contain only hex characters.
        # Prefer hex only at possible Telegram secret lengths.
        if len(raw_hex) in (16, 17) or (len(raw_hex) >= 18 and raw_hex[0] == 0xEE):
            return raw_hex
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error):
        return None


def valid_hostname(host: str, *, domain_only: bool = False) -> bool:
    """Syntactic validation only; public-address checks happen at connection time."""
    host = str(host or "").strip().rstrip(".")
    if not host or len(host) > 253 or any(c.isspace() for c in host):
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return not domain_only
    except ValueError:
        pass
    labels = host.split(".")
    # Reject dotted invalid IPv4 literals, as well as single-label/local hosts.
    if len(labels) < 2 or all(label.isdigit() for label in labels):
        return False
    return all(_LABEL.fullmatch(label) is not None for label in labels)


def secret_kind(value: str) -> str:
    raw = decode_secret(value)
    if raw is None:
        return "invalid"
    # A 16-byte key is plain even if its first byte happens to be dd or ee.
    if len(raw) == 16:
        return "plain"
    if len(raw) == 17 and raw[0] == 0xDD:
        return "dd"
    if 18 <= len(raw) <= 270 and raw[0] == 0xEE:
        try:
            domain = raw[17:].decode("ascii")
        except UnicodeDecodeError:
            return "invalid"
        if domain != domain.strip():
            return "invalid"
        return "fake_tls" if valid_hostname(domain, domain_only=True) else "invalid"
    return "invalid"


def canonical_secret_hex(value: str) -> str:
    raw = decode_secret(value)
    return raw.hex() if raw is not None and secret_kind(value) != "invalid" else ""


def normalize_mt_secret(value: str) -> str | None:
    """Compatibility helper for connectors which support only plain and dd."""
    return (
        canonical_secret_hex(value) if secret_kind(value) in {"plain", "dd"} else None
    )


def is_dd_secret(value: str) -> bool:
    return secret_kind(value) == "dd"
