"""Telegram messages and connection links. Never confuse server and check location."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from urllib.parse import quote

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from proxy_utils import canonical_secret_hex, secret_kind, valid_hostname


def _trunc(value: object, limit: int) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    try:
        port = int(value)
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def _nonnegative(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    try:
        number = int(value)
    except ValueError:
        return None
    return number if number >= 0 else None


def build_connect_link(proxy: dict) -> str:
    proto = str(proxy.get("protocol", "")).upper()
    server = str(proxy.get("ip", "")).strip()
    port = _port(proxy.get("port"))
    if not port or not valid_hostname(server, domain_only=proto == "WEB"):
        return ""
    if proto == "WEB" and port != 443:
        return ""
    encoded_server = quote(server, safe=".-_[]:")
    if proto == "SOCKS5":
        link = f"tg://socks?server={encoded_server}&port={port}"
        user = str(proxy.get("user", "") or "")
        password = str(proxy.get("pass", "") or "")
        if user:
            link += f"&user={quote(user, safe='')}"
        if password:
            link += f"&pass={quote(password, safe='')}"
        return link
    secret = canonical_secret_hex(str(proxy.get("secret", "")))
    if not secret:
        return ""
    if proto == "MTPROTO":
        return f"tg://proxy?server={encoded_server}&port={port}&secret={secret}"
    if proto == "WEB" and secret_kind(secret) in {"plain", "dd"}:
        return f"tg://webproxy?server={encoded_server}&secret={secret}"
    return ""


def _label(proxy: dict) -> str:
    proto = str(proxy.get("protocol", "")).upper()
    if proto == "MTPROTO":
        kind = secret_kind(str(proxy.get("secret", "")))
        return {"fake_tls": "MTProto · Fake TLS", "dd": "MTProto · Random padding"}.get(
            kind, "MTProto"
        )
    return {"WEB": "WEB Proxy", "SOCKS5": "SOCKS5"}.get(proto, proto or "Unknown")


def _format_date(value: object) -> str:
    try:
        parsed = datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            return "неизвестно"
        return parsed.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M:%S UTC")
    except ValueError:
        return "неизвестно"


def format_message(proxy: dict) -> str:
    """Render the check result without inventing missing measurements."""
    host = _trunc(proxy.get("ip", ""), 253) or "не указан"
    port = _port(proxy.get("port"))
    address = f"{host}:{port}" if port else host
    ping = _nonnegative(proxy.get("ping"))
    successes = _nonnegative(proxy.get("check_successes"))
    total = _nonnegative(proxy.get("check_total"))
    confirmed = _nonnegative(proxy.get("confirmation_ping_ms"))
    ping_label = f"{ping} ms (медиана)" if ping is not None else "неизвестно"
    check_label = (
        f"{successes}/{total}"
        if successes is not None and total and successes <= total
        else "неизвестно"
    )
    country = str(proxy.get("check_country", "")).upper()
    if len(country) != 2 or not country.isascii() or not country.isalpha():
        country = "не определена"
    lines = [
        f"<b>🔹 {escape(_label(proxy))}</b>",
        f"<b>📡 Сервер:</b> <code>{escape(address)}</code>",
        "",
        "<b>Проверка соединения</b>",
        f"<b>⚡ Время ответа:</b> {ping_label}",
        f"<b>🔬 Успешных проверок:</b> {check_label}",
    ]
    if confirmed is not None:
        lines.append(f"<b>✓ Финальная перепроверка:</b> {confirmed} ms")
    lines.extend(
        [
            f"<b>🧭 Точка проверки:</b> {escape(country)} (оценка по внешнему IP)",
            f"<b>🕒 Последняя проверка:</b> {escape(_format_date(proxy.get('checked_at')))}",
        ]
    )
    server_country = _trunc(proxy.get("country", ""), 30)
    if server_country:
        lines.append(f"<b>🌍 Страна сервера:</b> {escape(server_country)}")
    pid = _trunc(proxy.get("id", ""), 40)
    if pid:
        lines.append(f"\n<b>ID:</b> <code>{escape(pid)}</code>")
    lines.append("\nДоступность зависит от сети и может измениться.")
    return "\n".join(lines)


def build_keyboard(proxy: dict) -> InlineKeyboardMarkup | None:
    link = build_connect_link(proxy)
    if not link:
        return None
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔗 Добавить прокси в Telegram", url=link)]
        ]
    )
