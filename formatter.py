"""Telegram messages and connection links. Never confuse server and check location."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from urllib.parse import quote

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from proxy_utils import canonical_secret_hex, secret_kind


def _trunc(value: object, limit: int) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def build_connect_link(proxy: dict) -> str:
    proto = str(proxy.get("protocol", "")).upper()
    server = str(proxy.get("ip", "")).strip()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        return ""
    if not server or not 1 <= port <= 65535:
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
    pid = escape(str(proxy.get("id", "?")))
    host = escape(_trunc(proxy.get("ip", ""), 100))
    try:
        ping = max(0, int(proxy.get("ping", 0)))
        successes = int(proxy.get("check_successes", 0))
        total = int(proxy.get("check_total", 0))
    except (TypeError, ValueError):
        ping, successes, total = 0, 0, 0
    country = str(proxy.get("check_country", "")).upper()
    if len(country) != 2 or not country.isascii() or not country.isalpha():
        country = "не определена"
    lines = [
        f"<b>#{pid} · {escape(_label(proxy))}</b>",
        f"<b>📡 Сервер:</b> <code>{host}:{int(proxy.get('port', 0))}</code>",
        f"<b>⚡ Время ответа:</b> {ping} ms (медиана)",
        f"<b>🔬 Успешных проверок:</b> {successes}/{total} + перед публикацией",
        f"<b>🧭 Точка проверки:</b> {escape(country)} (оценка по внешнему IP)",
        f"<b>🕒 Последняя проверка:</b> {escape(_format_date(proxy.get('checked_at')))}",
    ]
    server_country = _trunc(proxy.get("country", ""), 30)
    if server_country:
        lines.append(f"<b>🌍 Страна сервера:</b> {escape(server_country)}")
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
