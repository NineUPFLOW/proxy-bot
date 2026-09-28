"""Telegram message formatting and deep links."""
from __future__ import annotations

from html import escape
from urllib.parse import quote
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


def _trunc(value: object, limit: int) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def build_connect_link(proxy: dict) -> str:
    proto = str(proxy.get("protocol", "")).upper()
    server = str(proxy.get("ip", "")).strip()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        return ""
    secret = str(proxy.get("secret", "")).strip()
    if not server or not 1 <= port <= 65535:
        return ""
    encoded_server = quote(server, safe=".-_[]:")
    encoded_secret = quote(secret, safe="")
    if proto == "MTPROTO":
        return f"tg://proxy?server={encoded_server}&port={port}&secret={encoded_secret}"
    if proto == "SOCKS5":
        return f"tg://socks?server={encoded_server}&port={port}"
    if proto == "WEB":
        return f"tg://webproxy?server={encoded_server}&port={port}&secret={encoded_secret}"
    return ""


def _label(proxy: dict) -> str:
    proto = str(proxy.get("protocol", "")).upper()
    secret = str(proxy.get("secret", "")).lower()
    if proto == "MTPROTO":
        return "MTProto · Random padding" if secret.startswith("dd") else "MTProto"
    if proto == "WEB":
        return "WEB Proxy"
    if proto == "SOCKS5":
        return "SOCKS5"
    return proto or "Unknown"


def format_message(proxy: dict) -> str:
    country = _trunc(proxy.get("country", "Unknown"), 20)
    city = _trunc(proxy.get("city", "Unknown"), 20)
    provider = _trunc(proxy.get("provider", "Unknown"), 24)
    host = _trunc(proxy.get("ip", ""), 64)
    flag = str(proxy.get("flag", "🏴") or "🏴")
    try:
        ping = int(proxy.get("ping", 0))
    except (TypeError, ValueError):
        ping = 0
    pid = escape(str(proxy.get("id", "?")))
    return (
        f"<b>#{pid}</b> · {escape(flag)} {escape(country)}\n\n"
        f"<b>🔌 Протокол:</b> {escape(_label(proxy))}\n"
        f"<b>⚡ Пинг:</b> {ping} ms\n"
        f"<b>🌍 Страна:</b> {escape(country)}\n"
        f"<b>🏙 Город:</b> {escape(city)}\n"
        f"<b>🏢 Провайдер:</b> {escape(provider)}\n"
        f"<b>📡 Сервер:</b> <code>{escape(host)}</code>"
    )


def build_keyboard(proxy: dict) -> InlineKeyboardMarkup | None:
    link = build_connect_link(proxy)
    if not link:
        return None
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔗 Добавить proxy в Telegram", url=link)]])
