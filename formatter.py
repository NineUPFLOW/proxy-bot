"""Telegram message formatting and deep links."""
from __future__ import annotations
from html import escape
from urllib.parse import quote
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


def _trunc(value: object, limit: int) -> str:
    value = str(value or "").strip()
    return value if len(value) <= limit else value[:limit - 1].rstrip() + "…"


def build_connect_link(proxy: dict) -> str:
    proto = str(proxy.get("protocol", "")).upper()
    server = str(proxy.get("ip", "")).strip()
    port = int(proxy.get("port", 0))
    secret = str(proxy.get("secret", "")).strip()
    if not server or not port:
        return ""
    s = quote(server, safe=".-_[]:/")
    if proto == "MTPROTO":
        return f"tg://proxy?server={s}&port={port}&secret={quote(secret, safe='') }"
    if proto == "SOCKS5":
        return f"tg://socks?server={s}&port={port}"
    if proto == "WEB":
        return f"tg://webproxy?server={quote(server, safe='.-_[]:/')}&secret={quote(secret, safe='')}"
    return ""


def _label(proxy: dict) -> str:
    proto = str(proxy.get("protocol", "")).upper()
    secret = str(proxy.get("secret", "")).lower()
    if proto == "MTPROTO":
        label = "MTProto"
        if secret.startswith("dd"):
            label += " · Randomized"
        if proxy.get("probe_resistant"):
            label += " · 🛡 probe"
        return label
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


def build_keyboard(proxy: dict):
    link = build_connect_link(proxy)
    if not link:
        return None
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(
        text="🔗 Добавить proxy в Telegram", url=link
    )]])
