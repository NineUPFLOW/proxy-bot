"""
Оформление сообщений с прокси.
"""

from html import escape

from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton


def build_connect_link(p: dict) -> str:
    proto = p["protocol"].upper()
    ip, port = p["ip"], p["port"]

    if proto == "MTPROTO":
        return f"tg://proxy?server={ip}&port={port}&secret={p['secret']}"
    if proto == "SOCKS5":
        return f"tg://socks?server={ip}&port={port}"
    if proto == "WEB":
        if port and int(port) != 443:
            return f"tg://webproxy?server={ip}&port={port}&secret={p['secret']}"
        return f"tg://webproxy?server={ip}&secret={p['secret']}"
    return ""


def format_message(p: dict) -> str:
    proto = p["protocol"].upper()
    flag = p.get("flag", "🏳️")
    country = escape(str(p.get("country", "Unknown")))
    city = escape(str(p.get("city", "Unknown")))
    provider = escape(str(p.get("provider", "Unknown")))
    ip_display = escape(str(p.get("ip", "")))
    ping = int(p.get("ping", 0))
    pid = p.get("id", 0)

    return (
        f"🔗 <b>#{pid}</b>: {flag} <b>{country}</b>\n"
        f"\n"
        f"┌ ✅ <b>Название:</b> {flag} {country}\n"
        f"├ 🔗 <b>Протокол:</b> {proto}\n"
        f"├ 🌐 <b>Пинг:</b> {ping} ms\n"
        f"├ 📍 <b>Страна:</b> {flag} {country}\n"
        f"├ 📍 <b>Город:</b> {city}\n"
        f"├ 🏠 <b>Провайдер:</b> {provider}\n"
        f"└ <b>IP:</b> <code>{ip_display}</code>"
    )


def build_keyboard(p: dict):
    link = build_connect_link(p)

    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🔑 Добавить proxy в Telegram", url=link)
    ]])
