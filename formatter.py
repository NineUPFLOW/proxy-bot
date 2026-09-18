"""
Аккуратное оформление сообщений с прокси.
"""

from html import escape

from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton


# ═══════════════════════════════════════════════════════════════════════
#  ПРОТОКОЛЫ
# ═══════════════════════════════════════════════════════════════════════
PROTO_TITLE = {
    "MTPROTO": "MTProto · Fake TLS",
    "SOCKS5": "SOCKS5",
    "WEB": "WEB · TgWebProxy",
}

PROTO_ICON = {
    "MTPROTO": "🔐",
    "SOCKS5": "🧦",
    "WEB": "🌐",
}


# ═══════════════════════════════════════════════════════════════════════
#  ССЫЛКА
# ═══════════════════════════════════════════════════════════════════════
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


# ═══════════════════════════════════════════════════════════════════════
#  СООБЩЕНИЕ
# ═══════════════════════════════════════════════════════════════════════
def format_message(p: dict) -> str:
    proto = p["protocol"].upper()
    flag = p.get("flag", "🏳️")
    country = escape(str(p.get("country", "Unknown")))
    city = escape(str(p.get("city", "Unknown")))
    provider = escape(str(p.get("provider", "Unknown")))
    ip_display = escape(str(p.get("ip", "")))
    ping = int(p.get("ping", 0))
    title = PROTO_TITLE.get(proto, proto)

    return (
        f"{flag} <b>{country}</b>\n"
        f"<blockquote>{title}\n"
        f"\n"
        f"📍 <code>{ip_display}</code>\n"
        f"🌐 {ping} ms · {city}\n"
        f"🏢 {provider}</blockquote>"
    )


# ═══════════════════════════════════════════════════════════════════════
#  КЛАВИАТУРА
# ═══════════════════════════════════════════════════════════════════════
def build_keyboard(p: dict):
    proto = p["protocol"].upper()
    link = build_connect_link(p)
    icon = PROTO_ICON.get(proto, "🔗")

    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=f"{icon} Подключить", url=link)
    ]])
