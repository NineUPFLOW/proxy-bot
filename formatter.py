import html

from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

PROTO_ICON = {
    "MTPROTO": "🔐",
    "SOCKS5": "🧦",
    "WEB": "🌐",
}

PROTO_LABEL = {
    "MTPROTO": "MTProto",
    "SOCKS5": "SOCKS5",
    "WEB": "WEB (TgWebProxy)",
}


def build_connect_link(p: dict) -> str:
    proto = p["protocol"].upper()
    ip, port = p["ip"], p["port"]

    if proto == "MTPROTO":
        return f"tg://proxy?server={ip}&port={port}&secret={p['secret']}"
    if proto == "SOCKS5":
        return f"tg://socks?server={ip}&port={port}"
    if proto == "WEB":
        # Порт 443 можно не указывать в ссылке, но если источник отдал
        # нестандартный порт — обязательно передаём его явно, иначе
        # ссылка будет вести не туда.
        if port and int(port) != 443:
            return f"tg://webproxy?server={ip}&port={port}&secret={p['secret']}"
        return f"tg://webproxy?server={ip}&secret={p['secret']}"
    return ""


def _build_label(p: dict) -> str:
    proto = p["protocol"].upper()
    label = PROTO_LABEL.get(proto, proto)
    if proto == "MTPROTO" and p.get("secret", "").startswith("ee"):
        label += " · 🛡 Fake TLS"
    if proto == "WEB":
        label += " · ⚠️ нестабильный"
    return label


def format_message(p: dict) -> str:
    proto = p["protocol"].upper()
    flag = p.get("flag", "🏳️")

    # Значения ниже приходят из внешнего API геолокации (ip-api.com) и
    # считаются недоверенными — экранируем перед вставкой в HTML-разметку
    # Telegram, иначе символы вроде < > & сломают отправку сообщения.
    country = html.escape(str(p.get("country", "Unknown")))
    city = html.escape(str(p.get("city", "Unknown")))
    provider = html.escape(str(p.get("provider", "Unknown")))
    ip_display = html.escape(str(p.get("ip", "")))
    ping = html.escape(str(p.get("ping", "N/A")))

    icon = PROTO_ICON.get(proto, "🔗")
    label = _build_label(p)
    ip_label = "🌐 Домен" if proto == "WEB" else "📍 IP"

    body = (
        f"{flag} <b>{country}</b> · <code>#{p['id']}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"\n"
        f"┌ {icon} <b>{label}</b>\n"
        f"├ 🌐 <b>Пинг:</b> <code>{ping}</code>\n"
        f"├ 🏳️ <b>Страна:</b> {flag} {country}\n"
        f"├ 🏙 <b>Город:</b> {city}\n"
        f"├ 🏢 <b>Провайдер:</b> {provider}\n"
        f"└ {ip_label}: <code>{ip_display}</code>\n"
    )

    footer_parts = []
    if proto == "SOCKS5":
        footer_parts.append("✅ Строгая проверка: Telegram + ya.ru пройдены")
    if proto == "WEB":
        footer_parts.append("⚠️ WEB-прокси работают нестабильно")
    if proto == "MTPROTO":
        footer_parts.append("⚠️ MTProto-прокси могут блокироваться ТСПУ")

    if footer_parts:
        body += "\n" + "\n".join(footer_parts)

    return body


def build_keyboard(p: dict):
    proto = p["protocol"].upper()
    link = build_connect_link(p)

    if proto == "WEB":
        label = "🌐 Подключить WEB-прокси"
    elif proto == "SOCKS5":
        label = "🧦 Подключить SOCKS5"
    elif proto == "MTPROTO":
        label = "🔐 Подключить MTProto"
    else:
        label = "🔑 Подключить прокси"

    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=label, url=link)
    ]])
