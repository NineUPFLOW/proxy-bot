from html import escape

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
        # Порт 443 подразумевается и НЕ указывается в ссылке
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
    """
    ВАЖНО: country/city/provider приходят из внешнего API (ip-api.com)
    и не считаются доверенными данными. Сообщение отправляется с
    parse_mode=HTML, поэтому спецсимволы (<, >, &) в этих полях нужно
    экранировать — иначе Telegram вернёт ошибку "can't parse entities"
    (и прокси просто не опубликуется) либо в текст попадёт "чужая" HTML-
    разметка.
    """
    proto = p["protocol"].upper()
    flag = p.get("flag", "🏳️")
    country = escape(str(p.get("country", "Unknown")))
    city = escape(str(p.get("city", "Unknown")))
    provider = escape(str(p.get("provider", "Unknown")))
    ping = escape(str(p.get("ping", "N/A")))
    ip = escape(str(p.get("ip", "")))
    pid = escape(str(p.get("id", "")))

    icon = PROTO_ICON.get(proto, "🔗")
    label = escape(_build_label(p))

    ip_label = "🌐 Домен" if proto == "WEB" else "📍 IP"

    body = (
        f"{flag} <b>{country}</b> · <code>#{pid}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"\n"
        f"┌ {icon} <b>{label}</b>\n"
        f"├ 🌐 <b>Пинг:</b> <code>{ping}</code>\n"
        f"├ 🏳️ <b>Страна:</b> {flag} {country}\n"
        f"├ 🏙 <b>Город:</b> {city}\n"
        f"├ 🏢 <b>Провайдер:</b> {provider}\n"
        f"└ {ip_label}: <code>{ip}</code>\n"
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
