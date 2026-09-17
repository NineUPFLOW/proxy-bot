from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# ─── ЭМОДЗИ ПРОТОКОЛОВ ─────────────────────────────────────────────────

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


# ─── ССЫЛКА ДЛЯ ПОДКЛЮЧЕНИЯ ────────────────────────────────────────────

def build_connect_link(p: dict) -> str:
    proto = p["protocol"].upper()
    ip, port = p["ip"], p["port"]

    if proto == "MTPROTO":
        return f"tg://proxy?server={ip}&port={port}&secret={p['secret']}"
    if proto == "SOCKS5":
        return f"tg://socks?server={ip}&port={port}"
    if proto == "WEB":
        return f"tg://webproxy?server={ip}&secret={p['secret']}"
    return ""


# ─── ТЕКСТ СООБЩЕНИЯ ───────────────────────────────────────────────────

def format_message(p: dict) -> str:
    proto = p["protocol"].upper()
    flag = p.get("flag", "🏳️")
    country = p.get("country", "Unknown")
    city = p.get("city", "Unknown")
    provider = p.get("provider", "Unknown")
    ping = p.get("ping", "N/A")
    white = p.get("is_white", False)

    icon = PROTO_ICON.get(proto, "🔗")
    label = PROTO_LABEL.get(proto, proto)

    # ── Шапка ──
    header = ""
    if white:
        header = (
            "💎 <b>WHITE IP PROXY</b> 💎\n"
            "━━━━━━━━━━━━━━━━━━━━━━━\n"
            "⭐️ Приоритетная публикация\n\n"
        )

    # ── Статус белого IP ──
    if white:
        white_line = "├ ✅ <b>Белый IP:</b> Да · подтверждён\n"
        if p.get("white_ips"):
            white_line += f"├ 💎 <b>Белые IP:</b> {', '.join(p['white_ips'])}\n"
    else:
        white_line = "├ ⚪️ <b>Белый IP:</b> Нет\n"

    # ── Подпись IP/домена ──
    ip_label = "🌐 Домен" if proto == "WEB" else "📍 IP"

    # ── Тело сообщения ──
    body = (
        f"{flag} <b>{country}</b> · <code>#{p['id']}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"\n"
        f"┌ {icon} <b>Протокол:</b> {label}\n"
        f"├ 🌐 <b>Пинг:</b> <code>{ping}</code>\n"
        f"{white_line}"
        f"├ 🏳️ <b>Страна:</b> {flag} {country}\n"
        f"├ 🏙 <b>Город:</b> {city}\n"
        f"├ 🏢 <b>Провайдер:</b> {provider}\n"
        f"└ {ip_label}: <code>{p['ip']}</code>\n"
    )

    return f"{header}{body}"


# ─── КЛАВИАТУРА ────────────────────────────────────────────────────────

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
