from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton


def build_connect_link(p: dict) -> str:
    proto = p["protocol"].upper()
    ip, port = p["ip"], p["port"]

    if proto == "MTPROTO":
        return f"tg://proxy?server={ip}&port={port}&secret={p['secret']}"
    if proto == "SOCKS5":
        return f"tg://socks?server={ip}&port={port}"
    if proto == "HTTP":
        return f"http://{ip}:{port}"
    if proto == "WEB":
        return f"tg://webproxy?server={ip}&secret={p['secret']}"
    return ""


def format_message(p: dict) -> str:
    proto = p["protocol"].upper()
    flag = p.get("flag", "🏳️")
    country = p.get("country", "Unknown")
    white = p.get("is_white", False)

    header = ""
    if white:
        header = ("💎 WHITE IP PROXY 💎\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  "🔗 Приоритетная публикация: белый IP\n\n")

    white_line = "├ ✅ Белый IP: Да · WHITE IP подтверждён\n" if white \
        else "├ ✅ Белый IP: Нет\n"

    ip_label = "Домен" if proto == "WEB" else "IP"

    body = (
        f"🔗 #{p['id']} | {flag} {country}\n\n"
        f"┌ ✅ Название: {flag} {country}\n"
        f"├ 🔗 Протокол: {proto}\n"
        f"├ 🌐 Пинг: {p.get('ping', 'N/A')}\n"
        f"{white_line}"
        f"├ 📍 Страна: {flag} {country}\n"
        f"├ 📍 Город: {p.get('city', 'Unknown')}\n"
        f"├ 🏠 Провайдер: {p.get('provider', 'Unknown')}\n"
        f"└ {ip_label}: {p['ip']}"
    )

    if proto == "HTTP":
        return f"{header}{body}\n\n{build_connect_link(p)}"

    return f"{header}{body}"


def build_keyboard(p: dict):
    proto = p["protocol"].upper()
    if proto == "HTTP":
        return None

    link = build_connect_link(p)
    label = "🔑 Добавить proxy в Telegram"
    if proto == "WEB":
        label = "🔑 Добавить WEB proxy в Telegram"

    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=label, url=link)
    ]])
