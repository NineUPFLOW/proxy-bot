"""
Оформление сообщений с прокси.
Все сообщения одинаковой высоты и структуры:
- длинные поля обрезаются до фиксированной длины
- количество строк всегда одинаковое
"""

from html import escape

from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton


# ═══════════════════════════════════════════════════════════════════════
#  НАСТРОЙКИ ОБРЕЗКИ
# ═══════════════════════════════════════════════════════════════════════
MAX_COUNTRY = 16
MAX_CITY = 16
MAX_PROVIDER = 22
MAX_IP = 30


def _trunc(value: str, max_len: int) -> str:
    """Обрезает строку до max_len, добавляя … если нужно."""
    value = str(value or "").strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - 1].rstrip() + "…"


# ═══════════════════════════════════════════════════════════════════════
#  ССЫЛКА ДЛЯ ПОДКЛЮЧЕНИЯ
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
#  ЛЕЙБЛ ПРОТОКОЛА
# ═══════════════════════════════════════════════════════════════════════
def _proto_label(p: dict) -> str:
    proto = p["protocol"].upper()
    secret = p.get("secret", "")

    if proto == "MTPROTO":
        return "MTProto · Fake TLS" if secret.startswith("ee") else "MTProto"
    if proto == "WEB":
        return "WEB · TgWebProxy"
    if proto == "SOCKS5":
        return "SOCKS5"
    return proto


# ═══════════════════════════════════════════════════════════════════════
#  ФОРМАТ СООБЩЕНИЯ
# ═══════════════════════════════════════════════════════════════════════
def format_message(p: dict) -> str:
    flag = p.get("flag", "🏳️")
    country = escape(_trunc(p.get("country", "Unknown"), MAX_COUNTRY))
    city = escape(_trunc(p.get("city", "Unknown"), MAX_CITY))
    provider = escape(_trunc(p.get("provider", "Unknown"), MAX_PROVIDER))
    ip_display = escape(_trunc(p.get("ip", ""), MAX_IP))
    ping = int(p.get("ping", 0))
    pid = p.get("id", 0)
    proto_label = _proto_label(p)

    # Флаг страны с fallback
    flag_str = f"{flag} {country}"

    return (
        f"🔗 <b>#{pid}</b>  |  {flag_str}\n"
        f"\n"
        f"┌ ✅ <b>Название:</b> {flag_str}\n"
        f"├ 🔗 <b>Протокол:</b> {proto_label}\n"
        f"├ 🌐 <b>Пинг:</b> {ping} ms\n"
        f"├ ✅ <b>Белый IP:</b> Нет\n"
        f"├ 📍 <b>Страна:</b> {flag_str}\n"
        f"├ 📍 <b>Город:</b> {city}\n"
        f"├ 🏠 <b>Провайдер:</b> {provider}\n"
        f"└ <b>IP:</b> <code>{ip_display}</code>"
    )


# ═══════════════════════════════════════════════════════════════════════
#  КЛАВИАТУРА
# ═══════════════════════════════════════════════════════════════════════
def build_keyboard(p: dict):
    link = build_connect_link(p)
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🔑 Добавить proxy в Telegram", url=link)
    ]])
