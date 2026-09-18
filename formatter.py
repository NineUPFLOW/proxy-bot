"""
Форматирование сообщений с премиальным оформлением.
Учитывает РУ-сегмент: предупреждения о ТСПУ, рекомендации по протоколам.
"""
import html
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# ─── Иконки по протоколам ──────────────────────────────────────────────
PROTO_ICON = {
    "MTPROTO": "🛡",
    "SOCKS5": "🔗",
    "WEB": "🌐",
}

PROTO_LABEL = {
    "MTPROTO": "MTProto",
    "SOCKS5": "SOCKS5",
    "WEB": "WEB (TgWebProxy)",
}


# ─── Индикаторы качества ───────────────────────────────────────────────
def _ping_badge(ping_ms: int) -> str:
    """Возвращает emoji-индикатор качества пинга."""
    if ping_ms is None:
        return "⚪"
    if ping_ms < 100:
        return "🟢"
    if ping_ms < 300:
        return "🟡"
    if ping_ms < 800:
        return "🟠"
    return "🔴"


def _quality_bar(ping_ms: int, max_ms: int = 2000) -> str:
    """Визуальная шкала качества."""
    if ping_ms is None:
        return "░" * 10
    filled = max(1, min(10, int(10 * (1 - min(ping_ms, max_ms) / max_ms))))
    return "█" * filled + "░" * (10 - filled)


# ─── Построение ссылок ─────────────────────────────────────────────────
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


def _build_label(p: dict) -> str:
    proto = p["protocol"].upper()
    label = PROTO_LABEL.get(proto, proto)

    if proto == "MTPROTO" and p.get("secret", "").startswith("ee"):
        label += " · Fake TLS"
    if proto == "WEB":
        label += " · ⚠️ нестабильный"
    return label


# ─── Форматирование сообщения ──────────────────────────────────────────
def format_message(p: dict) -> str:
    proto = p["protocol"].upper()
    flag = p.get("flag", "🏳️")

    country = html.escape(str(p.get("country", "Unknown")))
    city = html.escape(str(p.get("city", "Unknown")))
    provider = html.escape(str(p.get("provider", "Unknown")))
    ip_display = html.escape(str(p.get("ip", "")))
    ping = p.get("ping", 0)
    ping_str = html.escape(str(ping)) if ping else "N/A"

    icon = PROTO_ICON.get(proto, "📡")
    label = _build_label(p)
    ip_label = "🌍 Домен" if proto == "WEB" else "📍 IP"
    badge = _ping_badge(ping)
    bar = _quality_bar(ping)

    body = (
        f"<b>{flag} {country}</b> · <code>#{p['id']}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"\n"
        f"┌ {icon} <b>{label}</b>\n"
        f"├ {badge} Пинг: <code>{ping_str} ms</code>\n"
        f"├ {bar}\n"
        f"├ 🌍 Страна: {flag} {country}\n"
        f"├ 🏙 Город: {city}\n"
        f"├ 📡 Провайдер: {provider}\n"
        f"└ {ip_label}: <code>{ip_display}</code>\n"
    )

    footer_parts = []

    if proto == "SOCKS5":
        footer_parts.append("✅ Строгая проверка: Telegram + ya.ru пройдены")
        footer_parts.append("🛡 Может быть заблокирован ТСПУ — используйте как резервный")
    if proto == "WEB":
        footer_parts.append("⚠️ WEB-прокси работают нестабильно в РУ-сегменте")
    if proto == "MTPROTO":
        footer_parts.append("🛡 MTProto Fake TLS — устойчив к ТСПУ-блокировкам")
        footer_parts.append("💡 Если не работает — попробуйте переподключиться")

    if footer_parts:
        body += "\n" + "\n".join(footer_parts)

    return body


# ─── Клавиатура ────────────────────────────────────────────────────────
def build_keyboard(p: dict):
    proto = p["protocol"].upper()
    link = build_connect_link(p)

    if proto == "WEB":
        label = "🌐 Подключить WEB-прокси"
    elif proto == "SOCKS5":
        label = "🔗 Подключить SOCKS5"
    elif proto == "MTPROTO":
        label = "🛡 Подключить MTProto"
    else:
        label = "📡 Подключить"

    if not link:
        return None

    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=label, url=link)]]
    )
