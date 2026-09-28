"""
Оформление сообщений с прокси.
Добавлена эвристика определения страны по домену для WEB-прокси.
"""

from html import escape
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# ─── НАСТРОЙКИ ОБРЕЗКИ ─────────────────────────────────────────────────
MAX_COUNTRY = 16
MAX_CITY = 16
MAX_PROVIDER = 22
MAX_IP = 30


def _trunc(value: str, max_len: int) -> str:
    value = str(value or "").strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - 1].rstrip() + "…"


# ─── ЭВРИСТИКА ПО TLD ──────────────────────────────────────────────────
_TLD_MAP = {
    ".ru": ("Russia", "🇷🇺"),
    ".de": ("Germany", "🇩🇪"),
    ".nl": ("Netherlands", "🇳🇱"),
    ".fr": ("France", "🇫🇷"),
    ".us": ("United States", "🇺🇸"),
    ".co.uk": ("United Kingdom", "🇬🇧"),
    ".uk": ("United Kingdom", "🇬🇧"),
    ".ir": ("Iran", "🇮🇷"),
    ".fi": ("Finland", "🇫🇮"),
    ".se": ("Sweden", "🇸🇪"),
    ".pl": ("Poland", "🇵🇱"),
    ".tr": ("Turkey", "🇹🇷"),
    ".it": ("Italy", "🇮🇹"),
    ".es": ("Spain", "🇪🇸"),
    ".ch": ("Switzerland", "🇨🇭"),
    ".at": ("Austria", "🇦🇹"),
    ".cz": ("Czechia", "🇨🇿"),
    ".ro": ("Romania", "🇷🇴"),
    ".bg": ("Bulgaria", "🇧🇬"),
}


def guess_country_by_domain(domain: str) -> tuple[str, str]:
    """Возвращает (country, flag) по TLD домена."""
    if not domain:
        return ("Unknown", "🏳️")
    for tld in sorted(_TLD_MAP.keys(), key=len, reverse=True):
        if domain.endswith(tld):
            return _TLD_MAP[tld]
    return ("Unknown", "🏳️")


# ─── ССЫЛКА ДЛЯ ПОДКЛЮЧЕНИЯ ────────────────────────────────────────────
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


# ─── ЛЕЙБЛ ПРОТОКОЛА ───────────────────────────────────────────────────
def _proto_label(p: dict) -> str:
    proto = p["protocol"].upper()
    secret = p.get("secret", "")
    probe = p.get("probe_resistant", False)
    if proto == "MTPROTO":
        label = "MTProto"
        if secret.startswith("ee"):
            label += " · Fake TLS"
        if probe:
            label += " · PROBE"
        return label
    if proto == "WEB":
        return "WEB · TgWebProxy"
    if proto == "SOCKS5":
        return "SOCKS5"
    return proto


# ─── ФОРМАТ СООБЩЕНИЯ ──────────────────────────────────────────────────
def format_message(p: dict) -> str:
    flag = p.get("flag", "🏳️")
    country = escape(_trunc(p.get("country", "Unknown"), MAX_COUNTRY))
    city = escape(_trunc(p.get("city", "Unknown"), MAX_CITY))
    provider = escape(_trunc(p.get("provider", "Unknown"), MAX_PROVIDER))
    ip_display = escape(_trunc(p.get("ip", ""), MAX_IP))
    ping = int(p.get("ping", 0))
    pid = p.get("id", 0)
    proto_label = _proto_label(p)

    # Если страна неизвестна и это WEB — пробуем определить по домену
    if country == "Unknown" and p["protocol"].upper() == "WEB":
        guessed_country, guessed_flag = guess_country_by_domain(p["ip"])
        country = guessed_country
        flag = guessed_flag

    flag_str = f"{flag} {country}"

    return (
        f"🔗 <b>#{pid}</b>  |  {flag_str}\n"
        f"\n"
        f"┌ ✅ <b>Название:</b> {flag_str}\n"
        f"├ 🔗 <b>Протокол:</b> {proto_label}\n"
        f"├ 🌐 <b>Пинг:</b> {ping} ms\n"
        f"├ 📍 <b>Страна:</b> {flag_str}\n"
        f"├ 📍 <b>Город:</b> {city}\n"
        f"├ 🏠 <b>Провайдер:</b> {provider}\n"
        f"└ <b>IP:</b> <code>{ip_display}</code>"
    )


# ─── КЛАВИАТУРА ────────────────────────────────────────────────────────
def build_keyboard(p: dict):
    link = build_connect_link(p)
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🔑 Добавить proxy в Telegram", url=link)
    ]])
