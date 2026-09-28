"""
Оформление сообщений с прокси.
Добавлена эвристика определения страны по домену для WEB-прокси.
"""
from html import escape
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# ─── НАСТРОЙКИ ОБРЕЗКИ ────────────────────────────────────────────────
MAX_COUNTRY = 16
MAX_CITY = 16
MAX_PROVIDER = 22
MAX_IP = 30


def _trunc(value: str, max_len: int) -> str:
    value = str(value or "").strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - 1].rstrip() + "…"


# ─── ЭВРИСТИКА ПО TLD ─────────────────────────────────────────────────
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
        return ("Unknown", "🏴")
    domain_lower = domain.lower()
    for tld in sorted(_TLD_MAP.keys(), key=len, reverse=True):
        if domain_lower.endswith(tld):
            return _TLD_MAP[tld]
    return ("Unknown", "🏴")


# ─── ССЫЛКА ДЛЯ ПОДКЛЮЧЕНИЯ ──────────────────────────────────────────
def build_connect_link(p: dict) -> str:
    proto = p["protocol"].upper()
    ip = str(p.get("ip", "")).strip()
    port = p.get("port")
    secret = str(p.get("secret", "")).strip()

    if proto == "MTPROTO":
        return f"tg://proxy?server={ip}&port={port}&secret={secret}"
    if proto == "SOCKS5":
        return f"tg://socks?server={ip}&port={port}"
    if proto == "WEB":
        # Telegram принимает webproxy и с портом, и без.
        # Если порт 443 — его можно опустить.
        if port and int(port) != 443:
            return f"tg://webproxy?server={ip}&port={port}&secret={secret}"
        return f"tg://webproxy?server={ip}&secret={secret}"
    return ""


# ─── ЛЕЙБЛ ПРОТОКОЛА ──────────────────────────────────────────────────
def _proto_label(p: dict) -> str:
    proto = p["protocol"].upper()
    secret = p.get("secret", "")
    probe = p.get("probe_resistant", False)

    if proto == "MTPROTO":
        label = "MTProto"
        if secret.startswith("ee"):
            label += " · Fake TLS"
        if probe:
            label += " · 🛡 PROBE"
        return label
    if proto == "WEB":
        return "WEB · TgWebProxy"
    if proto == "SOCKS5":
        return "SOCKS5"
    return proto


# ─── ФОРМАТ СООБЩЕНИЯ ─────────────────────────────────────────────────
def format_message(p: dict) -> str:
    # ─── Безопасное получение значений ───
    country_raw = p.get("country", "Unknown")
    city_raw = p.get("city", "Unknown")
    provider_raw = p.get("provider", "Unknown")
    ip_raw = p.get("ip", "")
    ping_raw = p.get("ping", 0)
    pid_raw = p.get("id", "?")

    # ─── Пинг: приводим к int безопасно ───
    try:
        ping = int(ping_raw)
    except (TypeError, ValueError):
        ping = 0

    # ─── Эвристика для WEB: если страна Unknown — пробуем по домену ───
    if country_raw == "Unknown" and p.get("protocol", "").upper() == "WEB":
        guessed_country, guessed_flag = guess_country_by_domain(ip_raw)
        country_raw = guessed_country
        flag = guessed_flag
    else:
        flag = p.get("flag", "🏴") or "🏴"

    # ─── Экранирование HTML ───
    country = escape(_trunc(country_raw, MAX_COUNTRY))
    city = escape(_trunc(city_raw, MAX_CITY))
    provider = escape(_trunc(provider_raw, MAX_PROVIDER))
    ip_display = escape(_trunc(ip_raw, MAX_IP))
    proto_label = escape(_proto_label(p))
    pid = escape(str(pid_raw))

    # ─── Заголовок: флаг + страна ───
    flag_str = f"{flag} {country}".strip()

    return (
        f"#{pid} | {flag_str}\n"
        f"\n"
        f"┌ ✅ Название: {flag_str}\n"
        f"├ 🔌 Протокол: {proto_label}\n"
        f"├ ⚡ Пинг: {ping} ms\n"
        f"├ 🌍 Страна: {country}\n"
        f"├ 🏙 Город: {city}\n"
        f"├ 🏢 Провайдер: {provider}\n"
        f"└ 📡 IP: `{ip_display}`"
    )


# ─── КЛАВИАТУРА ───────────────────────────────────────────────────────
def build_keyboard(p: dict):
    link = build_connect_link(p)
    if not link:
        return None
    return InlineKeyboardMarkup(
        inline_keyboard=[[
            InlineKeyboardButton(
                text="🔗 Добавить proxy в Telegram",
                url=link,
            )
        ]]
    )
