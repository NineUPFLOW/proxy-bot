"""
Проверка прокси. Приоритет — MTProto для РФ.
"""
# (весь оригинальный код без изменений)

# ─── Скоринг ───────────────────────────────────────────────────────────
def compute_score(proxy: dict) -> int:
    """
    MTProto всегда приоритетнее SOCKS5, но внутри протокола сортируем по пингу.
    Формула: base_bonus - min(ping, 5000)
    """
    proto = proxy.get("protocol", "").upper()
    ping = proxy.get("ping", 0)

    base = {
        "MTPROTO": 10000,
        "WEB": 5000,
        "SOCKS5": 0,
    }.get(proto, 0)

    return base - min(ping, 5000)


API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
TG_SESSION = os.environ.get("TG_SESSION")

TEST_URL_TG = "https://api.telegram.org"
TEST_URL_RU = "https://ya.ru"

_http_session: aiohttp.ClientSession | None = None
_geo_cache: dict[str, dict] = {}
_geo_semaphore = asyncio.Semaphore(5)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def _get_http_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(headers=HEADERS)
    return _http_session


async def close_http_session():
    global _http_session
    if _http_session is not None and not _http_session.closed:
        await _http_session.close()
    _http_session = None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


async def _resolve(host: str) -> str | None:
    if _is_ip(host):
        return host
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception as e:
        logger.debug("resolve(%s) failed: %s", host, e)
    return None


def _stable_id(ip: str, port: int) -> int:
    digest = hashlib.md5(f"{ip}:{port}".encode()).hexdigest()
    return int(digest, 16) % 10_000_000


def _country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


async def geolocate(ip: str) -> dict:
    # ... (оригинальный код)

    # ─── Проверка WEB-прокси (MTProto-проверкой, как и MTProto) ───
    # Для веб-прокси можно добавить обычный aiohttp, если захочешь
    # async with aiohttp.ClientSession() as session:
    #     await session.get(f"http://{ip}:{port}", timeout=WEB_CHECK_TIMEOUT)
    # Но по дизайну оставляем MTProto-проверку (гарантирует работоспособность)

# (весь оригинальный код до конца)

async def process_proxy(raw: dict) -> dict | None:
    proto = raw.get("protocol", "").upper()

    if proto == "MTPROTO":
        if not raw.get("secret", "").startswith("ee"):
            return None
        return await check_mtproto(raw)

    if proto == "WEB":
        if not raw.get("secret", "").startswith("dd"):
            return None
        return await check_mtproto(raw)  # <--- MTProto-проверка для WEB (как в оригинале)

    if proto == "SOCKS5":
        return await check_socks5(raw)

    return None
