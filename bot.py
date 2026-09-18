    # ─── 7. Формирование выборки (выбираем ЛУЧШИЕ по score) ───
    # score = protocol_bonus - ping_ms
    # MTProto Fake TLS = +2000, WEB = +1000, SOCKS5 = 0
    working.sort(key=lambda p: p.get("score", 0), reverse=True)

    # Логируем топ-10 для наглядности
    logger.info("Топ-10 по качеству:")
    for p in working[:10]:
        logger.info(
            "  %s %s:%s ping=%sms score=%s",
            p["protocol"], p["ip"], p["port"],
            p.get("ping", "?"), p.get("score", "?"),
        )

    selected = working[:PUBLISH_COUNT]

    if not selected:
        logger.info("Нет прокси для публикации")
        return
