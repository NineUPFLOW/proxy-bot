# 🔐 Proxy Bot

Telegram-бот, который каждые 10 минут собирает прокси (MTProto / WEB / SOCKS5) из Telegram-каналов, проверяет их и публикует лучшие в чат или тему.

Работает на **GitHub Actions** — без сервера.

## ✨ Возможности

- 📡 Сбор из 17 Telegram-источников, включая темы (Topics)
- 🧠 Анализ Secret — приоритет Fake TLS и probe-resistant
- 🔬 Реальная проверка через handshake Telethon + ya.ru
- 🚫 Фильтр мусора — MAX_PING_MS = 5000
- 📊 Выборка 9 прокси: 3 MTProto + 3 SOCKS5 + 3 WEB
- 💾 SQLite-состояние (seen 2ч, published 24ч)
- 🚀 Автозапуск каждые 10 минут

## 🔐 Секреты (Settings → Secrets and variables → Actions)

| Имя | Обяз. | Описание |
|---|:---:|---|
| BOT_TOKEN | ✅ | Токен от @BotFather |
| CHAT_ID | ✅ | ID чата (например, -1001234567890) |
| TOPIC_ID | ⚠️ | ID темы (если есть). Иначе не добавлять |
| API_ID | ✅ | С my.telegram.org |
| API_HASH | ✅ | С my.telegram.org |
| TG_SESSION | ✅ | Строка сессии Telethon |

### 🔑 TG_SESSION — онлайн-генератор

SSG — String Session Generator: https://gabrielmaialva33.github.io/ssg/

1. Введите API_ID, API_HASH, номер телефона.
2. Введите код из Telegram.
3. Строка придёт в «Избранное» — скопируйте в TG_SESSION.

⚠️ Сессия = полный доступ к аккаунту. Используйте отдельный аккаунт.

### 💬 CHAT_ID

Перешлите любое сообщение из группы боту @userinfobot.

### 🧵 TOPIC_ID

Отправьте сообщение в нужную тему → правый клик → Copy Message Link. Ссылка вида https://t.me/c/1234567890/15/42 — число 15 это TOPIC_ID. Если тем нет — не создавайте секрет.

## 🚀 Запуск

1. Форк репозитория.
2. Добавьте 6 секретов.
3. Actions → Proxy Bot → Run workflow.

Дальше — сам каждые 10 минут.

## 📊 Что публикуется

| Протокол | Проверка | Приоритет |
|---|---|---|
| MTProto Fake TLS | Handshake 3/2 + probe | 🥇 |
| MTProto | Handshake 3/2 | 🥈 |
| WEB | Handshake 3/2 | 🥉 |
| SOCKS5 | Telegram + ya.ru | Обычный |

9 прокси за запуск: 3 MTProto + 3 SOCKS5 + 3 WEB. Чего не хватает — добирается MTProto.

## ⚙️ Настройка

bot.py:

| Параметр | По умолчанию |
|---|:---:|
| PUBLISH_COUNT | 9 |
| TARGET_MT / TARGET_SOCKS5 / TARGET_WEB | 3 / 3 / 3 |
| CONCURRENCY | 20 |
| MAX_MT_CHECK | 400 |
| MAX_SOCKS5_CHECK | 100 |

checker.py:

| Параметр | По умолчанию |
|---|:---:|
| MAX_PING_MS | 5000 |
| MT_ATTEMPTS / MT_REQUIRED | 3 / 2 |

Расписание в .github/workflows/run.yml:

    - cron: '*/10 * * * *'

## 💾 Состояние

SQLite proxy_state.db (в actions/cache, не в git):

| Таблица | TTL |
|---|---|
| seen_proxies | 2 часа |
| published_proxies | 24 часа |

## 🛠 Возможные проблемы

| Проблема | Решение |
|---|---|
| BOT_TOKEN invalid | Проверьте формат 123456:ABC... |
| CHAT_ADMIN_REQUIRED | Сделайте бота админом |
| Message thread not found | Уберите TOPIC_ID или проверьте ID |
| AuthKeyUnregisteredError | Перегенерируйте TG_SESSION |
| Cron не срабатывает | Пустой коммит в README.md + Enable workflow |
| SOCKS5 / WEB не публикуются | Норма — их мало живых |

## 📝 Лицензия

MIT.
