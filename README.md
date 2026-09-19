# 🔐 Proxy Bot

Telegram-бот, который каждые 15 минут собирает прокси из Telegram-каналов, проверяет их работоспособность и публикует лучшие в указанный чат.

Работает на **GitHub Actions** — без собственного сервера.

--- 

## ✨ Что умеет

- 📡 **Сбор** MTProto / WEB / SOCKS5 из Telegram-источников
- 🧠 **Анализ Secret** — извлечение домена-маски, приоритет Fake TLS
- 🌍 **Probe Resistance Test** — проверка устойчивости к DPI-зондированию
- 🔬 **Реальная проверка** через handshake Telethon + `ya.ru`
- 📊 **Умная сортировка** — probe-resistant MTProto первыми
- 💾 **SQLite-состояние** — дедупликация, без повторов 24 часа
- 🚀 **Публикация 6 прокси** каждые 15 минут

---

## 🔐 Переменные окружения

Добавить в **Settings → Secrets and variables → Actions**:

| Имя | Описание |
|---|---|
| `BOT_TOKEN` | Токен бота от [@BotFather](https://t.me/BotFather) |
| `CHAT_ID` | ID канала/чата для публикации |
| `API_ID` | API ID с [my.telegram.org](https://my.telegram.org) |
| `API_HASH` | API Hash с [my.telegram.org](https://my.telegram.org) |
| `TG_SESSION` | Строка сессии Telethon (обязательно) |

### 🔑 Получить `TG_SESSION`

Используйте онлайн-генератор: **[SSG — String Session Generator](https://gabrielmaialva33.github.io/ssg/)**

1. Введите `API_ID`, `API_HASH` и номер телефона.
2. Введите код из Telegram.
3. Готовая строка придёт в «Избранное» (Saved Messages).

> ⚠️ Сессия даёт полный доступ к аккаунту. Никому её не показывайте.

### 💬 Получить `CHAT_ID`

1. Добавьте бота в канал/группу как **администратора**.
2. Перешлите любое сообщение боту [@userinfobot](https://t.me/userinfobot).
3. Скопируйте ID (вида `-100xxxxxxxxxx`).

---

## 🚀 Запуск

1. Форкните репозиторий.
2. Добавьте 5 секретов (см. выше).
3. Откройте **Actions → Proxy Bot → Run workflow**.
4. Через 2–4 минуты в чате появятся прокси.

Дальше бот запускается **сам каждые 15 минут**.

---

## 📊 Что публикуется

| Протокол | Проверка | Приоритет |
|---|---|---|
| **MTProto Fake TLS** | Handshake ×3 + probe test | 🥇 Высший |
| **MTProto** | Handshake ×3 | 🥈 Обычный |
| **WEB** | Handshake ×3 | 🥉 По остатку |
| **SOCKS5** | Telegram + ya.ru | Минимум 1 из 6 |

---

## 📁 Структура

```
proxy-bot/
├── .github/workflows/run.yml   # Cron + публикация
├── bot.py                      # Основной цикл
├── sources.py                  # Парсер Telegram-источников
├── checker.py                  # Проверка + probe test
├── formatter.py                # Оформление сообщений
├── state.py                    # SQLite-состояние
└── requirements.txt
```

---

## 📝 Лицензия

MIT.
