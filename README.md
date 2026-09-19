<div align="center">


# 🔐 Proxy Bot

**Автоматический сбор, проверка и публикация рабочих прокси в Telegram**

[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-active-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)](https://github.com/NineUPFLOW/proxy-bot/actions)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![aiogram](https://img.shields.io/badge/aiogram-3.15-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://github.com/aiogram/aiogram)
[![Telethon](https://img.shields.io/badge/Telethon-1.36-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://github.com/LonamiWebs/Telethon)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](https://opensource.org/licenses/MIT)

Работает на **GitHub Actions** — без собственного сервера

</div>

---

## ✨ Возможности

| | |
|:---:|---|
| 📡 | Сбор из **Telegram-источников**, включая темы (Topics) |
| 🧠 | Анализ **Secret** — приоритет Fake TLS и probe-resistant |
| 🔬 | Реальная проверка через **handshake Telethon** + `ya.ru` |
| 🚫 | Фильтр мусора — `MAX_PING_MS = 5000` |
| 📊 | Выборка **9 прокси**: 3 MTProto + 3 SOCKS5 + 3 WEB |
| 💾 | **SQLite-состояние** (seen 2ч, published 24ч) |
| 🚀 | **Автозапуск** каждые 10 минут |

---

## 🔐 Секреты

<div align="center">

**Settings → Secrets and variables → Actions → New repository secret**

</div>

| Имя | Обяз. | Описание |
|---|:---:|---|
| `BOT_TOKEN` | ✅ | Токен от [@BotFather](https://t.me/BotFather) |
| `CHAT_ID` | ✅ | ID чата (например, `-1001234567890`) |
| `TOPIC_ID` | ⚠️ | ID темы (если есть). Иначе не добавлять |
| `API_ID` | ✅ | С [my.telegram.org](https://my.telegram.org) |
| `API_HASH` | ✅ | С [my.telegram.org](https://my.telegram.org) |
| `TG_SESSION` | ✅ | Строка сессии Telethon |

### 🔑 TG_SESSION

<div align="center">

### 👉 [**SSG — String Session Generator**](https://gabrielmaialva33.github.io/ssg/) 👈

</div>

1. Введите `API_ID`, `API_HASH`, номер телефона.
2. Введите код из Telegram.
3. Строка придёт в **«Избранное»** — скопируйте в `TG_SESSION`.

> ⚠️ Сессия = полный доступ к аккаунту. Используйте **отдельный аккаунт**.

### 💬 CHAT_ID

Перешлите любое сообщение из группы боту [@userinfobot](https://t.me/userinfobot).

### 🧵 TOPIC_ID

Отправьте сообщение в нужную тему → правый клик → **Copy Message Link**. Ссылка вида `https://t.me/c/1234567890/15/42` — число **15** это `TOPIC_ID`. Если тем нет — не создавайте секрет.

---

## 🚀 Запуск

```
1. Форк репозитория
2. Добавьте 6 секретов
3. Actions → Proxy Bot → Run workflow
```

Дальше — сам каждые 10 минут.

---

## 📊 Что публикуется

| Протокол | Проверка | Приоритет |
|---|---|:---:|
| 🔐 **MTProto Fake TLS** | Handshake 3/2 + probe | 🥇 |
| 🔐 **MTProto** | Handshake 3/2 | 🥈 |
| 🌐 **WEB** | Handshake 3/2 | 🥉 |
| 🧦 **SOCKS5** | проверка на доступ к  Telegram API| Обычный |

**9 прокси за запуск:** 3 MTProto + 3 SOCKS5 + 3 WEB. Чего не хватает — добирается MTProto.

---

## ⚙️ Настройка

<details>
<summary><b>bot.py</b></summary>

| Параметр | По умолчанию |
|---|:---:|
| `PUBLISH_COUNT` | `9` |
| `TARGET_MT` / `TARGET_SOCKS5` / `TARGET_WEB` | `3` / `3` / `3` |
| `CONCURRENCY` | `20` |
| `MAX_MT_CHECK` | `400` |
| `MAX_SOCKS5_CHECK` | `100` |

</details>

<details>
<summary><b>checker.py</b></summary>

| Параметр | По умолчанию |
|---|:---:|
| `MAX_PING_MS` | `5000` |
| `MT_ATTEMPTS` / `MT_REQUIRED` | `3` / `2` |

</details>

**Расписание** в `.github/workflows/run.yml`:

```yaml
- cron: '*/10 * * * *'
```

---

## 💾 Состояние

SQLite `proxy_state.db` (в `actions/cache`, не в git):

| Таблица | TTL |
|---|:---:|
| `seen_proxies` | 2 часа |
| `published_proxies` | 24 часа |

---

## 🛠 Возможные проблемы

<details>
<summary><b>BOT_TOKEN invalid</b></summary>
Проверьте формат <code>123456:ABC...</code>
</details>

<details>
<summary><b>CHAT_ADMIN_REQUIRED</b></summary>
Сделайте бота администратором группы.
</details>

<details>
<summary><b>Message thread not found</b></summary>
Уберите секрет <code>TOPIC_ID</code> или проверьте ID темы.
</details>

<details>
<summary><b>AuthKeyUnregisteredError</b></summary>
Перегенерируйте <code>TG_SESSION</code> через SSG.
</details>

<details>
<summary><b>Cron не срабатывает</b></summary>
Пустой коммит в <code>README.md</code> + включите workflow в Actions.
</details>

<details>
<summary><b>SOCKS5 / WEB не публикуются</b></summary>
Норма — их мало живых в открытых источниках.
</details>

---

## 📁 Структура

```
proxy-bot/
├── .github/workflows/run.yml   # Cron + запуск
├── bot.py                      # Основной цикл
├── sources.py                  # Парсер Telegram-источников
├── checker.py                  # Проверка + probe test
├── formatter.py                # Оформление сообщений
├── state.py                    # SQLite-состояние
├── requirements.txt            # Зависимости
└── README.md
```

---

<div align="center">

## 📝 Лицензия

**MIT** — используйте как хотите

---

⭐ **Если проект полезен — поставьте звезду!** ⭐

</div>
