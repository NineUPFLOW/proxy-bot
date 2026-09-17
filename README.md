<div align="center">

# 🔐 Proxy Bot

**Автоматический сбор, проверка и публикация рабочих прокси в Telegram**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![aiogram](https://img.shields.io/badge/aiogram-3.x-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://github.com/aiogram/aiogram)
[![Telethon](https://img.shields.io/badge/Telethon-1.x-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://github.com/LonamiWebs/Telethon)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-enabled-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)](https://github.com/features/actions)

</div>

---

## 📖 О проекте

Telegram-бот, который **каждые 15 минут** собирает прокси из открытых источников, проверяет их реальную работоспособность и публикует лучшие в ваш канал или чат.

Работает полностью на **GitHub Actions** — собственный сервер не нужен.

---

## ✨ Возможности

| | |
|:---:|:---|
| 🔐 | **MTProto** — реальный handshake через Telethon, только Fake TLS-прокси |
| 🌐 | **WEB (TgWebProxy)** — прокси для Telegram Web |
| 🧦 | **SOCKS5** — строгая проверка: доступ к `api.telegram.org` + `ya.ru` |
| 📍 | **Геолокация** — страна, город, провайдер через `ip-api.com` |
| 🚀 | **Кнопка подключения** — добавление прокси в Telegram в один тап |
| ⏰ | **Автозапуск** — каждые 15 минут без вашего участия |

---

## 🔄 Как это работает

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  sources.py │ ─▶ │  checker.py │ ─▶ │formatter.py │ ─▶ │   bot.py    │
│   Сбор      │    │  Проверка   │    │ Оформление  │    │ Публикация  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

1. **`sources.py`** — собирает прокси из открытых источников на GitHub
2. **`checker.py`** — проверяет работоспособность + определяет геолокацию
3. **`formatter.py`** — формирует красивое сообщение с кнопкой
4. **`bot.py`** — публикует лучшие прокси в ваш канал

---

## ⚙️ Настройка

Боту нужны **5 секретов**. Все они добавляются в:

> **Settings → Secrets and variables → Actions → New repository secret**

### 🔑 Обязательные переменные

| Переменная | Что это | Где взять |
|:---|:---|:---|
| `BOT_TOKEN` | Токен бота | [@BotFather](https://t.me/BotFather) |
| `CHAT_ID` | ID канала/чата | см. ниже |
| `API_ID` | Telegram API ID | [my.telegram.org](https://my.telegram.org) |
| `API_HASH` | Telegram API Hash | [my.telegram.org](https://my.telegram.org) |
| `TG_SESSION` | Сессия Telethon | см. ниже |

---

## 💬 Как получить `CHAT_ID`

1. Добавьте своего бота в канал/группу **как администратора**.
2. Перешлите любое сообщение из канала боту [@userinfobot](https://t.me/userinfobot) или [@getidsbot](https://t.me/getidsbot).
3. Бот покажет ID — это отрицательное число вида `-100xxxxxxxxxx`.
4. Скопируйте его в секрет `CHAT_ID`.

> 💡 **Альтернатива:** дайте доступ [@RawDataBot](https://t.me/RawDataBot) — он выведет полный JSON апдейта, включая `chat.id`.

---

## 🔑 Как получить `TG_SESSION`

`TG_SESSION` **обязательна** для проверки MTProto и WEB-прокси. Без неё бот проверит только SOCKS5.

### 📱 Способ: онлайн-генератор

<div align="center">

### 👉 [**SSG — String Session Generator**](https://gabrielmaialva33.github.io/ssg/) 👈

</div>

1. Откройте ссылку в браузере.
2. Введите `API_ID`, `API_HASH` и номер телефона (например, `+79991234567`).
3. Введите код подтверждения из Telegram.
4. Готовая строка **придёт в «Избранное»** (Saved Messages). Скопируйте её в секрет `TG_SESSION`.

> ⚠️ **Безопасность:** строка сессии даёт полный доступ к вашему Telegram-аккаунту. Никому её не показывайте и храните только в секретах. Используйте отдельный аккаунт.

---

## 🚀 Запуск

### 1️⃣ Форк или клонирование

```bash
git clone https://github.com/NineUPFLOW/proxy-bot.git
cd proxy-bot
```

### 2️⃣ Добавьте секреты

Перейдите: **Settings → Secrets and variables → Actions → New repository secret**

Добавьте все 5:

```
BOT_TOKEN     = ваш токен
CHAT_ID       = -100xxxxxxxxxx
API_ID        = 1234567
API_HASH      = abcdef123...
TG_SESSION    = 1BVtsOK4...
```

### 3️⃣ Первый запуск

1. Откройте вкладку **Actions** в репозитории.
2. Слева выберите **Proxy Bot**.
3. Нажмите **Run workflow → Run workflow**.
4. Через 2–4 минуты в канале появятся рабочие прокси.

### ✅ Дальше — автоматически

Бот будет запускаться **сам каждые 15 минут** без вашего участия.

---

## 📊 Что публикуется

| Протокол | Проверка | Особенности |
|:---:|:---|:---|
| 🔐 **MTProto** | 3 handshake (нужно 2) | Только `ee`-секреты (Fake TLS) |
| 🧦 **SOCKS5** | `api.telegram.org` + `ya.ru` | Строгая проверка |
| 🌐 **WEB** | 2 handshake | Нестабильны, помечаются ⚠️ |

---

## ⚙️ Параметры

Настраиваются в `bot.py`:

| Параметр | По умолчанию | Описание |
|:---|:---:|:---|
| `PUBLISH_COUNT` | `5` | Сколько прокси публиковать за раз |
| `CONCURRENCY` | `10` | Параллельных проверок |
| `MAX_SOCKS5_RATIO` | `0.4` | Макс. доля SOCKS5 |
| `MAX_WEB_COUNT` | `2` | Макс. WEB-прокси за раз |

**Расписание** в `.github/workflows/run.yml`:

```yaml
- cron: '7,22,37,52 * * * *'
```

> Запуски в **07, 22, 37, 52** минуты каждого часа (интервал 15 минут).

---

## 🧰 Стек

<div align="center">

| Технология | Назначение |
|:---:|:---|
| 🐍 **Python 3.11+** | Язык разработки |
| 🤖 **aiogram** | Telegram Bot API |
| 📡 **Telethon** | Проверка MTProto/WEB |
| 🌐 **aiohttp + aiohttp-socks** | Проверка SOCKS5 |

</div>

---

## 🛠 Возможные проблемы

<details>
<summary><b>Бот не запускается по расписанию</b></summary>

Сделайте любой коммит в `README.md` — GitHub пересинхронизирует cron. Запуски могут задерживаться на 10–30 минут — это норма для GitHub Actions.

</details>

<details>
<summary><b>SOCKS5 не публикуются</b></summary>

Это норма. Большинство SOCKS5 блокируются ТСПУ, строгая проверка отсеивает их. Публикуются только те, что прошли оба теста.

</details>

<details>
<summary><b>WEB-прокси почти нет</b></summary>

Технология новая (2026), источников мало. Постепенно их становится больше.

</details>

<details>
<summary><b>Ошибка AuthKeyUnregisteredError</b></summary>

`TG_SESSION` недействительна — сгенерируйте заново через [SSG](https://gabrielmaialva33.github.io/ssg/).

</details>

---

## 📝 Дисклеймер

Проект собирает прокси из открытых публичных источников и проверяет их реальную доступность. Автор не несёт ответственности за то, как используются опубликованные прокси.

---

<div align="center">

**⭐ Если проект полезен — поставьте звезду!**

</div>
