# Proxy Bot

Собирает открытые прокси для Telegram из HTTPS-каталогов и локальных файлов, **сам проверяет их из сети запуска** и публикует прошедшие проверку через Telegram Bot API. Для получения списков бот не читает Telegram-каналы и не использует личный аккаунт Telegram.

**Поддержка:** MTProto (`plain`, `dd`, Fake TLS `ee`), SOCKS5 и Telegram WEB Proxy. Пять исходных каталогов сохранены; список дополнен русскоязычными сайтами, API и репозиториями. Все адреса редактируются в [`sources.json`](sources.json).

> **Важно для России.** «Прокси находится в России» и «прокси работает из России» — разные утверждения. Для проверки последнего запускайте бот на машине с прямым выходом в интернет из нужной российской сети. По умолчанию бот прекращает работу, если страна исходящего IPv4 неизвестна или не `RU`. Даже проверка из РФ относится только к конкретному оператору, маршруту и моменту времени: для всех сетей и навсегда работоспособность не гарантируется.

## Как это работает

```text
HTTPS-источники и локальные файлы
             ↓  новая загрузка при каждом запуске
синтаксическая проверка → удаление дублей → выборка по источникам
             ↓
реальные протокольные проверки (по умолчанию 2 успеха из 3 попыток)
             ↓
отбор по протоколу, задержке и разнообразию IP
             ↓  свежая проверка непосредственно перед отправкой
Telegram Bot API → запись факта публикации в SQLite
```

- Источники — **кандидаты**, а не подтверждение работоспособности. При лимитах проверяются не все полученные записи; публикуются только прошедшие проверку и повторную проверку перед отправкой. Если прокси выбыл в последний момент, бот пробует следующий.
- MTProto и SOCKS5 проходят обмен `req_pq_multi` / `resPQ` с проверкой nonce. Для Fake TLS дополнительно проверяется HMAC ServerHello; WEB Proxy проверяется через его WEB-транспорт. Это больше, чем проверка открытого TCP-порта, но **не полноценная авторизация клиента** и не гарантия звонков, медиа или доступа ко всем DC.
- Источник загружается заново при каждом запуске, без локального кеша списка. Удалённый сайт или CDN всё равно может вернуть старые данные. Дата страницы, `Last-Modified`, дата коммита и HTTP 200 **не доказывают**, что конкретный прокси сейчас работает; проверка кандидата и финальная перепроверка выполняются самим ботом.
- Выборка распределяется между источниками, чтобы огромный SOCKS-список не вытеснял небольшие каталоги. Один и тот же прокси встречается в разных списках и после общей дедупликации относится к первому источнику, в котором найден.

## Быстрый старт

Нужны Python **3.11+**, Git для установки зафиксированной зависимости и доступ в интернет.

```bash
git clone --branch improve-code-quality https://github.com/NineUPFLOW/proxy-bot.git
cd proxy-bot
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

# Проверка без токена, отправки сообщений и изменений базы.
python bot.py --dry-run
```

Команда запускается в строгом режиме: проверяющий исходящий IPv4 должен определяться как российский. Для **отладочного** запуска за пределами РФ:

```bash
REQUIRE_RU_CHECK=0 python bot.py --dry-run
```

Такой запуск не подтверждает доступность из России. Обычная публикация тоже позволяет явно задать `REQUIRE_RU_CHECK=0`, но в сообщениях будет указана фактически определённая страна, а не `RU` по умолчанию.

### Публикация

Создайте бота через [@BotFather](https://t.me/BotFather), добавьте его в канал или чат с правом отправки сообщений и задайте переменные окружения:

```bash
export BOT_TOKEN='токен бота'
export CHAT_ID='-1001234567890'
# Необязательно: числовой ID темы супергруппы.
# export TOPIC_ID='123'
python bot.py
```

Неверный `TOPIC_ID` не заставит бота молча опубликовать сообщение в другой теме. Если Bot API недоступен из сети проверки, задайте `BOT_PROXY_URL`, например `socks5://user:password@host:port`: он применяется **только для отправки**. Сбор, определение страны и проверка прокси идут без него. Не используйте системный VPN или split tunnel, меняющий маршрут проверок, если вам нужен результат именно для исходной сети РФ.

Никогда не записывайте `BOT_TOKEN`, `BOT_PROXY_URL`, приватные списки или рабочие ключи в публичный репозиторий. Личный `TG_SESSION`, `API_ID`, `API_HASH` и `TELEGRAM_SOURCES` больше не нужны.

## Источники

В текущем [`sources.json`](sources.json) — **32 настроенных HTTPS-источника**, включая пять исходных. Это число адресов, а не независимых баз или рабочих серверов. Состав и доступность удалённых списков меняются; при ошибке одного источника остальные продолжают работать.

### Сохранённые исходные источники

| Имя в конфигурации | Источник | Данные |
|---|---|---|
| `ru-web-api` | [vnespiska.win API](https://vnespiska.win/api/proxies-ru.json) | MTProto; сервис заявляет проверку из РФ |
| `web-catalog` | [ryazhapov/tg-proxy-list](https://github.com/ryazhapov/tg-proxy-list) | MTProto и WEB |
| `mtproto-catalog` | [ALIILAPRO/MTProtoProxy](https://github.com/ALIILAPRO/MTProtoProxy) | MTProto |
| `proxifly-socks5` | [proxifly/free-proxy-list](https://github.com/proxifly/free-proxy-list) | SOCKS5 |
| `speedx-socks5` | [TheSpeedX/PROXY-List](https://github.com/TheSpeedX/PROXY-List) | SOCKS5 |

### Русскоязычные специализированные сайты

| Имя | Сайт или публичный API | Обычно содержит |
|---|---|---|
| `tg-proxy-net-catalog` | [tg-proxy.net](https://tg-proxy.net/) · [API каталога](https://tg-proxy.net/wp-json/tgprox/v1/catalog) | MTProto, WEB |
| `mtproxy-fyi` | [mtproxy.fyi](https://mtproxy.fyi/) | MTProto |
| `tgproxy-fyi` | [tgproxy.fyi](https://tgproxy.fyi/) | MTProto |
| `proksi-tg-top` | [proksi-tg.top](https://proksi-tg.top/) | MTProto |
| `proxy-tg-bond` | [proxy-tg.bond](https://proxy-tg.bond/) | MTProto |
| `proxytg-bond` | [proxytg.bond](https://proxytg.bond/) | MTProto |
| `mtproto-date` | [mtproto.date](https://mtproto.date/) | MTProto |
| `mtprotoserver-bond` | [mtprotoserver.bond](https://mtprotoserver.bond/) | MTProto |
| `mtprotoproxy-sbs` | [mtprotoproxy.sbs](https://mtprotoproxy.sbs/) | MTProto |
| `mtprotolist-bond` | [mtprotolist.bond](https://mtprotolist.bond/) | MTProto |
| `proxytelegram-bond` | [proxytelegram.bond](https://proxytelegram.bond/) | MTProto |
| `freemtproto-bond` | [freemtproto.bond](https://freemtproto.bond/) | MTProto |
| `mtpro-xyz` | [mtpro.xyz](https://mtpro.xyz/) | MTProto, WEB |

Каталог `tg-proxy.net` на странице загружается JavaScript: бот обращается к его публичному HTTPS API и не исполняет код страницы. Сайты могут пересекаться по серверам и инфраструктуре; не считайте их независимыми только из-за разных доменов.

### Дополнительные списки GitHub и SOCKS5

| Имя | Источник | Примечание |
|---|---|---|
| `shablin-mtproto` | [shablin/mtproto-proxy](https://github.com/shablin/mtproto-proxy) | Агрегатор, использует в том числе SoliSpirit и kort |
| `kort-mtproto` | [kort0881/telegram-proxy-collector](https://github.com/kort0881/telegram-proxy-collector) | Смешивает несколько источников |
| `solispirit-mirror` | [SoliSpirit/mtproto](https://github.com/SoliSpirit/mtproto) | Резервный список; при добавлении совпадал с ALIILAPRO |
| `proxydaiv-mtproto` | [McDaived/ProxyDaiv](https://github.com/McDaived/ProxyDaiv) | Проверяемый производный список SoliSpirit, JSON |
| `surya-mtproto` | [suryadev-sm/free-mtproto-proxy-list](https://github.com/suryadev-sm/free-mtproto-proxy-list) | MTProto |
| `ru2026-mtproto` | [Chumbayoumba/free-telegram-proxy-russia-2026](https://github.com/Chumbayoumba/free-telegram-proxy-russia-2026) | `host:port:secret`; автор заявляет проверку из РФ |
| `telegavpn-web` | [TelegaVPN/free-vpn-keys](https://github.com/TelegaVPN/free-vpn-keys) | WEB-ссылки в текстовой подписке |
| `proxyscrape-socks5` / `proxyscrape-mirror` | [ProxyScrape API](https://proxyscrape.com/free-proxy-list) / [GitHub](https://github.com/ProxyScrape/free-proxy-list) | API и зеркало, не две независимые базы |
| `dinoz0rg-socks5` | [dinoz0rg/proxy-list](https://github.com/dinoz0rg/proxy-list) | SOCKS5 |
| `proxmint-socks5` | [Proxmint](https://proxmint.com/) · [GitHub](https://github.com/proxmint/free-proxy-list) | SOCKS5; данные CC BY 4.0, указание автора Proxmint |
| `monosans-socks5` | [monosans/proxy-list](https://github.com/monosans/proxy-list) | SOCKS5 |
| `proxio-socks5` | [Proxio](https://proxio.io/) · [GitHub](https://github.com/proxio-io/proxy-list) | SOCKS5; данные CC BY 4.0, указание автора Proxio |
| `hookzof-socks5` | [hookzof/socks5_list](https://github.com/hookzof/socks5_list) | SOCKS5; возможны совпадения с другими списками |

Сторонние сайты могут заимствовать данные, в том числе из каталогов, которые используют Telegram. Например, `kort` смешивает веб-списки и агрегаторы с разным происхождением; `shablin` использует и его. **Прямых запросов бота к каналам за источниками нет**, но полная независимость происхождения всех записей не гарантируется. Если это принципиально, отключите сторонние источники и используйте собственный локальный файл или проверенного поставщика. Утверждения поставщиков о проверке в РФ не заменяют собственные замеры.

## Аудит свежести и доступности источников

Запускайте диагностику из той же сети, где будет работать бот:

```bash
# Случайно выбрать до трёх кандидатов на источник и проверить протоколом.
# Отчёт только со сводными данными; публикации и изменения SQLite нет.
python audit_sources.py --sample-per-source 3 > source-audit.json

# Только доступность и разбор списков, без проверки прокси и геолокации:
python audit_sources.py --sample-per-source 0 > source-audit.json

# Вариант для мониторинга из РФ: ненулевой код при общей проблеме или не-RU.
python audit_sources.py --sample-per-source 2 --require-ru \
  --fail-if-empty --fail-if-no-working > source-audit.json
```

Диагностика может работать из любой страны; при `--require-ru` она завершится с ошибкой, если страна не `RU`, не определилась или исходящий IP/страна изменились между началом и концом выборки. Без флага страна всё равно указана в `check_origin`: это **страна измерения**, не страна сервера прокси.

- `status: candidates` — источник вернул хотя бы одного синтаксически распознанного кандидата; это ещё **не** результат сетевой проверки. `empty` — ответ или файл получен, но кандидатов нет. `error` — загрузка/чтение не удались; тип ошибки и, при наличии, HTTP-код указаны без URL.
- `candidate_counts` — количество до удаления дублей между источниками. `sample.checked` / `sample.passed` — число случайно выбранных и прошедших **те же повторные протокольные проверки**, что используются при отборе ботом. Одна маленькая выборка не характеризует весь каталог; `0/2` не доказывает, что в нём совсем нет рабочих серверов.
- `retrieved_at` — время загрузки. `last_modified` — только заголовок сервера `Last-Modified` или время изменения локального файла; `null` значит, что значение неизвестно. Эти поля не являются временем проверки записей. В отчёте нет адресов источников, IP прокси или их секретов; сами имена источников, времена и страна проверки видны.
- `--fail-if-empty` возвращает код `1`, если ни один источник не дал кандидатов; `--fail-if-no-working` — если ни один проверенный кандидат не прошёл. С `--sample-per-source 0` последний флаг и `--require-ru` применять нельзя. Ошибка конфигурации или аргументов — код `2`.

Диагностика использует настройки `CHECK_ATTEMPTS`, `CHECK_REQUIRED` и таймауты из таблицы ниже. Увеличение `--sample-per-source` до 20 повышает нагрузку и время проверки; параллельность регулируется `--concurrency` от 1 до 50. Не размещайте секреты в **именах** источников: они попадают в отчёт.

## Собственные источники

Создайте, например, `sources.local.json`:

```json
{
  "sources": [
    {"name": "my-links", "format": "links", "path": "custom-proxies.txt"},
    {"name": "provider-mt", "format": "mtproto", "url": "https://example.com/mtproto.txt"},
    {"name": "provider-socks", "format": "socks5", "url": "https://example.com/socks5.txt"}
  ]
}
```

Замените `example.com` адресами своего поставщика. Для каждой записи укажите ровно одно из `url` и `path`; относительный путь локального файла считается от каталога JSON-конфигурации. Допускаются до 100 уникально названных источников. Сетевые источники и перенаправления — только HTTPS, без встроенных логина/пароля в URL; домены Telegram в качестве источников запрещены.

| Формат | Что распознаётся |
|---|---|
| `links` | `tg://proxy`, `tg://webproxy`, `tg://socks`, ссылки `t.me/proxy` / `socks` / `webproxy` как **данные**, `socks5://…`; в TXT, HTML, Markdown и строковых значениях JSON |
| `socks5` | То же, плюс отдельные строки `IPv4:port` как SOCKS5 |
| `mtproto` | Ссылки выше, плюс `host:port:secret` и JSON-объекты с полями `server` / `host` / `ip`, `port`, `secret`; поле `type` или `protocol`, если присутствует, должно быть `mtproto` или `mtproxy` |

Непомеченный `IPv4:port` в смешанном списке не превращается автоматически в SOCKS5. `host:port:secret` и отдельные поля JSON распознаются как MTProto **только** в источнике с `format: mtproto`. Все форматы проходят одинаковую проверку хоста, порта, секрета и публичного IPv4 перед соединением.

```bash
SOURCES_FILE=./sources.local.json python bot.py --dry-run
SOURCES_FILE=./sources.local.json python audit_sources.py --sample-per-source 2
```

Для Actions путь задаётся переменной `SOURCES_FILE`. Приватный локальный файл на self-hosted runner храните **вне checkout**: Actions может очистить рабочий каталог. В `.gitignore` включены `sources.local.json`, `custom-proxies.txt` и `source-audit.json`, но любые другие секретные файлы исключайте самостоятельно.

## GitHub Actions: запуск в российской сети

GitHub-hosted `ubuntu-latest` обычно не находится в РФ. Для реального измерения используйте **self-hosted runner** в нужной российской сети; VPS в РФ не эквивалентен мобильному интернету конкретного оператора.

1. В репозитории откройте **Settings → Actions → Runners → New self-hosted runner** и зарегистрируйте доверенную Linux-машину. Добавьте метку `ru-proxy`.
2. В **Settings → Secrets and variables → Actions → Variables** создайте `PROXY_RUNNER_LABELS` со значением `["self-hosted","linux","ru-proxy"]`.
3. В **Secrets** задайте `BOT_TOKEN` и `CHAT_ID`; при необходимости — `TOPIC_ID` и `BOT_PROXY_URL`. Для одного только аудита источников секреты Telegram не требуются.
4. В **Actions → Проверка и публикация прокси → Run workflow** сначала выберите `dry_run`, изучите страну и результаты, затем запустите публикацию.
5. В **Actions → Аудит источников** можно вручную получить JSON-артефакт на 7 дней. По умолчанию требуется стабильный egress `RU`; для честной диагностики за рубежом снимите `strict_ru` и смотрите страну в отчёте.

Публикация запланирована каждые 15 минут, аудит — каждые 6 часов. GitHub может задерживать cron; расписание использует workflow из **основной ветки** репозитория. До настройки `PROXY_RUNNER_LABELS` оба задания по расписанию пропускаются. Ручной запуск без runner использует GitHub-hosted машину: строгая проверка `RU` в этом случае обычно остановит публикацию/строгий аудит. Доступ к источникам, GitHub и сервисам определения страны должен быть разрешён.

База `proxy_state.db` восстанавливается и сохраняется через Actions cache; она содержит адреса проверенных/опубликованных узлов и хеши идентичностей. Ограничьте доступ к runner и его файлам. Не запускайте недоверенный код на self-hosted runner. Отчёт аудита содержит агрегаты и имена источников — убедитесь, что имена не раскрывают приватную информацию.

### Переход со старой версии

Обновите код и зависимости, удалите старые `TG_SESSION`, `API_ID`, `API_HASH`, `TELEGRAM_SOURCES` из окружения и настройте российский runner и Bot API. Старую личную сессию при необходимости завершите в Telegram: **Настройки → Устройства**. Схема SQLite сохранена, но некоторые идентификаторы прокси и ключ Actions cache изменились, поэтому после перехода возможна разовая повторная публикация ранее отправленных прокси.

## Параметры окружения

| Переменная | По умолчанию | Назначение |
|---|---:|---|
| `BOT_TOKEN`, `CHAT_ID`, `TOPIC_ID` | — | Токен, числовой ID чата и необязательный ID темы; для `--dry-run` и аудита не нужны. |
| `BOT_PROXY_URL` | — | Прокси только для отправки в Bot API; хранить как секрет. |
| `REQUIRE_RU_CHECK` | `1` | Для бота: требовать российский egress до и после проверки и остановиться при смене IP. |
| `SOURCES_FILE` | `sources.json` | Путь к конфигурации источников. |
| `PUBLISH_COUNT` | `9` | Максимум сообщений за запуск; при нехватке прошедших проверку может быть меньше. |
| `TARGET_MT`, `TARGET_SOCKS5`, `TARGET_WEB` | `3`, `3`, `3` | Желаемое количество по протоколам; остаток заполняется другими кандидатами. |
| `MAX_PER_IP` | `1` | Максимум публикаций на один проверенный IPv4 за запуск; `0` отключает ограничение. |
| `CONCURRENCY` | `20` | Число параллельных проверок бота. |
| `MAX_MT_CHECK`, `MAX_SOCKS5_CHECK`, `MAX_WEB_CHECK` | `150`, `150`, `30` | Лимит проверяемых кандидатов каждого типа за запуск. |
| `CHECK_ATTEMPTS`, `CHECK_REQUIRED` | `3`, `2` | Число попыток и минимум успехов: `1 ≤ required ≤ attempts ≤ 10`. |
| `CHECK_RETRY_DELAY` | `0.2` | Пауза между попытками, секунды. |
| `CHECK_TIMEOUT`, `SOCKS_CHECK_TIMEOUT`, `WEB_CHECK_TIMEOUT` | `8`, `8`, `12` | Таймаут одной попытки, секунды. |
| `MAX_PING_MS`, `MAX_WEB_PING_MS` | `5000`, `10000` | Максимальное время обмена; это не ICMP ping. |
| `WEB_PROXY_MODE` | `auto` | Автоматический режим WEB-транспорта; также `websocket-lanes`, `websocket`, `https`, `https-lanes`. |
| `SEEN_TTL`, `PUBLISHED_TTL`, `SOURCE_STATS_TTL` | `1800`, `21600`, `604800` | Период до повторной проверки неудачных, повторной публикации и очистки статистики, секунды. |
| `GEO_ENABLED` | `0` | Дополнительно определять страну **сервера** через ipwho.is; не заменяет страну проверки. |
| `SEND_STATUS` | `0` | Отправлять служебные сообщения, когда кандидатов нет. |
| `SOURCE_TIMEOUT`, `SOURCE_CONCURRENCY`, `MAX_SOURCE_BYTES`, `MAX_PER_SOURCE` | `20`, `4`, `2097152`, `10000` | Ограничения загрузки и разбора источников. |
| `STATE_DB`, `LOG_LEVEL`, `SEND_DELAY` | `proxy_state.db`, `INFO`, `2` | Путь к базе, уровень логирования и задержка отправки в секундах. |

Дополнительные переменные для Actions можно добавить в `env` соответствующего workflow; секреты не добавляйте в YAML.

## Тесты, безопасность и ограничения

```bash
python -m compileall -q audit_sources.py bot.py checker.py formatter.py network.py proxy_utils.py sources.py state.py
python -m unittest discover -s tests -t . -v
```

Тесты работают без внешней сети и Telegram-секретов; локально проверяются разбор форматов, исходные источники, безопасные DNS/redirect, протокольные обмены, nonce, состояние, `RU`-guard, аудит и процесс публикации.

Публичные источники недоверенные. Загрузка ограничена по размеру, времени и параллельности; внутренние, непубличные и смешанные DNS-ответы отклоняются. Для WEB проверенный IPv4 закрепляется за хостом на время соединения; перенаправления запрещены. Проверки используют IPv4. DNS пользователя может разрешить домен иначе, чем DNS проверяющей машины.

Определение страны внешнего IP приблизительно и не доказывает маршрут каждого соединения. Обмен с nonce без полной авторизации Telegram не защищает от умышленной подделки ответа владельцем прокси. Открытый прокси контролируется третьим лицом и видит ваш IP и часть метаданных — не считайте его приватным или доверенным.

Если новых публикаций нет, изучите логи и аудит: страну egress, доступность и формат источников, результаты выборки, таймауты, настройки чата и права бота. Если проверку ничего не прошло, бот не публикует непроверенные прокси «для количества».

## Лицензия и благодарности

Проект распространяется под [MIT](LICENSE). Протокольные примитивы — [mtproxychecker](https://github.com/alimghmi/mtproxychecker) (MIT, зафиксированный коммит); WEB-транспорт — `telethon-webproxy` (MIT). Списки принадлежат их авторам и могут иметь собственные условия; отдельно указываем [Proxio](https://proxio.io/) и [Proxmint](https://proxmint.com/) как авторов соответствующих списков CC BY 4.0. Перед повторным распространением проверяйте актуальные лицензии источников.
