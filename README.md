# Honeysight

![Go version](https://img.shields.io/badge/go-1.22%2B-00ADD8)
![CI](https://github.com/bin-qwerty/honeysight/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Многопротокольный deception-хонипот для исследования угроз и питания threat intelligence.

Honeysight выглядит как настоящая, слегка уязвимая цель — корпоративный портал,
облачный воркхолд, Redis-кеш — и записывает **всё**, что делает атакующий:
запросы, логины, команды, пейлоады. Каждое взаимодействие классифицируется в
реальном времени, получает оценку 0–100, обогащается контекстом, хранится
локально и экспортируется как IOC (JSON + STIX 2.1) в ваш
threat-intelligence конвейер.

[English README](README.en.md)

> ⚠️ **Этика и область применения.** Honeysight — *оборонительный*
> исследовательский инструмент. Он только наблюдает, фиксирует и замедляет
> трафик на **собственной** поверхности. Никакого сканирования, эксплуатации
> или «ответных атак». Разворачивайте только на инфраструктуре, которой вы
> владеете или имеете явное разрешение тестировать.

## Быстрый старт

Требования: Go 1.22+ (SQLite — чистый Go, cgo не нужен).

```bash
# сборка и запуск (слушатели :8080 и :8443)
go build -o honeysight ./cmd/honeysight
./honeysight -config config.example.yml

# в другом терминале — «атакуем»:
curl -s localhost:8080/                      # выглядит как корпоративный портал
curl -s "localhost:8080/?id=1' OR 1=1--"     # SQLi-проба
curl -s localhost:8080/.env                  # «утёкшие» (фейковые) секреты
curl -s -H "Host: 169.254.169.254" \
     localhost:8080/latest/meta-data/        # облачный metadata-эндпоинт
curl -s -A "sqlmap/1.8" localhost:8080/      # проба со сканером
curl -s -c jar -L -d "user=admin&pass=x" \
     localhost:8080/admin/login              # «успешный» вход → дашборд с данными
curl -sk -L -d "user=root&pass=y" \
     https://localhost:8443/admin/login      # то же по TLS (JA3 фиксируется)
ssh -p 2222 root@localhost                   # fake-OpenSSH: любой пароль,
                                             # шелл с «уточками» и canaries
```

События попадают в `data/honeysight.db` (SQLite):

```bash
sqlite3 data/honeysight.db \
  "SELECT ts, source_ip, score, severity, categories, action FROM events ORDER BY ts DESC LIMIT 20;"
```

Источники, чей накопленный счёт за скользящее окно превысил порог
(по умолчанию 100), автоматически попадают в **карантин**: хонипот перестаёт
кормить их приманкой и отвечает медленным 403 (tarpit) в течение TTL
(по умолчанию 10 минут). Тихие источники «остывают» по мере выхода событий
из окна.

## Архитектура

```
Слушатели (приманки):               Конвейер:                  Приёмники:
┌─ web   (HTTP-приманки)    ─┐      захват → нормализация →     ┌─ SQLite (события)
├─ ssh   (OpenSSH + шелл)   ─┼──► Bus ──► детекция (YAML-правила) ┼─ структурный лог
├─ redis (Redis 7.2 + keys) ─┼──►        → скор → трекер (окно,  └─ экспорт IOC:
└────────────────────────────┘       карантин/tarpit)              JSON + STIX 2.1 → webhook
```

Ключевые принципы:

- **Один Go-бинарник**, SQLite по умолчанию (zero-config), Postgres позже.
- **TLS-слушатель с JA3**: ClientHello разбирается до рукопожатия, поэтому
  JA3-отпечаток клиента попадает в каждое событие (см. «Отпечатки»).
- **Правила детекции — во внешних YAML** (`rules/`), с hot-reload и
  регрессионным корпусом пейлоадов (включая двойное кодирование).
- **Идентичность источника не подделывается заголовками**: X-Forwarded-For /
  X-Real-IP учитываются только от явно перечисленных trusted-прокси.
- **Карантин — локальный**: хонипот меняет только то, как отвечает на
  собственный трафик; до хоста атакующего он не обращается.
- **Fail-open**: упало хранилище — события пишутся в лог, сервис не падает.

## Структура

```
cmd/honeysight/        точка входа
internal/core/         модель события + шина
internal/config/       YAML-конфигурация
internal/detect/       сигнатурный движок (чистые функции, тесты) + YAML-правила
internal/track/        скользящий скор по источникам + карантин
internal/store/        интерфейсы хранилища + SQLite
internal/canary/       canary-токены: генерация, реестр, SQLite
internal/fingerprint/  разбор ClientHello, JA3, TLS-слушатель
internal/tlsutil/      самоподписанный сертификат (автогенерация)
internal/decoy/web/    HTTP-слушатель + приманки (портал, админка, metadata)
internal/decoy/ssh/    OpenSSH-сервер: захват логинов + fake-шелл с canaries
internal/decoy/redis/  Redis 7.2: захват AUTH + fake-keyspace с canaries (RESP)
rules/                 правила детекции по умолчанию
```

## Приманки (декой-поверхность)

Всё содержимое приманок **сфабриковано** — реальных секретов и сервисов за
ним нет:

| Поверхность | Что видит атакующий |
|---|---|
| `/` | «Корпоративный портал» с ссылками на админку, CMS, phpMyAdmin |
| `/.env` | «Утекшая» конфигурация с БД, Redis, AWS-ключами (все фейковые) |
| `/.git/config` | Фейковый git-репозиторий |
| `/admin`, `/wp-login.php`, `/phpmyadmin` | Формы входа |
| `/admin/dashboard` (после «входа») | «Живая» админ-консоль: пользователи, БД-подключения, cloud-ключи, внутренние хосты |
| `Host: 169.254.169.254`, `/latest/meta-data/` | Облачный metadata-сервис |

Любой другой путь отвечает 404 — но тоже уже зафиксирован как разведка.

### Canary-токены

«Вход» в админку **всегда** успешен — для любого пароля. После входа
атакующий получает дашборд с «ценными» данными, и каждое секретоподобное
значение в нём — **уникальный canary-токен этого источника**:

- пароль БД, API-ключ, AWS-пара ключей, имя администратора, внутренний IP;
- токен-набор привязан к IP источника, живёт 1 час, затем ротируется;
- значение сессии (cookie `ns_admin`) — тоже canary: сам IP набора.

Все токены пишутся в SQLite (`<db>-canaries.db`). Если позже где-то
(у атакующего, в дампе, на пастebin) появилось значение токена — источник
подтверждён: это был он.

### Экспорт IOC (STIX 2.1 + webhook)

События пакетами уходят на ваш webhook (TI-платформа, MISP, Elastic — что
угодно, что принимает POST JSON). Каждый батч — один payload:

- `events[]` — чистая JSON-схема: протокол, IP, действие, скор, категории,
  canary-id, JA3/отпечаток клиента, детали + `geo`/`asn` (если включено);
- `stix_bundle` — валидный STIX 2.1 bundle: по **индикатору на уникальный
  IP** (паттерн `ipv4-addr:value`, метки-категории, макс. скор, окно
  first/last seen, canaries и fingerprints в `x_honeysight`), по **tool** на
  каждый замеченный сканер (sqlmap, nikto, nmap, ...), и `report`,
  связывающий всё в батче.

Параметры: `batch_size` (по умолчанию 50), `flush_interval` (30s),
`retries` (3, backoff 1s/5s/25s). При недоступности вебхука батч
повторяется и затем отбрасывается с ошибкой в лог — honeypot никогда не
зависает из-за экспортa (fail-open).

### Обогащение (GeoIP/ASN)

Опционально: локальная MaxMind-база (`enrich.geoip_db`; GeoLite2-City
покрывает страну, город и ASN одним файлом). Чтение только из памяти,
внешних обращений honeysight **никуда** не делает — файл базы кладёте сами
(бесплатно: аккаунт на dev.maxmind.com).

### Redis-приманка

Слушатель `:6380` (на VPS обычно `:6379`) выдаёт себя за Redis 7.2.4. `AUTH`
принимает **любые** креденшелы (и `AUTH pass`, и `AUTH user pass`) и всегда
отвечает `+OK` — сами креденшелы фиксируются в событии `action=auth`.

Keyspace засевлен canary-набором источника (общий реестр с web и SSH):
`northwind:api:secret`, `northwind:db:password`, `northwind:db:host`,
`northwind:aws:*`, `northwind:admin:username`, `northwind:gateway:internal`.
`PING/ECHO/SELECT/INFO/DBSIZE/KEYS/SCAN/GET/MGET/EXISTS/TTL/TYPE/STRLEN/
SET/CONFIG/CLIENT` отвечают правдоподобно; `FLUSHALL` и `SLAVEOF` «работают»,
`SHUTDOWN` не роняет honeypot.

Каждая команда — событие `action=cmd`: правила `redis-recon` (KEYS *, INFO,
CONFIG GET, ...) и `redis-abuse` (FLUSHALL, CONFIG SET, SLAVEOF, EVAL, ...)
подсвечивают попытки эксплуатации. Карантин общий: зачаренный источник
получает ответы с tarpit-задержкой.

### SSH-приманка

Слушатель `:2222` выдаёт себя за `OpenSSH_8.9p1 Ubuntu`. Любые креденшелы
принимаются (password, publickey, keyboard-interactive); предложенный
public-ключ фиксируется по SHA256-отпечатку — сам по себе отличный IOC.
После «входа» открывается интерактивный шелл в образе Ubuntu-сервера
`northwind-app01` (postgres, redis, node-api):

- `whoami`, `id`, `ls`, `env`, `ps`, `netstat`, `last` и др. — правдоподобный вывод;
- `.env`, `deploy.sh`, `notes.txt`, `.bash_history`, `/etc/passwd`, `/etc/shadow`
  содержат **canary-токены этого источника** (те же наборы, что у web-админки);
- каждая команда — событие `action=cmd` с полным текстом: движок детекции
  ловит `; nc 1.2.3.4 4444`, `| sh`, `/etc/passwd` и прочий шелл-реверс;
- quarantine/tarpit общий: зачаренный источник получает ответы с задержкой.

### Отпечатки (JA3)

TLS-слушатель читает ClientHello до рукопожатия, воспроизводит байты и
только затем ведёт handshake. В каждое событие по TLS-соединению попадает
`fingerprint` — стандартный JA3-хеш (SHA1 по версии, шифрам, кривым,
форматам точек и расширениям в wire-порядке); для plain HTTP — `http/1.1`.
JA3 позволяет группировать источники по клиенту (curl, скрипт, браузер,
прокси-сеть) независимо от IP.

## Детекция

Правила в `rules/default.yml`: каждая — категория, вес и регулярные выражения
(по path+query+body и/или User-Agent). Скор = сумма весов совпавших категорий
(каждая категория учитывается один раз), потолок 100. Поля нормализуются:
сканируется сырое значение **и** до двух раундов percent-decode, поэтому
закодированные пейлоады не проходят мимо.

| Категория | Вес |
|---|---|
| command-injection | 50 |
| log4shell | 50 |
| webshell | 45 |
| sql-injection | 40 |
| path-traversal | 35 |
| credential-access | 30 |
| template-injection | 30 |
| xss | 25 |
| recon-scanner | 20 |

Severity: `low` 1–24 · `medium` 25–49 · `high` 50–79 · `critical` 80–100.

## Настройка

Копируйте `config.example.yml` в `config.yml` и правьте:

| Параметр | По умолчанию | Описание |
|---|---|---|
| `listen.http` | `:8080` | Адрес HTTP-слушателя |
| `listen.https` | `:8443` | Адрес TLS-слушателя (пусто = выключить) |
| `listen.ssh` | `:2222` | Адрес SSH-слушателя (пусто = выключить) |
| `listen.redis` | `:6380` | Адрес Redis-слушателя (пусто = выключить) |
| `tls_cert_dir` | `data/tls` | Каталог сертификата (создаётся автоматически) |
| `ssh_host_key_dir` | `data/ssh` | Каталог SSH host-ключа (создаётся автоматически) |
| `export.webhook_url` | `""` | URL вебхука для IOC (пусто = выключить) |
| `export.batch_size` | `50` | Размер батча |
| `export.flush_interval` | `30s` | Период выгрузки остатка |
| `export.retries` | `3` | Попыток на батч (backoff 1/5/25s) |
| `enrich.geoip_db` | `""` | Путь к MaxMind .mmdb (пусто = без обогащения) |
| `storage.sqlite_path` | `data/honeysight.db` | Файл БД (canaries — в `<path>-canaries.db`) |
| `rules.path` | `rules/default.yml` | Файл правил |
| `block_threshold` | `100` | Окно-скор, срабатывающий карантин |
| `window` | `5m` | Скользящее окно скоринга |
| `block_ttl` | `10m` | Длительность карантина |
| `tarpit` | `1.5s` | Задержка ответа карантинным источникам |
| `trusted_proxies` | — | Прокси, которым доверяются заголовки источника |

Каталог данных по умолчанию `data/` (SQLite, TLS-сертификат, SSH host-ключ)
можно переместить переменной окружения `HONEYSIGHT_DATA_DIR`
(в Docker-образе это `/data`). Флаг `--version` печатает версию сборки.

## Документация

- [**docs/deployment.md**](docs/deployment.md) — деплой на VPS: systemd и
  Docker, фаервол, GeoIP, боевой конфиг.
- [**docs/export.md**](docs/export.md) — схема webhook-пакета, STIX-маппинг,
  пример приёмника, fail-open поведение.
- [**docs/security.md**](docs/security.md) — безопасная эксплуатация,
  юридическая оговорка, что делать при canary-hit.

### Docker

```bash
docker run -d --name honeysight --restart unless-stopped \
  -p 8080:8080 -p 8443:8443 -p 2222:2222 -p 6380:6380 \
  -v /opt/honeysight/etc/config.yml:/etc/honeysight/config.yml:ro \
  -v /opt/honeysight/etc/rules.yml:/etc/honeysight/rules.yml:ro \
  -v /opt/honeysight/data:/data \
  ghcr.io/bin-qwerty/honeysight:latest
```

Образ на `gcr.io/distroless/static` (без shell), работает от nonroot.
Данные (SQLite, TLS-сертификат, SSH host-ключ) — в томе `/data`.
Подробности — в [docs/deployment.md](docs/deployment.md).

## Лицензия

MIT — см. [LICENSE](LICENSE).

Зависимости (все совместимы с MIT): `gopkg.in/yaml.v3` (Apache-2.0),
`modernc.org/sqlite` (MIT, чистый Go — cgo не нужен),
`golang.org/x/crypto` (BSD-3-Clause), `github.com/oschwald/maxminddb-golang`
(ISC, только при включённом GeoIP-обогащении).
