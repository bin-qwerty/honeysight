# Экспорт IOC: webhook и STIX 2.1

Honeysight шлёт события **пакетами** на ваш `export.webhook_url`
(POST, `Content-Type: application/json`). Пакет — один JSON:

```json
{
  "generated": "2026-09-15T15:00:00Z",
  "source": "honeysight",
  "events": [
    {
      "id": "ca13193f056dbe0b",
      "ts": "2026-09-15T14:59:12.001Z",
      "protocol": "http",
      "ip": "203.0.113.7",
      "port": 51234,
      "action": "request",
      "score": 85,
      "severity": "critical",
      "categories": ["sql-injection", "scanner"],
      "canary": "",
      "fingerprint": "http/1.1",
      "details": {
        "method": "GET",
        "path": "/index.php",
        "query": "id=1' UNION SELECT null,version()--",
        "user_agent": "sqlmap/1.9.2"
      },
      "geo": {"country": "RU", "city": "Moscow"},
      "asn": "AS12345"
    }
  ],
  "stix_bundle": { "type": "bundle", "id": "bundle--...", "objects": [ ... ] }
}
```

### Поля события

| Поле | Смысл |
|---|---|
| `id` | UUID события (стабилен между дублирующими доставками) |
| `protocol` | `http`, `https`, `ssh`, `redis` |
| `action` | `request`, `login`, `auth`, `cmd`, `exec`, `shell`, `banner`, `connect` … |
| `score` / `severity` | Скор по правилам и порог: `none/low/medium/high/critical` |
| `categories` | Срабатывания правил: `sql-injection`, `redis-abuse`, `credential-access` … |
| `canary` | ID canary-набора, если событие связано с приманкой |
| `fingerprint` | JA3 (TLS-протоколы) или `http/1.1` |
| `details` | Свободная карта: креденшелы, команды, пути, UA и т.д. |
| `geo` / `asn` | Только если включено `enrich.geoip_db` |

### STIX bundle: как читается

Один пакет → один bundle из трёх типов объектов:

1. **`indicator` — по каждому уникальному IP в пакете**
   - `pattern`: `[ipv4-addr:value = '203.0.113.7']` (IPv6 — `ipv6-addr`)
   - `name`: `Honeysight indicator: 203.0.113.7`
   - `labels`: категории + `severity-critical` и т.п.
   - `x_honeysight` (vendor extension): max score, first/last seen,
     canaries, fingerprint'ы, sample событий.
2. **`tool` — по каждому обнаруженному сканеру** (sqlmap, nikto, nmap, …)
   из user-agent'ов в пакете.
3. **`report` — один на пакет**, связывает indicator'ы и tool'ы
   (`object_refs`), с `published` = момент формирования пакета.

Это валидный STIX 2.1: bundle можно закинуть в MISP (`/import`),
TheHive, Cortex или любой STIX-совместимый коллектор.

### Как принять

Минимальный приёмник (Python, 10 строк):

```python
# pip install flask
from flask import Flask, request
app = Flask(__name__)

@app.post("/webhook/honeysight")
def recv():
    payload = request.get_json()
    for ev in payload["events"]:
        print(ev["ip"], ev["score"], ev["categories"], ev["details"])
    # payload["stix_bundle"] — сюда, если нужна STIX-сторона
    return "ok", 200
```

### Поведение при недоступности TI (fail-open)

- Пакет ретраится 3 раза с бэкоффом 1s/5s/25s.
- Не получилось — пакет **бросается с ошибкой в лог**. Honeypot никогда
  не останавливается из-за проблем с экспортом: захват и приманки работают
  в любом случае.
- Настройки: `export.batch_size` (50), `export.flush_interval` (30s),
  `export.retries` (3), `export.timeout` (10s).
