# Honeysight

Multi-protocol deception honeypot for threat intelligence research.

[Русскоязычная версия README](README.md)

Honeysight looks like a real, slightly vulnerable target — a corporate
portal, a cloud workload, a Redis cache — and records **everything** an
attacker does: requests, logins, commands, payloads. Every interaction is
classified in real time, scored 0–100, enriched, stored locally, and exported
as IOCs (JSON + STIX 2.1) for your threat-intelligence pipeline.

> ⚠️ **Ethics & scope.** Honeysight is a *defensive* research tool. It only
> observes, records and slows traffic against its **own** surface. No scanning,
> no exploitation, no hack-back. Deploy only on infrastructure you own or are
> explicitly authorized to test.

## Quickstart

```bash
go run ./cmd/honeysight -config config.example.yml
# or: go build -o honeysight ./cmd/honeysight && ./honeysight

# in another terminal:
curl -s localhost:8080/                 # looks like a corporate portal
curl -s "localhost:8080/?id=1' OR 1=1--"
curl -s localhost:8080/.env             # fake but convincing
curl -s -A "sqlmap/1.8" localhost:8080/
curl -s -c jar -L -d "user=admin&pass=x" localhost:8080/admin/login  # fake login -> data dashboard
curl -sk -L -d "user=root&pass=y" https://localhost:8443/admin/login # over TLS (JA3 captured)
ssh -p 2222 root@localhost   # fake OpenSSH: any password, canary-seeded shell
```

Events land in `data/honeysight.db` (SQLite):

```bash
sqlite3 data/honeysight.db "SELECT ts, source_ip, score, severity, categories, action FROM events ORDER BY ts DESC LIMIT 20;"
```

## Architecture

```
Listeners (deception):                Pipeline:                 Sinks:
┌─ web   (HTTP decoy)      ─┐        capture → normalize →     ┌─ SQLite (events)
├─ ssh   (OpenSSH + shell) ─┼──► Bus ──► detect (YAML rules) ──┼─ structured log
├─ redis (Redis 7.2 + keys) ┼──►        → score → track (window, └─ IOC export:
└───────────────────────────┘        quarantine/tarpit)            JSON + STIX 2.1 → webhook
```

- **Single Go binary**, SQLite by default (zero-config), Postgres later.
- **TLS listener with JA3**: the ClientHello is parsed before the handshake,
  so every event over TLS carries the client's JA3 fingerprint.
- **Canary tokens**: the admin dashboard plants unique fake credentials per
  source IP — if one shows up in the attacker's world, the source is confirmed.
- **Rules in YAML** (`rules/`), hot-reloadable, with a regression payload corpus.
- **Quarantine is local**: the honeypot only changes how it answers its own
  traffic (slow 403 tarpit); it never touches the attacker's host.

### Decoy surface

| Surface | What the attacker sees |
|---|---|
| `/` | "Corporate portal" with links to admin, CMS, phpMyAdmin |
| `/.env` | "Leaked" config with DB/Redis/AWS secrets (all fake) |
| `/.git/config` | Fake git repository |
| `/admin`, `/wp-login.php`, `/phpmyadmin` | Login forms |
| `/admin/dashboard` (after "login") | Admin console: users, DB connections, cloud keys, internal hosts |
| `Host: 169.254.169.254`, `/latest/meta-data/` | Cloud metadata service |

"Login" always succeeds. The dashboard is a honeypot jackpot: every
credential-looking value in it is a **canary token unique to that source IP**
(DB password, API key, AWS key pair, admin username, internal IP). Sets live
for an hour, then rotate. All tokens are persisted in SQLite
(`<db>-canaries.db`) for later "canary hit" correlation. The session cookie
value is the canary set id itself.

### IOC export (STIX 2.1 + webhook)

Events are shipped in batches to your webhook (TI platform, MISP, Elastic —
anything that accepts a POST JSON). Each batch is one payload:

- `events[]` — clean JSON schema: protocol, IP, action, score, categories,
  canary id, client JA3/fingerprint, details, plus `geo`/`asn` when enabled;
- `stix_bundle` — a valid STIX 2.1 bundle: one **indicator per unique
  source IP** (`ipv4-addr:value` pattern, category labels, max score,
  first/last seen window, canaries and fingerprints under `x_honeysight`),
  one **tool** per observed scanner (sqlmap, nikto, nmap, ...), and a
  **report** tying the batch together.

Tunables: `batch_size` (default 50), `flush_interval` (30s), `retries` (3,
backoff 1s/5s/25s). When the webhook is unreachable the batch is retried and
then dropped with an error log — the honeypot never stalls because of export
(fail-open).

### Enrichment (GeoIP/ASN)

Optional: a local MaxMind database (`enrich.geoip_db`; GeoLite2-City covers
country, city and ASN in one file). Reads are in-memory only — Honeysight
makes **no** external calls anywhere; you provide the database file
(free account at dev.maxmind.com).

### Redis decoy

The `:6380` listener (usually `:6379` on a VPS) pretends to be Redis 7.2.4.
`AUTH` accepts **any** credentials (both `AUTH pass` and `AUTH user pass`)
and always answers `+OK` — the credentials themselves are captured in the
`action=auth` event.

The keyspace is seeded with the source's canary set (the same registry as
web and SSH): `northwind:api:secret`, `northwind:db:password`,
`northwind:db:host`, `northwind:aws:*`, `northwind:admin:username`,
`northwind:gateway:internal`. `PING/ECHO/SELECT/INFO/DBSIZE/KEYS/SCAN/GET/
MGET/EXISTS/TTL/TYPE/STRLEN/SET/CONFIG/CLIENT` answer plausibly; `FLUSHALL`
and `SLAVEOF` "work"; `SHUTDOWN` does not take the honeypot down.

Every command is an `action=cmd` event: the `redis-recon` (KEYS *, INFO,
CONFIG GET, ...) and `redis-abuse` (FLUSHALL, CONFIG SET, SLAVEOF, EVAL, ...)
rules highlight exploitation attempts. Quarantine is shared: blocked sources
get tarpit-delayed replies.

### SSH decoy

The `:2222` listener pretends to be `OpenSSH_8.9p1 Ubuntu`. Any credentials
are accepted (password, publickey, keyboard-interactive); offered public keys
are recorded by SHA256 fingerprint — a strong IOC on its own. After "login"
you get an interactive shell on an Ubuntu box (`northwind-app01` with
postgres, redis and a node API):

- `whoami`, `id`, `ls`, `env`, `ps`, `netstat`, `last`, ... — plausible output;
- `.env`, `deploy.sh`, `notes.txt`, `.bash_history`, `/etc/passwd`,
  `/etc/shadow` carry **this source's canary tokens** (the same sets as the
  web admin console);
- every command is published as an `action=cmd` event with the full command
  text: the detection engine catches `; nc 1.2.3.4 4444`, `| sh`,
  `/etc/passwd` and other reverse-shell patterns;
- quarantine/tarpit is shared: blocked sources get delayed answers.

## Layout

```
cmd/honeysight/        entrypoint
internal/core/         event model + bus
internal/config/       YAML config
internal/detect/       signature engine (pure, tested) + YAML rules
internal/track/        rolling per-source scoring + quarantine
internal/store/        storage interfaces + SQLite
internal/canary/       canary tokens: generation, registry, SQLite
internal/fingerprint/  ClientHello parsing, JA3, TLS listener
internal/tlsutil/      self-signed certificate auto-generation
internal/decoy/web/    HTTP deception listener + bait (portal, admin, metadata)
internal/decoy/ssh/    OpenSSH server: login capture + fake shell with canaries
internal/decoy/redis/  Redis 7.2: AUTH capture + fake keyspace with canaries (RESP)
rules/                 default signature rules
```

## License

MIT — see [LICENSE](LICENSE).
