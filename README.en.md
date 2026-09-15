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
```

Events land in `data/honeysight.db` (SQLite):

```bash
sqlite3 data/honeysight.db "SELECT ts, source_ip, score, severity, categories, action FROM events ORDER BY ts DESC LIMIT 20;"
```

## Architecture

```
Listeners (deception):                Pipeline:                 Sinks:
┌─ web (HTTP decoy)        ─┐        capture → normalize →     ┌─ SQLite (events)
├─ ssh   (M2)              ─┼──► Bus ──► detect (YAML rules) ──┼─ structured log
└─ redis (M4)              ─┘        → score → track (window,  └─ IOC export (M3)
                                     quarantine/tarpit)             JSON + STIX 2.1
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
rules/                 default signature rules
```

## License

MIT — see [LICENSE](LICENSE).
