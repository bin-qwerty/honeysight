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
- **Rules in YAML** (`rules/`), hot-reloadable, with a regression payload corpus.
- **Quarantine is local**: the honeypot only changes how it answers its own
  traffic (slow 403 tarpit); it never touches the attacker's host.

## Layout

```
cmd/honeysight/        entrypoint
internal/core/         event model + bus
internal/config/       YAML config
internal/detect/       signature engine (pure, tested) + YAML rules
internal/track/        rolling per-source scoring + quarantine
internal/store/        storage interfaces + SQLite
internal/decoy/web/    HTTP deception listener + bait
rules/                 default signature rules
```

## License

MIT — see [LICENSE](LICENSE).
