# Деплой на VPS

Два равноправных способа: нативный бинарник под systemd или Docker.

## Что нужно

- VPS с публичным IP (Linux).
- Открытые порты для приманок — **только те, которые реально используете**:
  - `8080` (HTTP), `8443` (HTTPS), `2222` (SSH), `6380` (Redis).
  - Хотите «красивые» `80/443/22/6379` — можно, но это привилегированные
    порты: для бинарника нужен `CAP_NET_BIND_SERVICE` (или запуск от root —
    не рекомендуем), для Docker — `--cap-add=NET_BIND_SERVICE`.
- Фаервол: разрешите входящий трафик только на эти порты. Входящий SSH на
  **настоящий** 22 порт VPS оставьте как есть — honeypot слушает 2222.

> Предупреждение: чем «реалистичнее» порт, тем больше шума. Redis на 6379
> и SSH на 22 будут ловить сканеры 24/7. Это и есть цель, но учитывайте
> нагрузку на лог-хранилище и webhook.

## Вариант 1: бинарник + systemd

```bash
# на VPS:
sudo mkdir -p /opt/honeysight
cd /opt/honeysight
# скопируйте: honeysight (бинарник из релиза), config.yml, rules/
sudo useradd -r -s /usr/sbin/nologin honeysight
sudo chown -R honeysight:honeysight /opt/honeysight
```

`/etc/systemd/system/honeysight.service`:

```ini
[Unit]
Description=Honeysight deception honeypot
After=network-online.target
Wants=network-online.target

[Service]
User=honeysight
WorkingDirectory=/opt/honeysight
ExecStart=/opt/honeysight/honeysight -config /opt/honeysight/config.yml
Restart=always
RestartSec=5
# Минимальные права: honeypot не пишет в системные каталоги.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/honeysight

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now honeysight
journalctl -u honeysight -f
```

## Вариант 2: Docker

Образ: `ghcr.io/bin-qwerty/honeysight` (собирается CI на каждый тег;
`latest` — последняя версия).

```bash
mkdir -p /opt/honeysight/{data,etc}
# ВАЖНО: контейнер работает от nonroot (uid 65532) — каталог данных
# должен быть им записываем:
chown -R 65532:65532 /opt/honeysight/data

cat > /opt/honeysight/etc/config.yml <<'EOF'
listen:
  http: ":8080"
  https: ":8443"
  ssh: ":2222"
  redis: ":6380"
rules:
  path: "/etc/honeysight/rules.yml"
export:
  webhook_url: "https://your-ti.example/webhook/honeysight"
  batch_size: 50
  flush_interval: 30s
enrich:
  geoip_db: "/etc/honeysight/GeoLite2-City.mmdb"   # опционально
EOF
cp rules/default.yml /opt/honeysight/etc/rules.yml

docker run -d --name honeysight --restart unless-stopped \
  -p 8080:8080 -p 8443:8443 -p 2222:2222 -p 6380:6380 \
  -v /opt/honeysight/etc/config.yml:/etc/honeysight/config.yml:ro \
  -v /opt/honeysight/etc/rules.yml:/etc/honeysight/rules.yml:ro \
  -v /opt/honeysight/data:/data \
  ghcr.io/bin-qwerty/honeysight:latest
```

Обновление: `docker pull ghcr.io/bin-qwerty/honeysight:latest && docker compose up -d`
(или `docker rm -f honeysight && docker run ...` заново — данные живут в `/data`).

## GeoIP-обогатение (опционально)

1. Бесплатный аккаунт: <https://dev.maxmind.com/> → скачайте
   `GeoLite2-City.mmdb.gz`.
2. `gunzip GeoLite2-City.mmdb.gz`, положите файл туда, куда указывает
   `enrich.geoip_db` (в Docker — смонтируйте в контейнер).
3. Перезапустите. События появятся с полями `geo` (страна, город) и `asn`.

Внешних вызовов honeypot **никогда** не делает — файл читается локально.

## Проверка работы

```bash
curl -s http://<vps-ip>:8080/ | head          # лендинг Northwind
curl -sk https://<vps-ip>:8443/ | head        # тот же лендинг по TLS
echo PING | timeout 2 bash -c 'cat > /dev/tcp/<vps-ip>/6380'  # порт жив
# события:
journalctl -u honeysight | grep 'msg=event'    # вариант 1
docker logs honeysight | grep 'msg=event'      # вариант 2
```

## Боевой config.yml (пример)

См. `config.example.yml` в корне репозитория — там закомментировано всё,
включая `trusted_proxies` (если honeypot стоит за балансировом) и
`quarantine` (порог и окно скоринга).
