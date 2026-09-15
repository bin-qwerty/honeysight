#!/usr/bin/env bash
# Quick throughput smoke test: starts a throwaway honeysight, hammers it
# over HTTP, Redis and SSH, and reports captured events per second.
#
# Usage: make stress  (builds the binary first)
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
trap 'kill "$PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

cat > "$WORK/cfg.yml" <<EOF
listen:
  http: "127.0.0.1:18080"
  https: ""
  ssh: "127.0.0.1:18222"
  redis: "127.0.0.1:16380"
storage:
  sqlite_path: "$WORK/test.db"
rules:
  path: "rules/default.yml"
tarpit: 100ms   # keep the stress run fast; quarantined sources still slow down
EOF

./honeysight -config "$WORK/cfg.yml" > "$WORK/server.log" 2>&1 &
PID=$!
sleep 1

T0=$(date +%s)

# HTTP: 1000 requests, 20 in parallel, mix of benign and malicious paths.
seq 1 1000 | xargs -P 20 -n 1 sh -c '
  case $(( $1 % 4 )) in
    0) curl -s -o /dev/null "http://127.0.0.1:18080/" ;;
    1) curl -s -o /dev/null "http://127.0.0.1:18080/index.php?id=1%27%20OR%201=1--" ;;
    2) curl -s -o /dev/null "http://127.0.0.1:18080/.env" ;;
    3) curl -s -o /dev/null "http://127.0.0.1:18080/admin/login" ;;
  esac' _ &
HTTP_PID=$!

# Redis: 100 AUTH+GET connections, 4 in parallel, via a tiny python client.
python3 - <<'PY' &
import socket
from concurrent.futures import ThreadPoolExecutor

def one(_):
    try:
        s = socket.create_connection(("127.0.0.1", 16380), timeout=5)
        s.sendall(b"*2\r\n$4\r\nAUTH\r\n$4\r\npass\r\n*2\r\n$3\r\nGET\r\n$15\r\nsession:counter\r\n")
        s.recv(4096)
        s.close()
    except OSError:
        pass

with ThreadPoolExecutor(4) as ex:
    list(ex.map(one, range(100)))
PY
REDIS_PID=$!

# SSH is covered by protocol tests (needs a real handshake client); the
# stress run measures the pipeline over HTTP + Redis.

# Wait ONLY for the traffic generators — never a bare `wait` (that would
# also wait for the honeysight server, which runs forever).
wait "$HTTP_PID" "$REDIS_PID"
T1=$(date +%s)
DUR=$((T1 - T0)); [ "$DUR" -lt 1 ] && DUR=1

sleep 1  # let the dispatcher drain
EVENTS=$(grep -c "msg=event" "$WORK/server.log" || true)
echo "----------------------------------------"
echo "duration:  ${DUR}s"
echo "events:    ${EVENTS}  (~$((EVENTS / DUR))/s)"
echo "  http:    $(grep -c 'proto=http' "$WORK/server.log" || true)"
echo "  redis:   $(grep -c 'proto=redis' "$WORK/server.log" || true)"
echo "critical:  $(grep -c 'severity=critical' "$WORK/server.log" || true)"
echo "quarantined: $(grep -c 'source quarantined' "$WORK/server.log" || true)"
