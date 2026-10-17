#!/bin/sh
set -eu

: "${PORT:=8000}"
: "${FALKORDB_PASSWORD:?Set a strong FALKORDB_PASSWORD in the host's encrypted environment settings}"

# Persistent volumes may be mounted as root-owned. Repair ownership once at startup,
# then drop privileges before launching FalkorDB and the API.
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p /var/lib/falkordb/data
  chown -R app:app /var/lib/falkordb/data
  exec gosu app:app "$0" "$@"
fi

# Find the module supplied by the official FalkorDB server image rather than
# hard-coding a path that may change between upstream image versions.
FALKORDB_MODULE="$(find / -type f -name 'falkordb.so' -print -quit 2>/dev/null || true)"
if [ -z "$FALKORDB_MODULE" ]; then
  echo "FATAL: falkordb.so was not found in the base image." >&2
  exit 1
fi

mkdir -p /var/lib/falkordb/data
redis-server \
  --loadmodule "$FALKORDB_MODULE" \
  --bind 127.0.0.1 \
  --port 6379 \
  --protected-mode yes \
  --dir /var/lib/falkordb/data \
  --appendonly yes \
  --save 60 1 \
  --requirepass "$FALKORDB_PASSWORD" &
REDIS_PID=$!

API_PID=""
cleanup() {
  if [ -n "$API_PID" ]; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
  kill "$REDIS_PID" 2>/dev/null || true
  wait "$REDIS_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

export REDISCLI_AUTH="$FALKORDB_PASSWORD"
READY=0
i=0
while [ "$i" -lt 30 ]; do
  if redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null | grep -q PONG; then
    READY=1
    break
  fi
  if ! kill -0 "$REDIS_PID" 2>/dev/null; then
    echo "FATAL: FalkorDB process exited during startup." >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  echo "FATAL: FalkorDB did not become ready within 30 seconds." >&2
  exit 1
fi

uvicorn api:app --host 0.0.0.0 --port "$PORT" &
API_PID=$!
wait "$API_PID"
