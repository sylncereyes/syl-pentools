#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1
[ -f .env ] && { set -a; . ./.env; set +a; }
API="${API_URL:-http://localhost:8000}"
P=0; F=0
ok(){ echo "PASS  $1"; P=$((P+1)); }
no(){ echo "FAIL  $1"; F=$((F+1)); }
mkdir -p qa/evidence/F0

FE=""
for port in 3000 3001; do
  c=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: text/html' "http://localhost:$port/")
  [ "$c" = 200 ] && { FE="http://localhost:$port"; break; }
done
[ -n "$FE" ] && ok "Frontend 200 ($FE)" || no "Frontend tidak 200 di 3000/3001"

[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/api/health")" = 200 ] && ok "API /api/health" || no "API /api/health"
c=$(curl -s -o /dev/null -w '%{http_code}' "$API/socket.io/?EIO=4&transport=polling")
[ "$c" = 200 ] && ok "Socket.IO handshake" || no "Socket.IO handshake (HTTP $c)"
(echo > /dev/tcp/127.0.0.1/5433) 2>/dev/null && ok "Postgres 5433" || no "Postgres 5433"
(echo > /dev/tcp/127.0.0.1/6379) 2>/dev/null && ok "Redis 6379" || no "Redis 6379"
pgrep -f "celery.*worker" >/dev/null && ok "Celery worker" || no "Celery worker"
curl -sI "$API/api/health" > qa/evidence/F0/api_headers.txt
echo "HASIL: pass=$P fail=$F"
[ "$F" = 0 ]
