#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1
set -a; . ./.env; set +a
mkdir -p qa/auth; chmod 700 qa/auth
login(){ curl -s -o qa/auth/login.json -w '%{http_code}' -X POST "$API_URL/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$QA_USER_EMAIL\",\"password\":\"$QA_USER_PASS\"}"; }
c=$(login)
if [ "$c" != 200 ]; then
  echo "login HTTP $c -> coba register"
  curl -s -o /dev/null -w 'register HTTP %{http_code}\n' -X POST "$API_URL/api/auth/register" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$QA_USER_EMAIL\",\"password\":\"$QA_USER_PASS\",\"full_name\":\"QA User A\"}"
  c=$(login)
fi
echo "login HTTP $c"
jq -r '[.. | .access_token? // empty][0] // empty' qa/auth/login.json > qa/auth/access_token
chmod 600 qa/auth/*
[ -s qa/auth/access_token ] && echo "token tersimpan: qa/auth/access_token" \
  || { echo "token tidak ditemukan; struktur respons:"; jq -c 'paths|map(tostring)|join(".")' qa/auth/login.json | head; }
