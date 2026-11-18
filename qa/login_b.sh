#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1
set -a; . ./.env; set +a
mkdir -p qa/auth; chmod 700 qa/auth
EM="qa_b_$(date +%s)@example.com"
PW="Qa$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12)9x"
echo "$EM" > qa/auth/b_email; echo "$PW" > qa/auth/b_pass
H='Content-Type: application/json'
curl -s -o qa/auth/b_register.json -w 'register HTTP %{http_code}\n' -X POST "$API_URL/api/auth/register" \
  -H "$H" -d "{\"email\":\"$EM\",\"password\":\"$PW\",\"full_name\":\"QA User B\"}"
c=$(curl -s -o qa/auth/b_login.json -w '%{http_code}' -X POST "$API_URL/api/auth/login" \
  -H "$H" -d "{\"email\":\"$EM\",\"password\":\"$PW\"}")
echo "login B HTTP $c"
jq -r '[.. | .access_token? // empty][0] // empty' qa/auth/b_login.json > qa/auth/b_token
chmod 600 qa/auth/*
[ -s qa/auth/b_token ] && echo "token B tersimpan" || echo "token B tidak ada"
