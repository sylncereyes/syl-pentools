#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1
set -a; . ./.env; set +a
H='Content-Type: application/json'
L=$(curl -s -X POST "$API_URL/api/auth/login" -H "$H" -d "{\"email\":\"$QA_USER_EMAIL\",\"password\":\"$QA_USER_PASS\"}")
A=$(echo "$L" | jq -r .access_token)
R=$(echo "$L" | jq -r .refresh_token)
[ -n "$A" ] && [ "$A" != null ] || { echo "login gagal"; exit 1; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
echo "me sebelum logout          : $(code "$API_URL/api/auth/me" -H "Authorization: Bearer $A")"
echo "refresh token sbg access   : $(code "$API_URL/api/auth/me" -H "Authorization: Bearer $R") (harus 401)"
echo "access token sbg refresh   : $(code -X POST "$API_URL/api/auth/refresh" -H "$H" -d "{\"refresh_token\":\"$A\"}") (harus 401)"
echo "refresh normal             : $(code -X POST "$API_URL/api/auth/refresh" -H "$H" -d "{\"refresh_token\":\"$R\"}") (harus 200)"
echo "logout                     : $(code -X POST "$API_URL/api/auth/logout" -H "Authorization: Bearer $A")"
echo "me setelah logout          : $(code "$API_URL/api/auth/me" -H "Authorization: Bearer $A")"
echo "refresh setelah logout     : $(code -X POST "$API_URL/api/auth/refresh" -H "$H" -d "{\"refresh_token\":\"$R\"}")"
