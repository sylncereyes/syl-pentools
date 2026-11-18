#!/usr/bin/env bash
# bash qa/api.sh GET /api/auth/me
# bash qa/api.sh POST /api/assets '{"target":"scanme.nmap.org"}'
# TOKEN_FILE=/home/kali/.qa-auth/b_token bash qa/api.sh GET /api/assets
cd "$(dirname "$0")/.." || exit 1
set -a; . ./.env; set +a
M="${1:?method}"; P="${2:?path}"; B="${3:-}"
case "$P" in /*) ;; *) echo "path harus diawali /"; exit 2;; esac
T=$(cat "${TOKEN_FILE:-/home/kali/.qa-auth/access_token}" 2>/dev/null)
args=(-s -w '\nHTTP %{http_code}\n' -X "$M" "$API_URL$P" -H 'Content-Type: application/json')
[ -n "$T" ] && args+=(-H "Authorization: Bearer $T")
[ -n "$B" ] && args+=(-d "$B")
curl "${args[@]}" | sed -E 's/eyJ[A-Za-z0-9_.-]+/<JWT>/g'
