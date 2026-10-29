#!/usr/bin/env bash
# Verify the deployed logaudit Reasonix serve instance.
set -euo pipefail

BASE="${SERVE_URL:-http://127.0.0.1:8788}"
TOKEN="${REASONIX_SERVE_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -f "$HOME/.serve-logaudit/.env" ]; then
  TOKEN="$(sed -n 's/^DEEPSEEK_API_KEY=//p' "$HOME/.serve-logaudit/.env" | head -1)"
fi
if [ -z "$TOKEN" ]; then
  echo "set REASONIX_SERVE_TOKEN or ensure DEEPSEEK_API_KEY exists in $HOME/.serve-logaudit/.env" >&2
  exit 1
fi

echo "--- unauthenticated ---"
curl -s -m 5 -o /dev/null -w "root=%{http_code}\n" "$BASE/"
curl -s -m 5 -o /dev/null -w "status=%{http_code}\n" "$BASE/status"

echo "--- cookie auth ---"
curl -s -m 5 -H "Cookie: reasonix_token=$TOKEN" -o /tmp/rx-verify-status.json -w "status=%{http_code}\n" "$BASE/status"
head -c 300 /tmp/rx-verify-status.json; echo

echo "--- query auth ---"
curl -s -m 5 -L -c /tmp/rx-verify-cookies.txt -o /tmp/rx-verify-query.json -w "status=%{http_code}\n" "$BASE/status?token=$TOKEN"
head -c 300 /tmp/rx-verify-query.json; echo

echo "--- listener ---"
ss -tln | grep 8788 || true
echo "--- process ---"
ps -o user,pid,etime,args -C reasonix | grep 8788 || true
