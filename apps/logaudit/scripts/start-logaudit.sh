#!/usr/bin/env bash
# Start the logaudit Reasonix serve instance on 127.0.0.1:8788.
set -euo pipefail

RX="${REASONIX_BIN:-$HOME/.local/bin/reasonix}"
SERVE_HOME="${REASONIX_HOME:-$HOME/.serve-logaudit}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="${LOG_AUDIT_WORKDIR:-$HOME/aisoc/parts/logaudit}"
TOKEN="${REASONIX_SERVE_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -f "$SERVE_HOME/.env" ]; then
  TOKEN="$(sed -n 's/^DEEPSEEK_API_KEY=//p' "$SERVE_HOME/.env" | head -1)"
fi
if [ -z "$TOKEN" ]; then
  echo "set REASONIX_SERVE_TOKEN or ensure DEEPSEEK_API_KEY exists in $SERVE_HOME/.env" >&2
  exit 1
fi

mkdir -p "$SERVE_HOME" "$WORKDIR"
if [ ! -f "$SERVE_HOME/.env" ] && [ -f "$HOME/.serve-home/.env" ]; then
  cp "$HOME/.serve-home/.env" "$SERVE_HOME/.env"
fi
chmod 600 "$SERVE_HOME/.env"
if [ ! -f "$SERVE_HOME/config.toml" ] && [ -f "$HOME/.reasonix/config.toml" ]; then
  cp "$HOME/.reasonix/config.toml" "$SERVE_HOME/config.toml"
fi
chmod 600 "$SERVE_HOME/config.toml" 2>/dev/null || true
if [ "$WORKDIR" != "$REPO_ROOT" ]; then
  cp "$REPO_ROOT/logaudit.example.toml" "$WORKDIR/reasonix.toml"
fi

PORT="${LOG_AUDIT_PORT:-8788}"
cd "$WORKDIR"
REASONIX_HOME="$SERVE_HOME" nohup "$RX" serve \
  --addr "127.0.0.1:${PORT}" \
  --auth token \
  --token "$TOKEN" \
  --behind-proxy \
  >> "$HOME/serve-${PORT}.log" 2>&1 &
echo "logaudit serve started on 127.0.0.1:${PORT}"
