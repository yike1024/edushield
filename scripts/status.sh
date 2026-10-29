#!/usr/bin/env bash
# ============================================================================
# status.sh —— 一屏看清各模块进程/端口/健康（Linux 服务器版）
#
#   bash scripts/status.sh
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HELPER="scripts/lib/services.py"
PID_DIR="$ROOT/.run/pids"
mkdir -p "$PID_DIR"

listening() { # $1=port
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0 || return 1
  fi
}

printf '%-16s %-9s %-6s %-8s %-9s %-10s %s\n' ID GROUP PORT ENABLED PID HEALTH STATE
ok=0; on=0
while IFS=$'\t' read -r id order group port cwd hpath hexpect hauth cname cvar ppath pmethod pcvar; do
  [ -z "${id:-}" ] && continue
  pid=""; health="-"; state="down"

  while read -r line; do eval "$line"; done < <(python3 "$HELPER" env "$id")

  pid_file="$PID_DIR/${id}.pid"
  if [ -f "$pid_file" ]; then pid="$(cat "$pid_file" 2>/dev/null || echo)"; fi

  running=0
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then running=1; fi

  listen=0
  if listening "$port"; then listen=1; fi

  if [ "$listen" = "1" ]; then
    tok=""
    if [ -n "${cvar:-}" ]; then tok="${!cvar}"; fi
    if [ "$hauth" = "cookie" ] && [ -n "$tok" ]; then
      code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' -H "Cookie: ${cname}=${tok}" "http://127.0.0.1:${port}${hpath}" || true)
    else
      code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "http://127.0.0.1:${port}${hpath}" || true)
    fi
    if [ "${code:-0}" = "$hexpect" ]; then health="ok(${code})"; else health="fail(${code:-0})"; fi
  fi

  if [ "$running" = "1" ] && [ "$listen" = "1" ] && [ "${health#ok}" != "$health" ]; then state="ok"
  elif [ "$running" = "1" ] && [ "$listen" = "1" ]; then state="no-health"
  elif [ "$listen" = "1" ]; then state="port-only"
  elif [ "$running" = "1" ]; then state="starting"
  fi

  [ "$state" = "ok" ] && ok=$((ok+1))
  on=$((on+1))

  printf '%-16s %-9s %-6s %-8s %-9s %-10s %s\n' "$id" "$group" "$port" "$enabled" "${pid:-?}" "$health" "$state"
done < <(python3 "$HELPER" list --include-disabled)

echo ""
echo "健康 $ok / 服务 $on      日志：$ROOT/logs/<service>.out.log"
