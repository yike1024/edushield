#!/usr/bin/env bash
# ============================================================================
# dev-down.sh —— 逆序停止 dev-up.sh 拉起的进程（.run/pids/<id>.pid）
#
#   bash scripts/dev-down.sh                # 停全部
#   bash scripts/dev-down.sh --only brain   # 只停某个
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="${2:-}"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

PID_DIR="$ROOT/.run/pids"
HELPER="scripts/lib/services.py"
mkdir -p "$PID_DIR"

if [ -z "$(ls -A "$PID_DIR" 2>/dev/null)" ]; then
  echo "[dev-down] $PID_DIR 为空，没有 dev-up 启动的进程"
  exit 0
fi

# 逆序：startOrder 大的先停（前端 → 大脑 → adapter → serve）
mapfile -t ids < <(python3 "$HELPER" list --include-disabled | cut -f1)

stopped=0
for (( i=${#ids[@]}-1; i>=0; i-- )); do
  id="${ids[$i]}"
  [ -z "$id" ] && continue
  if [ -n "$ONLY" ] && [ "${ONLY}" != "$id" ]; then continue; fi
  pid_file="$PID_DIR/${id}.pid"
  [ -f "$pid_file" ] || continue
  svc_pid="$(cat "$pid_file" 2>/dev/null || echo)"
  if [ -z "$svc_pid" ] || ! kill -0 "$svc_pid" 2>/dev/null; then
    echo "[dev-down] $id pid=${svc_pid:-?} 已不在运行"
    rm -f "$pid_file"
    continue
  fi
  echo "[dev-down] 停止 $id pid=$svc_pid"
  kill -TERM "$svc_pid" 2>/dev/null
  for _ in $(seq 1 10); do
    kill -0 "$svc_pid" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$svc_pid" 2>/dev/null; then
    echo "[dev-down]   TERM 无效，强制 KILL"
    pkill -KILL -P "$svc_pid" 2>/dev/null
    kill -KILL "$svc_pid" 2>/dev/null
  fi
  rm -f "$pid_file"
  stopped=$((stopped+1))
done

echo "[dev-down] 已停止 $stopped 个进程"
