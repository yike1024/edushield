#!/usr/bin/env bash
# ============================================================================
# dev-up.sh —— Linux 服务器版启动编排（与 dev-up.ps1 等价，读同一份 services.json）
#
#   bash scripts/dev-up.sh                     # 起全部 enabled
#   bash scripts/dev-up.sh --group pentest     # 只起渗透域
#   bash scripts/dev-up.sh --only brain,tir
#   HEALTH_TIMEOUT=180 bash scripts/dev-up.sh  # 放宽健康等待
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GROUP=""; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --group) GROUP="${2:-}"; shift 2 ;;
    --only)  ONLY="${2:-}";  shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"
HELPER="scripts/lib/services.py"
LOG_DIR="$ROOT/logs"
RUN_DIR="$ROOT/.run/pids"
mkdir -p "$LOG_DIR" "$RUN_DIR"

command -v python3 >/dev/null || { echo "需要 python3" >&2; exit 1; }

# ---- 环境文件 ----
if [ ! -f config/env/shared.env ]; then
  echo "[dev-up] 缺少 config/env/shared.env，先执行 bash scripts/gen-env.sh"
  bash scripts/gen-env.sh
fi

probe() { # $1=url $2=auth $3=cookieName $4=token $5=expect
  local url="$1" auth="$2" cname="$3" tok="$4" expect="$5" code
  if [ "$auth" = "cookie" ] && [ -n "$tok" ]; then
    code=$(curl -s -o /dev/null -m 4 -w '%{http_code}' -H "Cookie: ${cname}=${tok}" "$url" || true)
  else
    code=$(curl -s -o /dev/null -m 4 -w '%{http_code}' "$url" || true)
  fi
  [ "${code:-0}" = "$expect" ]
}

FAILED=0
while IFS=$'\t' read -r id order group port cwd hpath hexpect hauth cname cvar ppath pmethod pcvar; do
  [ -z "${id:-}" ] && continue
  svc_dir="$ROOT/$cwd"
  base="http://127.0.0.1:${port}"
  out_log="$LOG_DIR/${id}.out.log"
  err_log="$LOG_DIR/${id}.err.log"
  pid_file="$RUN_DIR/${id}.pid"

  echo ""
  echo "==> ${id}   ${base}   (cwd: ${cwd})"

  if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    echo "    已在运行 pid=$(cat "$pid_file")，跳过（先 dev-down）"
    continue
  fi
  if [ ! -d "$svc_dir" ]; then
    echo "    工作目录不存在：$svc_dir" >&2; FAILED=1; continue
  fi

  # 合并 env（不污染当前 shell，只在本 while 体内生效）
  while read -r line; do eval "$line"; done < <(python3 "$HELPER" env "$id")

  # 启动命令
  mapfile -t argv < <(python3 "$HELPER" cmd "$id")
  exe="${argv[0]}"
  if [[ "$exe" == */* ]]; then
    case "$exe" in
      /*) : ;;
      *) exe="$svc_dir/$exe" ;;
    esac
    if [ ! -x "$exe" ]; then
      echo "    可执行文件不存在或不可执行：$exe（先在该目录 make build）" >&2
      FAILED=1; continue
    fi
  elif ! command -v "$exe" >/dev/null; then
    echo "    PATH 中找不到可执行文件：$exe" >&2; FAILED=1; continue
  fi

  args=()
  if [ "${#argv[@]}" -gt 1 ]; then args=("${argv[@]:1}"); fi

  if [ "${#args[@]}" -gt 0 ]; then
    ( cd "$svc_dir" && exec "$exe" "${args[@]}" ) >"$out_log" 2>"$err_log" &
  else
    ( cd "$svc_dir" && exec "$exe" ) >"$out_log" 2>"$err_log" &
  fi
  svc_pid=$!
  echo "$svc_pid" > "$pid_file"
  echo "    pid=$svc_pid  log=$id.out.log"

  # 健康等待
  deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  ok=0
  tok=""
  if [ -n "${cvar:-}" ]; then tok="${!cvar}"; fi
  while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 2
    if ! kill -0 "$svc_pid" 2>/dev/null; then break; fi
    if probe "${base}${hpath}" "${hauth}" "${cname}" "${tok}" "${hexpect}"; then ok=1; break; fi
  done

  if ! kill -0 "$svc_pid" 2>/dev/null; then
    echo "    进程已退出，最后 15 行日志：" >&2
    tail -n 15 "$out_log" "$err_log" 2>/dev/null | sed 's/^/      /' >&2
    FAILED=1
    rm -f "$pid_file"
    continue
  fi

  if [ "$ok" = "1" ]; then
    echo "    健康检查通过 (${hpath} -> ${hexpect})"
  else
    echo "    ${HEALTH_TIMEOUT}s 内健康检查未通过（进程仍在运行）"
    FAILED=1
  fi

  # reasonix serve 审批模式
  IFS=$'\t' read -r ppath pmethod pcvar pbody < <(python3 "$HELPER" post "$id")
  if [ -n "${ppath:-}" ]; then
    ptok=""
    if [ -n "${pcvar:-}" ]; then ptok="${!pcvar}"; fi
    curl -s -m 10 -X "$pmethod" "${base}${ppath}" \
      -H 'Content-Type: application/json' \
      -H "Cookie: reasonix_token=${ptok}" -d "$pbody" >/dev/null \
      && echo "    postStart OK -> ${ppath} ${pbody}" || echo "    postStart 失败（可手动重试）"
  fi
done < <(python3 "$HELPER" list --group "$GROUP" --only "$ONLY")

echo ""
echo "==================== 启动汇总 ===================="
python3 "$HELPER" list --group "$GROUP" --only "$ONLY" --include-disabled | while IFS=$'\t' read -r id order group port rest; do
  pid_file="$RUN_DIR/${id}.pid"
  if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    printf '  %-16s port=%-5s pid=%-8s %s\n' "$id" "$port" "$(cat "$pid_file")" "running"
  else
    printf '  %-16s port=%-5s pid=%-8s %s\n' "$id" "$port" "-" "down"
  fi
done
echo "日志目录：$LOG_DIR    状态：bash scripts/status.sh"
[ "$FAILED" = "0" ] || echo "注意：有服务未健康启动，见上方日志" >&2
