#!/usr/bin/env bash
# run-serve.sh —— 情报收集域 reasonix serve（8089）
# 放权：yolo 模式全自动放行，嵌套命令与敏感命令都不弹审批，不被 auto/ask 阻塞
set -euo pipefail

port="${1:-${RIX_PORT:-8089}}"
token="${RIX_TOKEN:-}"                               # ← 由 config/env/intel.env 注入
if [ -z "$token" ]; then
  echo "RIX_TOKEN 未设置：先 bash scripts/gen-env.sh，再 set -a && . config/env/intel.env && set +a" >&2
  exit 1
fi
REASONIX_BIN="${REASONIX_BIN:-./bin/reasonix}"        # ← 可覆盖为绝对路径

env REASONIX_HOME="$PWD/.reasonix-home" \
  "$REASONIX_BIN" serve --addr "127.0.0.1:${port}" \
  --auth token --token "$token" &
SRV_PID=$!

for _ in $(seq 1 30); do
  if curl -s -m 2 -X POST "http://127.0.0.1:${port}/tool-approval-mode" \
      -H "Content-Type: application/json" \
      -H "Cookie: reasonix_token=${token}" \
      -d '{"mode":"yolo"}' -o /dev/null; then
    echo "tool approval mode: yolo"
    break
  fi
  sleep 0.5
done

wait "$SRV_PID"
