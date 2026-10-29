#!/usr/bin/env bash
# Self-contained log-audit demo for the deployed logaudit Reasonix part.
set -euo pipefail

RX="${REASONIX_BIN:-$HOME/.local/bin/reasonix}"
WORK="${LOG_AUDIT_WORK:-/tmp/audit-demo}"
HOME_DIR="${REASONIX_HOME:-$HOME/.serve-logaudit}"

mkdir -p "$WORK"
cat > "$WORK/access.log" <<'EOF'
1.2.3.4 - - [15/Aug/2026:10:00:00 +0800] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
1.2.3.4 - - [15/Aug/2026:10:00:01 +0800] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
1.2.3.4 - - [15/Aug/2026:10:00:02 +0800] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
1.2.3.4 - - [15/Aug/2026:10:00:03 +0800] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
1.2.3.4 - - [15/Aug/2026:10:00:04 +0800] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
1.2.3.4 - - [15/Aug/2026:10:00:05 +0800] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
1.2.3.4 - - [15/Aug/2026:10:00:06 +0800] "POST /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"
5.6.7.8 - - [15/Aug/2026:10:00:07 +0800] "GET /admin/config.php?cmd=whoami HTTP/1.1" 200 300 "-" "curl/8.0"
EOF

cd "$HOME/aisoc/parts/logaudit"
REASONIX_HOME="$HOME_DIR" timeout 240 "$RX" run \
  -p "请严格按顺序执行：1. 用 log_ingest 读取 $WORK/access.log（format=nginx）；2. 用 anomaly_detect 分析异常；3. 用 correlation 分析时间线。最后用中文总结发现了什么。只读分析，不要修改任何文件。" \
  --permission-mode bypassPermissions \
  --output-format text
