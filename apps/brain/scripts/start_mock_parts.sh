#!/usr/bin/env bash
# 启动两个 mock 身体部件（联调用；队友真实 reasonix 就绪后停用）
set -e
cd "$(dirname "$0")/.."

echo "[mock] 启动 pentest:8787"
MOCK_PORT=8787 MOCK_DOMAIN=pentest nohup python3 mock_part.py > mock_pentest.log 2>&1 &

echo "[mock] 启动 logaudit:8788"
MOCK_PORT=8788 MOCK_DOMAIN=logaudit nohup python3 mock_part.py > mock_logaudit.log 2>&1 &

echo "[mock] 已启动两个 mock 部件"
