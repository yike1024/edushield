#!/usr/bin/env bash
# AiSOC 大脑启动脚本（服务器部署用，无需 sudo）
set -e
cd "$(dirname "$0")/.."

echo "[brain] 创建虚拟环境并安装依赖..."
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[brain] 已生成 .env，请先编辑填密钥"
  exit 1
fi

echo "[brain] 启动大脑（端口 6657）..."
nohup ./.venv/bin/python -m api.main > brain.log 2>&1 &
echo "[brain] 已启动，PID=$!，日志: brain.log"
