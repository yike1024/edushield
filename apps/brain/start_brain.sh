#!/usr/bin/env bash
# AiSOC 大脑启动脚本（T0-4 固化：环境变量 + 启动 + 日志，重启机器后执行本脚本即可）
set -u
cd "$HOME/aisoc-brain-lyx" || exit 1
export BRAIN_ATTACHMENT_DIR="$HOME/aisoc-brain-lyx/data/attachments"
mkdir -p "$BRAIN_ATTACHMENT_DIR"
pkill -f 'api[.]main' 2>/dev/null
sleep 2
setsid nohup "$HOME/miniconda3/bin/python" -m api.main >> brain.log 2>&1 </dev/null &
echo "brain started, pid=$!, log=$PWD/brain.log"
