#!/bin/bash
# 在 WSL 中启动 EduShield HTTP 服务器（修复 API 密钥问题）

set -e

echo "=== 启动 EduShield HTTP 服务器（带完整配置）==="

# 获取项目目录
PROJECT_DIR="/mnt/d/揭榜挂帅/EduShield-Security/DeepSeek-Reasonix"
cd "$PROJECT_DIR"

echo "步骤 1: 设置环境变量（强制设置）"
export GOROOT="$PROJECT_DIR/go-local/go"
export PATH="$GOROOT/bin:$PATH"
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"
export GOPROXY="https://goproxy.cn,direct"

# 重要：确保 API 密钥被正确设置
export DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}"
echo "API 密钥: ${DEEPSEEK_API_KEY:0:10}..."

echo "步骤 2: 创建必要的配置目录"
mkdir -p ~/.reasonix

echo "步骤 3: 创建配置文件（如果不存在）"
CONFIG_FILE="$HOME/.reasonix/config.toml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "创建配置文件: $CONFIG_FILE"
    cat > "$CONFIG_FILE" << 'EOF'
default_model = "deepseek-flash"

[[providers]]
name        = "deepseek-flash"
kind        = "openai"
base_url    = "https://api.deepseek.com"
model       = "deepseek-v4-flash"
api_key_env = "DEEPSEEK_API_KEY"
EOF
else
    echo "配置文件已存在: $CONFIG_FILE"
fi

echo "步骤 4: 创建 .env 文件（用于存储 API 密钥）"
ENV_FILE="$HOME/.reasonix/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "创建 .env 文件: $ENV_FILE"
    echo "DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY}" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"  # 保护文件权限
else
    echo ".env 文件已存在: $ENV_FILE"
fi

echo "步骤 5: 验证配置"
echo "配置文件: $CONFIG_FILE"
echo "环境文件: $ENV_FILE"
echo "当前 API 密钥变量: ${DEEPSEEK_API_KEY:0:10}..."

echo "步骤 6: 测试二进制文件"
if [ ! -f "bin/reasonix" ]; then
    echo "❌ 二进制文件不存在，需要先构建"
    exit 1
fi
echo "✅ 二进制文件存在"

echo "步骤 7: 启动 HTTP 服务器"
echo "======================================"
echo "EduShield HTTP 服务器启动中..."
echo "======================================"
echo ""
echo "📝 使用说明："
echo "1. 在浏览器中访问: http://127.0.0.1:2713"
echo "2. 现在你将看到真实的 EduShield 功能（不再是 mock 数据）"
echo "3. API 密钥已配置"
echo ""
echo "🔄 前端开发服务器仍在运行: http://127.0.0.1:5173"
echo ""

# 启动 HTTP 服务器
./bin/reasonix serve --addr 127.0.0.1:2713

