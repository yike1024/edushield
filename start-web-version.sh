#!/bin/bash
# 网页版真实API启动脚本
# 用于启动支持真实DeepSeek API的网页版

echo "=== EduShield 网页版 - 真实DeepSeek API集成 ==="
echo ""

PROJECT_DIR="/mnt/d/揭榜挂帅/EduShield-Security/DeepSeek-Reasonix"
cd "$PROJECT_DIR"

echo "✅ 步骤 1: 验证API配置"
if [ -f ".env" ]; then
    source .env
    if [ -n "$DEEPSEEK_API_KEY" ]; then
        echo "✅ DeepSeek API Key 已配置"
    else
        echo "❌ DEEPSEEK_API_KEY 未设置"
        exit 1
    fi
else
    echo "❌ .env 文件不存在"
    exit 1
fi

echo ""
echo "✅ 步骤 2: 检查前端构建"
cd desktop/frontend
if [ ! -d "node_modules" ]; then
    echo "📦 安装依赖..."
    pnpm install
fi

echo ""
echo "✅ 步骤 3: 启动前端开发服务器"
echo "🌐 网页版将访问真实的DeepSeek API"
echo "📋 访问地址: http://localhost:5173"
echo ""
echo "🔥 重要特性:"
echo "  ✅ 真实DeepSeek API调用"
echo "  ✅ 实时AI响应"
echo "  ✅ 无需mock数据"
echo "  ✅ 直接浏览器访问"
echo ""
echo "⚠️  注意事项:"
echo "  - 确保网络连接正常"
echo "  - API Key有效且有额度"
echo "  - 浏览器控制台可查看详细日志"
echo ""

# 启动开发服务器
pnpm dev