#!/bin/bash
# 简单的API连接测试
echo "测试 DeepSeek API 连接..."

API_KEY="${DEEPSEEK_API_KEY:-}"
API_URL="https://api.deepseek.com"

echo "API Key: ${API_KEY:0:10}..."
echo "API URL: $API_URL"

# 使用curl测试API连接（如果可用）
if command -v curl &> /dev/null; then
    echo "测试API连接..."
    RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/v1/models" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)

    if [ "$HTTP_CODE" = "200" ]; then
        echo "✅ API连接成功"
        echo "响应: $BODY" | head -c 200
        echo "..."
    else
        echo "⚠️  API连接测试: HTTP $HTTP_CODE"
        echo "响应: $BODY" | head -c 200
    fi
else
    echo "curl 不可用，跳过连接测试"
fi
