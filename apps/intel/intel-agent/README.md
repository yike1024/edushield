# 情报收集域 · AiSOC 大脑接入（8789 → 8089）

> 用途：把「情报收集」reasonix agent 接入 AiSOC 大脑，实现 `submit → 执行 → findings → 状态` 全链路。
> 参考实现：pentest 域（8786→4523）、logaudit 域（8788→18788）。本目录为其第三个实例。

## 端口与 token（本次已配置）

| 变量 | 值 |
|---|---|
| `ADAPTER_PORT`（大脑 registry 指向） | **8789** |
| `RIX_PORT`（reasonix serve） | **8089** |
| `RIX_TOKEN` = `BRAIN_TOKEN` | `<INTEL_PART_TOKEN>=<INTEL_SERVE_TOKEN>` |
| `BRAIN_TOKEN_LEGACY` | 空（无旧 token） |

> ⚠️ token 已直接写入 `adapter.py` / `run-serve.sh`。**不要把本目录提交进 git**；
> 若需入库，先把 token 换回 `sk-xxx` 占位符。

## 文件

| 文件 | 说明 |
|---|---|
| `adapter.py` | 大脑 → serve 适配层（Bearer 校验 → JSON 注入 → AI 审批门 → findings 捕获 → 看门狗） |
| `run-serve.sh` | serve 启动脚本：8089 + token + 自动切 auto 审批 |
| `.reasonix-home/config.toml` | serve 实例 home 配置：`[permissions] mode=allow` + 敏感命令 ask 列表 |

## 启动（顺序不能反）

```bash
cd /home/wangwei/rax/intel-agent

# 1. serve（8089）。默认用 ./bin/reasonix，已有二进制时覆盖：
#    REASONIX_BIN=/home/wangwei/DeepSeek-Reasonix/reasonix ./run-serve.sh
#    （serve 需 DEEPSEEK_API_KEY 环境变量，沿用现有 shell 环境即可）
nohup ./run-serve.sh > serve.log 2>&1 &

# 2. adapter（8789）
nohup python3 adapter.py > adapter.log 2>&1 &
# 若 8789 被占：ss -tlnp | grep 8789，杀掉旧进程（pkill -f '[.]adapter[.]py'，注意别自杀）
```

## 大脑 registry

请大脑方把 registry 的「情报收集」域改为：

```json
{"domain": "intel", "host": "127.0.0.1", "port": 8789,
 "token": "<INTEL_PART_TOKEN>=<INTEL_SERVE_TOKEN>", "auth": "bearer", "enabled": true}
```

## 协议速查（大脑侧视角）

| 端点 | 语义 |
|---|---|
| `POST /submit` `Bearer <token>` body `{"input","task_id"}` | 下发任务 → 202 |
| `GET /events` `Bearer <token>` | SSE：`turn_started → reasoning → message(纯 JSON) → turn_done`；15s `: ping` 心跳 |
| `GET /status?task_id=<id>` | `running` → `completed`（含 `findings` 数组）/ `failed`（含 `error`） |

## 验收

```bash
# 1. adapter 认证
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8789/submit -H "Content-Type: application/json" -d '{}'          # 401
curl -s -X POST http://127.0.0.1:8789/submit -H "Content-Type: application/json" -H "Authorization: Bearer <INTEL_PART_TOKEN>=<INTEL_SERVE_TOKEN>" -d '{"input":"任务 T (intel): 请执行该域安全情报收集任务并输出结构化发现。\n目标: 127.0.0.1","task_id":"smoke"}'   # 202
# 2. 等任务完成，查 findings
curl -s "http://127.0.0.1:8789/status?task_id=smoke"    # status=completed, findings=[...]
# 3. 大脑侧（6657）
curl -s "http://127.0.0.1:6657/api/tasks/<task_id>"     # findings_count > 0
curl -s "http://127.0.0.1:6657/api/findings?task_id=<task_id>"   # findings 数组
```

## 踩坑清单（沿用指南，重点 4 条）

1. 转发**必须用 Cookie 认证**（`Cookie: reasonix_token=`），`?token=` 会让 POST 302 丢 body
2. 响应必须带 `Content-Length` + `Connection: close`，否则客户端等 keep-alive 关闭超时
3. 嵌套命令卡死 → serve 必须 auto 模式 + adapter AI 审批门（`approval_request` → DeepSeek 校验 → approve）
4. SSE 无历史缓冲：大脑必须先订阅 `/events` 再 submit；断线会丢事件（大脑需重连 + fallback 查 `/status`）

日志：`adapter-debug.log`（转发/任务状态）、`ai-approval.log`（AI 审批门记录）、`serve.log`。
