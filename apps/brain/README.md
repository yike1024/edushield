# AiSOC 大脑（校园智盾 Brain）

多 Agent 安全运营平台的**大脑层**（FastAPI，端口 6657）。

## 已完成能力（阶段 1-4）

- **统一协议**：`protocol/`（TaskMessage / Finding / Report，照 aisoc-docs 02）
- **部件注册表**：`registry/`（pentest 8787 / logaudit 8788，可 JSON 覆盖）
- **SQLite 会话**：`session/`（tasks/findings/ledger/reports 落库 + 状态机）
- **编排调度**：`orchestrator/`（白名单 → 下发 `/submit` → 轮询 `/status` → 回收 Finding；支持 `data_leak` 管道：日志审计 → 渗透验证）
- **威胁判定**：`verdict/`（规则轨校园误报抑制 + LLM 轨双轨，可复核）
- **报告 + 审计导出**：`report/` + `GET /api/tasks/{id}/export`
- **知识库**：`knowledge/`（ChromaDB，seed 已修幂等）
- **深信服数据接入**：`data_source/`（官方 10 条告警样例离线可用 + XDR OpenAPI 签名客户端骨架）
- **实时事件 + 前端面板**：`eventhub/` + `/api/stream`（SSE）+ `static/index.html`

## 本地跑通

```bash
# 1) mock 身体部件（队友真实 reasonix 就绪后换掉）
python mock_part.py                          # logaudit:8788
# 另开终端：
MOCK_PORT=8787 MOCK_DOMAIN=pentest python mock_part.py

# 2) 大脑
pip install -r requirements.txt
python -m api.main                           # http://0.0.0.0:6657
```

打开 `http://127.0.0.1:6657/` 就是前端面板，可直接下任务。

命令行示例：

```bash
# 单域任务
curl -X POST http://127.0.0.1:6657/api/tasks -H "Content-Type: application/json" \
  -d '{"task":"分析日志","domain":"logaudit","target":"demo-campus.edu.cn"}'

# 多阶段管道（数据泄露调查：logaudit → pentest → 判定 → 报告）
curl -X POST http://127.0.0.1:6657/api/tasks -H "Content-Type: application/json" \
  -d '{"task":"数据泄露调查","domain":"logaudit","target":"demo-campus.edu.cn","pipeline":"data_leak"}'

# 查任务 / 证据 / 报告 / 审计导出
curl http://127.0.0.1:6657/api/tasks/<task_id>
curl "http://127.0.0.1:6657/api/findings?task_id=<task_id>"
curl http://127.0.0.1:6657/api/reports/<task_id>
curl http://127.0.0.1:6657/api/tasks/<task_id>/export
```

## 服务器部署（无 sudo）

```bash
# 上传整个 aisoc-brain 目录后，在服务器上：
cd ~/aisoc-brain
cp .env.example .env       # 编辑填密钥 / 白名单 / 注册表
bash scripts/start_brain.sh
# 队友部件就绪前：
bash scripts/start_mock_parts.sh
```

对外访问大脑面板：用 cpolar 或 SSH 本地转发把 `6657` 端口引出来（不要暴露 8787/8788）。

## 配置要点（.env）

| 项 | 说明 |
|---|---|
| `API_PORT` | 大脑端口，默认 6657 |
| `AUTHORIZED_TARGETS` | 授权白名单，逗号分隔，不在名单内 403 |
| `REGISTRY_FILE` | 部件注册表 JSON（留空用内置默认） |
| `XDR_BASE_URL` + `XDR_AUTH_CODE` | 深信服 XDR live 接入（不配则用样例数据） |
| `DEEPSEEK_API_KEY` | 判定 LLM 轨（不配则纯规则轨） |

## 目录

```
api/            路由层（含前端面板挂载）
protocol/       三协议
registry/       部件注册表
session/        SQLite 会话存储
orchestrator/   编排调度（单域 + 管道）
verdict/        威胁判定（规则 + LLM）
report/         报告生成
knowledge/      知识库（ChromaDB）
data_source/    XDR 告警样例 + OpenAPI 客户端
eventhub/       实时事件
static/         前端面板
mock_part.py    假身体部件
scripts/        部署脚本
```

## 后续待办

- [ ] 联调队友真实 reasonix serve（改 `REGISTRY_FILE` 即可，代码无需动）
- [ ] SSE 订阅真实部件 `/events`（eventhub 采集端）
- [ ] 等保合规检查 / docx 报告导出
- [ ] XDR live 模式真实联调（需联动码）
