# AiSOC 大脑 —— 前端对接文档

> 版本 v1.0 ｜ 适用：平台前端（React/Vue/原生皆可）
> 服务：`aisoc-brain`（FastAPI），端口 **6657**
> 前端呈现什么 = 大脑有什么。本文档即大脑全部对外能力。

---

## 1. 服务地址

| 环境 | 地址 |
|---|---|
| 服务器本机开发 | `http://127.0.0.1:6657` |
| 对外演示 | 由 cpolar/nginx 暴露后的地址（联调时提供） |

- CORS 已全开，前端任意端口直连即可
- 所有接口均为 `application/json`，事件流为 `text/event-stream`

---

## 2. 接口总览

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/api/tasks` | 下发任务（单域 / 多阶段管道） |
| POST | `/api/assess` | 自然语言一句话 → 自动编排子智能体（chat 转 task） |
| GET | `/api/tasks` | 最近任务列表（仪表盘） |
| GET | `/api/tasks/{task_id}` | 任务状态 + 阶段进度 + 思维链 |
| GET | `/api/tasks/{task_id}/export` | 审计导出（JSON） |
| GET | `/api/findings?task_id=` | 查询证据 |
| GET | `/api/reports/{task_id}` | 查询报告（Markdown） |
| GET | `/api/registry` | 部件注册表（token 已脱敏） |
| GET | `/api/agents/status` | 各 Agent 忙闲状态 + TIR 服务状态 |
| GET | `/api/whitelist` | 授权白名单查询 |
| POST | `/api/whitelist` | 授权白名单编辑（add/remove/set_enabled） |
| GET | `/api/settings/runtime` | 运行时行为设置（后端权威值） |
| POST | `/api/settings/runtime` | 运行时行为设置保存 |
| GET | `/api/data/alarms` | 深信服 XDR 告警样例 |
| GET | `/api/data/alarms/summary` | 告警统计 |
| GET | `/api/stream` | 平台实时事件流（SSE） |
| POST | `/api/approve` | 审批应答（有 TIR 预案时触发 decision，产出应急响应报告） |
| GET | `/api/tir/alerts?task_id=` | 应急响应告警（含 display_md，可直接渲染） |
| GET | `/api/tir/playbooks?task_id=` | 应急响应处置预案（含 display_md） |
| GET | `/api/tir/reports?task_id=` | 应急响应报告（审批后产生） |
| POST | `/api/chat` | 通用聊天（DeepSeek，非流式） |
| POST | `/api/chat/stream` | 通用聊天（DeepSeek，SSE 流式） |
| POST | `/api/auth/register` | 注册（15 号契约 §4） |
| POST | `/api/auth/login` | 登录（15 号契约 §4） |
| POST | `/api/auth/logout` | 注销当前会话 |
| GET | `/api/auth/me` | 当前登录用户信息 |
| PUT | `/api/auth/password` | 修改密码 |
| GET/POST | `/api/conversations` | 历史对话列表 / 创建（15 号契约 §5） |
| PUT/DELETE | `/api/conversations/{id}` | 更新 / 软删除对话 |
| GET/POST | `/api/conversations/{id}/messages` | 对话消息列表 / 追加 |
| GET | `/api/health` | 健康检查 |

---

## 3. 核心流程（前端推荐交互）

```
用户填表单 → POST /api/tasks（拿到 task_id，状态 pending）
        ↓
EventSource('/api/stream') 实时显示进度
        ↓
轮询或 SSE 状态变为 completed → GET /api/tasks/{id} 看状态/思维链
        ↓
GET /api/findings?task_id= 看证据列表
        ↓
GET /api/reports/{id} 看报告（Markdown 渲染）
```

---

## 4. 接口详情

### 4.1 下发任务

```
POST /api/tasks
```

**单域任务**（日志审计）：

```json
{
  "task": "分析目标日志并输出发现",
  "domain": "logaudit",
  "target": "demo-campus.edu.cn"
}
```

**单域任务**（渗透测试）：

```json
{
  "task": "对目标做基础侦察并输出发现",
  "domain": "pentest",
  "target": "127.0.0.1"
}
```

**多阶段管道**（数据泄露调查：日志审计 → 渗透验证 → 判定 → 报告）：

```json
{
  "task": "数据泄露调查",
  "domain": "logaudit",
  "target": "demo-campus.edu.cn",
  "pipeline": "data_leak"
}
```

字段说明：

| 字段 | 必填 | 说明 |
|---|---|---|
| `task` | ✅ | 自然语言任务描述 |
| `domain` | ✅ | `logaudit` / `pentest` / `intel`（威胁情报收集） |
| `target` | ✅ | 目标 IP/域名/URL，**必须在授权白名单内，否则 403** |
| `pipeline` | ❌ | 目前支持 `data_leak` |
| `params` | ❌ | 透传给部件的参数 |
| `tools` | ❌ | 工具白名单，缺省 = 部件全部 |

**响应**（202）：

```json
{"task_id": "T20260828-093200242", "status": "pending", "domain": "logaudit"}
```

---

### 4.1b 自然语言编排（chat 转 task）

```
POST /api/assess
```

用户在聊天框说一句话，大脑自动解析意图（域/目标/管道）并创建任务。

**请求**：

```json
{"message": "扫描 8.215.92.252"}
```

**响应（成功创建）**：

```json
{
  "status": "task_created",
  "task_id": "T20260829-...",
  "domain": "pentest",
  "target": "8.215.92.252",
  "pipeline": null,
  "reply": "已创建任务 T20260829-...（pentest，目标 8.215.92.252），正在执行。"
}
```

**响应（没识别到目标）**：

```json
{"status": "need_target", "reply": "请告诉我目标 IP 或域名，例如：扫描 8.215.92.252"}
```

**响应（目标不在白名单）**：

```json
{"status": "rejected", "reply": "目标 8.8.8.8 不在授权白名单内，拒绝执行。"}
```

前端拿到 `task_id` 后，用 `GET /api/stream`（SSE）订阅进度、`GET /api/tasks/{task_id}` 回显状态/阶段/结果。

---

### 4.1c 最近任务列表（仪表盘）

```
GET /api/tasks?limit=50
```

**响应示例**：

```json
{"tasks": [
  {
    "id": "T20260828-093200242",
    "domain": "logaudit",
    "target": "demo-campus.edu.cn",
    "status": "completed",
    "verdict": "false_positive",
    "confidence": 0.9,
    "created_at": "2026-08-28T09:32:00Z",
    "updated_at": "2026-08-28T09:34:27Z",
    "findings_count": 7,
    "current_stage": "report",
    "stages": [...]
  }
]}
```

---

### 4.1c 各 Agent 忙闲状态（状态墙）

```
GET /api/agents/status
```

**响应示例**：

```json
{
  "brain": {"status": "ok", "service": "aisoc-brain"},
  "parts": [
    {"domain": "pentest", "host": "127.0.0.1", "port": 8786, "auth": "bearer", "enabled": true, "busy": false},
    {"domain": "logaudit", "host": "127.0.0.1", "port": 8788, "auth": "cookie", "enabled": true, "busy": true},
    {"domain": "intel", "host": "127.0.0.1", "port": 8789, "auth": "bearer", "enabled": true, "busy": false}
  ],
  "services": {
    "tir": {"name": "应急响应 Agent", "port": 8090, "status": "online"}
  }
}
```

- `busy=true` 表示该 Agent 正有任务在执行（大脑串行排队）
- `services.tir` 是**应急响应**（REST 服务，端口 8090），`status` 由大脑实时探测：`online` / `offline`
- **注意**：渗透测试端口是 **8786**（不是 8787）

---

### 4.2 查询任务状态 + 阶段进度 + 思维链

```
GET /api/tasks/{task_id}
```

**响应示例**：

```json
{
  "id": "T20260828-093200242",
  "domain": "logaudit",
  "target": "demo-campus.edu.cn",
  "status": "completed",
  "verdict": "false_positive",
  "confidence": 0.9,
  "error": "",
  "created_at": "2026-08-28T09:32:00Z",
  "updated_at": "2026-08-28T09:34:27Z",
  "findings_count": 7,
  "current_stage": "report",
  "stages": [
    {"id": 1, "task_id": "T20260828-093200242", "stage": "logaudit",
     "status": "completed", "started_at": "2026-08-28T09:32:00Z",
     "finished_at": "2026-08-28T09:34:20Z", "findings_count": 7, "error": ""},
    {"id": 2, "task_id": "T20260828-093200242", "stage": "verdict",
     "status": "completed", "started_at": "2026-08-28T09:34:20Z",
     "finished_at": "2026-08-28T09:34:27Z", "findings_count": 0, "error": ""},
    {"id": 3, "task_id": "T20260828-093200242", "stage": "report",
     "status": "completed", "started_at": "2026-08-28T09:34:27Z",
     "finished_at": "2026-08-28T09:34:27Z", "findings_count": 7, "error": ""}
  ],
  "thought_chain": [
    {"id": 67, "task_id": "T20260828-093200242", "ts": "2026-08-28T09:32:00Z",
     "actor": "brain", "action": "task_created", "detail": {...}},
    {"id": 70, "task_id": "T20260828-093200242", "ts": "2026-08-28T09:34:27Z",
     "actor": "brain", "action": "status_completed", "detail": {...}}
  ]
}
```

- `current_stage`：当前正在执行（或最后完成）的环节
- `stages`：每个环节的开始/结束时间、状态、产出数量、错误信息

阶段（stage）枚举：`logaudit / pentest / verdict / tir / report`

状态枚举：`pending / running / approval / completed / failed / cancelled / archived`

判定枚举（verdict）：`real_threat / false_positive / pending_review`

---

### 4.3 查询证据

```
GET /api/findings?task_id={task_id}
```

**响应示例**：

```json
{
  "task_id": "T20260828-093200242",
  "findings": [
    {
      "id": "F-T20260828-093200242-001",
      "task_id": "T20260828-093200242",
      "domain": "logaudit",
      "target": "demo-campus.edu.cn",
      "tool": "log_ingest",
      "severity": "info",
      "cve": null, "cwe": null, "cvss": null,
      "title": "Ingested 51691 log records",
      "description": "Parsed 51691 records using nginx format",
      "evidence": "⚪ [log_ingest] Ingested 51691 ...",
      "remediation": "",
      "confidence": 0.8,
      "mitre": [],
      "ts": "2026-08-28T09:35:57Z"
    }
  ]
}
```

severity 枚举：`critical / high / medium / low / info`

---

### 4.4 查询报告

```
GET /api/reports/{task_id}
```

**响应**：

```json
{
  "task_id": "T20260828-093200242",
  "report": "# AiSOC 安全分析报告\n\n- task_id: ...",
  "tir_reports": [
    {"report_id": "tir_report_xxx", "playbook_id": "tir_playbook_xxx",
     "alert_id": "tir_alert_xxx", "decision": "approve",
     "report_md": "==== 应急响应报告 ====", "created_at": "2026-10-15T02:00:00Z"}
  ]
}
```

`report` 是 **Markdown 字符串**，前端用 Markdown 渲染组件显示即可。
`tir_reports` 为审批后产生的**应急响应报告**（8090 协议文档 §4.5），无则空数组。报告结构：

```
# AiSOC 安全分析报告
- task_id / domain / target / status / verdict / confidence / findings
## 判定理由
## 命中规则（如有）
## 确认威胁（列表，含证据、MITRE、修复建议）
## 误报排除（如有）
## 应急响应（TIR）（如真实威胁，含告警ID、预案ID）
## 思维链摘要
```

---

### 4.5 审计导出

```
GET /api/tasks/{task_id}/export
```

返回完整 JSON：任务 + findings + ledger + report。用于"审计留档导出"按钮。

---

### 4.6 部件注册表

```
GET /api/registry
```

```json
{"parts": [
  {"domain": "pentest", "host": "127.0.0.1", "port": 8787, "token": "***", "auth": "bearer", "enabled": true},
  {"domain": "logaudit", "host": "127.0.0.1", "port": 8788, "token": "***", "auth": "cookie", "enabled": true}
]}
```

前端一般只展示 `domain / port / enabled`，**token 不要显示**。

---

### 4.7 XDR 告警样例

```
GET /api/data/alarms?limit=10
GET /api/data/alarms/summary
```

第一个返回 `{source, count, alarms:[...]}`；第二个返回 `{total, by_severity, by_verdict_hint}`。用于"告警/数据"页面。

---

### 4.8 实时事件流（SSE）

```
GET /api/stream
```

前端用 `EventSource('/api/stream')` 一条连接收全平台实时事件。

**事件格式**（每帧 `data: <json>`）：

```json
{"task_id": "T20260828-093200242", "domain": "logaudit", "event": "status_running", "payload": {}}
```

事件类型：

| event | 含义 | payload |
|---|---|---|
| `task_created` | 任务已创建 | `{target, pipeline}` |
| `status_running` | 开始执行 | — |
| `stage_start` | 环节开始 | `{domain}` |
| `stage_finished` | 环节完成（含产出数） | `{domain, count}` |
| `stage_failed` | 环节失败 | `{domain, error}` |
| `findings_stored` | 某阶段证据入库 | `{domain, count}` |
| `verdict` | 判定完成 | `{verdict, confidence}` |
| `report_ready` | 报告已生成 | — |
| `status_completed` | 任务完成 | — |
| `status_failed` | 任务失败 | `{error}` |

> 注意：SSE 有 15 秒心跳（`: ping` 注释帧），前端 EventSource 自动忽略，无需处理。

---

### 4.9 审批应答

```
POST /api/approve
```

```json
{"task_id": "T20260828-093200242", "action": "firewall_block", "decision": "approved"}
```

`decision`: `approved` / `denied`。

- **无 TIR 预案**：仅记录账本，返回 `status: recorded`。
- **有 TIR 预案**（任务判定 real_threat 且已推 8090）：触发
  `POST /api/tir/playbooks/{id}/decision` → 产出并落库**应急响应报告**，
  返回 `status: responded` + `report_id` + `report_md`。
  `action` 可传 `tir_playbook_*` 指定预案，缺省取该任务最新预案。

---

### 4.9d 应急响应（TIR，8090）闭环

大脑把判定为真实威胁的发现推给应急响应子 Agent（8090，私有 REST 协议，**不是** reasonix part），
闭环时序见该子 Agent 的接入协议文档 §5/§6：

```
verdict=real_threat
  → POST 8090 /api/tir/ingest {event: DetectionEvent, task_id}   # 分级→告警→suggestion 预案
  → 落库 alert / playbook；notification.ledger_entry 写思维链账本
  → POST 8090 /api/tir/alerts/{id}/ack                            # notified → acknowledged
  → 前端展示 display_md / 告警列表
  → 用户点"批准" → POST 6657 /api/approve
      → POST 8090 /api/tir/playbooks/{id}/decision               # 产出应急响应报告
      → 报告落库；GET /api/reports/{task_id} 的 tir_reports 可见
```

**查询本任务 TIR 状态**（均需登录，带 task_id）：

```
GET /api/tir/alerts?task_id=T2026...      → {"task_id": "...", "alerts": [ ThreatAlert + display_md ]}
GET /api/tir/playbooks?task_id=T2026...   → {"task_id": "...", "playbooks": [ ResponsePlaybook + display_md ]}
GET /api/tir/reports?task_id=T2026...     → {"task_id": "...", "reports": [ IncidentReport + report_md ]}
```

- `display_md`（告警/预案）与 `report_md`（报告）是 8090 生成的 Markdown，**前端直接渲染**即可；
- 审计导出 `GET /api/tasks/{task_id}/export` 已包含 `tir.{alerts,playbooks,reports}`；
- 8090 无鉴权（见其协议文档 §9），**前端不应直连 8090**，一律经本服务中转。

---

### 4.9b 通用聊天（非流式，自动意图路由）

```
POST /api/chat
```

请求：

```json
{"message": "你好，用一句话介绍你自己"}
```

响应（闲聊）：

```json
{"kind": "chat", "reply": "我是 AiSOC 校园安全运营助手..."}
```

如果消息是任务意图（含目标 + 任务关键词），会自动创建任务：

```json
{"kind": "task", "task_id": "T20260829-...", "domain": "pentest", "target": "8.215.92.252", "reply": "已创建任务 ..."}
```

---

### 4.9c 通用聊天（SSE 流式，自动意图路由）

```
POST /api/chat/stream
```

请求同上。响应是 SSE 流，每帧一个文本增量；任务意图时先把"已创建任务..."作为一帧推给前端：

```
data: {"delta": "我是"}
data: {"delta": " Ai"}
...
data: {"delta": "已创建任务 T...（pentest，目标 ...），正在执行。"}
data: [DONE]
```

前端用 `fetch` 读流逐帧追加，或按 SSE 客户端处理。

**任务意图的接力帧**（07-chat-stream-adaptive-relay）：创建任务后，同一个流会继续透传部件执行过程，帧类型：`task_created`、`stage_start`、`thinking`、`tool_call`、`tool_result`、`answer`、`stage_finished`、`report_ready`、`error`，最后 `[DONE]`。旧客户端只渲染 `delta` 也不受影响。

---

### 4.10 健康检查

```
GET /api/health
```

```json
{"status": "ok", "service": "aisoc-brain"}
```

---

### 4.11 授权白名单管理

```
GET /api/whitelist
```

```json
{"enabled": true, "targets": ["127.0.0.1", "demo-campus.edu.cn", "8.215.92.252"]}
```

编辑（无需重启，立即生效，持久化）：

```
POST /api/whitelist
```

```json
{"action": "add", "target": "192.168.1.10"}
{"action": "remove", "target": "192.168.1.10"}
{"action": "set_enabled", "enabled": false}
```

---

### 4.12 运行时行为设置

```
GET /api/settings/runtime
```

```json
{"defaultToolApprovalMode":"auto","autoPlan":"off","memoryCompilerEnabled":false,
 "subagentEffort":"medium","maxSubagentDepth":2,"coldResumePrune":true,"reasoningLanguage":"auto"}
```

保存（部分字段即可，持久化到后端）：

```
POST /api/settings/runtime
```

```json
{"defaultToolApprovalMode": "yolo", "reasoningLanguage": "zh"}
```

---

## 5. 建议的前端页面结构

按大脑已有能力，建议 4 个页面：

1. **任务页（首页）**
   - 表单：任务描述、域选择（日志审计/渗透）、目标、管道选择（无 / data_leak）
   - "创建任务"按钮 → POST /api/tasks
   - 任务列表：task_id、域、目标、状态徽章、判定徽章、findings 数

2. **任务详情页**
   - 状态 + verdict + confidence 概览卡片
   - 思维链时间线（thought_chain 的 actor/action/ts）
   - 证据列表（findings，按 severity 着色）
   - 报告 Tab（Markdown 渲染）
   - "导出审计 JSON"按钮

3. **实时看板页**
   - EventSource('/api/stream') 实时滚动事件
   - Agent 状态墙（按 domain 分组：pentest / logaudit 是否 busy）

4. **数据/告警页（可选）**
   - XDR 告警样例列表 + severity 统计

---

## 6. 开发注意

1. **任务提交是异步的**：POST 返回 `pending` 后，任务在后台执行（可能要 1-5 分钟），不要同步等
2. **状态获取**：优先用 SSE 实时刷新；没有 SSE 时每 3-5 秒轮询一次 `GET /api/tasks/{id}`
3. **报告是 Markdown**：前端需准备 Markdown 渲染（如 `react-markdown`）
4. **白名单 403**：target 不在授权白名单会返回 403，前端要把错误信息展示出来
5. **token 脱敏**：`/api/registry` 返回里有 token，前端不要渲染

---

## 7. 联调自检

- [ ] `GET /api/health` 返回 ok
- [ ] 表单能创建任务并拿到 task_id
- [ ] 能通过 SSE 看到 `task_created → status_running → ... → status_completed`
- [ ] 任务详情能看到 thought_chain 和 findings
- [ ] 报告能 Markdown 正常渲染
- [ ] 403（白名单外目标）有友好提示

---

## 8. 认证与历史对话（15 号契约 Part A）

后端实现：SQLAlchemy 模型层，表结构对齐文档（users / sessions / conversations / messages）。

**数据库（15 号契约 §1）**：账号/对话表已切到 **PostgreSQL**（服务器 `edushield` 库），通过环境变量 `DATABASE_URL` 配置；未配置时自动回退 SQLite（本地开发零依赖）。任务表（tasks/findings/...）不在 15 号文档范围，仍由 SQLite 管理，两套存储互不影响。

```
# .env
DATABASE_URL=postgresql+psycopg://edushield:<password>@127.0.0.1:5432/edushield
```

### 8.1 注册

```
POST /api/auth/register
```

```json
{"username": "zhangsan", "email": "zs@edu.cn", "password": "abc12345", "confirmPassword": "abc12345", "phone": "可选"}
```

- 用户名：3-20 位字母/数字/下划线；邮箱需合法；密码至少 8 位且含字母和数字
- 响应 201：`{"user": {...}, "token": "..."}`（注册即登录）
- 错误（带 `code`）：`USERNAME_TAKEN`(409) / `EMAIL_TAKEN`(409) / `INVALID_USERNAME`(422) / `INVALID_EMAIL`(422) / `WEAK_PASSWORD`(422) / `PASSWORD_MISMATCH`(422)

### 8.2 登录

```
POST /api/auth/login
```

```json
{"identifier": "用户名或邮箱", "password": "...", "remember": true}
```

- 响应 200：`{"user": {...}, "token": "...", "expiresAt": 0}`
- `expiresAt=0` 表示永久（remember）；否则为 Unix 毫秒时间戳
- 错误：`INVALID_CREDENTIALS`(401) / `ACCOUNT_SUSPENDED`(403)

### 8.3 注销 / 当前用户 / 改密码

```
POST /api/auth/logout          # Authorization: Bearer <token>，响应 {"ok": true}
GET  /api/auth/me              # 返回当前用户信息（含 lastLoginAt）
PUT  /api/auth/password        # {"oldPassword":"...","newPassword":"..."}
```

### 8.4 历史对话

除以下说明外，其余字段/分页/筛选完全对齐文档 §5：

```
GET    /api/conversations?page=1&pageSize=50&domain=&pinned=&search=
POST   /api/conversations                    # {"title": "可选", "domain": "可选", "tabId": "可选"}
GET    /api/conversations/{id}/messages?limit=100&offset=0&order=desc
POST   /api/conversations/{id}/messages      # {"role":"user|assistant|tool|system","content":"...", ...}
PUT    /api/conversations/{id}               # {"title"?, "pinned"?, "status"?}
DELETE /api/conversations/{id}               # 软删除
```

以上接口均需 `Authorization: Bearer <token>`；不带 token 返回 401 `UNAUTHORIZED`。

### 8.5 聊天流自动落库

`POST /api/chat/stream` 新增可选字段：

```json
{"message": "...", "conversation_id": "uuid", "session_id": "..."}
```

- **可选认证**：带 `Authorization: Bearer <token>` 时绑定用户；不带 token 行为与旧版一致
- 已登录用户：
  - 传了 `conversation_id` → 校验归属后使用（404 若不存在/不属于该用户）
  - 没传 → 后端自动创建对话（标题取消息前 30 字）
- 流的第一帧会回 `data: {"kind": "conversation", "id": "...", "created": false}`
- 流结束后自动写入：`user` 消息、`tool` 调用消息（任务意图）、`assistant` 回复（含 reasoning），并更新对话 messageCount/tokenCount/updatedAt

### 8.6 认证错误统一格式

```json
{"error": "用户名已存在", "detail": "用户名已存在", "code": "USERNAME_TAKEN"}
```

`code` 供前端做精确分支，`error/detail` 用于展示。
