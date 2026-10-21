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
| GET | `/api/tasks` | 最近任务列表（仪表盘） |
| GET | `/api/tasks/{task_id}` | 任务状态 + 阶段进度 + 思维链 |
| GET | `/api/tasks/{task_id}/export` | 审计导出（JSON） |
| GET | `/api/findings?task_id=` | 查询证据 |
| GET | `/api/reports/{task_id}` | 查询报告（Markdown） |
| GET | `/api/registry` | 部件注册表 |
| GET | `/api/agents/status` | 各 Agent 忙闲状态（状态墙） |
| GET | `/api/data/alarms` | 深信服 XDR 告警样例 |
| GET | `/api/data/alarms/summary` | 告警统计 |
| GET | `/api/stream` | 实时事件流（SSE） |
| POST | `/api/approve` | 审批应答 |
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
| `domain` | ✅ | `logaudit` / `pentest` |
| `target` | ✅ | 目标 IP/域名/URL，**必须在授权白名单内，否则 403** |
| `pipeline` | ❌ | 目前支持 `data_leak` |
| `params` | ❌ | 透传给部件的参数 |
| `tools` | ❌ | 工具白名单，缺省 = 部件全部 |

**响应**（202）：

```json
{"task_id": "T20260828-093200242", "status": "pending", "domain": "logaudit"}
```

---

### 4.1b 最近任务列表（仪表盘）

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
    {"domain": "pentest", "host": "127.0.0.1", "port": 8787, "auth": "bearer", "enabled": true, "busy": false},
    {"domain": "logaudit", "host": "127.0.0.1", "port": 8788, "auth": "cookie", "enabled": true, "busy": true}
  ]
}
```

`busy=true` 表示该 Agent 正有任务在执行（大脑串行排队）。

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
{"task_id": "T20260828-093200242", "report": "# AiSOC 安全分析报告\n\n- task_id: ..."}
```

`report` 是 **Markdown 字符串**，前端用 Markdown 渲染组件显示即可。报告结构：

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

`decision`: `approved` / `denied`。当前阶段仅记录审计，后续接入处置门控。

---

### 4.10 健康检查

```
GET /api/health
```

```json
{"status": "ok", "service": "aisoc-brain"}
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

## 8. 认证补充说明（2026-10 同步）

认证基础契约（register / login / Bearer）见 `aisoc-docs/15-后端数据库与记忆架构设计.md`，本节补充三条语义。

### 8.1 POST /api/auth/logout —— 幂等

- 携带有效 token：吊销该会话，返回 200 `{"ok": true}`。
- 无 token / token 已失效 / 重复调用：同样返回 200 `{"ok": true}`（不返回 401/404）。
- 前端以 `fetch(..., { keepalive: true })` 发送，不 await；即使紧随页面 reload 请求也保证送达。

### 8.2 401 语义

所有 `/api/*` 业务接口的 401 不区分「token 无效 / 过期 / 已吊销」三种原因，前端统一按「需重新登录」处理。前端防抖策略：首个 401 后延迟 3s 复核，仅当复核仍 401 才登出，避免网络抖动或后端重启窗口期闪退。

### 8.3 GET /api/auth/me（待后端上线，P1）

- 请求：`Authorization: Bearer <token>`。
- 响应：200 `{ "user": { "id", "username", "email", "createdAt" } }`；token 无效/被吊销返回 401。
- 用途：① 401 防抖的复核请求（前端已按此契约对接，接口 404 时自动退化为 `GET /api/conversations?page=1&page_size=1` 探针）；② 前端启动时校验本地 session 是否仍被服务端承认。
