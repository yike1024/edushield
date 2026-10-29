# 模块间 HTTP 契约 v1

> 所有跨模块调用都在这份文档里。**代码是解释，这份文档是约定**：
> 字段要加，先改文档；破坏性变更要升 `PROTO_VER` 并回归全部域。
> 协议实现在 `apps/brain/protocol/__init__.py`（三张表），本文档是它的对外说明。

## 0. 通用约定

| 项 | 约定 |
|---|---|
| 地址 | 一律来自 `config/services.json`（`baseUrl`），不写死在代码里 |
| 传输 | HTTP/1.1，事件流用 SSE（`text/event-stream`），心跳 `: ping` 每 15s |
| 鉴权 | 见下表；**不要**给本地回环接口加无必要的鉴权，保持能 `curl` 调试 |
| 超时 | 下发 10s；单任务总时长 1800s；轮询 0.5s × 60 次；TIR 调用 120s |
| 错误 | 非 2xx 返回 `{"error": "..."}`；大脑侧统一包装成任务 `failed` + `error` 字段 |
| 编码 | UTF-8，JSON 一律 `ensure_ascii=false` |
| 幂等 | `/submit` 不幂等（每次是新任务）；`/status` 幂等 |

鉴权一览：

| 调用方 → 被调方 | Header | token 来源 |
|---|---|---|
| 大脑 → adapter（pentest 8786 / intel 8789） | `Authorization: Bearer <PART_TOKEN>` | `*_PART_TOKEN` |
| adapter → reasonix serve | `Cookie: reasonix_token=<SERVE_TOKEN>` | `*_SERVE_TOKEN` |
| 大脑 → logaudit serve（8788） | `Cookie: reasonix_token=<SERVE_TOKEN>` | `LOGAUDIT_SERVE_TOKEN` |
| 前端 → 大脑 | `Authorization: Bearer <用户登录 token>` | `/api/auth/login` 返回 |
| 任何人 → TIR | 无 | — |

> 现有实现里 logaudit 注册表写的是 `auth: "cookie"`，pentest/intel 是 `auth: "bearer"`，
> 这是历史差异，不是笔误：直连 serve 的域用 Cookie，经 adapter 的域用 Bearer。

## 1. 大脑 → 部件（adapter 形态，pentest / intel）

### POST /submit

```http
POST http://127.0.0.1:8786/submit
Authorization: Bearer sk-...
Content-Type: application/json

{"input": "任务 T20261024-101500123 (pentest): ...\n目标: demo-campus.edu.cn", "task_id": "T20261024-101500123"}
```

```json
// 202 Accepted
{"task_id": "T20261024-101500123", "status": "running"}
```

- `input` 是 `TaskMessage.to_input_text()` 压出来的**纯文本**，不是 JSON 包（防止把整包
  JSON 当提示词丢给模型，扩大注入面）。
- 会话忙时 adapter 内部排队（最多等 1800s），不丢任务。

### GET /status?task_id=

```http
GET http://127.0.0.1:8786/status?task_id=T20261024-101500123
```

```json
{
  "task_id": "T20261024-101500123",
  "status": "completed",          // running | completed | failed | queued
  "running": false,               // 引擎会话是否仍占用
  "findings": [ { ... } ],        // completed 时给出（结构见 §5）
  "tool_events": [ ... ],         // 可选：工具调用轨迹
  "error": "..."                  // failed 时给出
}
```

### GET /events（SSE）

```http
GET http://127.0.0.1:8786/events
Authorization: Bearer sk-...
Accept: text/event-stream
```

```
: ping
data: {"kind":"turn_started","task_id":"..."}
data: {"kind":"reasoning","text":"..."}
data: {"kind":"message","text":"..."}
data: {"kind":"tool_started","name":"nmap","args":{...}}
data: {"kind":"turn_done","err":null}
```

事件类型固定为 `turn_started | reasoning | message | tool_started | tool_output | turn_done`。
`turn_done` 带 `err` 表示本轮失败。大脑只依赖 `message`（取正文）与 `turn_done`（定稿），
其余用于前端展示。

### 前端网关通道（免认证）

adapter 对 `/api/*` 前缀免认证，供前端经 `serve_frontend.py` 直连：

| 前缀 | 上游 |
|---|---|
| `/adapter-pentest/events` | `http://127.0.0.1:8786/api/events` |
| `/adapter-logaudit/events` | `http://127.0.0.1:8788/api/events` |
| `/adapter-intel/events` | `http://127.0.0.1:8789/api/events` |

用途：大脑转发工具帧时会丢掉 `args`/`output`，前端需要原始流补全工具面板。

## 2. 大脑 → 部件（engine 直连形态，logaudit 8788）

reasonix serve 原生端点，鉴权 `Cookie: reasonix_token=<LOGAUDIT_SERVE_TOKEN>`：

| 端点 | 说明 |
|---|---|
| `POST /submit` body `{"input": "...", "format": "json_object"}` | 202 受理 / 409 会话忙 |
| `GET /status` | `{"running": bool, "session": "...", ...}` |
| `GET /events` | 同上 SSE 事件流 |
| `POST /tool-approval-mode` body `{"mode":"ask\|auto\|yolo"}` | 审批模式（headless 编排必须切 auto） |
| `GET /history` | 会话历史（adapter 用它回溯 findings） |

> 直连模式没有 adapter 的看门狗与 AI 审批门，大脑侧靠"15s 无进展即判定 completed"兜底。
> 如果 logaudit 也要 adapter 语义，把自己包一层（见 `docs/ADD-MODULE.md`），
> 端口改成 `18788` 并把 registry 的 logaudit 指向新 adapter 即可，其它域零改动。

## 3. 大脑 → TIR（8090）

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/tir/health` | 健康检查（无鉴权） |
| POST | `/api/tir/ingest` | 送入 DetectionEvent，返回 alert + playbook |
| GET | `/api/tir/alerts` | 告警列表 |
| GET | `/api/tir/alerts/{id}` | 告警详情 |
| POST | `/api/tir/alerts/{id}/ack` | 确认告警 |
| POST | `/api/tir/alerts/{id}/playbook` | 按告警生成处置预案 |
| GET | `/api/tir/playbooks` | 预案列表 |
| POST | `/api/tir/playbooks/{id}/decision` | 人工批准/驳回 → 产出应急响应报告 |
| GET | `/api/tir/reports`、`/api/tir/reports/{id}` | 报告查询 |

```json
// POST /api/tir/ingest
{
  "event": {
    "event_type": "webshell",          // brute_force | scan | webshell | data_leak | phishing | ...
    "severity_hint": "high",
    "target": "demo-campus.edu.cn",
    "evidence": "…原始片段…",
    "context": { "task_id": "T2026…", "domain": "pentest" }
  },
  "task_id": "T20261024-101500123"
}
```

```json
// 响应（节选）
{
  "alert": { "alert_id": "TIR-…", "severity": "high", "verdict": "real_threat" },
  "playbook": { "playbook_id": "PB-…", "mode": "advice", "steps": [ ... ] },
  "display_md": "### 威胁警报…",     // 直接渲染到前端对话
  "ledger_entry": { ... }             // 供思维链记账
}
```

约束（写进 TIR 的 `doctor` 与单测里）：应急响应只出建议/推演，**不调用任何真实执行原语**。

## 4. 前端 → 大脑（6657）

vite 与 `serve_frontend.py` 两套代理都把 5 个域前缀指向 6657：

| 前端前缀 | 上游 | 说明 |
|---|---|---|
| `/aisoc-brain/api/*` | `6657/api/*` | 大脑本身 |
| `/aisoc-pentest/api/*` | `6657/api/*` | 渗透域（经大脑转发） |
| `/aisoc-logaudit/api/*` | `6657/api/*` | 日志审计域 |
| `/aisoc-intel/api/*` | `6657/api/*` | 情报域（主路由） |
| `/aisoc-threatintel/api/*` | `6657/api/*` | 历史别名，保留兼容 |
| `/aisoc-incident/api/*` | `6657/api/*` | 应急响应域 |
| `/api/*` | `6657/api/*`（不去前缀） | 认证、会话等公共接口 |

大脑对外主要端点：

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/health` | 健康检查 |
| POST | `/api/tasks` (202) | 建任务（白名单校验 → 路由 → 下发） |
| GET | `/api/tasks`、`/api/tasks/{id}` | 任务列表/详情 |
| GET | `/api/tasks/{id}/export` | 报告 + 审计导出 |
| GET | `/api/stream` | 实时事件 SSE |
| GET | `/api/registry` | 部件注册表（前端 Agent 状态墙） |
| POST | `/api/auth/*`、`/api/conversations*`、`/api/memory*`、`/api/rag/search`、`/api/save-attachment` | 账号/会话/记忆/知识库/附件 |

## 5. 三张表（大脑 ↔ 部件）

权威实现在 `apps/brain/protocol/__init__.py`，`PROTO_VER = 1`。

### TaskMessage（大脑 → 部件）

| 字段 | 类型 | 说明 |
|---|---|---|
| `task_id` | str | `T<YYYYMMDD>-<ms>` |
| `domain` | enum | `pentest \| logaudit \| intel \| incident \| threatintel` |
| `target` | str | 必须在授权白名单内 |
| `params` | dict | `task/scope/timeout_s/max_steps` … |
| `tools` | list[str] | 工具白名单，空 = 该域全部 |
| `context` | {ref_task_ids, evidence_summary} | 跨域协作载体 |
| `auth` | str | 部件 token（大脑从 registry 注入） |
| `proto_ver` | int | 默认 1 |

### Finding（部件 → 大脑）

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | str | `F-<task_id>-<seq>` |
| `task_id` / `domain` / `target` | str | 溯源三件套 |
| `tool` | str | 产出工具名 |
| `severity` | enum | `critical \| high \| medium \| low \| info` |
| `title` / `description` / `evidence` | str | `evidence` 必须是原始工具输出摘录 |
| `confidence` | float 0~1 | 部件对该发现的置信度 |
| `cve` / `cwe` / `cvss` / `mitre` / `remediation` | 可选 | |
| `timestamp` | str | ISO8601 UTC |

> 部件侧模型输出的 JSON 只需要 `findings[]`（`type/severity/title/evidence/description/
> recommendation`），大脑负责补 id/task_id/domain/target 并归一化成 Finding。

### Report（大脑 → 用户）

| 字段 | 类型 | 说明 |
|---|---|---|
| `task_id` | str | |
| `domain` | str | `all` = 跨域综合报告 |
| `summary` | str | |
| `findings` | list[str] | 引用 Finding id（报告可追溯） |
| `verdict` | enum | `real_threat \| false_positive \| pending_review` |
| `confidence` | float 0~1 | |
| `mitre` / `appendix` | | |
| `created_at` | str | ISO8601 UTC |

## 6. 变更流程

1. 改字段 → 先改本文件 + `packages/contracts/`。
2. 加**可选**字段：不升 `PROTO_VER`，但要在本文件标注"v1.x 新增"。
3. 删字段/改语义：升 `PROTO_VER`，并在 `docs/HTTP-CONTRACT.md` 顶部记录迁移窗口。
4. 涉及两个以上域的改动，PR 里 @ 对应负责人（见 `CODEOWNERS`），不要单方面合。
