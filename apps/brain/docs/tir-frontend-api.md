# AiSOC 大脑（6657）— 应急响应（TIR）前端对接文档

> 面向 **前端（3000）** 对接规范 ｜ 后端：aisoc-brain FastAPI `http://127.0.0.1:6657`
> 对应子 Agent：威胁警报-应急响应（`threat-ir-agent`，8090，私有 REST 协议）
> 本文档只覆盖**应急响应（TIR）相关**接口；其余接口见 `docs/frontend-api.md`

---

## 0. 一句话说明

大脑把判定为 **真实威胁（`real_threat`）** 的发现推给 8090 应急响应子 Agent，产出**告警**和**处置预案**；
用户在**前端点"批准/拒绝"** → 大脑触发 8090 生成**应急响应报告**。
前端**只与本服务（6657）交互，永不直连 8090**（8090 无鉴权）。

---

## 1. 鉴权（必读）

除登录接口外，**所有 TIR 接口都需要登录**。

```http
POST /api/auth/login
Content-Type: application/json

{"identifier": "<用户名或邮箱>", "password": "<密码>", "remember": false}
```

响应：

```json
{
  "user": {"id": "u_xxx", "username": "alice", "email": "...", "phone": "...", "createdAt": "..."},
  "token": "sess_xxxxxxxx",
  "expiresAt": "2026-10-22T00:00:00Z"
}
```

后续所有请求带：

```http
Authorization: Bearer <token>
```

> 未带/失效 → `401 {"error":"未登录或 token 已失效","code":"UNAUTHORIZED"}`

---

## 2. 触发条件（很重要）

**TIR 记录不是每个任务都有。** 只有当任务判定为 `real_threat` 时，大脑才会推 8090 并落库。
判定门槛（大脑 `verdict` 模块）：

- 存在 `severity ∈ {critical, high}` **且** `confidence ≥ 0.7` 的发现；或 LLM 轨判定为 `real_threat`。

因此：**三个 TIR 列表接口返回空数组是正常状态**（任务未判定为真实威胁，或还没跑完）。
前端应先看任务的 `verdict` 字段：

```http
GET /api/tasks/{task_id}
→ {"verdict": "real_threat" | "false_positive" | "pending_review", "stages": [..., {"stage":"tir","findings_count":N}], ...}
```

`stages` 里出现 `tir` 阶段 = 已触发应急响应链路。

---

## 3. 端点清单

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/tir/alerts?task_id=` | 威胁告警列表（含可直接渲染的 Markdown） |
| GET | `/api/tir/playbooks?task_id=` | 处置预案列表（含可直接渲染的 Markdown） |
| GET | `/api/tir/reports?task_id=` | 应急响应报告列表（审批后产生） |
| POST | `/api/approve` | 审批预案：批准/拒绝 → 触发 decision → 产出报告 |
| GET | `/api/reports/{task_id}` | 任务综合报告（内含 `tir_reports`） |
| GET | `/api/tasks/{task_id}/export` | 审计导出（内含 `tir.{alerts,playbooks,reports}`） |

---

## 4. 接口详情

### 4.1 告警列表

```http
GET /api/tir/alerts?task_id=T20261015-001
Authorization: Bearer <token>
```

响应 200：

```json
{
  "task_id": "T20261015-001",
  "alerts": [
    {
      "alert_id": "tir_alert_1a28b242",
      "task_id": "T20261015-001",
      "event_ref": "tir_event_xxx",
      "level": "high",
      "status": "acknowledged",
      "display_md": "### ⚠️ 威胁警报\n...（Markdown，直接渲染）",
      "created_at": "2026-10-15T02:00:00Z",
      "payload": {
        "alert_id": "tir_alert_1a28b242",
        "title": "检测到 WebShell 上传",
        "level": "high",
        "attack_type": "webshell",
        "mitre_technique": "T1505",
        "confidence": 0.92,
        "source_ip": "111.1.216.150",
        "target": "http://jwc.xxx.edu.cn/uploads/",
        "summary": "...",
        "evidence": "...",
        "recommended_action": "...",
        "reasoning": "...",
        "verdict": "true_positive",
        "status": "acknowledged",
        "created_at": "2026-10-15T02:00:00Z",
        "notified_at": "2026-10-15T02:00:01+00:00"
      }
    }
  ]
}
```

**字段说明**

| 字段 | 说明 |
|---|---|
| `alert_id` | 告警 ID，`tir_alert_*` |
| `level` | **严格三档**：`high` / `medium` / `low` |
| `status` | `new` / `notified` / `acknowledged` / `responded` / `closed` |
| `display_md` | 8090 生成的告警 Markdown，**前端直接渲染** |
| `payload` | 告警完整字段（上表对象结构），需要细粒度展示时用 |
| `payload.verdict` | `true_positive` / `false_positive` / `benign` / `uncertain` |

### 4.2 预案列表

```http
GET /api/tir/playbooks?task_id=T20261015-001
Authorization: Bearer <token>
```

响应 200：

```json
{
  "task_id": "T20261015-001",
  "playbooks": [
    {
      "playbook_id": "tir_playbook_xxx",
      "alert_id": "tir_alert_1a28b242",
      "task_id": "T20261015-001",
      "mode": "suggestion",
      "display_md": "### 🛡️ 应急处置预案\n...（Markdown）",
      "created_at": "2026-10-15T02:00:02Z",
      "payload": {
        "playbook_id": "tir_playbook_xxx",
        "level": "high",
        "objective": "遏制并清除 WebShell",
        "mode": "suggestion",
        "summary": "...",
        "confidence": 0.9,
        "mitre": ["T1505"],
        "steps": [
          {
            "seq": 1,
            "phase": "遏制(Containment)",
            "action": "隔离受影响主机",
            "expected_command": "...（仅展示，禁止执行）",
            "risk_level": "medium",
            "requires_approval": true,
            "rationale": "...",
            "status": "pending",
            "simulated_result": null
          }
        ],
        "created_at": "2026-10-15T02:00:02Z"
      }
    }
  ]
}
```

**字段说明**

| 字段 | 说明 |
|---|---|
| `mode` | `suggestion`（建议，等人工确认）/ `simulation`（模拟推演） |
| `payload.steps[]` | 处置步骤；`expected_command` **仅展示，禁止执行** |
| `steps[].status` | `pending` / `approved` / `rejected` / `simulated` / `completed` |
| `steps[].requires_approval` | 是否需人工确认（前端可据此高亮） |
| `display_md` | 预案 Markdown，**前端直接渲染** |

### 4.3 报告列表

```http
GET /api/tir/reports?task_id=T20261015-001
Authorization: Bearer <token>
```

响应 200：

```json
{
  "task_id": "T20261015-001",
  "reports": [
    {
      "report_id": "tir_report_xxx",
      "task_id": "T20261015-001",
      "playbook_id": "tir_playbook_xxx",
      "alert_id": "tir_alert_1a28b242",
      "decision": "approve",
      "report_md": "==== 应急响应报告 ====\n...（Markdown）",
      "created_at": "2026-10-15T02:05:00Z",
      "payload": {
        "report_id": "tir_report_xxx",
        "domain": "incident-response",
        "decision": "approve",
        "mode": "suggestion",
        "operator": "alice",
        "summary": "...",
        "findings": [ { "id": "...", "target": "...", "tool": "...", "severity": "high",
                        "remediation": "...", "confidence": 0.9, "mitre": ["T1505"], "timestamp": "..." } ],
        "verdict": "...",
        "confidence": 0.9,
        "mitre": ["T1505"],
        "steps": [ { "...PlaybookStep 字段...": "", "result": "..." } ],
        "appendix": { "decision": "approve", "reject_reason": "", "mode": "suggestion" },
        "generated_at": "2026-10-15T02:05:00Z"
      }
    }
  ]
}
```

> 报告**只在用户审批后才产生**（见 4.4）。未审批时该数组为空。

### 4.4 审批预案（核心动作）

前端"批准 / 拒绝"按钮 → 调本接口 → 大脑触发 8090 `decision` → **产出并落库应急响应报告**。

```http
POST /api/approve
Authorization: Bearer <token>
Content-Type: application/json

{
  "task_id": "T20261015-001",
  "action": "tir_playbook_xxx",   // 可传 playbook_id；留空 "" 则取该任务最新预案
  "decision": "approved"          // "approved" 或 "denied"
}
```

**响应 200（该任务有 TIR 预案）**：

```json
{
  "task_id": "T20261015-001",
  "action": "tir_playbook_xxx",
  "decision": "approved",
  "status": "responded",
  "playbook_id": "tir_playbook_xxx",
  "report_id": "tir_report_xxx",
  "report_md": "==== 应急响应报告 ====\n...（Markdown，可直接渲染）"
}
```

**响应 200（该任务无 TIR 预案）**——仅记录账本：

```json
{"task_id": "T20261015-001", "action": "tir_playbook_xxx", "decision": "approved", "status": "recorded"}
```

**字段说明**

| 字段 | 说明 |
|---|---|
| `decision` | 前端传 `approved` / `denied`（也兼容 `approve` / `reject`） |
| `action` | 建议传具体 `playbook_id`；留空取最新预案 |
| `status` | `responded`（已产出报告）/ `recorded`（无预案，仅记账） |
| `report_md` | 应急响应报告 Markdown，可直接渲染（也可稍后从 4.3 拉取） |

**错误**

| 码 | 含义 |
|---|---|
| 401 | 未登录 |
| 404 | 任务不存在 |
| 502 | `TIR 预案决策失败（8090 不可用或预案不存在）` |

### 4.5 任务报告（含 TIR 报告）

```http
GET /api/reports/{task_id}
Authorization: Bearer <token>
```

响应 200：

```json
{
  "task_id": "T20261015-001",
  "report": "# AiSOC 安全分析报告\n...（任务综合报告 Markdown）",
  "tir_reports": [
    {
      "report_id": "tir_report_xxx",
      "playbook_id": "tir_playbook_xxx",
      "alert_id": "tir_alert_1a28b242",
      "decision": "approve",
      "report_md": "==== 应急响应报告 ====\n...",
      "created_at": "2026-10-15T02:05:00Z"
    }
  ]
}
```

> `tir_reports` 为新增字段（审批后填充，未审批时 `[]`）。
> 任务综合报告的「## 应急响应（TIR）」段落也已内联告警/预案的 `display_md`。

---

## 5. 前端推荐交互流程

```
任务详情页
 ├─ 轮询 GET /api/tasks/{id}（或订阅 /api/stream 的 verdict / stage_finished 事件）
 │    └─ verdict == "real_threat" 且 stages 含 "tir"
 │         ↓
 ├─ GET /api/tir/alerts?task_id=      → 渲染 alerts[].display_md（Markdown）+ level 徽章
 ├─ GET /api/tir/playbooks?task_id=   → 渲染 playbooks[].display_md，展示 steps（含风险等级/是否需确认）
 │    └─ 用户点「批准」/「拒绝」
 │         ↓
 ├─ POST /api/approve {task_id, action: playbook_id, decision}
 │    └─ 用返回的 report_md 直接展示，或再拉 GET /api/tir/reports?task_id=
 └─ GET /api/reports/{task_id}        → 报告页含 tir_reports
```

**渲染建议**

- `display_md` / `report_md` / `report` 都是 **Markdown 字符串**，用现成 Markdown 组件渲染；
- `level` 只有 `high` / `medium` / `low` 三档，可直接映射颜色；
- `payload` 用于需要结构化展示（如表格）的场景，`display_md` 用于快速渲染。

---

## 6. 注意事项

1. **不要直连 8090**：8090 无鉴权，且前端直连会绕过大脑的落库/审计。一律经本服务。
2. **空数组是正常态**：非 `real_threat` 任务没有 TIR 数据。
3. **`POST /api/approve` 现在需要登录**（此前无需）——请确保携带 `Authorization`。
4. **任务归属**：只能查询/审批**自己**的任务（他人的 task_id → 404）。
5. `steps[].expected_command` 是**参考命令文本，仅供展示，禁止自动执行**。
6. 单次任务最多推 **5 条**威胁到 8090（大脑侧限制）。

---

## 7. 自检清单

- [ ] `POST /api/auth/login` 能拿到 token
- [ ] 带 token 请求 `/api/tir/alerts?task_id=<真实任务>` 返回 200（即使 `alerts: []`）
- [ ] `verdict=real_threat` 的任务能看到 `alerts` / `playbooks` 非空并渲染 `display_md`
- [ ] 点「批准」→ `/api/approve` 返回 `status: responded` + `report_id`
- [ ] `GET /api/tir/reports?task_id=` 能看到刚生成的报告
- [ ] `GET /api/reports/{task_id}` 的 `tir_reports` 非空
