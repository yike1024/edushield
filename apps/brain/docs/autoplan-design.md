# AutoPlan：大脑侧"执行 → 评估 → replan → 再下发"设计

> 状态：**待批准执行**（未改动任何运行中代码）
> 目标：把 `runtime_settings.autoPlan`（现为纯存储、无行为）接入大脑编排层，
> 让一个调查请求能自动跑"最多 N 轮"任务：每轮结束由 LLM 评估大脑汇聚的最终输出，
> 决定继续（换 domain / pipeline / 带上前轮 evidence）还是停止。

## 0. 一句话语义

```
用户请求
  → 第 1 轮 run_task(task1, pipeline?)          # 现有逻辑，不动
  → 大脑汇聚该轮最终输出 = {findings, verdict, confidence, reason, report}
  → replan 决策（LLM + 规则兜底）
       ├─ continue=True 且 round < MAX  → 第 2 轮 run_task(task2,
       │                                  context.ref_task_ids=[task1], 带 evidence_summary)
       └─ 否则停止
```

## 1. 已确认的决策参数（用户拍板）

| 参数 | 取值 |
|---|---|
| replan 触发 | 每轮结束都由 LLM 判断是否继续 / 换 domain / 换 pipeline / 停 |
| 终止 | 固定最大轮数，默认 **2**（读 `maxSubagentDepth`，运行时可控） |
| 开启方式 | `runtime_settings.autoPlan == "on"`（默认 `"off"` → **零行为变化**，不影响现有服务） |
| 决策失败兜底 | LLM 不可用/超时 → 规则兜底（见 §5） |

## 2. 不改的东西（约束红线）

- `runtime_settings.py` schema、`/api/settings/runtime` 接口：不动（`autoPlan`/`maxSubagentDepth` 已存在）。
- `verdict/`、`llm/`、`protocol` 枚举：不动。
- `run_task` 既有签名与单轮语义：不改；autoPlan=off 时调用路径与现在完全一致。
- `models/state.py`（未被使用的 Planner/AgentState）：不依赖。

## 3. 涉及文件与改动点

### 3.1 `orchestrator/__init__.py`（核心）
- `build_task_message(..., ref_task_ids: list[str] | None = None)`：把上游轮次 task_id 填入
  `TaskContext.ref_task_ids`（该字段协议里已存在、当前恒空，属"启用预留字段"）。
- 新增 `_round_summary(task: dict, findings: list[dict]) -> dict`：
  提取单轮最终输出摘要 `{round, task_id, domain, findings_count, severities,
  verdict, confidence, reason, top_titles}`。
- 新增 `replan_decision(summary: dict, history: list[dict]) -> dict`：
  - LLM 轨：`chat_json`，system="你是安全调查规划者…"，user=summary+history 压缩文本，
    要求输出 JSON `{continue: bool, next_domain: "logaudit|pentest|intel",
    pipeline: "data_leak|", focus: str, reason: str}`；
  - 规则兜底（无 key / LLM 返回非法）：`findings 为空 → continue=True 且换默认互补域`
    （logaudit↔pentest），否则 `continue=False`。
- 新增 `run_task_autoplan(domain, target, params, tools, pipeline=None,
  session_id=None, max_rounds: int | None = None) -> dict`：
  循环调 `run_task`；max_rounds 默认取 `runtime_settings.get_all()["maxSubagentDepth"]`；
  每轮后 publish 新事件并写 ledger（见 §4）；返回**最终轮 task**（最末结果）。

### 3.2 `api/__init__.py`（入口接开关 + 事件透出）
- `_start_task_thread` / `_prepare_task` 之后，凡任务创建路径（`/api/tasks`、`/api/assess`、
  `/api/chat` 任务意图）判断 `runtime_settings.get_all()["autoPlan"]=="on"`：
  - 是 → 后台线程改跑 `run_task_autoplan(...)`；
  - 否 → 原 `run_task(...)`（现有路径，行为不变）。
- `create_task` 响应与 `/api/stream` 事件不变结构，但新增两类事件 kind 供前端 SSE 区展示：
  - `round_done`：`{round, task_id, domain, verdict, findings_count}`
  - `autoplan_decision`：`{continue, next_domain, pipeline, reason}`

### 3.3 `eventhub` / `session`
- 复用现有 `hub.publish` 与 `store.add_ledger`（无需新表）。
- ledger：每轮 replan 记 `actor="autoplan"`、`action="replan"`、detail=决策 JSON；
  最终轮结束后记 `action="autoplan_done"`，detail 含轮次链 `[task1, task2, ...]`。
- 报告：仅最终轮的 report 落 `store.save_report`（每轮独立任务记录天然保留在 tasks 表）。

## 4. 数据/事件契约（增量）

SSE 新增事件（前端"实时事件流"区即能看见多轮过程）：

```
{"domain":"all","event":"round_done","task_id":"T...","payload":{"round":1,"verdict":"pending_review","findings_count":3}}
{"domain":"all","event":"autoplan_decision","task_id":"T...","payload":{"continue":true,"next_domain":"pentest","pipeline":"data_leak","reason":"日志侧发现外联线索，需渗透验证"}}
```

每轮任务的 `context.ref_task_ids` = 前序轮次 task_id（可回溯整条调查链）。

## 5. 边界与兜底

- 死循环防护：`max_rounds` 硬上限（默认 2，可通过 runtime 设置调大但正整数校验已在）。
- LLM 每轮额外一次 chat_json 调用（成本可控：最多 2 次/调查）；LLM 失败一律规则兜底，绝不阻断主流程。
- 部件不可用：单轮 run_task 失败时，autoplan 视同该轮结束（continue=False），
  不因 replan 层掩盖部件故障——任务状态仍按现有 FAILED 语义走。
- 向后兼容：所有新增参数带默认值；autoPlan=off 时新代码零路径进入。

## 6. 验证方案（批准执行后按序）

1. **单元**：mock `chat_json` 返回 continue=True/False 两态 → 断言轮次数、ref_task_ids 串联、
   ledger 记录、SSE 事件发布（publish 注入 spy）。
2. **规则兜底**：无 DEEPSEEK key / LLM 返回非法 → 断言走规则（空 findings 换域重试一轮）。
3. **联调（mock 部件）**：`python mock_part.py`(logaudit:8788) + `MOCK_PORT=8787 MOCK_DOMAIN=pentest`，
   `runtime_settings.autoPlan="on"` 下发"调查 xxx"→ 观察 SSE 出现 round_done → autoplan_decision → 第二轮。
4. **回归**：autoPlan=off 跑现有单轮任务，行为与改动前逐字段一致。
5. **灰度（对当前服务最小冲击）**：批准后由你在宿主会话重启一次大脑，再 `POST /api/settings/runtime {"autoPlan":"on"}`。

## 7. 影响面与风险

| 项 | 说明 |
|---|---|
| 默认状态 | autoPlan=off → 现有任务/部件调用零变化（本次不打开） |
| 打开后 | 每个任务最多额外 1 次 replan LLM 调用 + 至多 1 轮部件任务 |
| 部件压力 | 8786/8788 共享实例可能被连跑两轮；建议先用 mock 联调，再小流量灰度 |
| 失败语义 | replan 不掩盖部件故障；单轮失败按现状 FAILED 结束 |

## 8. 批准后执行顺序（供到时直接照做）

1. `orchestrator`: build_task_message 加 ref_task_ids → 加 `_round_summary`/`replan_decision`/`run_task_autoplan`
2. `api`: 三个任务入口接 autoPlan 开关 + 事件发布
3. 单元测试 + mock 部件联调（§6.1-6.3）
4. 回归验证 autoPlan=off 零变化（§6.4）
5. 重启大脑 → runtime autoPlan=on → 小流量端到端（§6.5）
