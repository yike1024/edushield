# AiSOC 大脑 —— 项目架构说明

> 版本 v1.0 ｜ 服务：aisoc-brain（FastAPI，端口 6657）
> 配套文档：`frontend-api.md`（前端对接）、`README.md`（部署运行）

---

## 1. 系统定位

AiSOC 大脑是多 Agent 安全运营平台的**中枢**：

- 对外：给前端提供统一 REST/SSE 接口
- 对内：编排调度身体部件（渗透/日志审计/威胁情报），对接应急响应子 Agent
- 职责边界：大脑**只做编排、判定、报告、审计**，不重写 agent 循环

```
前端(3000)
   │ REST/SSE（统一走 /api）
   ▼
大脑 FastAPI(6657)
   ├── orchestrator  编排调度（意图识别、管道、SSE 派活）
   ├── verdict       威胁判定（规则 + LLM 双轨）
   ├── report        报告生成
   ├── session       SQLite 会话/账本/阶段
   ├── registry      部件注册表
   ├── knowledge     ChromaDB 知识库
   ├── data_source   XDR 告警样例 + OpenAPI 客户端
   ├── eventhub      平台实时事件
   ├── tir_client    应急响应(8090) REST 客户端
   ├── whitelist     授权白名单（运行时管理）
   └── runtime_settings  运行时行为设置
        │ HTTP /submit + /events(SSE) + /status
        ▼
身体部件（reasonix 适配层）
   pentest 8786 · logaudit 8788 · intel 8789
   tir(应急响应) 8090（REST，不走 /submit）
```

---

## 2. 端口与部署拓扑

| 组件 | 端口 | 说明 |
|---|---|---|
| 前端 | 3000 | 静态页面 + `/api` 反向代理到大脑 |
| 大脑 | 6657 | FastAPI，`0.0.0.0` |
| 渗透测试 | 8786 | reasonix 适配层，Bearer token |
| 日志审计 | 8788 | 原生 reasonix serve，Cookie token |
| 威胁情报 | 8789 | reasonix 适配层，Bearer token |
| 应急响应 | 8090 | TIR REST 服务（威胁报警 + 预案） |

对外访问：cpolar/nginx 暴露前端或大脑，部件不对外。

---

## 3. 大脑内部模块

| 模块 | 文件 | 职责 |
|---|---|---|
| API 层 | `api/__init__.py`、`api/main.py` | 全部 REST/SSE 路由、错误体统一、静态面板挂载 |
| 编排调度 | `orchestrator/__init__.py` | 意图解析、白名单校验、管道编排、SSE 派活、串行队列、断线重连、结果回收 |
| 统一协议 | `protocol/__init__.py` | TaskMessage / Finding / Report 三张表 + 枚举 |
| 部件注册表 | `registry/__init__.py` | domain → {host, port, token, auth} |
| 会话存储 | `session/__init__.py` | SQLite：tasks / findings / ledger / stages / reports，状态机 |
| 威胁判定 | `verdict/__init__.py` | 规则轨（校园误报抑制）+ LLM 轨，输出 verdict/confidence/reason |
| 报告生成 | `report/__init__.py` | Markdown 报告 + 审计导出 |
| 知识库 | `rag/__init__.py`、`knowledge/__init__.py` | ChromaDB 33 条，seed 幂等 |
| 数据接入 | `data_source/` | XDR 告警样例加载 + OpenAPI 签名客户端 |
| 实时事件 | `eventhub/__init__.py` | 进程内发布/订阅，前端 `/api/stream` |
| 应急响应 | `tir_client.py` | 8090 TIR 客户端（ingest/playbook/decision） |
| 白名单 | `whitelist.py` | 运行时增删改查 + 持久化 |
| 运行时设置 | `runtime_settings.py` | 7 个行为字段读写持久化 |
| LLM 适配 | `llm/__init__.py` | chat/chat_stream/chat_json，DeepSeek 可切换 |
| 前端面板 | `static/index.html` | 简单操作面板 |
| 部署脚本 | `scripts/` | 启动大脑 / mock 部件 |

---

## 4. 任务执行链路（核心数据流）

**4.1 单域任务**

```
POST /api/tasks {task, domain, target, pipeline?}
  → 白名单校验 → registry 找部件 → 落库(pending)
  → 后台线程 run_task：
      status_running
      → stage_start → wait_turn_done（先订阅 /events，再 /submit）
          → 收到 turn_done → fetch_final_status 拉 findings
      → findings 落库 → stage_finished
      → verdict 判定（规则+LLM）
      → 真实威胁 → tir_client 推 8090 生成告警+预案
      → report 生成 → status_completed
```

**4.2 管道任务（data_leak）**

```
logaudit(8788) → pentest(8786) → verdict → tir → report
```

同一部件的任务**串行排队**（reasonix 单会话串行，防 session busy）。

**4.3 聊天自动编排（chat → task）**

```
POST /api/chat 或 /api/chat/stream
  → parse_task_intent 提取 domain/target/pipeline
  → intent_is_task 判断是否任务意图
  → 是 → 走 /api/tasks 同一条创建逻辑，回传 task_id
  → 否 → 正常 LLM 聊天
```

---

## 5. 关键设计决策

| 决策 | 说明 |
|---|---|
| 协议统一 | 全部交互走 TaskMessage / Finding / Report，字段向后兼容 |
| SSE 事件驱动 | 先订阅 `/events` 再 `/submit`，避免事件丢失；断线重连 3 次；总超时 600s |
| 单部件串行 | 每部件一把锁，任务排队，防 reasonix 会话覆盖 |
| 鉴权双模式 | 适配层用 `Authorization: Bearer`；原生 reasonix 用 `Cookie: reasonix_token` |
| 判定双轨 | 规则（确定性、可解释）+ LLM（语义判断），LLM 不可用自动降级 |
| 星型拓扑 | 部件间不直连，证据全部经大脑落库 |
| 白名单两道校验 | 大脑创建任务时校验；部件内部自行复核 |
| 持久化 | SQLite（任务/证据/账本/阶段/报告）+ JSON（白名单/运行时设置） |
| 错误体统一 | `{"error": "...", "detail": "..."}`，404/403 均 JSON |

---

## 6. 对外接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/tasks` | 下发任务 |
| GET | `/api/tasks` | 任务列表 |
| GET | `/api/tasks/{id}` | 任务详情 + 阶段 + 思维链 |
| GET | `/api/tasks/{id}/export` | 审计导出 |
| GET | `/api/findings` | 证据查询 |
| GET | `/api/reports/{id}` | 报告 |
| GET | `/api/registry` | 部件注册表 |
| GET | `/api/agents/status` | Agent 状态墙 |
| GET/POST | `/api/whitelist` | 白名单管理 |
| GET/POST | `/api/settings/runtime` | 运行时设置 |
| GET | `/api/data/alarms` | XDR 告警样例 |
| GET | `/api/stream` | 平台实时事件 SSE |
| POST | `/api/approve` | 审批应答 |
| POST | `/api/chat` | 聊天（自动意图路由） |
| POST | `/api/chat/stream` | 流式聊天（自动意图路由） |
| POST | `/api/assess` | 自然语言直接编排任务 |
| GET | `/api/health` | 健康检查 |

---

## 7. 目录结构

```
aisoc-brain/
├── api/                # FastAPI 路由
├── orchestrator/       # 编排调度
├── protocol/           # 三协议模型
├── registry/           # 部件注册表
├── session/            # SQLite 会话
├── verdict/            # 威胁判定
├── report/             # 报告生成
├── rag/ knowledge/     # 知识库
├── data_source/        # XDR 接入
├── eventhub/           # 实时事件
├── llm/                # LLM 适配
├── config/             # 配置
├── data/samples/       # XDR 告警样例
├── docs/               # 架构 + 前端对接文档
├── static/             # 简单前端面板
├── scripts/            # 部署脚本
├── tir_client.py       # 应急响应客户端
├── whitelist.py        # 白名单
├── runtime_settings.py # 运行时设置
├── mock_part.py        # 联调假部件
└── requirements.txt
```

---

## 8. 扩展方式

1. **新增身体部件**：`registry.json` 加一行 `{domain, host, port, token, auth}`，`protocol.Domain` 加枚举值即可
2. **新增管道**：`orchestrator.PIPELINES` 加一个阶段序列
3. **新增接口**：`api/__init__.py` 加路由，同步 `docs/frontend-api.md`
4. **切换 LLM**：改 `.env` 的 `DEEPSEEK_API_BASE / DEEPSEEK_MODEL`
5. **切换 XDR live**：配 `XDR_BASE_URL + XDR_AUTH_CODE` 即可从样例切真实 API
