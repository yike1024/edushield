# threat_ir_agent 架构文档

> 版本 2.0 ｜ 2026-08 ｜ 对应代码库 `threat_ir_agent/`
> 本文档描述子 Agent 的总体架构、模块划分、核心流程、数据模型、设计原则与部署方式。

---

## 1. 定位与目标

**threat_ir_agent（威胁警报-应急响应 子Agent）** 是 edushield 校园智盾平台的**插件式子 Agent**，
严格按《安全智能体平台-项目计划书》的**威胁警报、应急响应**两个章节实现，功能范围限定为：

1. **威胁警报**：接收安全检测事件 → 威胁分级判定（高/中/低）→ 生成标准化威胁告警报文 →
   本地持久化 → 向主智能体推送告警（供主对话界面展示）；
2. **应急响应**：按告警等级自动生成处置预案/修复建议（建议模式/模拟响应模式）→
   接收主 agent 确认指令 → 输出完整应急响应报告；
3. **ingest 前置层（v2.0 扩展）**：直接摄入多种安全数据文件（pcap/syslog/csv/cef/misp...），
   自动识别格式并转换为标准 DetectionEvent JSON 后进入上述两条链路。

**非目标**：不实现计划书中其他功能模块（漏洞扫描、资产测绘、日志采集、渗透测试、
威胁情报聚合等），不修改 edushield 主系统与 DeepSeek-Reasonix-Security 模型任何存量文件。

---

## 2. 总体架构

```
┌────────────────────────────────────────────────────────────────────────┐
│                           接入层（三入口，对等）                         │
│   CLI (__main__.py)      HTTP (server.py /api/tir/*)      模块导入      │
│   ingest-file 命令        REST 调用                     ThreatIRSubAgent│
└───────────────┬────────────────────────────────┬────────────────────────┘
                │ DetectionEvent（统一输入契约）    │
┌───────────────▼────────────────────────────────▼────────────────────────┐
│                      ingest 前置层（数据文件 → 事件）                     │
│   FormatDetector(多策略识别) → ParserRegistry(23解析器) → Pipeline       │
│   → record_to_event → DetectionEvent（含 parse_error 降级、批量、溯源）   │
└───────────────┬────────────────────────────────────────────────────────┘
                │ DetectionEvent
┌───────────────▼────────────────────────────────────────────────────────┐
│                        ThreatIRSubAgent 门面                           │
│  ├─ 威胁警报：Classifier(规则预筛+模型研判双轨) → AlertBuilder           │
│  │            → AlertStore(持久化) → Notifier(推送)                     │
│  ├─ 应急响应：PlaybookGenerator(按等级) → Simulator(仅推演)              │
│  │            → ReportBuilder(确认指令 → 报告)                          │
│  └─ 门槛控制：min_alert_level（分析+输出双重门槛）                       │
└───────────────┬────────────────────────────────────────────────────────┘
                │ 推理调用（仅调用对外入口）
┌───────────────▼────────────────────────────────────────────────────────┐
│             ModelGateway（DeepSeek-Reasonix-Security 推理大脑）         │
│   reasonix-cli 通道 │ openai-api 通道 │ mock 通道（测试）  ── 自动降级    │
└────────────────────────────────────────────────────────────────────────┘

存储：storage/data/{alerts,playbooks,reports}（JSON，tir_ 命名空间，独立于主系统数据库）
```

### 分层原则（对齐计划书 3.4 "AI 只加在判断/生成处"）

- **AI（模型）只用于**：威胁分级研判、预案生成、报告生成（判断/生成处）；
- **确定性纯业务代码**：格式识别、解析、状态机、持久化、审批流转、门槛控制（流程/状态/存储处）。

---

## 3. 模块划分与职责

| 模块 | 文件 | 职责 |
|---|---|---|
| **门面** | `__init__.py` | `ThreatIRSubAgent`：事件→告警→预案→报告全流程编排；`min_alert_level` 输出门槛；`_below_alert_level` |
| **CLI** | `__main__.py` | 最小可运行入口：`serve` / `ingest` / `ingest-file` / `playbook` / `confirm` / `list` / `demo` / `doctor` |
| **HTTP 服务** | `server.py` | FastAPI，`/api/tir/*` 10 个端点 |
| **配置** | `config.py` | `TIR_` 命名空间配置；只读回退 edushield `.env` 的 DeepSeek 密钥 |
| **数据模型** | `models.py` | DetectionEvent / ThreatAlert / ResponsePlaybook / IncidentReport + 状态枚举（对齐计划书统一协议字段语义） |
| **推理网关** | `model_gateway.py` | DeepSeek-Reasonix-Security 大脑：reasonix-cli / openai-api / mock 三通道 + 自动降级 |
| **威胁警报** | `threat_alerts/` | `classifier`（规则预筛+模型研判双轨）、`alert_builder`（标准化告警报文）、`notifier`（推送） |
| **应急响应** | `incident_response/` | `playbook_generator`（按等级生成预案）、`simulator`（模拟推演，零真实命令）、`report_builder`（确认→报告） |
| **存储** | `storage/alert_store.py` | 本地 JSON 持久化（tir_ 命名空间，原子写，180 天留档清理） |
| **ingest 前置层** | `ingest/` | 格式识别（detector）、解析器插件（registry/base）、事件生成（event_builder）、流水线（pipeline）、23 个解析器（parsers/） |
| **注册脚本** | `register_subagent.py` | 写入注册信息 + 只读完整性自检 + 打印接入步骤 |

---

## 4. 核心流程

### 4.1 威胁警报流程

```
DetectionEvent（主平台事件 或 ingest 转换结果）
  → Classifier.classify()
     ├─ 规则引擎预筛：事件类型/严重度映射 + 校园误报抑制（爬虫≠攻击、选课高并发≠DDoS）
     ├─ 模型研判：DeepSeek-Reasonix（提示词去除易变字段 + 低温 0.1，保证确定性）
     └─ 双轨合并：模型为主、规则兜底，分歧记录
  → ThreatAlert（高/中/低三档 + confidence/verdict/MITRE/建议处置）
  → min_alert_level 门槛检查（低于门槛不产生告警，parse_error 除外）
  → AlertStore.save_alert（本地持久化）
  → Notifier.push（同步返回 display_md + 可选 webhook）
```

### 4.2 应急响应流程

```
ThreatAlert
  → PlaybookGenerator.generate(alert, mode)
     ├─ 等级模板骨架：高[遏制→根除→恢复→复盘] / 中[遏制→调查→加固→复盘] / 低[观察→加固→复盘]
     ├─ 模型充实具体步骤（含参考命令文本、风险等级、审批门控）
     └─ mode = SUGGESTION（建议，高危动作需人工确认）| SIMULATION（模拟）
  → Simulator.simulate（仅推演：每步生成 [simulated] 结果，AST 强制零真实命令）
  → Decision(approve/reject)（主 agent 确认指令）
  → ReportBuilder.build → IncidentReport（处置明细/判定/附录/模拟声明）
```

### 4.3 ingest 前置流程（v2.0）

```
数据文件 → FormatDetector（扩展名0.3 + Magic0.8~0.95 + 内容正则0.6~0.9 + Schema 多策略）
  → 选择解析器（置信度 ≥ 0.45，最高者）
  → Parser.parse → NormalizedRecord 列表（源/目的IP端口、协议、时间戳、事件类型、
     严重度、主机/用户、文件哈希/名、IOC、原始片段）
  → record_to_event → DetectionEvent（无法映射字段进 raw.raw_data/extra_context 保真；
     source_file+record_index 溯源；event_id 确定性派生）
  → min_severity 双重门槛：分析门槛（hint≥阈值）+ 输出门槛（最终级别≥阈值）
  → 送入威胁警报+应急响应
  → 识别失败/解析异常 → parse_error 标记事件 → 降级处理
```

---

## 5. 数据模型（models.py）

| 模型 | 关键字段 | 对齐 |
|---|---|---|
| `DetectionEvent` | event_id / event_type / source_ip / target / severity_hint / description / raw / context | 输入契约，主系统 AnalyzedThreat 兼容 |
| `ThreatAlert` | alert_id / level(high·medium·low) / attack_type / mitre / confidence / verdict / recommended_action / status | 计划书 Finding 证据协议语义 |
| `ResponsePlaybook` | playbook_id / level / mode / steps[phase·action·risk·requires_approval] / summary | 计划书 Report 协议语义 |
| `IncidentReport` | report_id / decision / mode / steps / findings / verdict / confidence / appendix | 计划书 Report 协议语义 |
| 枚举 | ThreatLevel / AlertStatus / PlaybookMode / StepStatus / Decision / IncidentStatus | 确定性状态机 |

> 兼容性保证：ingest 层**不修改 DetectionEvent Schema**，只复用现有 `raw`/`context` 字段
> 承载原始数据与溯源信息，现有威胁警报/应急响应核心逻辑零改动。

---

## 6. 推理大脑网关（model_gateway.py）

| 通道 | 说明 | 可用条件 |
|---|---|---|
| `reasonix-cli` | 调用 DeepSeek-Reasonix-Security 二进制对外暴露的 CLI 一次性入口（`reasonix run -p ... --output-format json`，无工具、dontAsk） | 目标机有 reasonix 二进制 |
| `openai-api` | 调用模型底层 DeepSeek OpenAI 兼容 API（与 edushield llm 适配层同源） | 配置了 DEEPSEEK_API_KEY |
| `mock` | 内置确定性回复（离线测试） | 始终可用（兜底） |

- 模式 `TIR_MODEL_GATEWAY = auto | reasonix-cli | openai-api | mock`；
- **容错降级**：模型通道失败（欠费/断网/超时）→ 返回空 → 分类器回退规则引擎（双轨设计）；
- **确定性设计**：分类提示词排除每次运行变化的 `event_id/occurred_at/received_at`，
  使用专用低温 `TIR_CLASSIFY_TEMPERATURE=0.1`；`event_id` 由 `source_file+record_index` 确定性派生。

---

## 7. 存储设计（storage/）

- **位置**：`<包>/storage/data/{alerts,playbooks,reports}/`（JSON 文件，原子写：临时文件+rename）；
- **命名空间**：`tir_` 前缀 ID，与 edushield 主系统（`_task_store` 内存、ChromaDB）完全隔离；
- **审计留档**：默认留存 180 天（`TIR_RETENTION_DAYS`），过期自动清理；
- **不触碰**：主系统数据库、ChromaDB 知识库。

---

## 8. HTTP API（server.py，`/api/tir/*`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/tir/health` | 健康检查 |
| POST | `/api/tir/ingest` | 接收检测事件 → 告警+预案 |
| GET | `/api/tir/alerts` | 告警列表 |
| GET | `/api/tir/alerts/{alert_id}` | 单条告警 |
| POST | `/api/tir/alerts/{alert_id}/ack` | 确认告警 |
| POST | `/api/tir/alerts/{alert_id}/playbook` | 生成预案（mode=suggestion\|simulation） |
| POST | `/api/tir/playbooks/{playbook_id}/decision` | 确认指令 → 应急响应报告 |
| GET | `/api/tir/playbooks` | 预案列表 |
| GET | `/api/tir/reports` | 报告列表 |
| GET | `/api/tir/reports/{report_id}` | 单条报告 |

---

## 9. 与 edushield 主系统的集成

- **非侵入**：不修改主系统任何源码；通过三入口之一对接：
  1. **模块导入**：`from threat_ir_agent import ThreatIRSubAgent`（插件式挂载，推荐）；
  2. **HTTP**：主系统调用 `/api/tir/*`（对齐计划书 HTTP REST 总线）；
  3. **CLI**：`python -m threat_ir_agent ...`（最小可运行入口）。
- **对话上下文与思维链复用**：事件可携带 `context`，返回 `display_md`（展示块）与
  `ledger_entry`（思维链账本条目），不侵入主系统；
- **桥接脚本** `bridge_edushield.py`（可选胶水）：只读调用 `run_security_task` 后喂给子Agent。

---

## 10. 部署架构

```
本地（开发/测试）                   远程服务器（生产/联调）
┌──────────────────┐     SSH/SFTP      ┌──────────────────────────┐
│ CLI / 直接调用     │ ◄──────────────► │ python3 -m threat_ir_agent │
│ 本地隧道 18090 ⇄  │     上传+启动     │ serve（0.0.0.0:8090）      │
│ 远程 8090         │                  │ nohup 后台，独立于主系统     │
└──────────────────┘                  └──────────────────────────┘
        公网访问：需另开 cpolar 隧道指向 8090，或防火墙放行+鉴权
```

- 远程环境要求：Python 3.10+，`pip install -r requirements.txt`
  （fastapi/uvicorn/pydantic/httpx/dotenv，无新第三方依赖）；
- 模型密钥：远程通过 `~/threat_ir_agent/.env` 或环境变量配置 `DEEPSEEK_API_KEY`；
  未配置时自动回退 mock 通道（可离线演示）；
- 部署工具：`deploy_remote.py`（SFTP 上传 / 远程自检 / 启动服务 / 本地端口转发隧道）。

---

## 11. 扩展性设计

| 机制 | 说明 |
|---|---|
| **解析器插件化** | 新增格式 = 实现 `BaseParser` + `@register_parser`，零改动框架；已有 23 个解析器 |
| **格式识别多策略** | 扩展名 + Magic + 内容正则 + Schema 校验，置信度融合取最高 |
| **批量与截断** | 多记录文件拆分多事件（source_file+record_index 溯源）；`max_events` 先按严重度排序再截断 |
| **严重度门槛** | `min_severity` 双重门槛（分析+输出），`parse_error` 豁免 |
| **模型通道可插拔** | 三通道 + 运行时 `set_mode()` 切换 |

---

## 12. 安全设计

1. **模拟响应零真实命令**：`simulator` 不调用 subprocess/os.system/os.popen 等原语，
   `doctor` 与测试用 AST 强制校验；预案中的命令仅为文本示例；
2. **建议模式审批门控**：高危处置步骤 `requires_approval=True`，需主 agent/人工确认；
3. **命名空间隔离**：`tir_` 前缀、独立存储目录，不触碰主系统数据；
4. **恶意样本只读**：样本解析仅提取元数据与哈希，不执行、不解压、不沙箱；
5. **信息不丢失**：无法映射字段进 `raw_data/extra_context`；TLS/加密/缺依赖格式给出明确提示不强行解析；
6. **存量零改动**：edushield 与 DeepSeek-Reasonix-Security 文件零修改（注册脚本只读完整性校验）。

---

## 13. 目录结构总览

```
threat_ir_agent/
├── __init__.py            # ThreatIRSubAgent 门面 + 门槛
├── __main__.py            # CLI
├── config.py              # TIR_ 配置
├── models.py              # 数据模型
├── model_gateway.py       # 推理大脑网关
├── server.py              # FastAPI /api/tir/*
├── register_subagent.py   # 注册脚本
├── requirements.txt / .env.example
├── storage/               # 本地持久化
├── threat_alerts/         # 威胁警报
├── incident_response/     # 应急响应
├── ingest/                # 前置层（识别+解析+转换）
│   └── parsers/           # 23 个格式解析器
├── tests/                 # 测试（35 用例）
└── docs/                  # 文档（本文件 / INGEST_DESIGN / FILE_MANIFEST / GITHUB_RESEARCH）
```

---

## 14. 质量与验证

- **测试**：`tests/` 35 个用例（威胁警报 6 + 应急响应 6 + 集成 2 + ingest 21），
  覆盖分级/误报抑制/双模式/零命令 AST 校验/格式识别/批量/降级/确定性/门槛；
- **回归**：原有核心逻辑测试全绿，ingest 层不改变既有行为；
- **真实场景验证**：1111.pcap（21070 包）→ 双向流合并 9468 条 → HTTP 401 弱口令爆破
  识别与 DeepSeek 研判一致；远程服务器 0.0.0.0:8090 端到端可用。
