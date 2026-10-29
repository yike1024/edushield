# 威胁警报-应急响应 子Agent（threat-ir-agent）

> edushield 校园智盾平台的**插件式子 Agent**，严格按《安全智能体平台-项目计划书》
> （威胁警报、应急响应章节）开发，**仅实现这两项功能**，不做计划书中任何其他模块。

---

## 1. 功能范围（严格限定）

| 模块 | 功能 | 计划书依据 |
|---|---|---|
| **威胁警报** | 接收主平台安全检测事件 → 威胁分级判定（高/中/低）→ 标准化威胁告警报文 → 本地持久化 → 向主智能体推送告警（供主对话界面展示） | 计划书：威胁判定、误报抑制、Finding/Report 统一协议 |
| **应急响应** | 按告警等级自动生成可执行处置预案/修复建议；建议模式（人工确认）/模拟响应模式（仅推演，禁止真实命令）；接收主 agent 确认指令，输出完整应急响应报告 | 计划书：应急响应部件、处置剧本、审批流、报告合规 |

> ❗ 未开发/未预留：漏洞扫描、资产测绘、日志采集、渗透测试、威胁情报聚合等
> 计划书中的其他功能模块 —— 本子 Agent 不编码、不设计、不预留相关接口。

## 2. 架构

```
edushield 主智能体（对话上下文 / 思维链 / 展示层）
        │  ① 传入安全检测事件（DetectionEvent）
        │  ② 回传告警/预案/报告（display_md 展示块 + ledger_entry 账本条目）
        ▼
┌─────────────────────────────────────────────────────────────┐
│  威胁警报-应急响应 子Agent（threat_ir_agent/，全部为新增文件）│
│                                                             │
│  ThreatIRSubAgent（门面，模块导入式挂载入口）                 │
│   ├─ 威胁警报: classifier(规则预筛+模型研判) → alert_builder  │
│   │            → notifier(同步返回+可选webhook)               │
│   ├─ 应急响应: playbook_generator(按等级生成预案)             │
│   │            → simulator(模拟推演,零真实命令)               │
│   │            → report_builder(确认指令→应急响应报告)        │
│   ├─ model_gateway: DeepSeek-Reasonix-Security 推理大脑网关   │
│   │   （reasonix-cli / openai-api / mock 三通道，自动降级）    │
│   └─ storage: 本地 JSON 持久化（tir_ 命名空间，独立目录）      │
└─────────────────────────────────────────────────────────────┘
```

## 3. 接入 edushield 的方式（均不修改主系统代码）

### 方式一：模块导入（推荐，插件式挂载）
```python
import sys
sys.path.insert(0, r"D:\学习资料\jiebang")   # 使 threat_ir_agent 可导入
from threat_ir_agent import ThreatIRSubAgent

agent = ThreatIRSubAgent()
result = agent.handle_event(
    {
        "source": "edushield:analyze",
        "event_type": "sql_injection",
        "target": "http://jwc.xxx.edu.cn",
        "source_ip": "10.1.2.3",
        "severity_hint": "medium",
        "description": "检测到 SQL 注入探测",
        "context": {"task_id": "edushield-task-001"},
    },
    task_id="edushield-task-001",
)
# result["display_md"]        → 注入主对话界面展示
# result["notification"]      → 告警推送报文（含 ledger_entry 供思维链记账）
# result["playbook"]          → 自动生成的建议模式处置预案
```

### 方式二：HTTP REST（对齐计划书 3.5 HTTP 总线）
```bash
python -m threat_ir_agent serve        # 默认 127.0.0.1:8090
```
```bash
curl -X POST http://127.0.0.1:8090/api/tir/ingest \
  -H "Content-Type: application/json" \
  -d '{"event": {"event_type": "webshell", "severity_hint": "high", ...}, "task_id": "t1"}'
curl -X POST http://127.0.0.1:8090/api/tir/playbooks/<playbook_id>/decision \
  -d '{"decision": "approve", "operator": "edushield-main-agent"}'
```

### 方式三：CLI（最小可运行入口）
```bash
python -m threat_ir_agent ingest --event-file evt.json
python -m threat_ir_agent playbook <alert_id> --mode simulation
python -m threat_ir_agent confirm <playbook_id> --decision approve
python -m threat_ir_agent doctor     # 接入自检
python -m threat_ir_agent demo       # 离线完整演示（mock 通道）
```

## 4. 推理大脑复用（不改任何模型文件）

| 通道 | 说明 |
|---|---|
| `reasonix-cli` | 调用 DeepSeek-Reasonix-Security 对外暴露的 CLI 一次性入口（`reasonix run -p ... --output-format json`），无工具、dontAsk 权限，仅取推理文本 |
| `openai-api` | 调用该模型底层 DeepSeek OpenAI 兼容 API（与 edushield llm 适配层同源），仅调用模型对外接口 |
| `mock` | 内置确定性回复，仅用于离线测试/演示 |

- `TIR_MODEL_GATEWAY=auto`（默认）：优先 reasonix-cli → openai-api → mock。
- **容错**：模型通道失败/欠费/断网时自动降级为空结果，分类器回退规则引擎
  （对齐计划书“判定走规则引擎+LLM双轨”）。
- 所有威胁研判、预案生成、报告生成均由该模型推理完成；**不修改模型权重、
  配置与调用逻辑**。

## 5. 复用 edushield 原有能力 vs 新增能力

**复用（只读调用，未修改）**：
- DeepSeek API 密钥/端点配置：只读回退读取 `edushield/edushield/.env`
  （config.py `_read_env`），不写入、不修改。
- 字段词汇兼容：`severity/confidence/mitre_technique/recommended_action/
  verdict` 等与 `edushield/models/state.py` 对齐，便于主系统解析展示。
- 依赖复用：fastapi/uvicorn/pydantic/httpx/python-dotenv 均为 edushield
  已具备依赖，**未引入任何新第三方依赖**。
- 对话上下文与思维链：事件可携带 `context`（复用主系统对话上下文），返回
  `ledger_entry` 供主系统思维链记账（不侵入主系统代码）。

**新增（全部为本子 Agent 专属文件）**：见 `docs/FILE_MANIFEST.md`。

## 6. 测试方法（仅威胁警报、应急响应）

```bash
cd D:\学习资料\jiebang
python threat_ir_agent\tests\test_threat_alert.py        # 威胁警报单测
python threat_ir_agent\tests\test_incident_response.py   # 应急响应单测
python threat_ir_agent\tests\test_run.py                 # 集成测试（含HTTP联调，服务未启动自动跳过）
```

详细触发步骤见 `docs/FILE_MANIFEST.md` 与 `register_subagent.py` 打印的接入步骤。

## 7. 安全约束（硬性）

- 应急响应**建议模式**只输出处置方案，交由人工确认；**模拟响应模式**仅推演，
  全程不调用 `subprocess/os.system/os.popen` 等任何真实执行原语
  （`tests/test_incident_response.py::test_simulator_forbids_exec_primitives`
  与 `doctor` 命令用 AST 强制校验）。
- 本地持久化仅写入子 Agent 专属 `storage/data/`，**不触碰 edushield 数据库/
  ChromaDB**。
- 全部产出文件位于工作目录 `threat_ir_agent/`，**未修改 edushield 与
  DeepSeek-Reasonix-Security 任何存量文件**（见 `subagent_registry.json`
  完整性校验与最终交付说明）。

## 8. ingest 前置层（v2.0：数据文件自动识别与转换）

支持直接摄入多种安全数据文件，自动识别格式 → 解析 → 生成标准 DetectionEvent →
送入威胁警报 + 应急响应。详见 `docs/INGEST_DESIGN.md`。

```bash
python -m threat_ir_agent ingest-file <文件> --run        # 一步到位（转换+分析）
python -m threat_ir_agent ingest-file <文件> --run --min-severity medium   # 只分析中危以上
python -m threat_ir_agent ingest-file <文件> --max-events 50 --out events.json
python -m threat_ir_agent ingest-file --list-formats      # 查看已注册解析器
```

```python
from threat_ir_agent.ingest import ingest_file
from threat_ir_agent import ThreatIRSubAgent
result = ingest_file("eve.json", feed=True, agent=ThreatIRSubAgent())
```

支持格式（23 个解析器）：PCAP/PCAPNG/Zeek/Suricata EVE/NetFlow v5/sFlow v5/IPFIX、
Syslog/Windows EVTX/Linux Auditd/EDR·OSQuery·Beats 遥测、哈希列表/MISP/STIX 2.x/
YARA 命中/恶意样本(PE·ELF·OLE·PDF·脚本)、JSON·JSONL/CSV·TSV/XML/
Parquet·Avro（缺依赖明确提示）、CEF/LEEF/IDMEF。
零新增第三方依赖；识别失败/解析异常自动生成 `parse_error` 标记事件降级处理。
