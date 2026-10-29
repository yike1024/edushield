# 新增文件清单（威胁警报-应急响应 子Agent）

> 全部文件均为**新增**，位于工作目录 `D:\学习资料\jiebang\threat_ir_agent\`。
> **无任何已有文件变更**（edushield、DeepSeek-Reasonix-Security 存量文件零改动，
> 见 `subagent_registry.json` 完整性校验）。

## 一、威胁警报模块文件

| 文件 | 作用 |
|---|---|
| `threat_alerts/__init__.py` | 威胁警报子模块包声明 |
| `threat_alerts/classifier.py` | **威胁分级判定**：规则引擎预筛（含校园误报抑制：爬虫≠攻击、选课高并发≠DDoS）+ DeepSeek-Reasonix 模型研判双轨合并，输出高/中/低三档 |
| `threat_alerts/alert_builder.py` | **标准化威胁告警报文**生成（含推送报文、主对话展示块 display_md、思维链 ledger_entry） |
| `threat_alerts/notifier.py` | **向 edushield 主智能体推送告警**：同步返回通道 + 可选异步 webhook（TIR_NOTIFY_URL） |

## 二、应急响应模块文件

| 文件 | 作用 |
|---|---|
| `incident_response/__init__.py` | 应急响应子模块包声明 |
| `incident_response/playbook_generator.py` | **按告警等级自动生成处置预案/修复建议**：遏制→根除→恢复→复盘 阶段模板 + 模型充实步骤；建议模式默认人工确认门控 |
| `incident_response/simulator.py` | **模拟响应模式**：仅推演处置流程（simulated 结果），强制零真实命令（AST 校验） |
| `incident_response/report_builder.py` | **接收主 agent 确认指令 → 完整应急响应报告**（approve/reject 两种决策，对齐计划书 Report 协议） |

## 三、公共/基础设施文件（威胁警报+应急响应共用）

| 文件 | 作用 |
|---|---|
| `__init__.py` | 包入口 + `ThreatIRSubAgent` 门面（模块导入式挂载入口，含完整流程编排） |
| `__main__.py` | **最小可运行入口**（CLI）：serve/ingest/playbook/confirm/list/demo/doctor |
| `config.py` | 子 Agent 独立配置（`TIR_` 命名空间，与主系统隔离；只读回退 edushield `.env` 的 DeepSeek 密钥） |
| `models.py` | 数据模型：DetectionEvent / ThreatAlert / ResponsePlaybook / IncidentReport / 状态枚举（对齐计划书统一协议字段语义） |
| `model_gateway.py` | **DeepSeek-Reasonix-Security 推理大脑网关**：reasonix-cli / openai-api / mock 三通道 + 自动降级（只调用模型对外入口，不改模型） |
| `storage/__init__.py` | 存储层包声明 |
| `storage/alert_store.py` | **告警/预案/报告本地持久化**（JSON 文件，`tir_` 命名空间，独立于主系统数据库；180 天审计留档清理） |
| `server.py` | 子 Agent FastAPI HTTP 服务（`/api/tir/*`，edushield 可 REST 调用） |
| `register_subagent.py` | **注册脚本**：写入子 Agent 注册信息（新增 `subagent_registry.json`）+ 只读完整性自检 + 打印接入步骤 |
| `requirements.txt` | 依赖说明（**无新第三方依赖**，复用 edushield 已有依赖） |
| `.env.example` | 子 Agent 环境变量模板（全部 `TIR_` 前缀） |
| `README.md` | 使用说明文档 |
| `docs/GITHUB_RESEARCH.md` | GitHub 调研报告 + 来源标注 + 校验说明 |
| `docs/FILE_MANIFEST.md` | 本清单 |

## 四、测试文件（仅威胁警报、应急响应）

| 文件 | 作用 |
|---|---|
| `tests/__init__.py` | 测试包声明 |
| `tests/test_threat_alert.py` | 威胁警报测试：高/中/低分级、误报抑制、告警报文、持久化、推送报文 |
| `tests/test_incident_response.py` | 应急响应测试：预案生成、建议/模拟两种模式、零真实命令 AST 校验、确认指令→报告 |
| `tests/test_run.py` | 集成测试：模块导入方式触发 + 可选 HTTP 联调（主服务未启动自动跳过） |

## 四点五、文档（新增 ARCHITECTURE）

| 文件 | 作用 |
|---|---|
| `docs/ARCHITECTURE.md` | **架构文档**：定位/分层架构/模块职责/核心流程/数据模型/推理网关/存储/API/集成/部署/扩展性/安全/质量 |

## 五、运行时生成（非交付源码）

| 路径 | 说明 |
|---|---|
| `subagent_registry.json` | 由 `register_subagent.py` 生成的注册信息（含完整性校验结果） |
| `storage/data/{alerts,playbooks,reports}/` | 运行时本地持久化目录（自动创建） |

## 六、ingest 前置层（新增 —— 数据文件自动识别与转换）

> 依据用户扩展需求新增：接收多种安全数据文件格式 → 自动识别 → 解析 →
> 生成标准 DetectionEvent JSON → 送入现有威胁警报 + 应急响应。

| 文件 | 作用 |
|---|---|
| `ingest/__init__.py` | 前置层导出（IngestPipeline / ingest_file） |
| `ingest/base.py` | `BaseParser` 解析器抽象基类 + NormalizedRecord 键约定 + ParseError |
| `ingest/registry.py` | 解析器插件注册表（`@register_parser`，新增格式零改动框架） |
| `ingest/detector.py` | 多策略格式识别器（扩展名 + Magic + 内容正则 + Schema） |
| `ingest/event_builder.py` | 规范化记录 → DetectionEvent（raw_data/extra_context 保真 + parse_error 事件） |
| `ingest/pipeline.py` | 主流水线：识别→解析→批量事件→下游；失败降级 |
| `ingest/parsers/__init__.py` | 解析器包（import 即注册全部） |
| `ingest/parsers/network_pcap.py` | PCAP / PCAPNG / Zeek / Suricata EVE / NetFlow v5 / sFlow v5 / IPFIX |
| `ingest/parsers/host_parsers.py` | Syslog / Windows EVTX / Linux Auditd / EDR·OSQuery·Beats 遥测 |
| `ingest/parsers/intel_parsers.py` | 哈希列表 / MISP / STIX 2.x / YARA 命中 / 恶意样本（PE·ELF·OLE·PDF·脚本） |
| `ingest/parsers/generic_parsers.py` | JSON·JSONL / CSV·TSV / XML / Parquet·Avro（缺依赖→明确提示） |
| `ingest/parsers/alert_cef_leef_idmef.py` | CEF / LEEF / IDMEF 告警聚合格式 |
| `tests/test_ingest.py` | 前置层测试（识别/解析/批量/parse_error/下游对接，15 用例） |
| `docs/INGEST_DESIGN.md` | ingest 层设计文档 |

> 范围说明：ingest 层仅做"格式识别 + 字段提取 + 事件生成"的数据接入转换，
> 不实现计划书中任何业务检测模块；威胁分级、预案、报告仍由原核心逻辑完成。
> 该层为独立前置模块，未修改 DetectionEvent Schema 与现有核心逻辑。

---

## 模块归属小结

- **威胁警报**：`threat_alerts/*`（classifier / alert_builder / notifier）
- **应急响应**：`incident_response/*`（playbook_generator / simulator / report_builder）
- **两者共用**：`models.py`、`model_gateway.py`、`storage/alert_store.py`、
  `config.py`、`server.py`、`__init__.py`、`__main__.py`、`register_subagent.py`
- **无其他无关模块文件**：未创建漏洞扫描、资产测绘、日志采集、渗透测试、
  威胁情报聚合等任何计划书外功能的文件。
