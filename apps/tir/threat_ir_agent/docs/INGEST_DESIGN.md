# ingest 前置层设计文档 —— 数据文件 → 标准检测事件

> 版本 1.0 ｜ 位置 `threat_ir_agent/ingest/`（全部为新增文件）

## 1. 定位与原则

| 项 | 说明 |
|---|---|
| 定位 | **独立前置处理层**：接收多种安全数据文件 → 自动识别格式 → 解析 → 生成标准 DetectionEvent JSON → 调用现有威胁警报 + 应急响应 |
| 兼容性 | **不修改** `models.py` 中 DetectionEvent Schema；**不改变**威胁报警/应急响应核心逻辑；现有仅接收 DetectionEvent 的行为完全一致 |
| 非侵入 | 新增模块全部位于 `ingest/` 子包，通过流水线调用现有 `ThreatIRSubAgent.handle_event()` 对接 |
| 信息保全 | 无法映射的字段写入 `raw.raw_data` / `raw.extra_context`，不丢原始关键信息 |
| 降级 | 格式识别失败 / 解析异常 → 生成带 `parse_error` 标记的 DetectionEvent，交由应急响应模块降级处理 |
| 插件化 | 新增格式 = 实现 `BaseParser` 子类 + `@register_parser` 装饰，零改动框架 |

## 2. Pipeline 流程

```
接收数据文件 → 格式识别 → 选择对应解析器 → 提取安全字段
→ 生成 DetectionEvent JSON → 调用现有威胁报警与应急响应逻辑
        │ 失败/异常
        ▼
parse_error 标记事件（错误详情 + 原始摘要）→ 同样进入应急响应降级处理
```

## 3. 模块划分

```
threat_ir_agent/ingest/
├── __init__.py        IngestPipeline / ingest_file 导出
├── base.py            BaseParser 抽象基类 + NormalizedRecord 键约定 + ParseError
├── registry.py        解析器注册表（@register_parser 插件机制）
├── detector.py        FormatDetector 多策略格式识别（扩展名+Magic+内容正则+Schema）
├── event_builder.py   NormalizedRecord → DetectionEvent（含 raw_data/extra_context/parse_error 事件）
├── pipeline.py        IngestPipeline 主流程（识别→解析→批量→下游；max_events 截断）
└── parsers/
    ├── __init__.py        import 即触发全部注册
    ├── network_pcap.py    PCAP / PCAPNG / Zeek / Suricata EVE / NetFlow v5 / sFlow v5 / IPFIX
    ├── host_parsers.py    Syslog(RFC3164/5424) / Windows EVTX / Linux Auditd / EDR·OSQuery·Beats 遥测
    ├── intel_parsers.py   哈希列表 / MISP JSON·CSV / STIX 2.x / YARA 命中 / 恶意样本(PE·ELF·OLE·PDF·脚本)
    ├── generic_parsers.py JSON·JSONL / CSV·TSV / XML / Parquet·Avro(缺依赖→明确提示)
    └── alert_cef_leef_idmef.py  CEF / LEEF / IDMEF
```

## 4. 格式识别多策略（detector.py）

每个解析器声明识别特征，`detect()` 返回 0~1 置信度，取最高者（≥0.45）：

| 策略 | 信号 | 置信度参考 |
|---|---|---|
| 文件扩展名 | `extensions` | 0.3（弱信号） |
| Magic Number | `magics`（如 `\xd4\xc3\xb2\xa1`→pcap、`ElfFile\x00`→EVTX、`%PDF-`→PDF） | 0.8~0.95 |
| 内容特征正则 | `content_patterns`（如 `^#fields\t`→Zeek、`^CEF:\d\|`→CEF、`"event_type":"alert"`→Suricata） | 0.6~0.9 |
| 已知 Schema 校验 | `schema_keys`（JSON/CSV 必含键，预留） | —— |

无法识别 → `parse_error` 事件（描述"无法识别文件格式" + 原始摘要）。

## 5. NormalizedRecord → DetectionEvent 映射（event_builder.py）

解析器产出规范化记录（约定键：timestamp/event_type/severity/src_ip/dst_ip/src_port/dst_port/
protocol/host/user/file_name/file_hash/ioc/summary/raw_data/extra），生成与现有 Schema
**完全兼容**的 DetectionEvent：

```json
{
  "event_id": "tir_event_xxxx",
  "source": "ingest:<parser_name>",
  "event_type": "<解析出的事件类型或 security_detection>",
  "target": "dst_ip:dst_port",
  "source_ip": "...",
  "severity_hint": "critical|high|medium|low|info",
  "description": "...",
  "raw": {
    "raw_data": "<原始日志片段/证据摘要，最多4000字符>",
    "extra_context": { "<无法映射字段>": "...", "ioc": [...] },
    "format": "<parser_name>",
    "parse_error": false
  },
  "context": {
    "source_file": "<文件路径>",
    "record_index": 1,
    "pipeline": "ingest",
    "task_id": "ingest:<文件名>#1"
  }
}
```

- **溯源**：`context.source_file + context.record_index`（批量拆分可追溯）
- **parse_error 事件**：`event_type="parse_error"`、`raw.parse_error=true`、`extra_context.error` 记录错误详情

## 6. 与现有子Agent 的集成方式

```python
from threat_ir_agent.ingest import ingest_file
from threat_ir_agent import ThreatIRSubAgent

agent = ThreatIRSubAgent()
result = ingest_file("eve.json", feed=True, agent=agent)
# result["events"]    → 标准 DetectionEvent 列表（与原有格式完全一致）
# result["results"]   → 每条事件的下游告警+预案结果
# result["parse_error"] → 是否有降级事件
```

或 CLI：`python -m threat_ir_agent ingest-file <file> [--run] [--max-events N] [--list-formats]`

## 7. 批量、截断与严重度过滤

- 多记录文件（Syslog/CSV/JSONL/EVTX/PCAP 多流）拆分为多个 DetectionEvent，逐条送入下游；
- `max_events` 参数控制单文件最大事件数（PCAP 等大文件先按严重度排序再截断，保留高价值流）；
- `min_severity` 是**双重门槛**：
  1. **分析门槛**（入口）：只分析严重度提示 ≥ 阈值的普通事件，忽略低价值流（省模型调用）；
  2. **输出门槛**（出口）：最终研判级别低于阈值的告警**不产生**（不持久化、不推送、不生成预案），
     返回 `skipped_by_level=True`，统计见 `alerts_filtered_by_verdict`；
  3. `parse_error` 事件不受任何门槛影响，始终处理（降级链路保留）；
- 单条下游失败不中断批量（try/except 包裹）。

## 8. 确定性设计（重复检测结果一致）

- 事件 ID 由 `source_file + record_index` 派生（确定性），同一输入重复运行生成相同 event_id；
- 分类器提示词排除易变字段（`event_id/occurred_at/received_at`），并使用较低温度
  `TIR_CLASSIFY_TEMPERATURE`（默认 0.1）→ 同一输入重复研判结果稳定；
- 完全可复现场景可用 `TIR_MODEL_GATEWAY=mock`（确定性通道）；真实模型下如需零随机性
  可设 `TIR_LLM_TEMPERATURE=0`；
- pcap 解析启发式与模型研判对齐：单条 SSH 连接标 `ssh_access/low`（同源 ≥5 条连接才升级
  `brute_force`）；HTTP 401≥3 判弱口令爆破、404≥20 判路径探测、URI 命中 SQLi/XSS 特征
  直接标注入侵类型，减少"解析器提示 vs 模型研判"分歧。

## 8. 安全与边界

- **零新增第三方依赖**（纯标准库）；Parquet/Avro 需 `pyarrow`/`fastavro`，未安装时抛出
  parse_error 并明确提示，不强行解析；
- **TLS 加密流量**：仅提取元数据并标注"不强行解密"；加密/压缩文件给出明确提示；
- **恶意样本**：只读提取元数据（格式/哈希/头部信息），不执行、不解压、不沙箱运行；
- 全部产出在工作目录内，未修改 edushield / DeepSeek-Reasonix-Security 任何存量文件。
