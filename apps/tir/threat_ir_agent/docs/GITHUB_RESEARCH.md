# GitHub 开源项目调研报告（威胁警报 / 应急响应）

> 调研日期：2026-08-22 ｜ 检索关键词：
> `security agent threat alert incident response`、`安全智能体 威胁告警 应急响应`、
> `cyber-security agent incident-response playbook`
>
> **定位声明：GitHub 开源项目仅作辅助参考（借鉴架构思路/数据结构/告警报文范式/
> 应急响应状态流转），绝不因开源实现不同而更改、删减、偏离项目计划书中威胁警报、
> 应急响应章节的业务需求、功能指标与平台架构。冲突时无条件舍弃开源方案，
> 严格按项目计划书实现。**

---

## 1. 检索到的高 Star 参考项目

| 仓库 | Star（约） | 开源协议 | 借鉴点（仅设计思想，未复制代码） |
|---|---|---|---|
| [TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) | 3.5k+ | AGPL-3.0 | Alert→Case 分层数据结构、告警生命周期状态流转（new→notified→acknowledged→resolved）、案件证据留存与审计思想 |
| [dfir-iris/iris-web](https://github.com/dfir-iris/iris-web) | 2.5k+ | LGPL-3.0 | 事件响应调查流程（Alert/Case/Playbook 分层）、处置步骤结构化、审批与状态机思想 |
| [TracecatHQ/tracecat](https://github.com/TracecatHQ/tracecat) | 3k+ | Apache-2.0 | 面向 AI 代理的安全自动化：规则+AI 双轨判定、工作流化处置步骤、可审计执行轨迹思想 |
| [meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response) | 7.5k+ | CC0/自定义（资源清单） | IR 方法论工具分类清单（遏制/根除/恢复/复盘）与处置阶段划分参考 |

> Star 数为调研时点的近似值，以 GitHub 页面为准。

## 2. 具体借鉴点与本子 Agent 的落地

| 借鉴点 | 来源仓库 | 在本子 Agent 中的落地位置 |
|---|---|---|
| 告警分层与生命周期状态机 | TheHive | `models.py::AlertStatus`（new/notified/acknowledged/responded/closed），`threat_alerts/notifier.py` |
| 处置步骤结构化 + 审批门控 | dfir-iris | `models.py::PlaybookStep`（phase/action/risk_level/requires_approval），`incident_response/playbook_generator.py` |
| 规则+AI 双轨判定、可审计轨迹 | Tracecat | `threat_alerts/classifier.py`（规则预筛 + 模型研判 + 分歧记录），`model_gateway.py`（通道降级） |
| 遏制→根除→恢复→复盘 阶段划分 | awesome-incident-response | `incident_response/playbook_generator.py::_PHASE_TEMPLATES` |

> 以上全部为**自主重写**实现，仅吸收设计思想，未克隆/下载任何第三方仓库到本地，
> 未直接引入第三方源码，未大段复制开源代码。

## 3. 冲突处理结论

计划书（威胁警报、应急响应章节）与本子 Agent 需求为最高优先级。经核对：
- 计划书要求“威胁分级判定（高/中/低）” → 子 Agent 严格三档（`ThreatLevel`），
  未采用开源项目中常见的中英混杂更多分档；
- 计划书要求“模拟响应模式禁止执行真实命令” → 子 Agent 以 AST 强制校验
  零执行原语，比开源 SOAR 的自动执行能力更保守，**以计划书安全约束为准**；
- 计划书要求“新建子 Agent 专属存储，不许篡改主系统数据库” → 子 Agent 使用
  独立 JSON 存储（`tir_` 命名空间），未沿用开源平台共库方案。

## 4. 校验说明（必做项）

> **已核对：仅实现威胁警报、应急响应功能，未开发计划书中其他无关模块
> （未实现漏洞扫描、资产测绘、日志采集、渗透测试、威胁情报聚合等），
> 本子 Agent 所有功能实现均对齐项目计划书对应章节（威胁判定、误报抑制、
> 应急响应预案、审批确认、报告合规、审计留档），未因开源参考变更业务需求。**

---

## 附：未适配说明

若上述参考项目均被认为不适用，按任务要求明确记录：
**“未找到适配高 star 开源参考项目，全部逻辑依据项目计划书（威胁警报、
应急响应部分）自主实现”** —— 本子 Agent 的规则引擎、三档分级、状态机、
预案生成与报告结构均为依据计划书自主设计实现，开源项目仅用于佐证
IR 方法论与数据结构合理性。
