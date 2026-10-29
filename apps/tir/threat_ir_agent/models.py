# -*- coding: utf-8 -*-
"""
威胁警报-应急响应 子Agent 数据模型
===================================
设计对齐：
1. 《安全智能体平台-项目计划书》3.3 统一协议：
   - 任务协议 TaskMessage{task_id, domain, target, params, tools}
   - 证据协议 Finding{id, target, tool, severity, cve, cwe, cvss, remediation, confidence, timestamp}
   - 报告协议 Report{task_id, domain, summary, findings[], verdict, confidence, mitre[], appendix}
2. edushield 主系统 models/state.py 的字段词汇（severity / confidence /
   mitre_technique / recommended_action / verdict 等）保持一致，便于主系统解析展示。
3. 借鉴开源 IR 平台（见 docs/GITHUB_RESEARCH.md）的
   Alert / Case / Playbook / Report 分层数据结构思想，但全部字段为本子 Agent
   自主定义，未复制任何开源代码。

本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _short_id(prefix: str) -> str:
    """生成带子 Agent 命名空间前缀的短 ID，如 tir_alert_3f2a9c1d。"""
    return f"{prefix}{uuid4().hex[:8]}"


# ===========================================================================
# 枚举
# ===========================================================================

class ThreatLevel(str, Enum):
    """威胁分级判定 —— 严格按项目计划书/需求：高 / 中 / 低 三档。"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_hint(cls, hint: Optional[str]) -> "ThreatLevel":
        """将主系统传入的严重度提示（critical/high/medium/low/info）归一到三档。"""
        if not hint:
            return cls.LOW
        h = str(hint).strip().lower()
        if h in ("critical", "high", "严重", "高"):
            return cls.HIGH
        if h in ("medium", "中", "中等"):
            return cls.MEDIUM
        return cls.LOW


class AlertStatus(str, Enum):
    """告警生命周期状态（确定性状态机，纯业务）。"""
    NEW = "new"                    # 已生成
    NOTIFIED = "notified"          # 已推送主智能体
    ACKNOWLEDGED = "acknowledged"  # 主智能体已确认
    RESPONDED = "responded"        # 已生成应急响应报告
    CLOSED = "closed"              # 关闭


class PlaybookMode(str, Enum):
    """应急响应两种模式（严格按需求）：
    - SUGGESTION ：建议模式 —— 输出处置方案，交由人工确认（不自动执行）
    - SIMULATION ：模拟响应模式 —— 仅推演处置流程，禁止执行真实主机/网络命令
    """
    SUGGESTION = "suggestion"
    SIMULATION = "simulation"


class StepStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SIMULATED = "simulated"
    COMPLETED = "completed"


class Decision(str, Enum):
    """主 agent 下发的确认指令。"""
    APPROVE = "approve"   # 批准处置（在建议模式下代表“人工确认采纳该方案”）
    REJECT = "reject"     # 拒绝/调整


class IncidentStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REJECTED = "rejected"


# ===========================================================================
# 输入：主平台安全检测事件
# ===========================================================================

class DetectionEvent(BaseModel):
    """来自 edushield 主平台的安全检测事件数据（任务协议 TaskMessage 语义）。

    edushield 主智能体调用子 Agent 时，把安全检测结果（如 Analyst 确认的威胁、
    日志审计异常、威胁情报命中）封装为本事件传入。字段尽量与主系统
    AnalyzedThreat / AgentState 兼容。
    """
    event_id: str = Field(default_factory=lambda: _short_id("tir_event_"),
                          description="事件ID（子Agent命名空间）")
    source: str = Field(default="edushield", description="事件来源，如 edushield:analyze")
    domain: str = Field(default="threat-alert", description="域标记（对齐计划书 domain）")
    event_type: str = Field(default="security_detection", description="事件类型")
    target: str = Field(default="", description="防护目标，如 http://jwc.xxx.edu.cn")
    source_ip: Optional[str] = Field(default=None, description="来源IP")
    severity_hint: Optional[str] = Field(default=None,
                                         description="主系统严重度提示 critical/high/medium/low/info")
    description: str = Field(default="", description="事件描述")
    attack_type_hint: Optional[str] = Field(default=None, description="攻击类型提示，如 sql_injection")
    mitre_hint: Optional[str] = Field(default=None, description="MITRE ATT&CK 技术ID提示")
    confidence_hint: Optional[float] = Field(default=None, ge=0, le=1,
                                             description="主系统置信度提示 0~1")
    raw: dict[str, Any] = Field(default_factory=dict, description="原始检测数据")
    context: dict[str, Any] = Field(default_factory=dict,
                                    description="对话上下文（主系统传入，复用现有对话上下文）")
    occurred_at: datetime = Field(default_factory=_now_utc, description="事件发生时间")
    received_at: datetime = Field(default_factory=_now_utc, description="子Agent接收时间")

    @classmethod
    def from_dict(cls, d: dict) -> "DetectionEvent":
        """容错构造：允许缺失字段/额外字段。"""
        known = {f: d[f] for f in cls.model_fields if f in d}
        known["raw"] = {k: v for k, v in d.items() if k not in cls.model_fields}
        return cls(**known)


# ===========================================================================
# 输出1：标准化威胁告警报文
# ===========================================================================

class ThreatAlert(BaseModel):
    """标准化威胁告警报文（对齐计划书 Finding 证据协议字段语义）。

    生成后本地持久化（子Agent专属存储），并向 edushield 主智能体推送，
    供主对话界面展示。
    """
    alert_id: str = Field(default_factory=lambda: _short_id("tir_alert_"))
    event_ref: str = Field(default="", description="关联的检测事件ID")
    task_id: str = Field(default="", description="主系统任务ID（如有，贯穿追溯）")
    title: str = Field(default="", description="告警标题")
    level: ThreatLevel = Field(default=ThreatLevel.LOW, description="威胁分级：high/medium/low")
    attack_type: str = Field(default="unknown", description="攻击类型")
    mitre_technique: Optional[str] = Field(default=None, description="MITRE ATT&CK 技术ID")
    confidence: float = Field(default=0.0, ge=0, le=1, description="置信度 0~1")
    source_ip: Optional[str] = Field(default=None)
    target: str = Field(default="")
    summary: str = Field(default="", description="告警摘要")
    evidence: str = Field(default="", description="关键证据")
    recommended_action: str = Field(default="", description="建议处置（remediation 语义）")
    reasoning: str = Field(default="", description="分级判定依据（模型推理/规则说明）")
    verdict: str = Field(default="uncertain",
                         description="对齐主系统 ThreatVerdict：true_positive/false_positive/benign/uncertain")
    status: AlertStatus = Field(default=AlertStatus.NEW)
    created_at: datetime = Field(default_factory=_now_utc)
    notified_at: Optional[datetime] = None

    def to_notification(self) -> dict:
        """生成推送 edushield 主智能体的告警通知报文（可直接供对话界面展示）。"""
        return {
            "alert_id": self.alert_id,
            "level": self.level.value,
            "title": self.title,
            "attack_type": self.attack_type,
            "mitre_technique": self.mitre_technique,
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "target": self.target,
            "summary": self.summary,
            "recommended_action": self.recommended_action,
            "verdict": self.verdict,
            "created_at": self.created_at.isoformat(),
            # 主对话界面可直接渲染的 Markdown 展示块
            "display_md": self.to_markdown(),
        }

    def to_markdown(self) -> str:
        """Markdown 告警展示块（供 edushield 主对话界面展示）。"""
        lvl = {"high": "🔴 高", "medium": "🟡 中", "low": "🟢 低"}.get(self.level.value, self.level.value)
        lines = [
            "---",
            f"### ⚠️ 威胁警报 [{lvl}风险]",
            f"**告警ID**: `{self.alert_id}`",
            f"**标题**: {self.title}",
            f"**攻击类型**: {self.attack_type}  |  **MITRE**: {self.mitre_technique or '未知'}",
            f"**置信度**: {self.confidence:.0%}  |  **判定**: {self.verdict}",
            f"**来源IP**: {self.source_ip or '未知'}  |  **目标**: {self.target or '未知'}",
            "",
            f"**摘要**: {self.summary}",
            f"**证据**: {self.evidence}",
            f"**建议处置**: {self.recommended_action}",
            "",
        ]
        return "\n".join(lines)


# ===========================================================================
# 输出2：应急响应预案（Playbook）
# ===========================================================================

class PlaybookStep(BaseModel):
    """预案中的单个处置步骤（仅描述性动作，不执行任何真实系统命令）。

    对齐 edushield ProposedAction 的 risk_level / requires_approval / rationale 语义。
    """
    seq: int = Field(description="步骤序号")
    phase: str = Field(default="", description="阶段：遏制/根除/恢复/复盘")
    action: str = Field(default="", description="处置动作描述（可执行预案文本）")
    expected_command: str = Field(default="", description="参考命令（仅文本示例，禁止实际执行）")
    risk_level: str = Field(default="low", description="low/medium/high")
    requires_approval: bool = Field(default=True, description="人工确认门控（建议模式默认需确认）")
    rationale: str = Field(default="", description="为什么这样做")
    status: StepStatus = Field(default=StepStatus.PENDING)
    simulated_result: Optional[str] = Field(default=None, description="模拟响应模式下的推演结果")


class ResponsePlaybook(BaseModel):
    """按告警等级自动生成的应急处置预案。

    对齐计划书 3.3 报告协议 Report 语义：summary/findings/verdict/confidence/mitre。
    """
    playbook_id: str = Field(default_factory=lambda: _short_id("tir_playbook_"))
    alert_id: str = Field(default="")
    task_id: str = Field(default="")
    level: ThreatLevel = Field(default=ThreatLevel.LOW)
    objective: str = Field(default="", description="处置目标")
    mode: PlaybookMode = Field(default=PlaybookMode.SUGGESTION)
    steps: list[PlaybookStep] = Field(default_factory=list)
    summary: str = Field(default="", description="预案摘要")
    confidence: float = Field(default=0.0, ge=0, le=1)
    mitre: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now_utc)

    def to_markdown(self) -> str:
        lines = [
            "---",
            f"### 🛡️ 应急处置预案（{self.mode.value}模式）",
            f"**预案ID**: `{self.playbook_id}`  |  关联告警: `{self.alert_id}`",
            f"**等级**: {self.level.value}  |  **目标**: {self.objective}",
            "",
            f"**摘要**: {self.summary}",
            "",
        ]
        for st in self.steps:
            mark = "✅" if st.status in (StepStatus.COMPLETED, StepStatus.SIMULATED) else "⏳"
            lines.append(f"{mark} {st.seq}. [{st.phase}] {st.action}")
            if st.expected_command:
                lines.append(f"     参考命令(仅文本，不执行): `{st.expected_command}`")
            if st.simulated_result:
                lines.append(f"     推演结果: {st.simulated_result}")
            if st.requires_approval:
                lines.append("     （需人工确认）")
        lines.append("---")
        return "\n".join(lines)


# ===========================================================================
# 输出3：应急响应报告
# ===========================================================================

class IncidentReport(BaseModel):
    """主 agent 下发确认指令后输出的完整应急响应报告。

    对齐计划书 3.3 报告协议 Report{task_id, domain, summary, findings[],
    verdict, confidence, mitre[], appendix}。
    """
    report_id: str = Field(default_factory=lambda: _short_id("tir_report_"))
    playbook_id: str = Field(default="")
    alert_id: str = Field(default="")
    task_id: str = Field(default="")
    domain: str = Field(default="incident-response")
    decision: Decision = Field(default=Decision.APPROVE)
    mode: PlaybookMode = Field(default=PlaybookMode.SUGGESTION)
    operator: str = Field(default="edushield-main-agent", description="确认人/确认方")
    summary: str = Field(default="")
    findings: list[dict[str, Any]] = Field(default_factory=list)
    verdict: str = Field(default="uncertain")
    confidence: float = Field(default=0.0, ge=0, le=1)
    mitre: list[str] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list, description="处置步骤及结果")
    appendix: dict[str, Any] = Field(default_factory=dict, description="附录（证据/原始事件等）")
    generated_at: datetime = Field(default_factory=_now_utc)

    def to_markdown(self) -> str:
        lines = [
            "=" * 60,
            "       威胁警报-应急响应 子Agent — 应急响应报告",
            "=" * 60,
            f"报告ID: {self.report_id}   模式: {self.mode.value}   决策: {self.decision.value}",
            f"关联告警: {self.alert_id}   关联预案: {self.playbook_id}",
            f"确认方: {self.operator}",
            "",
            f"【结论】{self.summary}",
            f"【判定】{self.verdict}  置信度: {self.confidence:.0%}  MITRE: {', '.join(self.mitre) or '无'}",
            "",
            "【处置明细】",
        ]
        for i, st in enumerate(self.steps, 1):
            lines.append(f"  {i}. {st.get('phase', '')}: {st.get('action', '')}")
            if st.get("simulated_result"):
                lines.append(f"     推演结果: {st['simulated_result']}")
            if st.get("result"):
                lines.append(f"     结果: {st['result']}")
        lines.append("")
        lines.append("【附录】")
        lines.append(json.dumps(self.appendix, ensure_ascii=False, indent=2))
        lines.append("")
        lines.append("=" * 60)
        lines.append("  报告由 威胁警报-应急响应 子Agent 自动生成（模拟/建议模式，未执行真实系统操作）")
        lines.append("=" * 60)
        return "\n".join(lines)


# ===========================================================================
# 工具函数
# ===========================================================================

def to_jsonable(obj: BaseModel) -> dict:
    """Pydantic 模型 → JSON 可序列化 dict。"""
    return json.loads(obj.model_dump_json())
