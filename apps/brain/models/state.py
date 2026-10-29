"""EduShield 核心数据模型 — 借鉴 AiSOC 的 Pydantic State 设计。

每一个 Agent 步骤都产生一条 InvestigationEvent，
完整记录 prompt → tool_call → evidence → rationale 的思维链。
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ============================================================
# Enums
# ============================================================

class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreatVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    UNCERTAIN = "uncertain"


class ActionRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    BRUTE_FORCE = "brute_force"
    DIRECTORY_SCAN = "directory_scan"
    PORT_SCAN = "port_scan"
    FILE_UPLOAD = "file_upload"
    COMMAND_INJECTION = "command_injection"
    DDOS = "ddos"
    DATA_EXFIL = "data_exfiltration"
    WEBSHELL = "webshell"
    CVE_EXPLOIT = "cve_exploit"
    UNKNOWN = "unknown"


# ============================================================
# Investigation Ledger models（借鉴 AiSOC ledger.py 设计）
# ============================================================

class InvestigationEvent(BaseModel):
    """Agent 执行链中的单步记录。

    对应 AiSOC 的 investigation_events 表。
    每一步都记录：谁做的、做了什么、看到了什么、为什么这样判断。
    """
    event_id: UUID = Field(default_factory=uuid4)
    seq: int = Field(description="步骤序号")
    kind: str = Field(description="事件类型: thought | tool_call | observation | verdict")
    agent: str = Field(description="执行的Agent: Planner | Worker | Analyst")
    summary: str = Field(description="本步摘要")
    detail: dict[str, Any] = Field(default_factory=dict, description="详细payload")
    duration_ms: float = Field(default=0.0, description="耗时(ms)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class LedgerEntry(BaseModel):
    """单次调查的完整思维链记录。

    对应 AiSOC 的 investigation_runs + events。
    """
    run_id: UUID = Field(default_factory=uuid4)
    task: str = Field(default="", description="用户原始请求")
    defense_target: str = Field(default="", description="防护目标")
    status: AgentStatus = AgentStatus.PENDING
    events: list[InvestigationEvent] = Field(default_factory=list)
    report_md: str = Field(default="", description="最终报告(Markdown)")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    def add_event(self, kind: str, agent: str, summary: str, detail: dict | None = None, duration_ms: float = 0.0) -> InvestigationEvent:
        evt = InvestigationEvent(
            seq=len(self.events) + 1,
            kind=kind,
            agent=agent,
            summary=summary,
            detail=detail or {},
            duration_ms=duration_ms,
        )
        self.events.append(evt)
        return evt


# ============================================================
# Core domain models
# ============================================================

class AnalyzedThreat(BaseModel):
    """Analyst 确认的单个威胁"""
    title: str = Field(description="威胁标题")
    attack_type: AttackType = Field(default=AttackType.UNKNOWN)
    severity: str = Field(default="medium", description="critical | high | medium | low | info")
    confidence: float = Field(default=0.0, ge=0, le=1, description="置信度")
    source_ip: Optional[str] = None
    target: Optional[str] = None
    evidence: str = Field(default="")
    mitre_technique: Optional[str] = Field(default=None, description="MITRE ATT&CK 技术ID")
    recommended_action: str = Field(default="")


class ProposedAction(BaseModel):
    """Worker 建议/执行的处置动作。

    借鉴 AiSOC 的 ProposedAction，每步都有风险等级和审批门控。
    """
    action_id: UUID = Field(default_factory=uuid4)
    action_type: str = Field(description="工具名: firewall_block | firewall_unblock | ...")
    description: str = Field(default="")
    risk_level: ActionRisk = ActionRisk.LOW
    target: str = Field(default="")
    parameters: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = Field(default=False)
    rationale: str = Field(default="")
    executed: bool = Field(default=False)
    result: Optional[str] = None


class PlannerOutput(BaseModel):
    """Planner 结构化输出"""
    reasoning: str = Field(description="CoT 思维链：为什么这样做")
    current_plan: str = Field(description="当前执行策略")
    next_step: str = Field(description="下一步工具名 或 'finish'")
    next_target: str = Field(default="", description="下一步操作目标（IP/域名等），如 10.50.1.88")
    next_action: str = Field(default="execute", description="工具的 action 参数，remote_shell 可选: fetch_logs|system_status|check_ports|read_file|run_command")
    is_finished: bool = Field(default=False)


class AnalystOutput(BaseModel):
    """Analyst 结构化输出"""
    threats: list[AnalyzedThreat] = Field(default_factory=list)
    false_positives: list[dict[str, str]] = Field(default_factory=list)
    summary: str = Field(default="")
    verdict: ThreatVerdict = ThreatVerdict.UNCERTAIN


# ============================================================
# LangGraph Agent State
# ============================================================

class AgentState(BaseModel):
    """EduShield 全局 Agent 状态。

    借鉴 AiSOC InvestigationState + a文件夹 AgentState 的融合。
    通过 LangGraph 在各节点间流转。
    """
    # ---- 用户输入 ----
    user_request: str = Field(default="")
    defense_target: str = Field(default="校园网站")

    # ---- 工具 ----
    available_tools: list[str] = Field(default_factory=list)

    # ---- Planner ----
    current_plan: str = Field(default="")
    next_step: str = Field(default="")
    next_target: str = Field(default="")
    next_action: str = Field(default="execute")

    # ---- 分析结果 ----
    threats: list[AnalyzedThreat] = Field(default_factory=list)
    false_positives: list[dict[str, str]] = Field(default_factory=list)
    verdict: ThreatVerdict = ThreatVerdict.UNCERTAIN
    confidence: float = Field(default=0.0, ge=0, le=1)

    # ---- 处置 ----
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    executed_actions: list[ProposedAction] = Field(default_factory=list)

    # ---- 知识 ----
    mitre_mappings: list[str] = Field(default_factory=list)
    rag_context: list[str] = Field(default_factory=list)

    # ---- 状态控制 ----
    status: AgentStatus = AgentStatus.PENDING
    iteration_count: int = Field(default=0)
    max_iterations: int = Field(default=15)
    is_finished: bool = Field(default=False)
    error: Optional[str] = None

    # ---- Ledger ----
    ledger: LedgerEntry = Field(default_factory=LedgerEntry)

    def to_dict(self) -> dict:
        import json as _json
        return _json.loads(self.model_dump_json())

    @classmethod
    def from_dict(cls, d: dict) -> "AgentState":
        return cls.model_validate(d)
