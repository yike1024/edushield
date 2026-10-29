"""统一协议 —— 大脑 ↔ 身体部件的三张数据表。

权威来源：aisoc-docs/02-通信协议规范.md（v0.1）。
本文件是协议的 Python 实现，所有大脑/部件交互必须走这三个模型。

三张表：
    TaskMessage  大脑 → 部件  任务下发
    Finding      部件 → 大脑  证据上报
    Report       大脑 → 用户  报告输出
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

# 协议版本：向后兼容时新增可选字段即可，不兼容变更需升级并全量回归
PROTO_VER = 1


def utc_now_iso() -> str:
    """ISO8601 UTC 时间戳（协议统一用这个）。"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_task_id() -> str:
    """生成全局唯一 task_id：T+YYYYMMDD-序号。

    序号使用当天 0 点以来的毫秒数，单进程内足够唯一；
    多进程部署时建议接入雪花/序列号服务（阶段 1 不处理）。
    """
    now = datetime.now(timezone.utc)
    return f"T{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S%f')[:-3]}"


def new_finding_id(task_id: str, seq: int) -> str:
    """生成 Finding id：F-<task_id>-<seq>。"""
    return f"F-{task_id}-{seq:03d}"


# ============================================================
# Enums（与 aisoc-docs 02 一致）
# ============================================================

class Domain(str, Enum):
    """domain 路由依据。一期只做 pentest / logaudit；intel 为威胁情报收集。"""

    PENTEST = "pentest"
    LOGAUDIT = "logaudit"
    THREATINTEL = "threatintel"  # 历史别名，兼容
    INTEL = "intel"              # 威胁情报收集部件（8789）
    INCIDENT = "incident"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    REAL_THREAT = "real_threat"
    FALSE_POSITIVE = "false_positive"
    PENDING_REVIEW = "pending_review"


class TaskStatus(str, Enum):
    """任务生命周期状态机（aisoc-docs 03 §2.3）。"""

    PENDING = "pending"
    RUNNING = "running"
    APPROVAL = "approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ARCHIVED = "archived"


# ============================================================
# TaskMessage —— 任务下发（aisoc-docs 02 §2）
# ============================================================

class TaskContext(BaseModel):
    """跨域上下文：星型协作的载体（A 部件产出 → 大脑 → B 部件输入）。"""

    ref_task_ids: list[str] = Field(default_factory=list)
    evidence_summary: str = ""


class TaskMessage(BaseModel):
    task_id: str = Field(description="全局唯一任务号")
    domain: Domain = Field(description="路由依据")
    target: str = Field(description="目标 IP/域名/URL，必须在授权白名单内")
    params: dict[str, Any] = Field(default_factory=dict, description="参数：scope/timeout_s/max_steps 等")
    tools: list[str] = Field(default_factory=list, description="可用工具白名单，缺省=部件全部")
    context: TaskContext = Field(default_factory=TaskContext)
    auth: str = Field(default="", description="部件实例 token（从注册表注入）")
    proto_ver: int = Field(default=PROTO_VER)

    def to_input_text(self) -> str:
        """序列化为 reasonix serve 的 input 文本。

        aisoc-docs 02 §6 规定：只传结构化文本，严禁把整包 JSON
        当提示词原文丢给模型（防 prompt 注入面扩大）。
        """
        import json

        lines = [f"任务 {self.task_id} ({self.domain.value}): 请执行该域安全任务并输出结构化发现。",
                 "这是一次全新的独立任务：请忽略会话历史中任何相同或相似的任务，从零开始、完整执行，不要因为目标重复而跳过。"]
        if self.params.get("task"):
            lines.append(f"用户要求: {self.params['task']}")
        lines.append(f"目标: {self.target}")
        if self.params:
            lines.append(f"参数: {json.dumps(self.params, ensure_ascii=False)}")
        if self.tools:
            lines.append(f"可用工具: {', '.join(self.tools)}")
        if self.context.evidence_summary:
            lines.append(f"上下文: {self.context.evidence_summary}")
        if self.context.ref_task_ids:
            lines.append(f"来源任务: {', '.join(self.context.ref_task_ids)}")
        return "\n".join(lines)


# ============================================================
# Finding —— 证据上报（aisoc-docs 02 §3）
# ============================================================

class Finding(BaseModel):
    id: str = Field(description="F-<task_id>-<seq>")
    task_id: str
    domain: Domain
    target: str
    tool: str = Field(description="产出工具名")
    severity: Severity
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    title: str
    description: str
    evidence: str = Field(description="支撑证据片段（原始工具输出摘录）")
    remediation: Optional[str] = None
    confidence: float = Field(ge=0, le=1, description="部件对该发现的置信度 0~1")
    mitre: list[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=utc_now_iso)


# ============================================================
# Report —— 报告（aisoc-docs 02 §4）
# ============================================================

class Report(BaseModel):
    task_id: str
    domain: str = Field(description="报告域，domain='all' 表示跨域综合报告")
    summary: str
    findings: list[str] = Field(description="引用 Finding id 列表（报告可追溯）")
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    mitre: list[str] = Field(default_factory=list)
    appendix: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now_iso)
