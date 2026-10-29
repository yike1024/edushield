# -*- coding: utf-8 -*-
"""
应急响应报告生成模块
====================
需求：可接收主 agent 下发的确认指令（approve/reject），输出完整应急响应报告。

流程（确定性状态机，纯业务）：
  alert ──► playbook(建议/模拟) ──► decision(approve/reject) ──► report
- 建议模式 + approve：报告记录“处置方案已获人工确认”，步骤标记 APPROVED；
- 建议模式 + reject ：报告记录拒绝原因，步骤标记 REJECTED，输出调整建议；
- 模拟模式 + approve：报告记录模拟推演轨迹（全部 simulated=true），
  明确声明未执行任何真实系统操作。

对齐计划书 3.3 报告协议 Report{task_id, domain, summary, findings[],
verdict, confidence, mitre[], appendix}。本文件为【新增文件】。
"""

from __future__ import annotations

import logging
from typing import Optional

from ..models import (
    Decision,
    IncidentReport,
    IncidentStatus,
    PlaybookMode,
    ResponsePlaybook,
    StepStatus,
    ThreatAlert,
    to_jsonable,
)

logger = logging.getLogger(__name__)


class ReportBuilder:
    """应急响应报告构建器。"""

    def build(self, playbook: ResponsePlaybook, decision: Decision,
              alert: Optional[ThreatAlert] = None,
              operator: str = "edushield-main-agent",
              reject_reason: str = "") -> IncidentReport:
        """根据确认指令生成完整应急响应报告。"""
        report = IncidentReport(
            playbook_id=playbook.playbook_id,
            alert_id=playbook.alert_id,
            task_id=playbook.task_id,
            decision=decision,
            mode=playbook.mode,
            operator=operator,
            summary=self._summary(playbook, decision, reject_reason),
            findings=self._findings(playbook, alert),
            verdict=(alert.verdict if alert else "uncertain"),
            confidence=playbook.confidence,
            mitre=playbook.mitre,
            steps=[self._step_row(s, decision) for s in playbook.steps],
            appendix=self._appendix(playbook, alert, decision, reject_reason),
        )
        logger.info("[Report] 生成应急响应报告 %s（决策=%s 模式=%s）",
                    report.report_id, decision.value, playbook.mode.value)
        return report

    # ------------------------------------------------------------------
    @staticmethod
    def _summary(playbook: ResponsePlaybook, decision: Decision, reject_reason: str) -> str:
        if decision == Decision.REJECT:
            return (f"主智能体拒绝了预案 `{playbook.playbook_id}` 的处置方案"
                    f"{('，原因：' + reject_reason) if reject_reason else ''}，"
                    f"未执行任何处置动作（{playbook.mode.value} 模式）。")
        if playbook.mode == PlaybookMode.SIMULATION:
            return (f"模拟响应完成：预案 `{playbook.playbook_id}` 已按模拟模式推演 "
                    f"{len(playbook.steps)} 个处置步骤，全程未执行真实主机/网络命令。")
        return (f"处置方案已获主智能体确认（预案 `{playbook.playbook_id}`），"
                f"共 {len(playbook.steps)} 步，交由人工按步骤执行。")

    @staticmethod
    def _findings(playbook: ResponsePlaybook, alert: Optional[ThreatAlert]) -> list[dict]:
        """报告 findings[]（对齐计划书 Finding 证据协议字段语义）。"""
        if alert is None:
            return []
        return [{
            "id": alert.alert_id,
            "target": alert.target,
            "tool": "threat-ir-agent",
            "severity": alert.level.value,
            "remediation": alert.recommended_action,
            "confidence": alert.confidence,
            "mitre": alert.mitre_technique,
            "timestamp": alert.created_at.isoformat(),
        }]

    @staticmethod
    def _step_row(step, decision: Decision) -> dict:
        row = to_jsonable(step)
        if decision == Decision.REJECT:
            row["result"] = "未执行（方案被拒绝）"
            row["status"] = StepStatus.REJECTED.value
        elif step.status == StepStatus.SIMULATED:
            row["result"] = "模拟推演完成（simulated，无真实操作）"
        else:
            row["result"] = "已确认，待人工执行（建议模式）"
            row["status"] = StepStatus.APPROVED.value
        return row

    @staticmethod
    def _appendix(playbook: ResponsePlaybook, alert: Optional[ThreatAlert],
                  decision: Decision, reject_reason: str) -> dict:
        return {
            "decision": decision.value,
            "reject_reason": reject_reason,
            "mode": playbook.mode.value,
            "alert": to_jsonable(alert) if alert else None,
            "simulation_note": "本报告所有处置均为建议/推演结果，未执行真实系统操作",
        }


report_builder = ReportBuilder()
