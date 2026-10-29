# -*- coding: utf-8 -*-
"""
应急处置预案生成模块
====================
需求：根据威胁告警等级，自动生成对应可执行应急处置预案、修复建议步骤。
支持两种模式：
- 建议模式（SUGGESTION）   ：输出处置方案交由人工确认（不自动执行）
- 模拟响应模式（SIMULATION）：仅推演处置流程，禁止执行真实主机/网络命令

实现（AI 只在“生成”处，流程/状态为确定性纯业务）：
1. 等级模板骨架：按 高/中/低 三档预置 遏制→根除→恢复→复盘 阶段骨架
   （借鉴主流 IR 方法论 NIST 800-61 / SANS PICERL 的分阶段思想，自主编写）。
2. 模型充实：调用 DeepSeek-Reasonix-Security 推理大脑，结合告警的攻击类型、
   目标、证据，为每个阶段生成具体处置动作与修复建议步骤。
3. 所有动作均为**描述性文本**，仅附“参考命令（文本示例）”，
   本子 Agent 任何路径都不会执行这些命令（见 simulator.py 的硬性约束）。

借鉴点（仅设计思想，见 docs/GITHUB_RESEARCH.md）：
- TheHive / dfir-iris 的 Playbook 结构化步骤与阶段思想；
- 计划书 3.3 报告协议 Report 字段语义（summary/findings/verdict/confidence/mitre）。
本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import logging
from typing import Optional

from ..model_gateway import gateway
from ..models import (
    IncidentStatus,
    PlaybookMode,
    PlaybookStep,
    ResponsePlaybook,
    StepStatus,
    ThreatAlert,
    ThreatLevel,
    to_jsonable,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 等级模板骨架（确定性纯业务；阶段划分借鉴 NIST SP 800-61 IR 流程思想）
# ---------------------------------------------------------------------------
_PHASE_TEMPLATES: dict[str, list[str]] = {
    "high": ["遏制(Containment)", "根除(Eradication)", "恢复(Recovery)", "复盘(Lessons)"],
    "medium": ["遏制(Containment)", "调查(Investigation)", "加固(Hardening)", "复盘(Lessons)"],
    "low": ["观察(Monitor)", "加固建议(Hardening)", "复盘(Lessons)"],
}

_PLAYBOOK_SYSTEM_PROMPT = """你是校园网络安全应急响应专家（应急响应子Agent的预案生成大脑）。
根据威胁告警报文生成可执行的应急处置预案，输出 JSON（不要输出其他内容）。

安全约束（硬性）：
- 只输出处置方案文本，不执行任何真实系统命令；
- 涉及封禁/下线/重启等高危动作必须标注 requires_approval=true，交由人工确认；
- 参考命令仅作为文本示例给出（expected_command 字段），绝不实际执行。

输出 JSON 结构：
{
  "objective": "处置目标(中文)",
  "summary": "预案摘要(中文)",
  "steps": [
    {
      "phase": "阶段名",
      "action": "处置动作描述(中文，可执行)",
      "expected_command": "参考命令文本示例(仅展示，不执行)或空串",
      "risk_level": "low|medium|high",
      "requires_approval": true或false,
      "rationale": "为什么这样做(中文)"
    }
  ]
}"""

# 每个阶段模型至少要补充的步骤数
_STEPS_PER_PHASE_MIN = 1
_STEPS_PER_PHASE_MAX = 2


class PlaybookGenerator:
    """预案生成器。"""

    def generate(self, alert: ThreatAlert, mode: PlaybookMode,
                 operator_context: Optional[dict] = None) -> ResponsePlaybook:
        """按告警等级与模式生成预案。

        建议模式：所有高危动作 requires_approval=True，等待主智能体/人工确认。
        模拟模式：生成的预案将交给 simulator 推演（本方法只生成预案本体）。
        """
        phases = _PHASE_TEMPLATES[alert.level.value]
        steps = self._model_steps(alert, phases)
        steps = self._normalize_steps(steps, phases)

        playbook = ResponsePlaybook(
            alert_id=alert.alert_id,
            level=alert.level,
            mode=mode,
            objective=f"对 {alert.level.value.upper()} 级威胁「{alert.title}」执行应急处置",
            steps=steps,
            summary=f"已按 {alert.level.value} 级威胁自动生成 {len(steps)} 步处置预案"
                    f"（{mode.value} 模式）",
            confidence=alert.confidence,
            mitre=[alert.mitre_technique] if alert.mitre_technique else [],
        )
        logger.info("[Playbook] 生成预案 %s 模式=%s 步骤=%d",
                    playbook.playbook_id, mode.value, len(steps))
        return playbook

    # ------------------------------------------------------------------
    def _model_steps(self, alert: ThreatAlert, phases: list[str]) -> list[dict]:
        """调用推理大脑生成具体处置步骤。"""
        user_prompt = (
            "## 威胁告警报文\n"
            f"{to_jsonable(alert)}\n\n"
            f"## 预案阶段骨架（请按此阶段组织步骤）\n{phases}\n\n"
            "请为每个阶段生成具体处置动作与修复建议步骤，只输出 JSON。"
        )
        result = gateway.complete(_PLAYBOOK_SYSTEM_PROMPT, user_prompt)
        steps = result.get("steps") if isinstance(result, dict) else None
        if not isinstance(steps, list):
            logger.warning("[Playbook] 模型未返回步骤，回退阶段骨架占位")
            steps = [{"phase": p, "action": f"按 {p} 阶段执行人工确认后的处置", 
                      "expected_command": "", "risk_level": "medium",
                      "requires_approval": True, "rationale": "模型未给出，回退占位"} 
                     for p in phases]
        return steps

    @staticmethod
    def _normalize_steps(steps: list[dict], phases: list[str]) -> list[PlaybookStep]:
        """清洗/归一化模型步骤：字段兜底、顺序重排、审批门控。"""
        # 按阶段顺序重排：模型可能乱序返回
        phase_order = {p: i for i, p in enumerate(phases)}
        ordered = sorted(
            steps,
            key=lambda s: phase_order.get(str(s.get("phase", "")).split("(")[0], 999),
        )
        normalized: list[PlaybookStep] = []
        seq = 0
        for s in ordered[: len(phases) * _STEPS_PER_PHASE_MAX]:
            phase = str(s.get("phase", "复盘(Lessons)"))
            action = str(s.get("action", "")).strip() or f"执行 {phase} 阶段处置"
            risk = str(s.get("risk_level", "medium")).lower()
            if risk not in ("low", "medium", "high"):
                risk = "medium"
            # 高危动作默认需人工确认（建议模式门控）
            needs_approval = bool(s.get("requires_approval", risk in ("high", "medium")))
            seq += 1
            normalized.append(PlaybookStep(
                seq=seq,
                phase=phase,
                action=action,
                expected_command=str(s.get("expected_command", ""))[:200],
                risk_level=risk,
                requires_approval=needs_approval,
                rationale=str(s.get("rationale", "")),
            ))
        # 阶段去重兜底：若模型漏掉某阶段，补齐占位步骤
        covered = {st.phase.split("(")[0] for st in normalized}
        for p in phases:
            if p.split("(")[0] not in covered:
                seq += 1
                normalized.append(PlaybookStep(
                    seq=seq, phase=p,
                    action=f"按 {p} 阶段完成人工确认后的处置",
                    requires_approval=True,
                    rationale="阶段骨架兜底步骤",
                ))
        return normalized


playbook_generator = PlaybookGenerator()
