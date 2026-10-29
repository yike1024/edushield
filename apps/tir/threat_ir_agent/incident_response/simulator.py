# -*- coding: utf-8 -*-
"""
模拟响应模式 —— 仅推演处置流程，禁止执行真实系统操作
====================================================
需求：模拟响应模式仅推演处置流程，禁止实际执行主机/网络命令，不做真实系统操作。

硬性安全约束（代码层面强制）：
1. 本模块（及整个子 Agent）不调用 subprocess / os.system / os.popen / socket 等
   任何真实执行原语 —— 处置动作一律以“推演”形式产生模拟结果；
2. 推演结果明确标注 simulated=true，不产生任何真实系统副作用；
3. 参考命令仅以文本形式回显在结果中，绝不执行。

借鉴点（仅设计思想，见 docs/GITHUB_RESEARCH.md）：
- 攻防演练/沙盘推演（tabletop exercise）的“无副作用推演”思想。
本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import logging

from ..models import PlaybookStep, ResponsePlaybook, StepStatus

logger = logging.getLogger(__name__)

# 禁止使用真实执行原语的自我约束声明（供测试断言）
FORBIDDEN_EXEC_IMPORTS = ("subprocess", "os.system", "os.popen", "os.exec", "pty")


class ResponseSimulator:
    """处置流程推演器：逐步骤生成模拟执行结果，全程无真实系统操作。"""

    def simulate(self, playbook: ResponsePlaybook) -> ResponsePlaybook:
        """对预案执行推演：为每一步生成 simulated_result 并标记 SIMULATED。"""
        logger.info("[Simulator] 开始模拟推演 %s（%d 步，无真实系统操作）",
                    playbook.playbook_id, len(playbook.steps))
        for step in playbook.steps:
            step.simulated_result = self._simulate_step(step)
            step.status = StepStatus.SIMULATED
        return playbook

    # ------------------------------------------------------------------
    @staticmethod
    def _simulate_step(step: PlaybookStep) -> str:
        """单步推演：根据动作/风险等级返回模拟结果文本（无副作用）。

        注意：这里只做“如果执行会怎样”的推演，不真正执行。
        """
        risk = step.risk_level
        if step.requires_approval:
            approval_note = "（该步需人工确认，推演中视为已批准）"
        else:
            approval_note = "（低风险步骤，推演中视为自动放行）"
        if risk == "high":
            outcome = "推演：高影响动作已隔离目标并阻断传播，业务影响窗口约X分钟，需人工复核"
        elif risk == "medium":
            outcome = "推演：已加固相关配置并采集证据快照，等待观察期"
        else:
            outcome = "推演：执行观察与记录，无业务影响"
        cmd_note = f"参考命令(未执行): {step.expected_command}" if step.expected_command else "参考命令: 无"
        return f"[simulated] {outcome}。{cmd_note}{approval_note}"


simulator = ResponseSimulator()
