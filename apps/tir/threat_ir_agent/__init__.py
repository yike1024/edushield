# -*- coding: utf-8 -*-
"""
威胁警报-应急响应 子Agent（threat-ir-agent）
============================================
edushield 校园智盾平台的插件式子 Agent，仅实现两大功能（严格按
《安全智能体平台-项目计划书》威胁警报、应急响应章节，不做其他功能）：
1. 威胁警报  ：接收主平台安全检测事件 → 威胁分级(高/中/低) → 标准化告警报文
               → 本地持久化 → 向主智能体推送告警（供主对话界面展示）
2. 应急响应  ：按告警等级自动生成处置预案/修复建议；建议模式（人工确认）/
               模拟响应模式（仅推演，禁止真实命令）；接收主 agent 确认指令，
               输出完整应急响应报告

接入方式（全部为插件式，不修改 edushield 任何代码）：
- 模块导入：`from threat_ir_agent import ThreatIRSubAgent`（推荐，见下）
- HTTP 服务：`python -m threat_ir_agent serve`（FastAPI，edushield 可 REST 调用）
- CLI 入口：`python -m threat_ir_agent ingest ...`

推理大脑：复用 DeepSeek-Reasonix-Security 模型对外暴露的调用入口
（reasonix CLI / OpenAI 兼容 API），仅调用、不修改模型任何文件。

本包全部文件均为【新增文件】，未修改 edushield、DeepSeek-Reasonix-Security
任何存量文件。
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Optional

# Windows 控制台默认 GBK 编码无法输出部分展示字符（如 ⚠️），
# 统一将标准输出/错误重配置为 UTF-8，保证 CLI 展示与日志正常。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001 - 非 TTY 环境可忽略
        pass

from .config import config
from .incident_response.playbook_generator import playbook_generator
from .incident_response.report_builder import report_builder
from .incident_response.simulator import simulator
from .models import (
    AlertStatus,
    Decision,
    DetectionEvent,
    IncidentReport,
    PlaybookMode,
    ResponsePlaybook,
    StepStatus,
    ThreatAlert,
    to_jsonable,
)
from .storage.alert_store import store
from .threat_alerts.alert_builder import build_alert_payload
from .threat_alerts.classifier import classifier
from .threat_alerts.notifier import notifier

__version__ = "1.0.0"
__all__ = ["ThreatIRSubAgent", "classifier", "playbook_generator", "store"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


class ThreatIRSubAgent:
    """子 Agent 门面（模块导入式挂载入口）。

    edushield 主智能体可 `from threat_ir_agent import ThreatIRSubAgent` 后直接调用，
    复用主系统现有对话上下文（event.context 透传），返回结果可注入主对话界面展示、
    可写入主系统思维链账本 —— 全程不修改主系统内部代码。
    """

    # ------------------------------------------------------------------
    # 威胁警报
    # ------------------------------------------------------------------
    def ingest_event(self, event: dict | DetectionEvent, task_id: str = "",
                     min_alert_level: Optional[str] = None) -> dict:
        """接收主平台安全检测事件 → 分级 → 告警 → 持久化 → 推送。

        参数：
          min_alert_level  输出最低告警级别（critical/high/medium/low/info）。
                           最终研判级别低于该值时，不产生告警（不持久化、不推送、
                           不生成预案），返回 skipped_by_level=True 标记；
                           parse_error 事件不受此门槛影响，始终处理（降级链路保留）。
        返回：{alert, notification, playbook, display_md}，其中 notification
        可直接供主对话界面展示。
        """
        evt = event if isinstance(event, DetectionEvent) else DetectionEvent.from_dict(event)
        # 1) 威胁分级判定 + 标准化告警报文
        alert = classifier.classify(evt)
        alert.task_id = task_id or evt.context.get("task_id", "")
        # 1.5) 输出最低告警级别门槛：最终研判低于门槛 → 不产生告警
        if min_alert_level and not evt.raw.get("parse_error") \
                and _below_alert_level(alert.level, min_alert_level):
            return {
                "alert": to_jsonable(alert),
                "notification": None,
                "playbook": None,
                "display_md": "",
                "skipped_by_level": True,
                "reason": (f"最终研判级别 {alert.level.value} 低于输出门槛 "
                           f"{min_alert_level}，不产生告警"),
            }
        # 2) 本地持久化（子 Agent 专属存储）
        store.save_alert(alert.alert_id, to_jsonable(alert))
        # 3) 推送告警给主智能体（同步返回 + 可选异步 webhook）
        payload = build_alert_payload(alert, alert.task_id)
        notifier.push(alert, payload)
        store.save_alert(alert.alert_id, to_jsonable(alert))
        # 4) 默认附带一版建议模式预案（需求：根据告警等级自动生成处置预案）
        playbook = self.generate_playbook(alert.alert_id, mode=PlaybookMode.SUGGESTION)
        return {
            "alert": to_jsonable(alert),
            "notification": payload,
            "playbook": to_jsonable(playbook),
            "display_md": alert.to_markdown() + "\n" + playbook.to_markdown(),
        }

    def acknowledge_alert(self, alert_id: str) -> dict:
        """主智能体确认收到告警。"""
        alert = self.get_alert(alert_id)
        if alert is None:
            return {"error": f"告警不存在: {alert_id}"}
        alert.status = AlertStatus.ACKNOWLEDGED
        store.save_alert(alert.alert_id, to_jsonable(alert))
        return {"alert_id": alert_id, "status": alert.status.value,
                "display_md": f"✅ 威胁警报 `{alert_id}` 已确认。"}

    def get_alert(self, alert_id: str) -> Optional[ThreatAlert]:
        data = store.get_alert(alert_id)
        return ThreatAlert(**data) if data else None

    def list_alerts(self) -> list[dict]:
        return store.list_alerts()

    # ------------------------------------------------------------------
    # 应急响应
    # ------------------------------------------------------------------
    def generate_playbook(self, alert_id: str,
                          mode: PlaybookMode | str = PlaybookMode.SUGGESTION) -> ResponsePlaybook:
        """根据告警等级自动生成应急处置预案。

        - SUGGESTION：输出处置方案，交由人工确认（默认）
        - SIMULATION：仅推演处置流程（simulator 负责推演，无真实命令）
        """
        if isinstance(mode, str):
            mode = PlaybookMode(mode)  # 兼容字符串入参（如 "simulation"）
        alert = self.get_alert(alert_id)
        if alert is None:
            raise ValueError(f"告警不存在: {alert_id}")
        playbook = playbook_generator.generate(alert, mode)
        playbook.task_id = alert.task_id
        if mode == PlaybookMode.SIMULATION:
            playbook = simulator.simulate(playbook)  # 仅推演，无真实操作
        store.save_playbook(playbook.playbook_id, to_jsonable(playbook))
        return playbook

    def get_playbook(self, playbook_id: str) -> Optional[ResponsePlaybook]:
        data = store.get_playbook(playbook_id)
        return ResponsePlaybook(**data) if data else None

    def list_playbooks(self) -> list[dict]:
        return store.list_playbooks()

    def confirm_decision(self, playbook_id: str, decision: str = "approve",
                         operator: str = "edushield-main-agent",
                         reject_reason: str = "") -> dict:
        """接收主 agent 下发的确认指令，输出完整应急响应报告。

        decision ∈ {approve, reject}
        """
        playbook = self.get_playbook(playbook_id)
        if playbook is None:
            return {"error": f"预案不存在: {playbook_id}"}
        dec = Decision(decision.lower())
        alert = self.get_alert(playbook.alert_id)
        report = report_builder.build(playbook, dec, alert=alert,
                                      operator=operator, reject_reason=reject_reason)
        report.task_id = playbook.task_id
        store.save_report(report.report_id, to_jsonable(report))
        # 更新告警状态 → responded / closed
        if alert is not None:
            alert.status = AlertStatus.RESPONDED
            store.save_alert(alert.alert_id, to_jsonable(alert))
        return {
            "report": to_jsonable(report),
            "report_md": report.to_markdown(),
            "display_md": report.to_markdown(),
        }

    def get_report(self, report_id: str) -> Optional[IncidentReport]:
        data = store.get_report(report_id)
        return IncidentReport(**data) if data else None

    def list_reports(self) -> list[dict]:
        return store.list_reports()

    # ------------------------------------------------------------------
    # 便捷入口
    # ------------------------------------------------------------------
    def handle_event(self, event: dict | DetectionEvent, task_id: str = "",
                     min_alert_level: Optional[str] = None) -> dict:
        """一站式入口：事件 → 告警 + 预案（供主智能体一键接入）。

        min_alert_level：输出最低告警级别门槛（见 ingest_event）。
        """
        return self.ingest_event(event, task_id=task_id,
                                 min_alert_level=min_alert_level)

    def run_full_flow(self, event: dict | DetectionEvent,
                      mode: PlaybookMode = PlaybookMode.SIMULATION,
                      decision: str = "approve",
                      task_id: str = "") -> dict:
        """完整闭环演示：事件 → 告警 → 预案(指定模式) → 确认 → 应急响应报告。

        仅用于测试/演示；模拟模式全程无真实系统操作。
        """
        result = self.ingest_event(event, task_id=task_id)
        alert_id = result["alert"]["alert_id"]
        playbook = self.generate_playbook(alert_id, mode=mode)
        report = self.confirm_decision(playbook.playbook_id, decision=decision)
        return {
            "alert": result["alert"],
            "notification": result["notification"],
            "playbook": to_jsonable(playbook),
            "report": report["report"],
            "report_md": report["report_md"],
        }


# ===========================================================================
# 严重度门槛工具（3 档告警域：high/medium/low，与 ThreatLevel 对齐）
# ===========================================================================

_THREE_TIER_RANK = {"high": 1, "medium": 2, "low": 3}
# 门槛归一：critical 视为 high（3 档域没有 critical 档）
_MIN_RANK_MAP = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 3}


def _below_alert_level(level, min_alert_level: str) -> bool:
    """最终告警级别是否低于输出门槛（返回 True = 应被门槛拦截）。"""
    lvl = getattr(level, "value", str(level)).lower()
    min_rank = _MIN_RANK_MAP.get(str(min_alert_level).strip().lower(), 3)
    return _THREE_TIER_RANK.get(lvl, 3) > min_rank
