# -*- coding: utf-8 -*-
"""
标准化威胁告警报文生成模块
==========================
需求：生成标准化威胁告警报文，并封装成可推送 edushield 主智能体的通知报文，
供主对话界面展示威胁警报信息。

对齐计划书 3.3 统一协议（Finding/Report 字段语义），与 edushield 主系统
AnalyzedThreat 字段词汇兼容。本文件为【新增文件】。
"""

from __future__ import annotations

from ..models import ThreatAlert


def build_alert_payload(alert: ThreatAlert, task_id: str = "") -> dict:
    """组装标准化威胁告警报文（含任务追溯字段）。"""
    payload = alert.to_notification()
    payload["task_id"] = task_id
    payload["namespace"] = "tir_"
    payload["source_subagent"] = "threat-ir-agent"
    payload["domain"] = "threat-alert"
    # 供 edushield 主系统思维链（LedgerEntry）记录用的摘要块
    payload["ledger_entry"] = {
        "kind": "verdict",
        "agent": "threat-ir-agent",
        "summary": f"[威胁警报] {alert.level.value.upper()} | {alert.title}",
        "detail": {
            "alert_id": alert.alert_id,
            "attack_type": alert.attack_type,
            "confidence": alert.confidence,
        },
    }
    return payload


def alert_acknowledge_payload(alert: ThreatAlert) -> dict:
    """确认回执报文（主智能体确认收到告警后使用）。"""
    return {
        "alert_id": alert.alert_id,
        "status": alert.status.value,
        "acknowledged": True,
        "display_md": f"✅ 威胁警报 `{alert.alert_id}` 已由主智能体确认接收。",
    }
