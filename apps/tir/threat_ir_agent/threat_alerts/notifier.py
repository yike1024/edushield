# -*- coding: utf-8 -*-
"""
告警推送模块 —— 向 edushield 主智能体推送告警通知
==================================================
需求：向 edushield 主智能体推送告警通知，可供主对话界面展示威胁警报信息。

实现两条通道（均不修改主系统代码）：
1. 同步返回通道（默认、必做）：调用方（edushield 主智能体）总是从子 Agent
   返回值中获得告警报文（含 display_md 展示块），直接注入主对话界面展示。
2. 异步推送通道（可选）：配置 TIR_NOTIFY_URL 后，子 Agent 以 HTTP POST
   推送告警到该地址（由 edushield 部署方提供桥接端点接收并展示）。

本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from ..config import config
from ..models import AlertStatus, ThreatAlert

logger = logging.getLogger(__name__)


class AlertNotifier:
    """告警通知器。"""

    def push(self, alert: ThreatAlert, payload: Optional[dict] = None) -> dict:
        """推送告警：
        - 始终返回同步报文（调用方拿它展示）；
        - 若配置了 TIR_NOTIFY_URL 则同时异步 POST 推送（失败不阻塞）。
        """
        notif = payload or alert.to_notification()
        if config.NOTIFY_URL:
            self._async_push(config.NOTIFY_URL, notif)
        alert.status = AlertStatus.NOTIFIED
        alert.notified_at = datetime.now(timezone.utc)
        return notif

    @staticmethod
    def _async_push(url: str, payload: dict) -> None:
        try:
            resp = httpx.post(url, json=payload, timeout=config.NOTIFY_TIMEOUT_SECONDS)
            logger.info("[Notifier] 异步推送告警到 %s → HTTP %s", url, resp.status_code)
        except Exception as e:  # noqa: BLE001 - 推送失败不影响主流程
            logger.warning("[Notifier] 异步推送失败（不阻塞）: %s", e)


notifier = AlertNotifier()
