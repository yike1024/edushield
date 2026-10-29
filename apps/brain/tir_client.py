"""应急响应（TIR）子 Agent 客户端 —— 威胁警报 + 应急响应（8090）。

计划书身体部件 D：处置剧本/工单。8090 是 FastAPI REST 服务，
协议与 reasonix 部件不同，所以单独写一个薄客户端。

流程（大脑侧）：
    verdict=real_threat 的 Finding → POST /api/tir/ingest
    → 得到 alert_id → POST /api/tir/alerts/{id}/playbook
    → 得到 playbook_id（预案）→ 写进报告/审计
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from config.settings import settings

logger = logging.getLogger(__name__)


class TirClient:
    def __init__(self, base_url: str = "", timeout: float = 90):
        self.base_url = (base_url or settings.TIR_BASE_URL).rstrip("/")
        # 威胁分级走规则+LLM，推理可能 30~60s，超时需放宽（8090 协议文档 §8/§9）
        self.timeout = timeout

    def _get(self, path: str) -> Optional[dict]:
        try:
            r = httpx.get(f"{self.base_url}{path}", timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.warning(f"[tir] GET {path} 失败: {e}")
            return None

    def _post(self, path: str, body: Optional[dict] = None) -> Optional[dict]:
        try:
            r = httpx.post(f"{self.base_url}{path}", json=body or {}, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.warning(f"[tir] POST {path} 失败: {e}")
            return None

    def health(self) -> Optional[dict]:
        return self._get("/api/tir/health")

    def ingest(self, task_id: str, event: dict) -> Optional[dict]:
        """推送安全检测事件 → 威胁分级告警。"""
        return self._post("/api/tir/ingest", {"task_id": task_id, "event": event})

    def list_alerts(self) -> Optional[dict]:
        return self._get("/api/tir/alerts")

    def get_alert(self, alert_id: str) -> Optional[dict]:
        return self._get(f"/api/tir/alerts/{alert_id}")

    def create_playbook(self, alert_id: str, mode: str = "suggestion") -> Optional[dict]:
        """为告警生成应急预案（suggestion=建议 / simulation=模拟）。"""
        return self._post(f"/api/tir/alerts/{alert_id}/playbook", {"mode": mode})

    def decision(self, playbook_id: str, decision: str = "approve",
                 operator: str = "aisoc-brain", reject_reason: str = "") -> Optional[dict]:
        """预案决策：approve / reject。产出应急响应报告 {report, report_md, display_md}。"""
        return self._post(f"/api/tir/playbooks/{playbook_id}/decision", {
            "decision": decision, "operator": operator, "reject_reason": reject_reason,
        })

    def ack(self, alert_id: str) -> Optional[dict]:
        """确认告警：状态机 notified → acknowledged（8090 协议文档 §3.5，无请求体）。"""
        return self._post(f"/api/tir/alerts/{alert_id}/ack")

    def get_playbook(self, playbook_id: str) -> Optional[dict]:
        """单条预案（§3.8 之外的按 id 查询）。"""
        return self._get(f"/api/tir/playbooks/{playbook_id}")

    def get_report(self, report_id: str) -> Optional[dict]:
        """单条应急响应报告（§3.10）。"""
        return self._get(f"/api/tir/reports/{report_id}")

    def list_playbooks(self) -> Optional[dict]:
        return self._get("/api/tir/playbooks")

    def list_reports(self) -> Optional[dict]:
        return self._get("/api/tir/reports")


def get_tir_client() -> TirClient:
    return TirClient()
