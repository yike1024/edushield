"""TIR（8090）适配链路测试 —— 协议文档 §4/§5 闭环。

覆盖：
  - _push_to_tir：ingest → ack → alert/playbook 落库 → ledger_entry 入账本 → display_md 透传
  - 事件结构为 §4.1 DetectionEvent（severity_hint / source_ip / event_type / context）
  - ingest 未附预案时回退单独生成（§3.6）
  - TIR_ENABLED=false 时短路
  - /api/approve → decision → 应急响应报告落库（§5 步骤⑤⑥）
全程 mock 8090，不走真实网络/LLM。
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import orchestrator  # noqa: E402
import tir_client  # noqa: E402
from session import SessionStore  # noqa: E402


class FakeTir:
    """模拟 8090：记录调用，返回协议文档 §3.2 形状的响应。"""

    def __init__(self, *args, **kwargs):
        self.calls: list[tuple] = []

    def ingest(self, task_id: str, event: dict) -> dict:
        self.calls.append(("ingest", task_id, event))
        return {
            "alert": {"alert_id": "tir_alert_test1", "level": "high",
                      "status": "notified", "task_id": task_id},
            "notification": {"ledger_entry": {
                "kind": "verdict", "agent": "threat-ir-agent",
                "summary": "[威胁警报] HIGH | 检测到高危威胁",
                "detail": {"alert_id": "tir_alert_test1"},
            }},
            "playbook": {"playbook_id": "tir_playbook_test1",
                         "alert_id": "tir_alert_test1", "mode": "suggestion"},
            "display_md": "### ⚠️ 威胁警报",
        }

    def ack(self, alert_id: str) -> dict:
        self.calls.append(("ack", alert_id))
        return {"alert_id": alert_id, "status": "acknowledged"}

    def create_playbook(self, alert_id: str, mode: str = "suggestion") -> dict:
        self.calls.append(("playbook", alert_id, mode))
        return {"playbook": {"playbook_id": "tir_playbook_fallback", "alert_id": alert_id}}

    def decision(self, playbook_id: str, decision: str = "approve",
                 operator: str = "", reject_reason: str = "") -> dict:
        self.calls.append(("decision", playbook_id, decision, operator))
        return {
            "report": {"report_id": "tir_report_test1", "playbook_id": playbook_id,
                       "alert_id": "tir_alert_test1", "decision": decision},
            "report_md": "# 应急响应报告",
        }


class TirFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = SessionStore(os.path.join(self.tmp, "t.sqlite3"))
        self.store.create_task("T1", "logaudit", "demo-campus.edu.cn")
        self.fake = FakeTir()
        self._tir_enabled = orchestrator.settings.TIR_ENABLED
        orchestrator.settings.TIR_ENABLED = True
        self._patch = mock.patch.object(tir_client, "TirClient", lambda *a, **k: self.fake)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        orchestrator.settings.TIR_ENABLED = self._tir_enabled

    @staticmethod
    def _assessment() -> dict:
        return {
            "verdict": "real_threat", "confidence": 0.9, "reason": "测试判定",
            "threats": [{
                "id": "F-T1-1", "task_id": "T1", "tool": "log_ingest", "severity": "high",
                "confidence": 0.9, "title": "Webshell 上传",
                "description": "POST /uploads/shell.php?cmd=whoami 返回 200",
                "evidence": "111.1.216.150 POST /uploads/shell.php 200",
                "mitre": ["T1505"], "remediation": "隔离主机并清除后门",
            }],
        }

    def test_push_to_tir_full_flow(self):
        result = orchestrator._push_to_tir("T1", self._assessment(), self.store)

        self.assertEqual(result["alerts"], ["tir_alert_test1"])
        self.assertEqual(result["playbooks"], ["tir_playbook_test1"])
        self.assertEqual(result["display_md"], ["### ⚠️ 威胁警报"])
        self.assertEqual(self.fake.calls[0][0], "ingest")
        self.assertIn(("ack", "tir_alert_test1"), self.fake.calls)

        event = self.fake.calls[0][2]
        self.assertEqual(event["severity_hint"], "high")          # §4.1
        self.assertEqual(event["event_type"], "log_ingest")
        self.assertEqual(event["source_ip"], "111.1.216.150")
        self.assertEqual(event["confidence_hint"], 0.9)
        self.assertIn("context", event)

        alerts = self.store.list_tir_alerts("T1")
        self.assertEqual([a["alert_id"] for a in alerts], ["tir_alert_test1"])
        self.assertEqual(alerts[0]["display_md"], "### ⚠️ 威胁警报")
        pbs = self.store.list_tir_playbooks("T1")
        self.assertEqual([p["playbook_id"] for p in pbs], ["tir_playbook_test1"])

        actions = [x["action"] for x in self.store.list_ledger("T1")]
        self.assertIn("verdict", actions)          # notification.ledger_entry.kind（§4.3）
        self.assertIn("alerts_created", actions)

    def test_ingest_without_playbook_falls_back(self):
        self.fake.ingest = lambda task_id, event: {
            "alert": {"alert_id": "tir_alert_x"}, "notification": {}, "display_md": ""}
        result = orchestrator._push_to_tir("T1", self._assessment(), self.store)
        self.assertEqual(result["playbooks"], ["tir_playbook_fallback"])

    def test_disabled_returns_empty(self):
        orchestrator.settings.TIR_ENABLED = False
        self.assertEqual(orchestrator._push_to_tir("T1", self._assessment(), self.store), {})

    def test_approve_triggers_decision_and_saves_report(self):
        """/api/approve → decision → 报告落库（§5 步骤⑤⑥）。"""
        import api
        self.store.save_tir_playbook(
            {"playbook_id": "tir_playbook_test1", "alert_id": "tir_alert_test1"}, "T1")

        with mock.patch.object(api, "get_store", lambda: self.store):
            req = api.ApproveRequest(task_id="T1", action="", decision="approved")
            out = asyncio.new_event_loop().run_until_complete(api.approve(req, {"id": "u1"}))

        self.assertEqual(out["status"], "responded")
        self.assertEqual(out["report_id"], "tir_report_test1")
        self.assertIn(("decision", "tir_playbook_test1", "approve", "u1"), self.fake.calls)
        reports = self.store.list_tir_reports("T1")
        self.assertEqual(reports[0]["report_md"], "# 应急响应报告")
        self.assertEqual(reports[0]["decision"], "approve")


if __name__ == "__main__":
    unittest.main()
