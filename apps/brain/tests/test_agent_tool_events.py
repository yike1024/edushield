"""工具事件接入 6657 总线 —— 回归测试。

覆盖：_normalize_tool_event 帧归一（reasonix 原生 / adapter 归一 / 非工具事件）、
      /status.tool_events 补齐与 ts 去重。

运行：python -m unittest tests.test_agent_tool_events
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

_APP = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, _APP)

import orchestrator  # noqa: E402


class NormalizeToolEventTest(unittest.TestCase):
    def test_native_dispatch_shape(self):
        ev = {"kind": "tool_dispatch",
              "tool": {"id": "call_00_x", "name": "bash", "args": '{"command": "whoami"}', "readOnly": False},
              "ts": 1789887375.95}
        out = orchestrator._normalize_tool_event(ev)
        self.assertEqual(out["kind"], "tool_dispatch")
        self.assertEqual(out["name"], "bash")
        self.assertIn("whoami", out["args"])
        self.assertFalse(out["readOnly"])
        self.assertEqual(out["ts"], 1789887375.95)

    def test_native_result_shape(self):
        ev = {"kind": "tool_result",
              "tool": {"name": "bash", "resolvedName": "bash", "output": "wangwei\n", "readOnly": True}}
        out = orchestrator._normalize_tool_event(ev)
        self.assertEqual(out["kind"], "tool_result")
        self.assertEqual(out["output"], "wangwei\n")
        self.assertTrue(out["readOnly"])

    def test_adapter_flat_shape(self):
        ev = {"kind": "tool_progress", "name": "", "args": "", "output": "wangwei\n",
              "err": "", "readOnly": False, "ts": 1789887376.03}
        out = orchestrator._normalize_tool_event(ev)
        self.assertEqual(out["kind"], "tool_progress")
        self.assertEqual(out["output"], "wangwei\n")

    def test_non_tool_events_ignored(self):
        for k in ("reasoning", "text", "turn_started", "turn_phase", "message", "usage", None):
            self.assertIsNone(orchestrator._normalize_tool_event({"kind": k}), k)

    def test_tool_call_alias(self):
        out = orchestrator._normalize_tool_event({"kind": "tool_call", "tool": {"name": "curl", "args": "x"}})
        self.assertEqual(out["kind"], "tool_dispatch")
        self.assertEqual(out["name"], "curl")

    def test_truncation_limits(self):
        out = orchestrator._normalize_tool_event(
            {"kind": "tool_result", "tool": {"name": "bash", "args": "a" * 900, "output": "b" * 3000}})
        self.assertEqual(len(out["args"]), 500)
        self.assertEqual(len(out["output"]), 1000)

    def test_ts_defaults_when_missing(self):
        out = orchestrator._normalize_tool_event({"kind": "tool_dispatch", "tool": {"name": "bash"}})
        self.assertIsInstance(out["ts"], float)
        self.assertGreater(out["ts"], 0)


class PublishStatusToolEventsTest(unittest.TestCase):
    def test_backfill_and_dedup(self):
        published = []

        class _SpyHub:
            def publish(self, task_id, domain, event_type, payload=None):
                published.append((task_id, domain, event_type, payload))

        status = {"tool_events": [
            {"kind": "tool_dispatch", "name": "bash", "args": "whoami", "ts": 1.0},
            {"kind": "tool_progress", "name": "", "output": "wangwei", "ts": 2.0},
            {"kind": "tool_result", "name": "bash", "output": "wangwei\n", "ts": 3.0},
        ]}
        with mock.patch.object(orchestrator, "get_hub", return_value=_SpyHub()):
            n = orchestrator._publish_status_tool_events("T1", "pentest", status, sent_ts={2.0})
        self.assertEqual(n, 2)  # ts=2.0 已实时转发，不重复
        self.assertEqual(len(published), 2)
        for _tid, dom, etype, payload in published:
            self.assertEqual((dom, etype), ("pentest", "agent_tool"))
            self.assertEqual(payload["kind"], "agent_tool")
            self.assertIn(payload["tool_event"]["kind"], ("tool_dispatch", "tool_result"))

    def test_empty_and_garbage_safe(self):
        with mock.patch.object(orchestrator, "get_hub", return_value=mock.Mock()):
            self.assertEqual(orchestrator._publish_status_tool_events("T", "pentest", {}, None), 0)
            self.assertEqual(orchestrator._publish_status_tool_events("T", "pentest", {"tool_events": None}, None), 0)
            self.assertEqual(orchestrator._publish_status_tool_events("T", "pentest", {"tool_events": ["x"]}, None), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
