# -*- coding: utf-8 -*-
"""
威胁警报模块测试用例
====================
覆盖：接收事件 → 威胁分级(高/中/低) → 标准化告警报文 → 本地持久化 → 推送报文。
使用 mock 推理通道（确定性），不依赖网络/密钥。
不包含任何其他无关功能测试。

运行：
  python -m pytest tests/test_threat_alert.py -v
  或直接：python tests/test_threat_alert.py
"""

import os
import sys
import tempfile

# 必须在导入子Agent包之前设置环境：mock 推理通道 + 临时存储目录
_TMP = tempfile.mkdtemp(prefix="tir_test_alert_")
os.environ["TIR_MODEL_GATEWAY"] = "mock"
os.environ["TIR_STORE_DIR"] = _TMP
os.environ["TIR_NOTIFY_URL"] = ""  # 关闭异步推送，避免测试网络请求

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from threat_ir_agent import ThreatIRSubAgent  # noqa: E402
from threat_ir_agent.models import ThreatLevel  # noqa: E402

agent = ThreatIRSubAgent()


def _event(event_type="sql_injection", sev="medium", desc="", source_ip="1.2.3.4"):
    return {
        "source": "edushield:analyze",
        "event_type": event_type,
        "target": "http://jwc.xxx.edu.cn",
        "source_ip": source_ip,
        "severity_hint": sev,
        "description": desc or f"检测到 {event_type} 行为",
        "context": {"task_id": "test-task-1"},
    }


def test_high_risk_classified():
    """高危事件 → level=high，生成标准化告警报文。"""
    r = agent.handle_event(_event("webshell", "high"), task_id="test-task-1")
    assert r["alert"]["level"] == "high"
    assert r["alert"]["title"]
    assert r["alert"]["confidence"] > 0
    assert r["notification"]["display_md"].startswith("---")
    assert r["alert"]["alert_id"].startswith("tir_alert_")


def test_medium_risk_classified():
    """中危事件 → level=medium。"""
    r = agent.handle_event(_event("brute_force", "medium"))
    assert r["alert"]["level"] == "medium"


def test_campus_false_positive_rule():
    """校园误报抑制：爬虫密集访问 ≠ 攻击 → level=low / false_positive。"""
    r = agent.handle_event(_event("directory_scan", "high", desc="搜索引擎爬虫密集访问页面"))
    assert r["alert"]["level"] == "low"
    assert r["alert"]["verdict"] == "false_positive"


def test_alert_persisted_locally():
    """告警本地持久化：可查询到刚生成的告警。"""
    r = agent.handle_event(_event("sql_injection", "high"))
    alert_id = r["alert"]["alert_id"]
    got = agent.get_alert(alert_id)
    assert got is not None
    assert got.alert_id == alert_id
    assert got.level == ThreatLevel.HIGH


def test_alert_push_payload_for_chat():
    """推送报文可供主对话界面展示（含 display_md 与 ledger_entry）。"""
    r = agent.handle_event(_event("ddos", "medium"))
    n = r["notification"]
    assert "display_md" in n
    assert n["ledger_entry"]["agent"] == "threat-ir-agent"
    assert n["ledger_entry"]["kind"] == "verdict"


def test_low_risk_info_event():
    """低危/信息性事件 → level=low。"""
    r = agent.handle_event(_event("port_scan", "info", desc="正常运维探测"))
    assert r["alert"]["level"] == "low"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
