# -*- coding: utf-8 -*-
"""
集成测试用例 —— 如何在 edushield 主对话中触发该子Agent
======================================================
两类测试：
A. 本地集成（必跑）：直接以模块导入方式（ThreatIRSubAgent 门面）模拟
   edushield 主智能体触发子 Agent，验证威胁警报、应急响应全流程生效。
B. 真机联调（可选）：若 edushield 主系统 HTTP 服务已在运行，模拟
   “主对话 → 主系统 → 子Agent HTTP” 链路调用 /api/tir/ingest。

只覆盖威胁警报、应急响应，无任何其他功能测试。

运行：
  python -m pytest tests/test_run.py -v
  或直接：python tests/test_run.py
"""

import os
import sys
import tempfile

_TMP = tempfile.mkdtemp(prefix="tir_test_run_")
os.environ["TIR_MODEL_GATEWAY"] = "mock"
os.environ["TIR_STORE_DIR"] = _TMP
os.environ["TIR_NOTIFY_URL"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from threat_ir_agent import ThreatIRSubAgent  # noqa: E402

agent = ThreatIRSubAgent()

# 模拟 edushield 主对话下发的一条安全检测事件（来自主系统 Analyst/日志审计）
SAMPLE_EVENT = {
    "source": "edushield:analyze",
    "event_type": "data_exfiltration",
    "target": "http://jwc.xxx.edu.cn",
    "source_ip": "111.1.216.150",
    "severity_hint": "high",
    "description": "检测到疑似数据窃取行为(SQLite)",
    "raw": {"log_line": "GET /backup/db.sqlite 200 111.1.216.150"},
    "context": {"task_id": "edushield-run-001", "dialogue": "用户：检查最近有没有被攻击"},
}


def test_local_module_import_integration():
    """方式A：edushield 主智能体以模块导入触发子Agent（插件式挂载）。"""
    result = agent.handle_event(SAMPLE_EVENT, task_id="edushield-run-001")
    alert = result["alert"]
    # 威胁警报生效
    assert alert["level"] == "high"
    assert alert["event_ref"]
    assert result["notification"]["display_md"]
    # 应急响应预案自动附带（建议模式）
    assert result["playbook"]["alert_id"] == alert["alert_id"]
    # 主对话界面展示块
    assert "威胁警报" in result["display_md"]
    # 确认指令 → 应急响应报告
    pb = agent.generate_playbook(alert["alert_id"], mode="simulation")
    rep = agent.confirm_decision(pb.playbook_id, decision="approve")
    assert rep["report"]["report_id"].startswith("tir_report_")
    assert "处置明细" in rep["report_md"]


def test_http_integration_if_main_running():
    """方式B：若子Agent HTTP 服务已启动（python -m threat_ir_agent serve），
    模拟主系统 HTTP 调用 /api/tir/ingest。服务未启动则跳过。"""
    import httpx
    base = os.environ.get("TIR_TEST_API", "http://127.0.0.1:8090")
    try:
        r = httpx.get(f"{base}/api/tir/health", timeout=3)
        r.raise_for_status()
    except Exception:
        print("  [SKIP] 子Agent HTTP 服务未启动，跳过 HTTP 联调（先运行 python -m threat_ir_agent serve）")
        return
    r = httpx.post(f"{base}/api/tir/ingest",
                   json={"event": SAMPLE_EVENT, "task_id": "http-run-001"}, timeout=30)
    r.raise_for_status()
    data = r.json()
    assert data["alert"]["level"] == "high"
    assert data["notification"]["display_md"]
    # 应急响应闭环：预案 → 确认 → 报告
    playbook_resp = httpx.post(
        f"{base}/api/tir/alerts/{data['alert']['alert_id']}/playbook",
        json={"mode": "simulation"}, timeout=30)
    pb = playbook_resp.json()["playbook"]
    dec = httpx.post(f"{base}/api/tir/playbooks/{pb['playbook_id']}/decision",
                     json={"decision": "approve"}, timeout=30)
    assert dec.json()["report"]["report_id"].startswith("tir_report_")


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
