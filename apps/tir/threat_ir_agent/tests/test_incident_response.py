# -*- coding: utf-8 -*-
"""
应急响应模块测试用例
====================
覆盖：按告警等级生成预案 → 建议模式（人工确认）/模拟响应模式（仅推演，
禁止真实命令）→ 接收确认指令 → 输出完整应急响应报告。
使用 mock 推理通道，不依赖网络/密钥。不包含任何其他无关功能测试。

运行：
  python -m pytest tests/test_incident_response.py -v
  或直接：python tests/test_incident_response.py
"""

import os
import sys
import tempfile

_TMP = tempfile.mkdtemp(prefix="tir_test_ir_")
os.environ["TIR_MODEL_GATEWAY"] = "mock"
os.environ["TIR_STORE_DIR"] = _TMP
os.environ["TIR_NOTIFY_URL"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from threat_ir_agent import ThreatIRSubAgent  # noqa: E402
from threat_ir_agent.models import PlaybookMode  # noqa: E402

agent = ThreatIRSubAgent()


def _make_high_alert() -> str:
    r = agent.handle_event({
        "source": "edushield:analyze",
        "event_type": "webshell",
        "target": "http://jwc.xxx.edu.cn",
        "source_ip": "111.1.216.150",
        "severity_hint": "high",
        "description": "检测到 webshell 命令执行",
    })
    return r["alert"]["alert_id"]


def test_playbook_generated_per_level():
    """按告警等级自动生成处置预案（建议模式，步骤含人工确认门控）。"""
    alert_id = _make_high_alert()
    pb = agent.generate_playbook(alert_id, mode=PlaybookMode.SUGGESTION)
    assert pb.playbook_id.startswith("tir_playbook_")
    assert pb.alert_id == alert_id
    assert len(pb.steps) >= 3
    assert all(s.seq > 0 for s in pb.steps)
    # 高危预案：核心动作要求人工确认
    assert any(s.requires_approval for s in pb.steps)


def test_simulation_mode_no_real_execution():
    """模拟响应模式：全部步骤 simulated，无真实系统命令执行。"""
    alert_id = _make_high_alert()
    pb = agent.generate_playbook(alert_id, mode=PlaybookMode.SIMULATION)
    for s in pb.steps:
        assert s.status.value == "simulated"
        assert s.simulated_result and "simulated" in s.simulated_result
        assert s.simulated_result.startswith("[simulated]")


def test_simulator_forbids_exec_primitives():
    """硬性约束：推演器不得引用真实执行原语（subprocess/os.system/os.popen等）。
    通过 AST 检查真实 import 与调用，文档字符串中的禁用词说明不计入。"""
    import ast

    import threat_ir_agent.incident_response.simulator as sim
    src = open(sim.__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    imported: set[str] = set()
    dangerous_calls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr in ("system", "popen", "spawn", "exec", "execve")):
            dangerous_calls.append(node.func.attr)
    assert not (imported & set(sim.FORBIDDEN_EXEC_IMPORTS)), f"发现禁止的真实执行导入: {imported}"
    assert not dangerous_calls, f"发现禁止的真实执行调用: {dangerous_calls}"


def test_confirm_approve_produces_report():
    """主agent下发确认指令(approve) → 输出完整应急响应报告。"""
    alert_id = _make_high_alert()
    pb = agent.generate_playbook(alert_id, mode=PlaybookMode.SUGGESTION)
    r = agent.confirm_decision(pb.playbook_id, decision="approve",
                               operator="edushield-main-agent")
    report = r["report"]
    assert report["report_id"].startswith("tir_report_")
    assert report["decision"] == "approve"
    assert report["playbook_id"] == pb.playbook_id
    assert len(report["steps"]) == len(pb.steps)
    assert "display_md" in r
    # 报告已持久化
    assert agent.get_report(report["report_id"]) is not None


def test_confirm_reject_produces_report():
    """主agent下发确认指令(reject) → 报告记录拒绝，步骤标记 rejected。"""
    alert_id = _make_high_alert()
    pb = agent.generate_playbook(alert_id, mode=PlaybookMode.SIMULATION)
    r = agent.confirm_decision(pb.playbook_id, decision="reject",
                               reject_reason="业务窗口不允许中断")
    report = r["report"]
    assert report["decision"] == "reject"
    assert "拒绝" in report["summary"]
    assert report["steps"][0]["status"] == "rejected"


def test_full_flow_demo():
    """完整闭环：事件→告警→预案(模拟)→确认→报告，全程无真实操作。"""
    result = agent.run_full_flow({
        "event_type": "sql_injection", "severity_hint": "medium",
        "target": "http://jwc.xxx.edu.cn", "source_ip": "9.9.9.9",
        "description": "检测到 SQL 注入探测",
    }, mode=PlaybookMode.SIMULATION)
    assert result["alert"]["alert_id"]
    assert result["playbook"]["playbook_id"]
    assert result["report"]["report_id"]
    assert "应急响应报告" in result["report_md"]


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
