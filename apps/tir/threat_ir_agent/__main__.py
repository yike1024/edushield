# -*- coding: utf-8 -*-
"""
威胁警报-应急响应 子Agent 最小可运行入口（CLI）
===============================================
用法：
  python -m threat_ir_agent serve                         # 启动子Agent HTTP 服务
  python -m threat_ir_agent ingest --event '<json>'       # 接收事件→告警→预案
  python -m threat_ir_agent ingest --event-file evt.json  # 从文件读事件
  python -m threat_ir_agent playbook <alert_id> [--mode simulation]
  python -m threat_ir_agent confirm <playbook_id> [--decision approve|reject]
  python -m threat_ir_agent list [alerts|playbooks|reports]
  python -m threat_ir_agent demo                          # 内置示例事件完整演示
  python -m threat_ir_agent doctor                        # 接入自检

本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import argparse
import json
import sys

from .models import PlaybookMode, to_jsonable


def _print(obj, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    else:
        print(obj)


def main(argv: list[str] | None = None) -> int:
    from . import ThreatIRSubAgent
    from .config import config

    agent = ThreatIRSubAgent()
    parser = argparse.ArgumentParser(prog="threat_ir_agent", description="威胁警报-应急响应 子Agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # serve
    p_serve = sub.add_parser("serve", help="启动子Agent HTTP 服务")
    p_serve.add_argument("--host", default=config.API_HOST)
    p_serve.add_argument("--port", type=int, default=config.API_PORT)

    # ingest
    p_in = sub.add_parser("ingest", help="接收主平台安全检测事件，生成告警与预案")
    p_in.add_argument("--event", default="", help="JSON 字符串形式的事件")
    p_in.add_argument("--event-file", default="", help="JSON 文件形式的事件")
    p_in.add_argument("--task-id", default="", help="主系统任务ID（可选）")

    # ingest-file：数据文件 → 自动识别格式 → 解析 → DetectionEvent → 分析
    p_if = sub.add_parser(
        "ingest-file",
        help="摄入安全数据文件（pcap/syslog/csv/cef/misp/stix...），自动识别格式并转换",
    )
    p_if.add_argument("path", nargs="?", help="数据文件路径（--list-formats 时可不填）")
    p_if.add_argument("--run", action="store_true", help="转换后直接送入威胁报警+应急响应")
    p_if.add_argument("--max-events", type=int, default=None, help="最多生成事件数")
    p_if.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"],
                      default=None,
                      help="只处理严重度≥该级别的事件（parse_error 事件不受影响，始终保留）")
    p_if.add_argument("--out", default="", help="事件 JSON 输出路径（默认不落盘）")
    p_if.add_argument("--list-formats", action="store_true", help="列出所有已注册解析器")

    # playbook
    p_pb = sub.add_parser("playbook", help="按告警等级生成处置预案")
    p_pb.add_argument("alert_id")
    p_pb.add_argument("--mode", choices=["suggestion", "simulation"], default="suggestion")

    # confirm
    p_cf = sub.add_parser("confirm", help="接收主agent确认指令，输出应急响应报告")
    p_cf.add_argument("playbook_id")
    p_cf.add_argument("--decision", choices=["approve", "reject"], default="approve")
    p_cf.add_argument("--operator", default="edushield-main-agent")
    p_cf.add_argument("--reject-reason", default="")

    # list
    p_ls = sub.add_parser("list", help="列出本地告警/预案/报告")
    p_ls.add_argument("kind", choices=["alerts", "playbooks", "reports"])

    # demo
    sub.add_parser("demo", help="内置示例事件完整闭环演示（默认模拟模式）")

    # doctor
    sub.add_parser("doctor", help="子Agent 接入自检")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        from .server import create_app
        import uvicorn
        uvicorn.run(create_app(), host=args.host, port=args.port)
        return 0

    if args.cmd == "ingest":
        if args.event_file:
            loaded = json.loads(open(args.event_file, encoding="utf-8").read())
        elif args.event:
            loaded = json.loads(args.event)
        else:
            print("错误：请提供 --event 或 --event-file")
            return 2
        # 支持单事件 dict 或批量事件数组（如 pcap_to_events.py 的输出）
        events = loaded if isinstance(loaded, list) else [loaded]
        for i, evt in enumerate(events, 1):
            if len(events) > 1:
                print(f"\n===== 事件 {i}/{len(events)} =====")
            result = agent.handle_event(evt, task_id=args.task_id or f"batch-{i}")
            _print(result["display_md"])
            _print(result["notification"], as_json=True)
        return 0

    if args.cmd == "ingest-file":
        from .ingest import IngestPipeline
        from .ingest.registry import all_parsers

        if args.list_formats:
            print("已注册解析器（插件化，可扩展）：")
            for p in all_parsers():
                print(f"  - {p.name:18s} {p.display_name} [{p.category}]")
            return 0
        if not args.path:
            print("错误：请提供数据文件路径")
            return 2
        result = IngestPipeline(agent=agent).ingest_file(
            args.path, feed=args.run, max_events=args.max_events,
            min_severity=args.min_severity)
        print(f"[ingest-file] {result['detect_note']}")
        print(f"[ingest-file] 记录数={result['records']} 事件数={len(result['events'])} "
              f"parse_error={result['parse_error']}")
        if result.get("events_filtered_out"):
            print(f"[ingest-file] 已按 min_severity 过滤 {result['events_filtered_out']} 条"
                  f"（生成 {result['events_total']} 条，保留 {len(result['events'])} 条）")
        if result.get("alerts_filtered_by_verdict"):
            print(f"[ingest-file] 另有 {result['alerts_filtered_by_verdict']} 条因最终研判级别"
                  f"低于 {args.min_severity} 未产生告警（skipped_by_level）")
        if args.out:
            import pathlib
            pathlib.Path(args.out).write_text(
                json.dumps(result["events"], ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"[ingest-file] 事件已保存: {args.out}")
        for evt in result["events"]:
            print(f"  - [{evt['severity_hint']:8s}] {evt['event_type']:22s} "
                  f"{evt.get('source_ip') or '-':16s} {evt['description'][:60]}")
        if args.run:
            print("\n===== 下游威胁警报 + 应急响应结果 =====")
            for i, res in enumerate(result["results"], 1):
                if "error" in res:
                    print(f"  事件{i}: 处理失败 {res['error']}")
                    continue
                if res.get("skipped_by_level"):
                    print(f"  (事件{i} 跳过: {res.get('reason', '低于输出门槛')})")
                    continue
                print(f"\n--- 事件{i} 告警 ---")
                print(res["notification"]["display_md"])
        return 0

    if args.cmd == "playbook":
        pb = agent.generate_playbook(args.alert_id, mode=PlaybookMode(args.mode))
        _print(pb.to_markdown())
        return 0

    if args.cmd == "confirm":
        result = agent.confirm_decision(args.playbook_id, decision=args.decision,
                                        operator=args.operator,
                                        reject_reason=args.reject_reason)
        if "error" in result:
            print(result["error"])
            return 1
        _print(result["report_md"])
        return 0

    if args.cmd == "list":
        rows = {"alerts": agent.list_alerts, "playbooks": agent.list_playbooks,
                "reports": agent.list_reports}[args.kind]()
        _print(rows, as_json=True)
        return 0

    if args.cmd == "demo":
        # 离线确定性演示：强制 mock 推理通道（生产使用 TIR_MODEL_GATEWAY=auto）
        from .model_gateway import gateway
        gateway.set_mode("mock")
        print("[demo] 使用 mock 推理通道（离线确定性），生产环境请配置 TIR_MODEL_GATEWAY=auto")
        sample = {
            "source": "edushield:analyze",
            "event_type": "webshell",
            "target": "http://jwc.xxx.edu.cn",
            "source_ip": "111.1.216.150",
            "severity_hint": "high",
            "description": "检测到 webshell 命令执行行为",
            "raw": {"log_line": "POST /uploads/shell.php?cmd=whoami 200"},
            "context": {"task_id": "demo-task-001"},
        }
        result = agent.run_full_flow(sample, mode=PlaybookMode.SIMULATION)
        _print(result["notification"]["display_md"])
        _print(result["report_md"])
        return 0

    if args.cmd == "doctor":
        import ast as _ast

        from .model_gateway import gateway
        import threat_ir_agent.incident_response.simulator as sim
        ok = True
        print("== 威胁警报-应急响应 子Agent 自检 ==")
        print(f"命名空间: {config.SUBAGENT_NAMESPACE}")
        print(f"存储目录: {config.STORE_DIR}")
        print(f"推理通道: {gateway.current_transport()}")
        print("告警数:", len(agent.list_alerts()),
              "预案数:", len(agent.list_playbooks()),
              "报告数:", len(agent.list_reports()))
        # 校验：推演器未引用真实执行原语（AST 检查真实 import/调用，
        # 文档字符串中的禁用词说明不计入）
        tree = _ast.parse(open(sim.__file__, encoding="utf-8").read())
        imported: set[str] = set()
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, _ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        bad = imported & set(sim.FORBIDDEN_EXEC_IMPORTS)
        if bad:
            print(f"⚠️ 检测到真实执行原语导入: {sorted(bad)}")
            ok = False
        print("自检结果:", "通过 ✅" if ok else "未通过 ❌")
        return 0 if ok else 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
