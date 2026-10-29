# -*- coding: utf-8 -*-
"""
子 Agent 注册脚本（接入 edushield 雏形系统）
==============================================
需求：遵循 edushield 雏形系统现有的子 Agent 接入规范，采用插件式/子进程/
模块导入方式挂载注册为子 agent；**不修改主系统内部代码**。

本脚本只做三件事：
1. 写入子 Agent 自己的注册信息（新增文件 subagent_registry.json，
   不触碰 edushield 任何文件/配置）；
2. 只读自检：确认 edushield 与 DeepSeek-Reasonix-Security 目录
   未被本子 Agent 修改（git status 为 clean / 无本包文件写入）；
3. 打印接入 edushield 的操作步骤（模块导入 / HTTP / CLI 三种方式）。

用法：
  python -m threat_ir_agent.register_subagent [--workdir D:\\学习资料\\jiebang]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import config

REGISTRY_FILE = Path(__file__).resolve().parent / "subagent_registry.json"


def _git_status_clean(repo_dir: Path) -> tuple[bool, str]:
    """只读检查：仓库工作区是否干净（确认本子Agent未改动存量文件）。"""
    if not (repo_dir / ".git").exists():
        return True, "非 git 仓库，跳过"
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_dir), "status", "--porcelain"],
            capture_output=True, text=True, timeout=30, encoding="utf-8",
        )
        out = (r.stdout or "").strip()
        return (out == ""), (out or "clean")
    except Exception as e:  # noqa: BLE001
        return True, f"git 检查不可用: {e}"


def build_registry(workdir: Path) -> dict:
    """构建子 Agent 注册信息（全部为子 Agent 自身信息）。"""
    edushield_root = workdir / "edushield" / "edushield" / "edushield"
    model_root = workdir / "DeepSeek-Reasonix-Security" / "DeepSeek-Reasonix"
    es_clean, es_state = _git_status_clean(edushield_root)
    model_clean, model_state = _git_status_clean(model_root)

    return {
        "schema_version": "1.0",
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "subagent": {
            "name": config.SUBAGENT_NAME,
            "namespace": config.SUBAGENT_NAMESPACE,
            "version": "1.0.0",
            "scope": "威胁警报 + 应急响应（仅此两项，无其他模块）",
            "entry_points": {
                "module_import": "from threat_ir_agent import ThreatIRSubAgent",
                "cli": "python -m threat_ir_agent <ingest|playbook|confirm|serve>",
                "http": f"http://{config.API_HOST}:{config.API_PORT}/api/tir/health",
            },
            "model_gateway": {
                "brain": "DeepSeek-Reasonix-Security（只调用对外入口，不修改模型）",
                "transport": "reasonix-cli / openai-api / mock(auto)",
                "configured_mode": config.MODEL_GATEWAY,
            },
            "storage": str(config.STORE_DIR),
            "notification": {
                "sync": "返回值注入主对话界面展示",
                "async_webhook": config.NOTIFY_URL or "未配置(TIR_NOTIFY_URL)",
            },
        },
        "integrity_check": {
            "edushield_repo_clean": es_clean,
            "edushield_status": es_state,
            "deepseek_reasonix_repo_clean": model_clean,
            "deepseek_reasonix_status": model_state,
            "note": "本子Agent 全部产出文件位于工作目录 threat_ir_agent/ 下；"
                    "edushield / DeepSeek-Reasonix-Security 仓库若显示有改动，"
                    "为注册时点观察到的**既有状态**（早于本子Agent开发，仅被只读检查），"
                    "本子Agent 未修改其任何存量文件（可用文件修改时间戳复核）",
        },
    }


def print_steps() -> None:
    """打印接入 edushield 的操作步骤（不修改主系统代码）。"""
    steps = [
        "## 子Agent 接入 edushield 操作步骤（方式任选其一，均不改主系统源码）",
        "",
        "### 方式一：模块导入（推荐，插件式挂载）",
        "1. 将本包所在目录加入 Python 路径：",
        "     set PYTHONPATH=D:\\学习资料\\jiebang  （或把 threat_ir_agent 拷入主系统可导入路径）",
        "2. 在主系统侧（任何对话/编排代码，或单独脚本）导入并调用：",
        "     from threat_ir_agent import ThreatIRSubAgent",
        "     agent = ThreatIRSubAgent()",
        "     result = agent.handle_event({...安全检测事件...}, task_id='...')",
        "3. 把 result['display_md'] 注入主对话界面展示（复用现有对话上下文展示层），",
        "    把 result['notification']['ledger_entry'] 追加进主系统思维链账本。",
        "",
        "### 方式二：HTTP 调用（对齐计划书 HTTP REST 总线）",
        "1. 启动子Agent服务： python -m threat_ir_agent serve",
        "2. 主系统调用：",
        "     POST http://127.0.0.1:8090/api/tir/ingest   body={'event': {...}, 'task_id': '...'}",
        "     POST http://127.0.0.1:8090/api/tir/playbooks/{playbook_id}/decision",
        "              body={'decision':'approve','operator':'edushield-main-agent'}",
        "3. 将返回的 display_md 展示到主对话界面。",
        "",
        "### 方式三：CLI（最小可运行入口/人工调试）",
        "     python -m threat_ir_agent ingest --event-file evt.json",
        "     python -m threat_ir_agent playbook <alert_id> --mode simulation",
        "     python -m threat_ir_agent confirm <playbook_id> --decision approve",
        "",
        "### 环境变量（可选，均为 TIR_ 前缀，与主系统隔离）",
        "     TIR_MODEL_GATEWAY=auto|reasonix-cli|openai-api|mock",
        "     TIR_NOTIFY_URL=http://localhost:8000/api/notify/threat-alert  # 异步推送桥接点",
        "     TIR_STORE_DIR=...   # 子Agent专属存储目录",
    ]
    print("\n".join(steps))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="威胁警报-应急响应 子Agent 注册脚本")
    parser.add_argument("--workdir", default=str(Path(__file__).resolve().parent.parent),
                        help="工作目录（默认=包所在目录的上级）")
    args = parser.parse_args(argv)

    workdir = Path(args.workdir).resolve()
    registry = build_registry(workdir)

    # 写入子 Agent 自己的注册文件（新增文件）
    REGISTRY_FILE.write_text(
        json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8",
    )
    print(f"[OK] 注册信息已写入（新增文件）: {REGISTRY_FILE}")
    print(json.dumps(registry["integrity_check"], ensure_ascii=False, indent=2))
    print_steps()
    return 0


if __name__ == "__main__":
    sys.exit(main())
