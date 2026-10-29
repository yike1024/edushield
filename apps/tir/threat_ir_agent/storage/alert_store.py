# -*- coding: utf-8 -*-
"""
子 Agent 专属本地持久化存储
============================
需求：告警事件本地持久化存储 —— **新建子 Agent 专属存储文件，
不许篡改主系统数据库**（edushield 的 _task_store 为内存字典、ChromaDB 知识库
均不触碰）。

实现：标准库 JSON 文件存储（零新增第三方依赖），目录为
<包>/storage/data/{alerts,playbooks,reports}，全部为子 Agent 新增文件。
命名空间前缀 tir_，与主系统隔离，互不污染。

借鉴点（仅设计思想，见 docs/GITHUB_RESEARCH.md）：
- TheHive / dfir-iris 的 Case/Alert 持久化分层与事件溯源思想。
本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Optional

from ..config import config

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()


class JsonStore:
    """按类型分目录的 JSON 文件存储（原子写、防并发写坏）。"""

    def __init__(self, kind: str, base_dir: Path) -> None:
        self.kind = kind
        self.dir = base_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, obj_id: str) -> Path:
        return self.dir / f"{obj_id}.json"

    def save(self, obj_id: str, data: dict) -> None:
        with _LOCK:
            target = self._path(obj_id)
            tmp = target.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(data, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            tmp.replace(target)

    def get(self, obj_id: str) -> Optional[dict]:
        p = self._path(obj_id)
        if not p.is_file():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.error("[Store] 读取 %s 失败: %s", p, e)
            return None

    def list_all(self) -> list[dict]:
        out = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                continue
        return out


class AlertStore:
    """告警/预案/报告统一存储入口（子 Agent 专属命名空间 tir_）。"""

    def __init__(self) -> None:
        config.ensure_dirs()
        self.alerts = JsonStore("alert", config.ALERTS_DIR)
        self.playbooks = JsonStore("playbook", config.PLAYBOOKS_DIR)
        self.reports = JsonStore("report", config.REPORTS_DIR)

    # ---- 告警 ----
    def save_alert(self, alert_id: str, data: dict) -> None:
        self.alerts.save(alert_id, data)

    def get_alert(self, alert_id: str) -> Optional[dict]:
        return self.alerts.get(alert_id)

    def list_alerts(self) -> list[dict]:
        return self.alerts.list_all()

    # ---- 预案 ----
    def save_playbook(self, playbook_id: str, data: dict) -> None:
        self.playbooks.save(playbook_id, data)

    def get_playbook(self, playbook_id: str) -> Optional[dict]:
        return self.playbooks.get(playbook_id)

    def list_playbooks(self) -> list[dict]:
        return self.playbooks.list_all()

    # ---- 报告 ----
    def save_report(self, report_id: str, data: dict) -> None:
        self.reports.save(report_id, data)

    def get_report(self, report_id: str) -> Optional[dict]:
        return self.reports.get(report_id)

    def list_reports(self) -> list[dict]:
        return self.reports.list_all()

    # ---- 审计留档（对齐计划书：审计留档 180 天）----
    def retention_cleanup(self) -> None:
        """清理超过留存期限的历史文件（默认 180 天），仅作用于子Agent存储。"""
        import time

        deadline = time.time() - config.RETENTION_DAYS * 86400
        for store in (self.alerts, self.playbooks, self.reports):
            for p in store.dir.glob("*.json"):
                if p.stat().st_mtime < deadline:
                    p.unlink(missing_ok=True)
                    logger.info("[Store] 清理过期留档: %s", p.name)


store = AlertStore()
