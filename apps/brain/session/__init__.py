"""会话管理 —— SQLite 落库 + 生命周期状态机（纯业务，确定性逻辑）。

权威来源：aisoc-docs 03 §5/§6。
阶段 1 职责：
    tasks / findings / ledger / reports 四张表
    任务状态机 pending→running→completed/failed（approval/archived 预留）
    所有写入操作可审计（ledger 只增不改）
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional

from protocol import TaskStatus, utc_now_iso

logger = logging.getLogger(__name__)

# 状态机允许的迁移（aisoc-docs 03 §2.3）
_ALLOWED_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.PENDING: {TaskStatus.RUNNING, TaskStatus.CANCELLED, TaskStatus.FAILED},
    TaskStatus.RUNNING: {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.APPROVAL},
    TaskStatus.APPROVAL: {TaskStatus.RUNNING, TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED},
    TaskStatus.COMPLETED: {TaskStatus.ARCHIVED},
    TaskStatus.FAILED: {TaskStatus.ARCHIVED},
    TaskStatus.CANCELLED: {TaskStatus.ARCHIVED},
    TaskStatus.ARCHIVED: set(),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,                -- task_id
    domain TEXT NOT NULL,
    target TEXT NOT NULL,
    user_id TEXT NOT NULL DEFAULT '',   -- 归属用户（16 号方案 B8 用户隔离；空 = 匿名）
    status TEXT NOT NULL,
    verdict TEXT DEFAULT '',
    confidence REAL DEFAULT 0,
    error TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id),
    domain TEXT NOT NULL,
    target TEXT NOT NULL,
    tool TEXT NOT NULL,
    severity TEXT NOT NULL,
    cve TEXT,
    cwe TEXT,
    cvss REAL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT,
    confidence REAL NOT NULL,
    mitre TEXT,                         -- JSON array
    ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id);

CREATE TABLE IF NOT EXISTS ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT DEFAULT ''              -- JSON
);
CREATE INDEX IF NOT EXISTS idx_ledger_task ON ledger(task_id);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,                -- task_id（一任务一份综合报告）
    task_id TEXT UNIQUE NOT NULL,
    domain TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS stages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    stage TEXT NOT NULL,                -- 环节：logaudit/pentest/verdict/tir/report
    status TEXT NOT NULL,               -- running/completed/failed
    started_at TEXT NOT NULL,
    finished_at TEXT DEFAULT '',
    findings_count INTEGER DEFAULT 0,
    error TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_stages_task ON stages(task_id);

-- 应急响应（TIR 8090）落库：告警 / 预案 / 报告（协议文档 §4.2/§4.4/§4.5）
CREATE TABLE IF NOT EXISTS tir_alerts (
    alert_id TEXT PRIMARY KEY,          -- tir_alert_*
    task_id TEXT NOT NULL,
    event_ref TEXT DEFAULT '',
    level TEXT DEFAULT '',              -- high|medium|low
    status TEXT DEFAULT '',             -- new|notified|acknowledged|responded|closed
    display_md TEXT DEFAULT '',         -- 前端可直接渲染的 Markdown
    payload TEXT NOT NULL,              -- JSON：ThreatAlert 全文
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tir_alerts_task ON tir_alerts(task_id);

CREATE TABLE IF NOT EXISTS tir_playbooks (
    playbook_id TEXT PRIMARY KEY,       -- tir_playbook_*
    alert_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    mode TEXT DEFAULT '',               -- suggestion|simulation
    display_md TEXT DEFAULT '',
    payload TEXT NOT NULL,              -- JSON：ResponsePlaybook 全文
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tir_playbooks_task ON tir_playbooks(task_id);

CREATE TABLE IF NOT EXISTS tir_reports (
    report_id TEXT PRIMARY KEY,         -- tir_report_*
    task_id TEXT NOT NULL,
    playbook_id TEXT DEFAULT '',
    alert_id TEXT DEFAULT '',
    decision TEXT DEFAULT '',           -- approve|reject
    report_md TEXT DEFAULT '',
    payload TEXT NOT NULL,              -- JSON：IncidentReport 全文
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tir_reports_task ON tir_reports(task_id);
"""


class SessionStore:
    """SQLite 会话存储。线程安全（单连接 + 锁），阶段 1 够用。"""

    def __init__(self, db_path: str = "./data/brain.sqlite3"):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()
        self._lock = threading.Lock()
        logger.info(f"[session] SQLite 就绪: {path}")

    def _migrate(self):
        """轻量迁移：老库补 tasks.user_id 列（16 号方案 B8 用户隔离）。"""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(tasks)").fetchall()}
        if "user_id" not in cols:
            self._conn.execute("ALTER TABLE tasks ADD COLUMN user_id TEXT NOT NULL DEFAULT ''")
            logger.info("[session] 迁移：tasks 增加 user_id 列")

    # ---- 基础 ----
    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def close(self):
        with self._lock:
            self._conn.close()

    # ---- 任务 ----
    def create_task(self, task_id: str, domain: str, target: str, user_id: str = "") -> dict:
        now = utc_now_iso()
        self._execute(
            "INSERT INTO tasks (id, domain, target, user_id, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (task_id, domain, target, user_id or "", TaskStatus.PENDING.value, now, now),
        )
        self.add_ledger(task_id, "brain", "task_created", {"domain": domain, "target": target, "user_id": user_id or ""})
        return self.get_task(task_id)

    def get_task(self, task_id: str) -> Optional[dict]:
        rows = self._query("SELECT * FROM tasks WHERE id=?", (task_id,))
        return dict(rows[0]) if rows else None

    def transition(self, task_id: str, new_status: TaskStatus, error: str = "") -> dict:
        task = self.get_task(task_id)
        if task is None:
            raise KeyError(f"任务不存在: {task_id}")
        old = TaskStatus(task["status"])
        if old != new_status and new_status not in _ALLOWED_TRANSITIONS.get(old, set()):
            raise ValueError(f"非法状态迁移: {old.value} -> {new_status.value}")
        self._execute(
            "UPDATE tasks SET status=?, error=?, updated_at=? WHERE id=?",
            (new_status.value, error, utc_now_iso(), task_id),
        )
        self.add_ledger(task_id, "brain", f"status_{new_status.value}", {"from": old.value, "error": error})
        return self.get_task(task_id)

    def set_verdict(self, task_id: str, verdict: str, confidence: float):
        self._execute(
            "UPDATE tasks SET verdict=?, confidence=?, updated_at=? WHERE id=?",
            (verdict, confidence, utc_now_iso(), task_id),
        )

    # ---- Findings ----
    def add_findings(self, findings: list[dict]) -> int:
        """批量落库 Findings（先到先得，id 冲突跳过）。"""
        n = 0
        for f in findings:
            try:
                self._execute(
                    """INSERT OR IGNORE INTO findings
                    (id, task_id, domain, target, tool, severity, cve, cwe, cvss,
                     title, description, evidence, remediation, confidence, mitre, ts)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        f.get("id"), f.get("task_id"), f.get("domain"), f.get("target"),
                        f.get("tool"), f.get("severity"), f.get("cve"), f.get("cwe"),
                        f.get("cvss"), f.get("title"), f.get("description"), f.get("evidence"),
                        f.get("remediation"), f.get("confidence"),
                        json.dumps(f.get("mitre") or [], ensure_ascii=False), f.get("ts") or utc_now_iso(),
                    ),
                )
                n += 1
            except Exception as e:  # 单条坏数据不拖垮整批
                logger.warning(f"[session] Finding 落库失败: {e}")
        if n:
            self.add_ledger(findings[0].get("task_id", ""), "brain", "findings_stored", {"count": n})
        return n

    def list_findings(self, task_id: str) -> list[dict]:
        rows = self._query("SELECT * FROM findings WHERE task_id=? ORDER BY severity, id", (task_id,))
        out = []
        for r in rows:
            d = dict(r)
            d["mitre"] = json.loads(d.get("mitre") or "[]")
            out.append(d)
        return out

    # ---- Ledger ----
    def add_ledger(self, task_id: str, actor: str, action: str, detail: Any = None):
        self._execute(
            "INSERT INTO ledger (task_id, ts, actor, action, detail) VALUES (?,?,?,?,?)",
            (task_id, utc_now_iso(), actor, action, json.dumps(detail or {}, ensure_ascii=False, default=str)),
        )

    def list_ledger(self, task_id: str) -> list[dict]:
        rows = self._query("SELECT * FROM ledger WHERE task_id=? ORDER BY id", (task_id,))
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d.get("detail") or "{}")
            except json.JSONDecodeError:
                pass
            out.append(d)
        return out

    # ---- Report ----
    def save_report(self, task_id: str, domain: str, content: str):
        self._execute(
            "INSERT OR REPLACE INTO reports (id, task_id, domain, content, created_at) VALUES (?,?,?,?,?)",
            (task_id, task_id, domain, content, utc_now_iso()),
        )

    def get_report(self, task_id: str) -> Optional[dict]:
        rows = self._query("SELECT * FROM reports WHERE task_id=?", (task_id,))
        return dict(rows[0]) if rows else None

    # ---- 应急响应（TIR 8090，协议文档 §4）：告警 / 预案 / 报告 ----
    @staticmethod
    def _tir_row(row) -> dict:
        d = dict(row)
        try:
            d["payload"] = json.loads(d.get("payload") or "{}")
        except json.JSONDecodeError:
            d["payload"] = {}
        return d

    def save_tir_alert(self, alert: dict, task_id: str, display_md: str = "") -> str:
        """落库威胁告警（ThreatAlert §4.2）；display_md 供前端直接渲染。"""
        alert_id = str(alert.get("alert_id") or "")
        if not alert_id:
            raise ValueError("alert 缺少 alert_id")
        self._execute(
            "INSERT OR REPLACE INTO tir_alerts "
            "(alert_id, task_id, event_ref, level, status, display_md, payload, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (alert_id, task_id, str(alert.get("event_ref") or ""), str(alert.get("level") or ""),
             str(alert.get("status") or ""), display_md,
             json.dumps(alert, ensure_ascii=False, default=str), utc_now_iso()),
        )
        return alert_id

    def get_tir_alert(self, alert_id: str) -> Optional[dict]:
        rows = self._query("SELECT * FROM tir_alerts WHERE alert_id=?", (alert_id,))
        return self._tir_row(rows[0]) if rows else None

    def list_tir_alerts(self, task_id: str) -> list[dict]:
        rows = self._query("SELECT * FROM tir_alerts WHERE task_id=? ORDER BY created_at", (task_id,))
        return [self._tir_row(r) for r in rows]

    def save_tir_playbook(self, playbook: dict, task_id: str, display_md: str = "") -> str:
        """落库处置预案（ResponsePlaybook §4.4）。"""
        playbook_id = str(playbook.get("playbook_id") or "")
        if not playbook_id:
            raise ValueError("playbook 缺少 playbook_id")
        self._execute(
            "INSERT OR REPLACE INTO tir_playbooks "
            "(playbook_id, alert_id, task_id, mode, display_md, payload, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (playbook_id, str(playbook.get("alert_id") or ""), task_id,
             str(playbook.get("mode") or ""), display_md,
             json.dumps(playbook, ensure_ascii=False, default=str), utc_now_iso()),
        )
        return playbook_id

    def get_tir_playbook(self, playbook_id: str) -> Optional[dict]:
        rows = self._query("SELECT * FROM tir_playbooks WHERE playbook_id=?", (playbook_id,))
        return self._tir_row(rows[0]) if rows else None

    def list_tir_playbooks(self, task_id: str) -> list[dict]:
        rows = self._query("SELECT * FROM tir_playbooks WHERE task_id=? ORDER BY created_at", (task_id,))
        return [self._tir_row(r) for r in rows]

    def latest_tir_playbook(self, task_id: str) -> Optional[dict]:
        pbs = self.list_tir_playbooks(task_id)
        return pbs[-1] if pbs else None

    def save_tir_report(self, report: dict, task_id: str, report_md: str = "") -> str:
        """落库应急响应报告（IncidentReport §4.5）。"""
        report_id = str(report.get("report_id") or "")
        if not report_id:
            raise ValueError("report 缺少 report_id")
        self._execute(
            "INSERT OR REPLACE INTO tir_reports "
            "(report_id, task_id, playbook_id, alert_id, decision, report_md, payload, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (report_id, task_id, str(report.get("playbook_id") or ""), str(report.get("alert_id") or ""),
             str(report.get("decision") or ""), report_md,
             json.dumps(report, ensure_ascii=False, default=str), utc_now_iso()),
        )
        return report_id

    def get_tir_report(self, report_id: str) -> Optional[dict]:
        rows = self._query("SELECT * FROM tir_reports WHERE report_id=?", (report_id,))
        return self._tir_row(rows[0]) if rows else None

    def list_tir_reports(self, task_id: str) -> list[dict]:
        rows = self._query("SELECT * FROM tir_reports WHERE task_id=? ORDER BY created_at", (task_id,))
        return [self._tir_row(r) for r in rows]

    def export_task(self, task_id: str) -> Optional[dict]:
        """审计导出：任务 + 证据 + 账本 + 报告（一次性打包）。"""
        task = self.get_task(task_id)
        if task is None:
            return None
        return {
            "task": task,
            "findings": self.list_findings(task_id),
            "ledger": self.list_ledger(task_id),
            "stages": self.list_stages(task_id),
            "report": self.get_report(task_id),
            "tir": {
                "alerts": self.list_tir_alerts(task_id),
                "playbooks": self.list_tir_playbooks(task_id),
                "reports": self.list_tir_reports(task_id),
            },
        }

    # ---- 阶段（过程可见性） ----
    def start_stage(self, task_id: str, stage: str):
        self._execute(
            "INSERT INTO stages (task_id, stage, status, started_at) VALUES (?,?,?,?)",
            (task_id, stage, "running", utc_now_iso()),
        )

    def finish_stage(self, task_id: str, stage: str, findings_count: int = 0, error: str = ""):
        status = "failed" if error else "completed"
        self._execute(
            """UPDATE stages SET status=?, finished_at=?, findings_count=?, error=?
               WHERE task_id=? AND stage=? AND status='running'""",
            (status, utc_now_iso(), findings_count, error, task_id, stage),
        )

    def list_stages(self, task_id: str) -> list[dict]:
        rows = self._query("SELECT * FROM stages WHERE task_id=? ORDER BY id", (task_id,))
        return [dict(r) for r in rows]

    def list_tasks(self, limit: int = 50, user_id: Optional[str] = None) -> list[dict]:
        if user_id is not None:
            rows = self._query(
                "SELECT * FROM tasks WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
                (user_id, limit),
            )
        else:
            rows = self._query(
                "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,),
            )
        return [dict(r) for r in rows]


# 全局单例（FastAPI 应用级）
_store: Optional[SessionStore] = None
_store_lock = threading.Lock()


def get_store() -> SessionStore:
    global _store
    with _store_lock:
        if _store is None:
            from config.settings import settings
            _store = SessionStore(settings.BRAIN_DB_PATH)
        return _store
