"""编排调度（阶段 4 完整版）—— 多部件管道派活。

职责：
    白名单校验 → 任务分解（单域 / 多阶段管道）→ 逐部件下发(/submit)
    → 轮询回收 Finding → 落库 → 判定(verdict) → 报告(report) → 实时事件(eventhub)

注意（aisoc-docs 01 ADR-4）：大脑不重写 agent 循环，
重试/压缩/子代理/沙箱留在 reasonix 部件里。
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from pathlib import Path
from typing import Any, Optional

import httpx

from config.settings import settings
from eventhub import get_hub
from protocol import Domain, Finding, TaskMessage, TaskStatus, Verdict, new_finding_id, new_task_id
from registry import PartSpec, Registry
from report import build_report
from session import SessionStore, get_store
from verdict import evaluate

logger = logging.getLogger(__name__)

# 多阶段管道（aisoc-docs 03 §2.2；一期只做旗舰场景）
PIPELINES: dict[str, list[Domain]] = {
    "data_leak": [Domain.LOGAUDIT, Domain.PENTEST],  # 数据泄露调查：先审计定位，再渗透验证
}

# reasonix serve 单会话串行：同一部件同一时刻只能跑一个 turn。
# 大脑对每个部件加锁排队，避免并发 submit 互相覆盖（session busy）。
_PART_LOCKS: dict[str, threading.Lock] = {}
_PART_LOCKS_GUARD = threading.Lock()


def _part_lock(domain: str) -> threading.Lock:
    with _PART_LOCKS_GUARD:
        if domain not in _PART_LOCKS:
            _PART_LOCKS[domain] = threading.Lock()
        return _PART_LOCKS[domain]


# ---- 部件会话隔离缓存（前端 session_id → 已开过新会话的部件域） ----
# 设计要点（与 aisoc-brain/20260906 会话隔离 spec 对齐）：
#   1. 前端会话首次发任务 → /new（清空部件历史上下文）→ 缓存 (session_id, domain)
#   2. 同一前端会话后续任务 → 命中复用（不调 /new，保留部件上下文）
#   3. 前端换会话 / 刷新 → 新 session_id → 未命中 → /new（隔离）
#   4. 旧调用方不传 session_id → _has_session_opened 直接 False → 退化原行为（每次都 /new）
#
# 缓存以 (session_id, domain) 为主键，值为上次开 /new 的 unix 时间戳；
# TTL 6 小时无活动视为过期，额外后台 task 每 30 分钟主动 GC 避免内存膨胀。
# 进程重启即清零——部件侧会话由服务端内存维持，重启后部件侧也会重建，
# 所以这个丢失在语义上是正确的。

_PART_SESSION_OPENED: dict[tuple[str, str], float] = {}
_PART_SESSION_TTL_SEC = 6 * 3600  # 6 小时
_PART_SESSION_LOCK = threading.Lock()


def _mark_session_opened(session_id: str, domain: str) -> None:
    """记录 (session_id, domain) 已开过部件新会话。session_id 为空时 noop。"""
    if not session_id:
        return
    with _PART_SESSION_LOCK:
        _PART_SESSION_OPENED[(session_id, domain)] = time.time()


def _has_session_opened(session_id: str | None, domain: str) -> bool:
    """命中：(session_id, domain) 已开过新会话且未过期。

    session_id 为空或 None → 始终 False（不命中），强制开 /new（退化原行为）。
    命中时同时滑动该条目的时间戳，避免长会话在 TTL 内被 GC。
    """
    if not session_id:
        return False
    with _PART_SESSION_LOCK:
        ts = _PART_SESSION_OPENED.get((session_id, domain))
        if ts is None:
            return False
        if time.time() - ts > _PART_SESSION_TTL_SEC:
            _PART_SESSION_OPENED.pop((session_id, domain), None)
            return False
        # 命中滑动过期时间
        _PART_SESSION_OPENED[(session_id, domain)] = time.time()
        return True


def gc_expired_sessions() -> int:
    """主动 GC 过期条目，返回清理数量。可挂后台任务定期调用。"""
    now = time.time()
    expired = 0
    with _PART_SESSION_LOCK:
        keys = list(_PART_SESSION_OPENED.keys())
        for k in keys:
            if now - _PART_SESSION_OPENED[k] > _PART_SESSION_TTL_SEC:
                _PART_SESSION_OPENED.pop(k, None)
                expired += 1
    if expired:
        logger.info(f"[orchestrator] 会话缓存 GC 清理 {expired} 条过期条目")
    return expired


def part_busy(domain: str) -> bool:
    """该部件是否正有任务在执行（供 /api/agents/status 展示忙闲）。"""
    with _PART_LOCKS_GUARD:
        lock = _PART_LOCKS.get(domain)
        return bool(lock and lock.locked())


def _extract_target(message: str) -> str:
    """从自然语言里提取目标：优先 IP，其次域名，最后附件绝对路径（21 号）。"""
    import re
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", message or "")
    if m:
        return m.group(0)
    m = re.search(r"[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+(edu\.cn|com\.cn|com|cn|net|org|top)", message or "")
    if m:
        return m.group(0)
    # 附件路径：[附件] name → /abs/path/...（L-4：纯附件场景的 target；兼容 Windows 盘符）
    m = re.search(r"\[附件\][^\n→]*→\s*((?:[A-Za-z]:)?/[^\s，。；;（）()\[\]]+)", message or "")
    if m:
        return m.group(1).strip()
    return ""


def parse_task_intent(message: str) -> dict:
    """把自然语言转成任务意图：{domain, target, pipeline}。

    规则快速路 + LLM 增强（关键词能判定的不调 LLM；LLM 8s 超时，失败退回规则）。
    """
    # 默认：提到目标且是任务意图时，优先交给渗透 Agent（CTF/扫描/打靶场景最多）
    domain = Domain.PENTEST
    if any(k in message.lower() for k in ["日志", "审计", "log", "audit", "访问记录"]):
        domain = Domain.LOGAUDIT
    if any(k in message.lower() for k in ["情报", "intel", "信誉", "osint", "溯源"]):
        domain = Domain.INTEL
    # L-4 / T1-6：反诈意图关键词命中即 logaudit（不调 LLM，也不允许 LLM 覆盖）
    fraud_hit = any(k in message.lower() for k in _FRAUD_KEYWORDS)
    if fraud_hit:
        domain = Domain.LOGAUDIT

    pipeline = "data_leak" if any(k in message for k in ["泄露", "数据泄露", "调查", "溯源"]) else None
    target = _extract_target(message)

    # T0-3 规则快速路：反诈关键词命中或规则已能判定意图 → 不调 LLM。
    rule_intent = {"domain": domain, "target": target, "pipeline": pipeline}
    if fraud_hit or intent_is_task(message, rule_intent):
        return rule_intent

    # LLM 增强解析（仅规则判定不了时才调，收紧超时 8s、不重试）
    if settings.DEEPSEEK_API_KEY:
        try:
            from llm import chat_json
            res = chat_json(
                system_prompt=(
                    "从用户的安全需求中提取任务信息，只输出 JSON："
                    '{"domain":"logaudit|pentest|intel","target":"IP或域名","pipeline":"data_leak 或空字符串"}'
                ),
                user_prompt=message,
                max_retries=0,
                timeout=8,
            )
            if res:
                d = res.get("domain")
                if d in [x.value for x in Domain]:
                    domain = Domain(d)
                if res.get("target"):
                    target = res["target"]
                if res.get("pipeline") in PIPELINES:
                    pipeline = res["pipeline"]
        except Exception as e:
            logger.warning(f"[orchestrator] 意图解析 LLM 失败，用规则: {e}")

    return {"domain": domain, "target": target, "pipeline": pipeline}


_TASK_INTENT_KEYWORDS = (
    "扫", "渗透", "审计", "日志", "漏洞", "情报", "查", "分析", "检测", "调查",
    "泄露", "侦察", "评估", "应急", "获取", "拿下", "打", "flag", "ctf",
    "靶机", "靶场", "测试", "攻击", "入侵", "exploit", "pentest", "get",
    # L-4 / T1-6：反诈意图关键词（命中即任务，domain=logaudit）
    "钓鱼", "举报", "诈骗", "垃圾邮件", "冒充", "助学金", "仿冒", "涉诈",
)

# L-4：反诈关键词独立常量（parse_task_intent 用它直接短路，不允许 LLM 覆盖 domain）
_FRAUD_KEYWORDS = ("钓鱼", "举报", "诈骗", "垃圾邮件", "冒充", "助学金", "仿冒", "涉诈")


def intent_is_task(message: str, intent: dict) -> bool:
    """判断一句话是不是"要调度子智能体"的任务意图（而非普通闲聊）。

    条件：能提取到目标，且包含任务类关键词。
    """
    return bool(intent.get("target")) and any(k in message.lower() for k in _TASK_INTENT_KEYWORDS)


class BrainError(Exception):
    """大脑侧业务错误（会反映到任务状态 error 字段）。"""


def check_target_whitelisted(target: str) -> bool:
    """授权白名单校验。不在名单内一律拒绝（白名单关闭时放行）。"""
    import whitelist
    return whitelist.contains(target)


def _is_attachment_path(target: str) -> bool:
    """附件绝对路径（21 号）作为 logaudit target 时放行白名单。

    归属校验在 api 层 _is_user_attachment_target 完成，这里只做形态识别。
    """
    if not target:
        return False
    return os.path.isabs(target) and "/attachments/" in target.replace("\\", "/")


def build_task_message(domain: Domain, target: str, params: dict, tools: list[str],
                       part: PartSpec, task_id: str | None = None,
                       evidence_summary: str = "") -> TaskMessage:
    return TaskMessage(
        task_id=task_id or new_task_id(),
        domain=domain,
        target=target,
        params=params or {},
        tools=tools or [],
        context={"ref_task_ids": [], "evidence_summary": evidence_summary} if evidence_summary else {},
        auth=part.token,
    )


def _auth_headers(token: str, auth: str = "bearer") -> dict:
    """按部件鉴权方式构造请求头。

    - bearer: Authorization: Bearer <token>（8787 适配层）
    - cookie: Cookie: reasonix_token=<token>（8788 原生 reasonix serve）
    """
    if not token:
        return {}
    if auth == "cookie":
        return {"Cookie": f"reasonix_token={token}"}
    return {"Authorization": f"Bearer {token}"}


# 工具事件 → 前端工具卡片（文档：agent 工具事件接入 6657 总线）
_TOOL_KIND_MAP = {
    "tool_call": "tool_dispatch",
    "tool_dispatch": "tool_dispatch",
    "tool_progress": "tool_progress",
    "tool_result": "tool_result",
}


def _normalize_tool_event(ev: dict) -> Optional[dict]:
    """把部件 /events（或 /status.tool_events）的工具事件归一为前端卡片结构。

    兼容两类帧：
      - reasonix 原生：{"kind":"tool_dispatch","tool":{"name","args","output",...}}
      - adapter 归一：{"kind":"tool_dispatch","name","args","output","err","readOnly","ts"}
    非工具事件返回 None。args 截断 500、output 截断 1000（协议规范）。
    """
    if not isinstance(ev, dict):
        return None
    raw = str(ev.get("kind") or ev.get("type") or "").lower()
    kind = _TOOL_KIND_MAP.get(raw)
    if not kind:
        return None

    tool = ev.get("tool")
    if isinstance(tool, dict):
        name = tool.get("name") or tool.get("resolvedName") or ""
        args = tool.get("args")
        output = tool.get("output")
        err = tool.get("err") or tool.get("error") or ""
        read_only = tool.get("readOnly")
    else:
        name = tool or ev.get("name") or ""
        args = ev.get("args")
        output = ev.get("output") or ev.get("text")
        err = ev.get("err") or ev.get("error") or ""
        read_only = ev.get("readOnly")

    if ev.get("readOnly") is not None:  # 平铺字段优先
        read_only = ev.get("readOnly")

    return {
        "kind": kind,
        "name": str(name or ""),
        "args": str(args or "")[:500],
        "output": str(output or "")[:1000],
        "err": str(err or "")[:1000],
        "readOnly": bool(read_only),
        "ts": float(ev.get("ts") or time.time()),
    }


def _publish_status_tool_events(task_id: str, domain: str, status: dict,
                                sent_ts: set | None = None) -> int:
    """结束后从 /status.tool_events 补齐工具事件（SSE 断线/重连丢事件的兜底）。

    按 ts 去重（sent_ts 为实时转发过的集合），返回本次补发条数。
    """
    raw = status.get("tool_events") or []
    if not isinstance(raw, list) or not raw:
        return 0
    sent = sent_ts if sent_ts is not None else set()
    hub = get_hub()
    n = 0
    for item in raw:
        te = _normalize_tool_event(item if isinstance(item, dict) else {})
        if not te or te["ts"] in sent:
            continue
        sent.add(te["ts"])
        try:
            hub.publish(task_id, domain, "agent_tool", {"kind": "agent_tool", "tool_event": te})
            n += 1
        except Exception as e:
            logger.warning(f"[orchestrator] 补齐工具事件失败: {e}")
    return n


def wait_turn_done(base: str, token: str, task_id: str, task_input: str, auth: str = "bearer",
                   domain: str = "") -> dict:
    """SSE 事件驱动：先订阅 /events，再 submit，等 turn_done。

    - /events 是全局广播，无历史缓冲 → 必须先订阅、再 submit
    - 断线自动重连（最多 3 次）；重连仍失败或总超时 → 由调用方走 /status 兜底
    - 15s ": ping" 心跳注释帧忽略；只处理 "data: <json>"
    """
    events: queue.Queue = queue.Queue()
    stop = threading.Event()
    sent_ts: set = set()  # 已转发的工具事件 ts，供结束后 /status 补齐去重

    def _listen():
        attempts = 0
        while not stop.is_set():
            try:
                with httpx.stream(
                    "GET", f"{base}/events",
                    headers=_auth_headers(token, auth),
                    timeout=30,  # 有 ": ping" 每 15s 一次，30s 无数据才算断线
                ) as r:
                    attempts = 0  # 连接成功即清零重连计数
                    for line in r.iter_lines():
                        if stop.is_set():
                            break
                        if not line.startswith("data:"):
                            continue  # ": connected" / ": ping"
                        try:
                            events.put(json.loads(line[5:].strip()))
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.warning(f"[orchestrator] SSE 断线: {e}")
            if stop.is_set():
                break
            attempts += 1
            if attempts > 3:
                events.put({"kind": "stream_error", "err": "SSE 断线重连 3 次仍失败"})
                return
            time.sleep(min(2 * attempts, 5))

    threading.Thread(target=_listen, daemon=True).start()
    time.sleep(0.5)  # 关键：先订阅（线程已启动，等 TCP 连上）再提交，不等待任何事件

    if not submit_to_part_for_sse(base, token, task_id, task_input, auth):
        stop.set()
        return {"status": "failed", "error": "submit rejected"}

    deadline = time.monotonic() + settings.PART_TURN_TIMEOUT_S
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stop.set()
            return {"status": "timeout", "error": "SSE 等待 turn_done 超时", "tool_ts": sent_ts}
        try:
            ev = events.get(timeout=remaining)
        except queue.Empty:
            stop.set()
            return {"status": "timeout", "error": "SSE 等待 turn_done 超时", "tool_ts": sent_ts}
        kind = ev.get("kind")
        if kind == "turn_done":
            stop.set()
            return {"status": "failed" if ev.get("err") else "done", "error": ev.get("err", ""),
                    "task_id": task_id, "tool_ts": sent_ts}
        if kind == "stream_error":
            stop.set()
            return {"status": "stream_error", "error": ev.get("err", ""), "tool_ts": sent_ts}

        # 工具事件 → 转发到平台总线（前端工具卡片数据源，文档 §4 帧格式）
        tool_ev = _normalize_tool_event(ev)
        if tool_ev:
            sent_ts.add(tool_ev["ts"])
            try:
                get_hub().publish(task_id, domain, "agent_tool",
                                  {"kind": "agent_tool", "tool_event": tool_ev})
            except Exception as e:
                logger.warning(f"[orchestrator] 工具事件转发失败: {e}")


def submit_to_part_for_sse(base: str, token: str, task_id: str, task_input: str, auth: str = "bearer") -> bool:
    """与 wait_turn_done 配套的 /submit（不依赖 PartSpec）。"""
    headers = {"Content-Type": "application/json", **_auth_headers(token, auth)}
    resp = httpx.post(
        f"{base}/submit", json={"input": task_input, "task_id": task_id},
        headers=headers, timeout=settings.PART_SUBMIT_TIMEOUT_S,
    )
    return resp.status_code == 202


def fetch_status_once(part: PartSpec, task_id: str) -> dict:
    """单次 GET /status（仅 SSE 断线/超时兜底，或 turn_done 后拉取结构化结果）。"""
    url = f"{part.base_url}/status"
    try:
        resp = httpx.get(url, params={"task_id": task_id}, headers=_auth_headers(part.token, part.auth),
                         timeout=settings.PART_SUBMIT_TIMEOUT_S)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as e:
        raise BrainError(f"查询部件状态失败 {url}: {e}") from e


def fetch_final_status(part: PartSpec, task_id: str, attempts: int = 10, interval: float = 1.0) -> dict:
    """turn_done 后拉取最终结果。

    adapter 有时先发 turn_done、后把 /status 从 running 翻成 completed，
    所以做短重试；只要状态到 completed/done，或已出现 findings 就返回。
    """
    last: dict = {}
    for _ in range(attempts):
        last = fetch_status_once(part, task_id)
        st = str(last.get("status", "")).lower()
        if st in ("completed", "done", ""):
            return last
        if last.get("findings") is not None:
            return last
        time.sleep(interval)
    return last


def _normalize_findings(payload: dict, task: TaskMessage) -> list[dict]:
    """把部件返回的 findings 归一化成落库字典（按 protocol.Finding 字段）。"""
    raw = payload.get("findings") or []
    out = []
    for i, item in enumerate(raw, 1):
        kwargs: dict[str, Any] = {
            "id": item.get("id") or new_finding_id(task.task_id, i),
            "task_id": task.task_id,
            "domain": task.domain,
            "target": item.get("target") or task.target,
            # 兼容两种字段名：标准 tool / 队友 adapter 的 type
            "tool": item.get("tool") or item.get("type") or "",
            "severity": item.get("severity", "info"),
            "cve": item.get("cve"),
            "cwe": item.get("cwe"),
            "cvss": item.get("cvss"),
            "title": item.get("title", ""),
            "description": item.get("description", ""),
            "evidence": item.get("evidence", ""),
            # 兼容：标准 remediation / 队友 adapter 的 recommendation
            "remediation": item.get("remediation") or item.get("recommendation"),
            "confidence": float(item.get("confidence", 0.8) or 0.8),
            "mitre": item.get("mitre") or [],
        }
        ts = item.get("timestamp") or item.get("ts")
        if ts:
            kwargs["timestamp"] = ts
        out.append(Finding(**kwargs).model_dump(mode="json"))
    return out


def _evidence_summary(findings: list[dict]) -> str:
    if not findings:
        return ""
    parts = []
    for f in findings[:3]:
        parts.append(f"[{f.get('severity', 'info')}] {f.get('title', '')}")
    return "；".join(parts)[:500]


def _severity_to_level(severity: str) -> str:
    return {"critical": "high", "high": "high", "medium": "medium"}.get(severity, "low")


def _first_ip(text: str) -> str:
    import re
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", text or "")
    return m.group(0) if m else ""


def _push_to_tir(task_id: str, assessment: dict, store: SessionStore) -> dict:
    """判定为真实威胁后，把威胁推给 TIR 子 Agent（8090）生成告警和应急预案。"""
    if not settings.TIR_ENABLED:
        return {}
    threats = assessment.get("threats", [])
    if not threats:
        return {}

    from tir_client import TirClient
    tir = TirClient()
    alerts: list[str] = []
    playbooks: list[str] = []

    for f in threats[:5]:  # 单次最多推 5 条，控制成本
        event = {
            "title": f.get("title", ""),
            "level": _severity_to_level(f.get("severity", "info")),
            "attack_type": "suspicious",
            "mitre_technique": (f.get("mitre") or [None])[0],
            "confidence": float(f.get("confidence", 0) or 0),
            "source_ip": _first_ip(f.get("evidence", "")),
            "target": f.get("target", ""),
            "summary": f.get("description", ""),
            "evidence": f.get("evidence", ""),
            "recommended_action": f.get("remediation", ""),
            "reasoning": assessment.get("reason", ""),
            "verdict": assessment.get("verdict", ""),
        }
        resp = tir.ingest(task_id, event)
        if not resp:
            continue
        alert_id = (resp.get("alert") or {}).get("alert_id")
        if not alert_id:
            continue
        alerts.append(alert_id)

        pb = tir.create_playbook(alert_id, mode="suggestion")
        if pb:
            pid = pb.get("playbook_id") or (pb.get("playbook") or {}).get("playbook_id")
            if pid:
                playbooks.append(pid)

    result = {"alerts": alerts, "playbooks": playbooks}
    if alerts:
        store.add_ledger(task_id, "tir", "alerts_created", result)
    return result


def _new_session(part: PartSpec) -> bool:
    """给部件开新会话（POST /new），防止 reasonix 单会话串扰历史上下文。

    部分适配层可能未实现 /new，失败时仅告警不阻断。
    返回是否成功调用 /new（False 仅表示未调或失败，但不影响后续任务提交）。
    """
    try:
        r = httpx.post(
            f"{part.base_url}/new",
            json={},
            headers=_auth_headers(part.token, part.auth),
            timeout=10,
        )
        if r.status_code in (200, 202, 204):
            logger.info(f"[orchestrator] 已为部件 {part.base_url} 新建会话")
            return True
        logger.warning(f"[orchestrator] 部件 /new 返回 {r.status_code}（忽略，继续）")
        return False
    except Exception as e:
        logger.warning(f"[orchestrator] 部件 /new 调用失败（忽略）: {e}")
        return False


def _run_stage(task_id: str, domain: Domain, target: str, params: dict, tools: list[str],
               evidence_summary: str, registry: Registry,
               session_id: str | None = None) -> list[dict]:
    """执行单个部件阶段：SSE 事件驱动（先订阅后 submit，等 turn_done），
    turn_done 后单次 GET /status 拉取结构化 Finding。

    session_id 不为空时：
      - 命中缓存（同一前端会话同一部件） → 复用部件会话，**不调 /new**
      - 未命中（首次 / 换会话 / 超时） → 调 /new 开新部件会话，标记缓存
    session_id 为空时 → 每次都调 /new（退化原行为，保持向后兼容）。
    """
    part = registry.get(domain)
    task = build_task_message(domain, target, params, tools, part, task_id=task_id, evidence_summary=evidence_summary)
    task_input = task.to_input_text()

    # 单部件串行：同一时刻只允许一个任务在该部件上执行
    with _part_lock(domain.value):
        if _has_session_opened(session_id, domain.value):
            logger.info(f"[orchestrator] 复用部件 {domain.value} 会话 session_id={session_id}")
        else:
            if _new_session(part):
                _mark_session_opened(session_id or "", domain.value)
        result = wait_turn_done(part.base_url, part.token, task_id, task_input, auth=part.auth,
                                domain=domain.value)
        sent_ts = result.get("tool_ts") or set()

        if result["status"] == "done":
            # turn_done 后短重试拉最终状态（adapter 可能稍后才把 running 翻成 completed）
            status = fetch_final_status(part, task_id)
            if str(status.get("status", "")).lower() not in ("completed", "done", "") and status.get("findings") is None:
                raise BrainError(f"部件 {domain.value} 事件 done 但状态异常: {status.get('status')}")
            # 工具事件兜底补齐（SSE 断线/重连期间可能丢帧）
            _publish_status_tool_events(task_id, domain.value, status, sent_ts)
            return _normalize_findings(status, task)

        # SSE 断线/超时兜底：单次 /status 查询（不做轮询循环）
        if result["status"] in ("stream_error", "timeout"):
            logger.warning(f"[orchestrator] SSE {result['status']}，走 /status 兜底: {result.get('error')}")
            status = fetch_status_once(part, task_id)
            _publish_status_tool_events(task_id, domain.value, status, sent_ts)
            if str(status.get("status", "")).lower() == "completed":
                return _normalize_findings(status, task)
            detail = status.get("error") or status.get("status") or result.get("error", "")
            raise BrainError(f"部件 {domain.value} 任务失败: {detail}")

    raise BrainError(f"部件 {domain.value} 任务未完成: {result.get('status')} {result.get('error', '')}")


def run_task(domain: Domain, target: str, params: Optional[dict] = None,
             tools: Optional[list[str]] = None, registry: Optional[Registry] = None,
             store: Optional[SessionStore] = None, task_id: Optional[str] = None,
             pipeline: Optional[str] = None,
             session_id: Optional[str] = None) -> dict:
    """执行一次任务（同步主流程，由 API 层放到后台线程调用）。

    session_id：前端会话 ID；不为空时，同一会话内的多个任务复用部件上下文（详见 _run_stage）。
    管道任务（pipeline）内所有 stage 共享同一 session_id。
    """
    store = store or get_store()
    registry = registry or get_registry()

    if not _is_attachment_path(target) and not check_target_whitelisted(target):
        raise BrainError(f"目标不在授权白名单内: {target}")

    stages: list[Domain]
    task_domain: str
    if pipeline:
        if pipeline not in PIPELINES:
            raise BrainError(f"未知管道: {pipeline}，可选 {list(PIPELINES)}")
        stages = PIPELINES[pipeline]
        task_domain = "all"
    else:
        stages = [domain]
        task_domain = domain.value

    if task_id is None:
        task = build_task_message(domain, target, params or {}, tools or [], registry.get(stages[0]))
        store.create_task(task.task_id, task_domain, target)
        task_id = task.task_id
    else:
        if store.get_task(task_id) is None:
            raise BrainError(f"任务不存在: {task_id}")

    hub = get_hub()
    hub.publish(task_id, task_domain, "task_created", {"target": target, "pipeline": pipeline or domain.value})

    try:
        store.transition(task_id, TaskStatus.RUNNING)
        hub.publish(task_id, task_domain, "status_running")

        all_findings: list[dict] = []
        evidence = ""
        seq = 1
        for stage in stages:
            store.start_stage(task_id, stage.value)
            hub.publish(task_id, task_domain, "stage_start", {"domain": stage.value})
            try:
                findings = _run_stage(task_id, stage, target, params or {}, tools or [],
                                      evidence, registry, session_id=session_id)
            except BrainError as e:
                store.finish_stage(task_id, stage.value, 0, error=str(e))
                hub.publish(task_id, task_domain, "stage_failed", {"domain": stage.value, "error": str(e)})
                raise
            # 管道内统一重新编号，避免多部件各自从 001 开始造成 id 冲突
            for f in findings:
                f["id"] = new_finding_id(task_id, seq)
                seq += 1
            if findings:
                store.add_findings(findings)
                all_findings.extend(findings)
                hub.publish(task_id, task_domain, "findings_stored", {"domain": stage.value, "count": len(findings)})
            store.finish_stage(task_id, stage.value, findings_count=len(findings))
            hub.publish(task_id, task_domain, "stage_finished", {"domain": stage.value, "count": len(findings)})
            evidence = _evidence_summary(findings)

        # 判定（规则 + LLM 双轨）
        store.start_stage(task_id, "verdict")
        assessment = evaluate(all_findings)
        store.set_verdict(task_id, assessment["verdict"], assessment["confidence"])
        store.finish_stage(task_id, "verdict", findings_count=len(assessment.get("threats", [])))
        hub.publish(task_id, task_domain, "verdict", {
            "verdict": assessment["verdict"], "confidence": assessment["confidence"],
        })
        hub.publish(task_id, task_domain, "stage_finished",
                    {"domain": "verdict", "count": len(assessment.get("threats", []))})

        # 真实威胁 → 推送应急响应子 Agent（8090）生成告警与预案
        tir_result: dict = {}
        if assessment["verdict"] == Verdict.REAL_THREAT.value:
            store.start_stage(task_id, "tir")
            tir_result = _push_to_tir(task_id, assessment, store)
            store.finish_stage(task_id, "tir", findings_count=len(tir_result.get("alerts", [])))
            hub.publish(task_id, task_domain, "stage_finished",
                        {"domain": "tir", "count": len(tir_result.get("alerts", []))})

        # 报告（先置完成态，报告里状态才是 completed）
        store.start_stage(task_id, "report")
        store.transition(task_id, TaskStatus.COMPLETED)

        task = store.get_task(task_id)
        ledger = store.list_ledger(task_id)
        report_md = build_report(task, all_findings, assessment, ledger, tir=tir_result)
        store.save_report(task_id, task_domain, report_md)
        store.finish_stage(task_id, "report", findings_count=len(all_findings))
        hub.publish(task_id, task_domain, "report_ready")
        hub.publish(task_id, task_domain, "stage_finished", {"domain": "report", "count": len(all_findings)})
        hub.publish(task_id, task_domain, "status_completed")
    except BrainError as e:
        logger.error(f"[orchestrator] 任务失败 {task_id}: {e}")
        store.transition(task_id, TaskStatus.FAILED, error=str(e))
        hub.publish(task_id, task_domain, "status_failed", {"error": str(e)})
    except Exception as e:
        logger.exception(f"[orchestrator] 任务异常 {task_id}")
        store.transition(task_id, TaskStatus.FAILED, error=str(e))
        hub.publish(task_id, task_domain, "status_failed", {"error": str(e)})

    return store.get_task(task_id)


# 延迟初始化注册表（避免 import 循环）
_registry: Optional[Registry] = None


def get_registry() -> Registry:
    global _registry
    if _registry is None:
        _registry = Registry.load(settings.REGISTRY_FILE or None)
    return _registry
