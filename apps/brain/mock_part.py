"""Mock 身体部件 —— 联调用的假 reasonix serve（阶段 4 版，含 /events SSE）。

模拟适配层协议：
    POST /submit   body {"input","task_id"} → 202
    GET  /events   SSE：先订阅后 submit 可收到完整事件流
    GET  /status   ?task_id= → {"status","findings"}（turn_done 后拉结果用）
    GET  /health

用法：
    python mock_part.py                                        # logaudit:8788
    MOCK_PORT=8787 MOCK_DOMAIN=pentest python mock_part.py
    MOCK_TASK_SECONDS=60 python mock_part.py                   # 模拟长任务（验证 600s 超时）

队友真实 reasonix 适配层就绪后，把大脑注册表指向真实端口，本脚本退役。
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import re
import threading
import time

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="Mock 身体部件")

MOCK_DOMAIN = os.getenv("MOCK_DOMAIN", "logaudit")
MOCK_PORT = int(os.getenv("MOCK_PORT", "8788"))
MOCK_TASK_SECONDS = float(os.getenv("MOCK_TASK_SECONDS", "1"))

# 内存任务表 + SSE 广播（真实 reasonix /events 是广播给所有订阅者）
_TASKS: dict[str, dict] = {}
_TOOL_EVENTS: dict[str, list] = {}
_SUBSCRIBERS: list[queue.Queue] = []
_SUB_LOCK = threading.Lock()


def _broadcast(event: dict):
    with _SUB_LOCK:
        subs = list(_SUBSCRIBERS)
    for q in subs:
        try:
            q.put_nowait(event)
        except queue.Full:
            pass

_SAMPLE_FINDINGS = {
    "logaudit": [
        {
            "tool": "anomaly_detect",
            "severity": "high",
            "title": "对登录接口的暴力破解",
            "description": "短时间内同一源 IP 产生大量 401，疑似口令爆破",
            "evidence": "172.16.5.20 在 60s 内 POST /login 401 共 47 次",
            "remediation": "临时封禁源 IP 并启用登录限速/验证码",
            "confidence": 0.92,
            "mitre": ["T1110"],
        },
        {
            "tool": "anomaly_detect",
            "severity": "low",
            "title": "搜索引擎爬虫密集抓取",
            "description": "Googlebot 大量 404 属正常爬虫行为，判定误报",
            "evidence": "66.249.66.1 UA=Googlebot/2.1 访问 404 12 次",
            "remediation": "无需处置",
            "confidence": 0.85,
            "mitre": [],
        },
    ],
    "pentest": [
        {
            "tool": "port_scan",
            "severity": "medium",
            "title": "后台管理入口暴露",
            "description": "检测到 /admin 返回登录页，暴露后台管理入口",
            "evidence": "GET /admin 200，Server: nginx/1.18.0",
            "remediation": "限制后台访问 IP 白名单，隐藏版本号",
            "confidence": 0.8,
            "mitre": ["T1592"],
        },
    ],
}


class SubmitBody(BaseModel):
    input: str
    task_id: str | None = None


@app.get("/health")
async def health():
    return {"status": "ok", "domain": MOCK_DOMAIN}


@app.post("/submit", status_code=202)
async def submit(body: SubmitBody):
    # 与大脑 to_input_text() 对齐：首行 "任务 <task_id> (<domain>): ..."
    m = re.search(r"任务\s+(\S+)\s+\(", body.input)
    task_id = body.task_id or (m.group(1) if m else None)
    if not task_id:
        raise HTTPException(status_code=400, detail="input 缺少 task_id")

    _TASKS[task_id] = {"status": "running", "submitted_at": time.time(),
                       "tool_events": _TOOL_EVENTS.setdefault(task_id, [])}
    _broadcast({"task_id": task_id, "kind": "turn_started"})
    _broadcast({"task_id": task_id, "kind": "turn_phase", "phase": "working", "text": "working"})

    def _emit_tool(kind: str, **kw):
        """模拟 agent 工具事件（形状与真实 adapter 一致，供大脑转发联调）。"""
        ev = {"kind": kind, "name": kw.get("name", ""), "args": kw.get("args", ""),
              "output": kw.get("output", ""), "err": kw.get("err", ""),
              "readOnly": kw.get("readOnly", False), "ts": time.time()}
        _TOOL_EVENTS.setdefault(task_id, []).append(ev)
        _broadcast({"task_id": task_id, **ev})

    def _finish():
        time.sleep(MOCK_TASK_SECONDS)
        _emit_tool("tool_dispatch", name="bash", args='{"command": "whoami; date"}')
        time.sleep(0.2)
        _emit_tool("tool_progress", output="wangwei\n")
        time.sleep(0.2)
        _emit_tool("tool_result", name="bash", args='{"command": "whoami; date"}',
                   output="wangwei\n", readOnly=True)
        time.sleep(0.2)
        _broadcast({"task_id": task_id, "kind": "message", "text": f"[mock:{MOCK_DOMAIN}] 任务完成"})
        _broadcast({"task_id": task_id, "kind": "turn_done"})
        _TASKS[task_id]["status"] = "completed"

    threading.Thread(target=_finish, daemon=True).start()
    return {"task_id": task_id, "status": "running"}


@app.get("/events")
async def events():
    """SSE 全局广播（适配层语义：先订阅后 submit）。"""
    q: queue.Queue = queue.Queue(maxsize=200)
    with _SUB_LOCK:
        _SUBSCRIBERS.append(q)

    async def gen():
        try:
            while True:
                try:
                    ev = await asyncio.to_thread(q.get, timeout=15)
                    yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            with _SUB_LOCK:
                if q in _SUBSCRIBERS:
                    _SUBSCRIBERS.remove(q)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/status")
async def status(task_id: str):
    task = _TASKS.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    if task["status"] != "completed":
        return {"task_id": task_id, "status": "running",
                "tool_events": _TOOL_EVENTS.get(task_id, [])}
    findings = _SAMPLE_FINDINGS.get(MOCK_DOMAIN, [])
    out = []
    for i, f in enumerate(findings, 1):
        out.append({
            **f,
            "id": f"F-{task_id}-{i:03d}",
            "task_id": task_id,
            "domain": MOCK_DOMAIN,
            "target": "demo-campus.edu.cn",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
    return {"task_id": task_id, "status": "completed", "findings": out,
            "tool_events": _TOOL_EVENTS.get(task_id, [])}


if __name__ == "__main__":
    import uvicorn
    print(f"[mock_part] domain={MOCK_DOMAIN} 监听 0.0.0.0:{MOCK_PORT}，任务耗时 {MOCK_TASK_SECONDS}s")
    uvicorn.run(app, host="0.0.0.0", port=MOCK_PORT)
