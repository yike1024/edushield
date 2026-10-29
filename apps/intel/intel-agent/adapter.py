#!/usr/bin/env python3
"""AiSOC 大脑 -> reasonix serve 适配层（情报收集域，8789 -> 8089）。"""
import os, http.server, json, urllib.request, urllib.error, datetime, threading, time, ssl
from urllib.parse import urlparse, parse_qs

# ============ 配置（全部来自环境变量，config/env/intel.env 由 dev-up 注入）============


def _env(name, default=""):
    return os.getenv(name, default)


def _is_unset(value) -> bool:
    """空串、或仍是占位符（sk-xxxx）都算"未配置"。"""
    v = (value or "").strip()
    return (not v) or ("xxxx" in v.lower())


ADAPTER_PORT = int(_env("ADAPTER_PORT", "8789"))     # ← adapter 监听端口（大脑 registry 指向）
RIX_PORT = int(_env("RIX_PORT", "8089"))             # ← reasonix serve 端口
RIX_BASE = _env("RIX_BASE", f"http://127.0.0.1:{RIX_PORT}")
RIX_TOKEN = _env("RIX_TOKEN", "")                    # ← reasonix --token（转发用 Cookie）
BRAIN_TOKEN = _env("BRAIN_TOKEN", "")                # ← 大脑 registry 的 bearer token
BRAIN_TOKEN_LEGACY = _env("BRAIN_TOKEN_LEGACY", "")  # 兼容旧 token，可留空串
DEEPSEEK_KEY = _env("DEEPSEEK_API_KEY", "") or RIX_TOKEN   # AI 审批门用的 key
# ==============================================================================

# 环境 python（miniconda）默认 CA 链不可用，显式用系统 CA；文件缺失时回退系统默认
_CA_FILE = _env("SSL_CA_FILE", "/etc/ssl/certs/ca-certificates.crt")
_SSL_CTX = ssl.create_default_context(cafile=_CA_FILE) if os.path.isfile(_CA_FILE) else ssl.create_default_context()

# 日志目录（默认仓根 logs/，由 ADAPTER_LOG_DIR 指定）
LOG_DIR = _env("ADAPTER_LOG_DIR", ".")
os.makedirs(LOG_DIR, exist_ok=True)
LOG = open(os.path.join(LOG_DIR, "adapter-debug.log"), "a", buffering=1)
def dbg(msg):
    LOG.write(f"{datetime.datetime.now().isoformat()} {msg}\n")

STALL_LIMIT = int(_env("STALL_LIMIT", "300"))        # 看门狗：无任何事件秒数阈值
MAX_RETRIES = int(_env("MAX_RETRIES", "2"))
WATCHDOG_INTERVAL = int(_env("WATCHDOG_INTERVAL", "20"))

_last_any_event = time.time()

AI_LOG = open(os.path.join(LOG_DIR, "ai-approval.log"), "a", buffering=1)
def ai_log(msg):
    AI_LOG.write(f"{datetime.datetime.now().isoformat()} {msg}\n")

def ai_check_command(command, task_input) -> tuple:
    if _is_unset(DEEPSEEK_KEY):
        # 未配置（空 / 仍是 sk-xxxx 占位符）→ 不做模型裁决，否则每次 401 会把敏感命令全拒掉
        ai_log(f"ai gate skipped (DEEPSEEK_API_KEY unset or placeholder): {command[:120]!r}")
        return True, "no-key-skip"
    prompt = (
        "你是安全命令校验器。授权渗透测试 agent 请求执行以下 shell 命令。\n"
        f"任务上下文：{task_input[:500]}\n命令：{command[:1000]}\n"
        "判断：命令是否在授权测试范围内、安全且必要。系统级破坏（关机/格式化/"
        "删除任务无关文件/篡改系统配置）必须拒绝。只返回 JSON，格式："
        '{"decision":"allowed"|"denied","reason":"一句话理由"}'
    )
    body = {"model": _env("AIGATE_MODEL", "deepseek-v4-flash"),
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 300, "response_format": {"type": "json_object"}}
    req = urllib.request.Request(
        _env("AIGATE_URL", "https://api.deepseek.com/chat/completions"), method="POST",
        data=json.dumps(body).encode())
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {DEEPSEEK_KEY}")
    for attempt in (0, 1, 2):            # 首次 + 2 次重试，失败保守拒绝
        if attempt:
            time.sleep(2 * attempt)
        try:
            with urllib.request.urlopen(req, timeout=60, context=_SSL_CTX) as r:
                raw = json.loads(r.read().decode())
            parsed = json.loads(raw["choices"][0]["message"]["content"])
            d = parsed.get("decision", "denied")
            return d == "allowed", parsed.get("reason", "")
        except Exception as e:
            ai_log(f"ai_check attempt{attempt} fail: {e}")
    return False, "AI gate error after retries"

def handle_approval(ev):
    appr = ev.get("approval", {})
    aid, subject = appr.get("id", ""), appr.get("subject", "")
    if not aid:
        return
    task_input = ""
    with tasks_lock:
        for t in tasks.values():
            if t.get("status") == "running":
                task_input = t.get("input", ""); break
    allowed, reason = ai_check_command(subject, task_input)
    rix_req("POST", "/approve", {"id": aid, "allow": allowed, "session": True})
    ai_log(f"approval id={aid} allowed={allowed} reason={reason!r} cmd={subject[:120]!r}")

tasks, tasks_lock = {}, threading.Lock()
_last_status_check, _cached_running = 0.0, False
_suppress_err_done = threading.Event()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
_opener = urllib.request.build_opener(NoRedirect)

def rix_req(method, path, body=None):
    req = urllib.request.Request(f"{RIX_BASE}{path}", method=method)
    req.add_header("Cookie", f"reasonix_token={RIX_TOKEN}")   # 必须用 Cookie，勿用 ?token=（会 302 丢 body）
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with _opener.open(req, data=data, timeout=60) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)

def extract_findings(text):
    if not isinstance(text, str) or "{" not in text:
        return None
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start:end + 1])
    except Exception:
        return None
    f = parsed.get("findings")
    return f if isinstance(f, list) else None

def _latest_running():
    best = None
    for t in tasks.values():
        if t.get("status") == "running":
            if best is None or t.get("submitted_at", 0) > best.get("submitted_at", 0):
                best = t
    return best

def event_monitor():
    global _last_any_event
    while True:
        try:
            req = urllib.request.Request(f"{RIX_BASE}/events")
            req.add_header("Cookie", f"reasonix_token={RIX_TOKEN}")
            with _opener.open(req, timeout=None) as r:
                for raw in r:
                    if raw and raw.startswith(b"data:"):
                        _last_any_event = time.time()
                        try:
                            ev = json.loads(raw[5:].strip())
                            if ev.get("kind") == "approval_request":
                                threading.Thread(target=handle_approval, args=(ev,), daemon=True).start()
                            elif ev.get("kind") == "message":
                                findings = extract_findings(ev.get("text", ""))
                                if findings is not None:
                                    with tasks_lock:
                                        if (b := _latest_running()) is not None:
                                            b["findings"] = findings
                                            dbg(f"saved {len(findings)} findings")
                            elif ev.get("kind") == "turn_done":
                                with tasks_lock:
                                    if (b := _latest_running()) is not None:
                                        b["status"] = "failed" if ev.get("err") else "completed"
                                        dbg(f"task -> {b['status']}")
                        except Exception:
                            pass
        except Exception as e:
            dbg(f"event_monitor: reconnect after {e}")
            time.sleep(3)

def watchdog():
    while True:
        time.sleep(WATCHDOG_INTERVAL)
        now = time.time()
        with tasks_lock:
            for tid, t in list(tasks.items()):
                if t.get("status") != "running":
                    continue
                if now - max(t.get("last_progress_ts", now), _last_any_event) <= STALL_LIMIT:
                    continue
                if t.get("retries", 0) >= MAX_RETRIES:
                    t["status"] = "failed"
                    t["error"] = f"watchdog: stalled {STALL_LIMIT}s"
                    _suppress_err_done.clear()
                    rix_req("POST", "/cancel", {})
                    dbg(f"{tid} gave up")
                    continue
                _suppress_err_done.set()
                rix_req("POST", "/cancel", {})
                time.sleep(1.5)
                rix_req("POST", "/new", {})
                time.sleep(1.0)
                code, resp = rix_req("POST", "/submit",
                                     {"input": t.get("input", ""), "format": "json_object"})
                t["retries"] += 1
                t["submitted_at"] = t["last_progress_ts"] = time.time()
                t["status"] = "running" if code == 202 else "failed"
                dbg(f"{tid} retry #{t['retries']} -> {code}")

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def _reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))   # 必须带，否则客户端等 keep-alive 关闭
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _auth_ok(self):
        # 未配置 BRAIN_TOKEN 视为本地调试（放行）；生产必须配，见 config/env/intel.env.tmpl
        if not BRAIN_TOKEN and not BRAIN_TOKEN_LEGACY:
            return True
        a = self.headers.get("Authorization")
        return a == f"Bearer {BRAIN_TOKEN}" or (BRAIN_TOKEN_LEGACY and a == f"Bearer {BRAIN_TOKEN_LEGACY}")

    def do_POST(self):
        if not self._auth_ok():
            self._reply(401, {"error": "unauthorized"}); return
        if self.path != "/submit":
            self._reply(404, {"error": "not found"}); return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            body = {}
        task_id = body.get("task_id") or f"T{datetime.datetime.now().strftime('%Y%m%d-%H%M%S%f')}"
        raw_input = body.get("input", "")
        enhanced = raw_input
        if "结构化发现" in raw_input and "json" not in raw_input.lower():
            enhanced = raw_input + (
                "\n\n请以 JSON 格式输出结构化发现（只输出 JSON，不要 Markdown 代码块）："
                '{"findings":[{"type":"...","severity":"low|medium|high|critical",'
                '"title":"...","evidence":"...","description":"...","recommendation":"..."}]}'
            )
        with tasks_lock:
            tasks[task_id] = {"status": "running", "input": enhanced,
                              "submitted_at": time.time(), "last_progress_ts": time.time(), "retries": 0}
        code, resp = rix_req("POST", "/submit", {"input": enhanced, "format": "json_object"})
        with tasks_lock:
            tasks[task_id]["status"] = "running" if code == 202 else "failed"
            if code != 202:
                tasks[task_id]["error"] = resp
        dbg(f"POST /submit task={task_id} code={code}")
        self._reply(202, {"task_id": task_id, "status": tasks[task_id]["status"]})

    def do_GET(self):
        if self.path.startswith("/events"):
            if not self._auth_ok():
                self._reply(401, {"error": "unauthorized"}); return
            req = urllib.request.Request(f"{RIX_BASE}/events")
            req.add_header("Cookie", f"reasonix_token={RIX_TOKEN}")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                with _opener.open(req, timeout=None) as r:
                    for raw in r:
                        if not raw:
                            continue
                        if _suppress_err_done.is_set() and raw.startswith(b"data:"):
                            try:
                                ev = json.loads(raw[5:].strip())
                                if ev.get("kind") == "turn_done" and ev.get("err"):
                                    _suppress_err_done.clear()
                                    continue
                            except Exception:
                                pass
                        if raw.startswith(b"data:"):
                            try:
                                ev = json.loads(raw[5:].strip())
                                txt = ev.get("text", "")
                                if ev.get("kind") == "message" and isinstance(txt, str) and "{" in txt:
                                    s, e = txt.find("{"), txt.rfind("}")
                                    if s != -1 and e > s:
                                        cand = txt[s:e + 1]
                                        json.loads(cand)
                                        if cand != txt:
                                            ev["text"] = cand
                                            raw = (f"data: {json.dumps(ev, ensure_ascii=False)}\n\n").encode()
                            except Exception:
                                pass
                        self.wfile.write(raw)
                        self.wfile.flush()
            except Exception as e:
                dbg(f"events proxy ended: {e}")
            return
        if self.path.startswith("/status"):
            task_id = parse_qs(urlparse(self.path).query).get("task_id", [""])[0]
            global _last_status_check, _cached_running
            now = time.time()
            with tasks_lock:
                if now - _last_status_check > 2.0:
                    code, raw = rix_req("GET", "/status")
                    try:
                        _cached_running = bool(json.loads(raw).get("running", False))
                    except Exception:
                        pass
                    _last_status_check = now
                t = tasks.get(task_id, {})
                running = _cached_running
                if t.get("error"):
                    status = "failed"
                elif t.get("status") in ("completed", "failed"):
                    status = t["status"]
                elif running or now - t.get("submitted_at", now) < 15.0:
                    status = "running"
                else:
                    status = "completed"
            out = {"task_id": task_id, "status": status, "running": running}
            if t.get("error"):
                out["error"] = t["error"]
            if status == "completed" and t.get("findings"):
                out["findings"] = t["findings"]
            self._reply(200, out)
            return
        self._reply(404, {"error": "not found"})

threading.Thread(target=event_monitor, daemon=True).start()
threading.Thread(target=watchdog, daemon=True).start()
http.server.ThreadingHTTPServer(("127.0.0.1", ADAPTER_PORT), H).serve_forever()
