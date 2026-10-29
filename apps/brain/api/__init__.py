"""AiSOC 大脑 — FastAPI 接口层（阶段 4 完整版）。

端口：6657（aisoc-docs 01）。
路由：
    POST /api/tasks                  创建任务（单域 或 pipeline 多阶段）
    GET  /api/tasks/{task_id}        任务状态 + 思维链
    GET  /api/tasks/{task_id}/export 审计导出（JSON）
    GET  /api/findings               查询证据（?task_id=）
    GET  /api/reports/{task_id}      报告
    GET  /api/registry               部件注册表
    GET  /api/data/alarms            深信服 XDR 告警（样例模式）
    GET  /api/data/alarms/summary    告警统计
    GET  /api/stream                 实时事件流（SSE）
    POST /api/approve                审批应答（记录账本）
    GET  /api/health                 健康检查
    /                                前端面板（static/index.html）
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import mimetypes
import os
import queue
import re
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import httpx

import account.service as account
from account.service import AccountError
from config.settings import settings
from data_source import get_sample_loader
from data_source.xdr_client import live_enabled
from eventhub import get_hub
from llm import chat_stream, chat_stream_events, chat_text
from orchestrator import (
    PIPELINES,
    BrainError,
    _auth_headers,
    check_target_whitelisted,
    gc_expired_sessions,
    get_registry,
    intent_is_task,
    part_busy,
    parse_task_intent,
    run_task,
)
from protocol import Domain, TaskStatus, new_task_id
import runtime_settings
from session import get_store
import whitelist

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("aisoc-brain")

# ---- 附件上传（19 号方案：小文本内联 + 服务端副本） ----

_ATTACHMENT_MAX_BYTES = 50 * 1024 * 1024  # 50 MB 上限（21 号 §3.1）
_ATTACHMENT_PENDING_TTL_S = 24 * 3600     # _pending 未 bind 清理阈值（21 号 §3.4）
_ATTACHMENT_ALLOWED_EXTS = {
    "txt", "log", "bin", "exe", "json", "csv", "md", "out",
    "pcap", "pcapng", "xml", "html", "htm", "pdf", "png", "jpg",
    "jpeg", "gif", "zip", "tar", "gz", "sql", "yaml", "yml", "sh",
}


def _resolve_attachment_dir() -> str:
    override = os.environ.get("BRAIN_ATTACHMENT_DIR")
    if override:
        return override
    rx = os.environ.get("REASONIX_HOME")
    if rx:
        return str(Path(rx).joinpath(".reasonix", "attachments").as_posix())
    return str(Path.home().joinpath(".reasonix", "attachments").as_posix())


ATTACHMENT_DIR = _resolve_attachment_dir()


def _attachment_filename(name: str, ts: float) -> str:
    """生成安全落盘文件名：clipboard-<ts>.<扩展名>。

    - 只取原始文件名的最后一个扩展名，且必须在白名单内，否则无扩展名
    - 路径穿越（../../etc/passwd）→ basename 后无合法扩展 → 中性化为 clipboard-<ts>
    - ts 转无点字符串，避免 float 小数点进入文件名
    """
    base = Path(name or "").name
    ext = ""
    if "." in base:
        candidate = base.rsplit(".", 1)[1].lower()
        if candidate in _ATTACHMENT_ALLOWED_EXTS:
            ext = candidate
    ts_str = str(ts).replace(".", "")
    return f"clipboard-{ts_str}.{ext}" if ext else f"clipboard-{ts_str}"


def _safe_attachment_filename(name: str, ts: float) -> str:
    """19 号 §3.2：保留 safe 后的用户原始文件名（clipboard 命名只作兜底）。

    规则：
    - 取 basename，去掉路径成分与非法字符（控制字符、\\/:*?"<>|）
    - stem 截断到 64 字符；扩展名保留原始（小写，仅字母数字，最长 10）
    - 加时间戳防同名覆盖：{stem}_{ts}.{ext}；无扩展名则无点
    """
    base = Path(name or "").name
    cleaned = re.sub(r"[\x00-\x1f\\/:*?\"<>|]", "_", base).strip(" .")
    if not cleaned:
        return f"clipboard-{str(ts).replace('.', '')}"
    if "." in cleaned:
        stem, _, ext = cleaned.rpartition(".")
        stem = stem[:64] or "file"
        ext = re.sub(r"[^a-z0-9]", "", ext.lower())[:10]
    else:
        stem, ext = cleaned[:64], ""
    ts_str = str(ts).replace(".", "")
    return f"{stem}_{ts_str}.{ext}" if ext else f"{stem}_{ts_str}"


def _safe_attachment_name(name: str) -> str:
    """21 号 §2：safe-name（去路径穿越、去控制字符），保留原始文件名，不加时间戳。"""
    base = Path(name or "").name
    cleaned = re.sub(r"[\x00-\x1f\\/:*?\"<>|]", "_", base).strip(" .")
    if not cleaned:
        return "file"
    return cleaned[:128]


def _attachment_user_dir(user_id: str) -> Path:
    return Path(_resolve_attachment_dir()) / user_id


def _safe_join_user_dir(user_id: str, *parts: str) -> Path:
    """在用户附件目录下安全拼接相对路径，realpath 校验防穿越（21 号 §3.5）。"""
    base = _attachment_user_dir(user_id)
    base.mkdir(parents=True, exist_ok=True)
    base = base.resolve()
    rel = "/".join(p for p in parts if p)
    target = (base / rel).resolve()
    if not str(target).startswith(str(base) + os.sep):
        raise ValueError("附件路径越界")
    return target


def _pending_gc() -> int:
    """21 号 §3.4：清理超过 24h 未 bind 的 _pending 文件（含空 _pending 目录）。

    返回删除的文件数；异常一律捕获，不影响调用方。
    """
    root = Path(_resolve_attachment_dir())
    removed = 0
    cutoff = time.time() - _ATTACHMENT_PENDING_TTL_S
    try:
        if not root.is_dir():
            return 0
        for pending_dir in root.glob("*/_pending"):
            if not pending_dir.is_dir():
                continue
            for f in pending_dir.iterdir():
                try:
                    if f.is_file() and f.stat().st_mtime < cutoff:
                        f.unlink()
                        removed += 1
                except OSError:
                    continue
            # 空目录清理
            try:
                if not any(pending_dir.iterdir()):
                    pending_dir.rmdir()
            except OSError:
                pass
    except OSError:
        pass
    return removed


class SaveAttachmentRequest(BaseModel):
    name: Optional[str] = Field(default=None, description="原始文件名（仅用于提取扩展名）")
    dataUrl: Optional[str] = Field(default=None, description="data:<mime>;base64,<data> 或纯 base64")
    conversation_id: Optional[str] = Field(default=None, description="会话 ID（21 号 §3.1）；无则落 _pending 并返回 upload_id")


class BindAttachmentsRequest(BaseModel):
    upload_ids: list[str] = Field(description="pending 上传返回的 upload_id 列表")
    conversation_id: str = Field(description="目标会话 ID（必须属于当前用户）")

app = FastAPI(
    title="AiSOC 大脑（校园智盾）",
    description="多 Agent 安全运营平台大脑：编排调度 · 威胁判定 · 会话管理 · 审计留档 · 报告",
    version="0.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---- 部件会话缓存 GC（启动期后台 task，每 30 分钟跑一次） ----
async def _session_gc_loop() -> None:
    """每 30 分钟清理一次 (session_id, domain) 过期条目。"""
    while True:
        try:
            await asyncio.sleep(30 * 60)
            n = gc_expired_sessions()
            if n:
                logger.info(f"[api] 后台 GC 清理 {n} 条过期会话缓存")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"[api] 会话 GC 异常（忽略）: {e}")


async def _pending_gc_loop() -> None:
    """21 号 §3.4：每小时清理一次超过 24h 未 bind 的 _pending 附件。"""
    while True:
        try:
            await asyncio.sleep(60 * 60)
            n = await asyncio.to_thread(_pending_gc)
            if n:
                logger.info(f"[api] 附件 pending GC 清理 {n} 个过期文件")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"[api] 附件 pending GC 异常（忽略）: {e}")


@app.on_event("startup")
async def _on_startup() -> None:
    app.state.session_gc_task = asyncio.create_task(_session_gc_loop())
    logger.info("[api] 会话缓存 GC 后台任务已启动（周期 30 分钟）")
    app.state.pending_gc_task = asyncio.create_task(_pending_gc_loop())
    logger.info("[api] 附件 pending GC 后台任务已启动（周期 1 小时，TTL 24h）")

    # RAG 幂等播种：后台线程执行（chroma 首次建库算 embedding 略慢，不阻塞启动；
    # 库已存在则立刻跳过）。启动瞬间 ingest 的检索可能在库就绪前返回空=无注入，属正常。
    def _rag_seed():
        try:
            from rag import get_knowledge_base
            get_knowledge_base().ensure_seeded()
        except Exception as e:
            logger.warning(f"[RAG] 后台播种异常: {e}")

    threading.Thread(target=_rag_seed, daemon=True).start()


@app.on_event("shutdown")
async def _on_shutdown() -> None:
    task = getattr(app.state, "session_gc_task", None)
    if task:
        task.cancel()


# 统一错误体：{"error": "...", "detail": "..."}（前端契约）；带 code 时补 code（15 号契约）
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    content = {"error": str(exc.detail), "detail": str(exc.detail)}
    code = (exc.headers or {}).get("X-Error-Code")
    if code:
        content["code"] = code
    return JSONResponse(status_code=exc.status_code, content=content)


@app.exception_handler(AccountError)
async def account_error_handler(request, exc: AccountError):
    return JSONResponse(
        status_code=exc.status,
        content={"error": exc.message, "detail": exc.message, "code": exc.code},
    )


# ---- API Models ----

class TaskRequest(BaseModel):
    task: str = Field(description="自然语言任务描述")
    domain: str = Field(description="路由域：pentest | logaudit", examples=["logaudit"])
    target: str = Field(description="目标 IP/域名/URL，必须在授权白名单内", examples=["demo-campus.edu.cn"])
    params: dict = Field(default_factory=dict)
    tools: list[str] = Field(default_factory=list)
    pipeline: Optional[str] = Field(default=None, description="多阶段管道：data_leak（可空）", examples=["data_leak"])
    session_id: Optional[str] = Field(default=None, description="前端会话 ID；同会话内复用部件上下文，换会话自动重置（aisoc-docs 14 §会话隔离）")


class ApproveRequest(BaseModel):
    task_id: str
    action: str = Field(description="审批的动作，如 firewall_block")
    decision: str = Field(description="approved | denied")


class TirDecisionRequest(BaseModel):
    decision: str = Field(description="approve | reject")
    operator: str = Field(default="aisoc-brain", description="操作者标识")
    reject_reason: str = Field(default="", description="拒绝原因（decision=reject 时）")


class ChatRequest(BaseModel):
    message: str = Field(description="用户消息")
    system: str = Field(default="你是 AiSOC 校园安全运营助手，回答简洁专业。")
    pass_through: bool = Field(default=False, description="true 时部件事件原样透传（10 号契约）")
    session_id: Optional[str] = Field(default=None, description="前端会话 ID；同会话内复用部件上下文，换会话自动重置")
    conversation_id: Optional[str] = Field(default=None, description="历史对话 ID（已登录用户可传，流结束后自动落库）")
    project_id: Optional[str] = Field(default=None, description="项目 ID（17 号 §5.8：创建会话时写入 conversations.project_id）")
    domain: Optional[str] = Field(default=None, description="显式路由域（L-3）：pentest|logaudit|intel|incident，传了优先于意图推断")
    target: Optional[str] = Field(default=None, description="显式目标 IP/域名/URL（L-3），传了优先于意图推断并直接建任务")
    pipeline: Optional[str] = Field(default=None, description="显式管道（L-3）：如 data_leak，传了优先于意图推断")
    attachments: Optional[list[dict]] = Field(default=None, description="附件元数据（21 号 §3.3）：[{name,path}]，只注入路径引用，不内联全文")
    use_rag: bool = Field(default=True, description="true 时普通问答前先检索本地安全知识库并注入上下文")
    use_memory: bool = Field(default=True, description="true 时检索用户长期记忆并注入上下文（16 号方案 B3）")
    use_profile: bool = Field(default=True, description="true 时注入用户画像（M2 落地，M1 预留字段）")


class RegisterRequest(BaseModel):
    username: str = Field(description="3-20 位字母/数字/下划线")
    email: str = Field(description="合法邮箱")
    password: str = Field(description="明文密码（TLS 保护）")
    confirmPassword: str = Field(description="必须与 password 一致")
    phone: Optional[str] = Field(default=None)


class LoginRequest(BaseModel):
    identifier: str = Field(description="用户名或邮箱")
    password: str = Field(description="明文密码")
    remember: bool = Field(default=False)


class PasswordChangeRequest(BaseModel):
    oldPassword: str
    newPassword: str


class ConversationCreateRequest(BaseModel):
    title: Optional[str] = Field(default=None)
    domain: Optional[str] = Field(default=None)
    tabId: Optional[str] = Field(default=None)
    projectId: Optional[str] = Field(default=None)
    project_id: Optional[str] = Field(default=None)


class ConversationUpdateRequest(BaseModel):
    title: Optional[str] = None
    pinned: Optional[bool] = None
    status: Optional[str] = None
    projectId: Optional[str] = None
    project_id: Optional[str] = None


class MessageAppendRequest(BaseModel):
    role: str = Field(description="user | assistant | tool | system")
    content: str
    reasoning: Optional[str] = None
    toolName: Optional[str] = None
    toolArgs: Optional[dict] = None
    toolOutput: Optional[str] = None
    toolExitCode: Optional[int] = None
    model: Optional[str] = None


class MemoryCreateRequest(BaseModel):
    content: str = Field(description="记忆内容，1-2000 字")
    type: Optional[str] = Field(default=None, description="fact | preference | goal | entity | skill")
    importance: Optional[int] = Field(default=None, description="0-100，手动标记强制 >=80")
    keywords: Optional[list[str]] = Field(default=None)


class MemoryUpdateRequest(BaseModel):
    content: Optional[str] = None
    type: Optional[str] = None
    importance: Optional[int] = None
    keywords: Optional[list[str]] = None


class RuntimeSettingsBody(BaseModel):
    defaultToolApprovalMode: Optional[str] = None
    autoPlan: Optional[str] = None
    memoryCompilerEnabled: Optional[bool] = None
    subagentEffort: Optional[str] = None
    maxSubagentDepth: Optional[int] = None
    coldResumePrune: Optional[bool] = None
    reasoningLanguage: Optional[str] = None


class WhitelistBody(BaseModel):
    action: str = Field(description="add | remove | set_enabled")
    target: Optional[str] = None
    enabled: Optional[bool] = None


# ---- 认证辅助（15 号契约 §4；可选认证：无 token 不强制） ----

def _bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    prefix = "Bearer "
    if authorization.startswith(prefix):
        return authorization[len(prefix):].strip()
    return authorization.strip()


def require_user(authorization: Optional[str] = Header(default=None)) -> dict:
    token = _bearer_token(authorization)
    user = account.get_user_by_token(token) if token else None
    if user is None:
        raise HTTPException(status_code=401, detail="未登录或 token 已失效",
                            headers={"X-Error-Code": "UNAUTHORIZED"})
    return user


def optional_user(authorization: Optional[str] = Header(default=None)) -> Optional[dict]:
    """可选认证：不带 token → None；带了但无效 → 401。"""
    token = _bearer_token(authorization)
    if not token:
        return None
    user = account.get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="无效或过期的 token",
                            headers={"X-Error-Code": "INVALID_TOKEN"})
    return user


# ---- Routes ----

@app.get("/")
async def root():
    return {
        "name": "AiSOC 大脑（校园智盾）",
        "version": "0.4.0",
        "docs": "/docs",
        "panel": "/static/index.html",
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "aisoc-brain"}


@app.post("/save-attachment")
@app.post("/api/save-attachment")
async def save_attachment(req: SaveAttachmentRequest, user: dict = Depends(require_user)):
    """附件上传（21 号方案）：会话级目录落盘。

    - 带 conversation_id：校验会话归属（非本人 404）→ 落 {root}/{userId}/{convId}/{safeName}
    - 不带 conversation_id：落 {root}/{userId}/_pending/{uploadId}_{safeName}，返回 upload_id
    - 单文件上限 50MB（解码后），超限 413；未带 Bearer 401
    """
    name = (req.name or "").strip()
    data_url = (req.dataUrl or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name 不能为空")
    if not data_url:
        raise HTTPException(status_code=400, detail="dataUrl 不能为空")

    # 解析 dataUrl：data:<mime>;base64,<payload> 或纯 base64
    payload = data_url
    if "," in data_url and data_url.split(",", 1)[0].lower().endswith("base64"):
        payload = data_url.split(",", 1)[1].strip()
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="dataUrl 不是合法 base64")

    if len(raw) == 0 or len(raw) > _ATTACHMENT_MAX_BYTES:
        raise HTTPException(status_code=413, detail="attachment exceeds 50MB limit")

    safe_name = _safe_attachment_name(name)
    if req.conversation_id:
        conv = account.get_conversation(user["id"], req.conversation_id)
        if conv is None:
            raise HTTPException(status_code=404, detail="会话不存在",
                                headers={"X-Error-Code": "NOT_FOUND"})
        target_dir = _safe_join_user_dir(user["id"], req.conversation_id)
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / safe_name).write_bytes(raw)
        rel_path = f"{user['id']}/{req.conversation_id}/{safe_name}"
        logger.info(f"[api] 附件落盘 {rel_path}（{len(raw)} bytes, user={user['id']}）")
        return {"path": rel_path, "name": safe_name, "size": len(raw),
                "conversation_bound": True}
    # 无会话：落 _pending，返回 upload_id
    upload_id = uuid.uuid4().hex
    pending_dir = _safe_join_user_dir(user["id"], "_pending")
    pending_dir.mkdir(parents=True, exist_ok=True)
    pending_name = f"{upload_id}_{safe_name}"
    (pending_dir / pending_name).write_bytes(raw)
    rel_path = f"{user['id']}/_pending/{pending_name}"
    logger.info(f"[api] 附件落 pending {rel_path}（{len(raw)} bytes, user={user['id']}）")
    return {"path": rel_path, "upload_id": upload_id, "name": safe_name,
            "size": len(raw), "conversation_bound": False}


@app.post("/api/attachments/bind")
async def bind_attachments(req: BindAttachmentsRequest, user: dict = Depends(require_user)):
    """21 号 §3.2：把 _pending 文件 move 进会话目录（前端收到 conversation_bound 帧后调用）。"""
    conv = account.get_conversation(user["id"], req.conversation_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="会话不存在",
                            headers={"X-Error-Code": "NOT_FOUND"})
    pending_dir = _safe_join_user_dir(user["id"], "_pending")
    target_dir = _safe_join_user_dir(user["id"], req.conversation_id)
    target_dir.mkdir(parents=True, exist_ok=True)

    bound: list[str] = []
    for upload_id in req.upload_ids:
        uid = (upload_id or "").strip()
        if not uid or "/" in uid or ".." in uid or "\\" in uid:
            continue
        # 找到 _pending 下该 upload_id 开头的文件（{uploadId}_{safeName}）
        matches = sorted(pending_dir.glob(f"{uid}_*"))
        if not matches:
            continue
        src = matches[0]
        safe_name = src.name[len(uid) + 1:]  # 去掉 uploadId_ 前缀
        dst = target_dir / safe_name
        shutil.move(str(src), str(dst))
        bound.append(f"{user['id']}/{req.conversation_id}/{safe_name}")
        logger.info(f"[api] 附件绑定 {src.name} -> {user['id']}/{req.conversation_id}/{safe_name}")
    return {"bound": bound}


def _attachment_authorized_path(user_id: str, path: str) -> Path:
    """21 号 §3.6 共用路径鉴权：path 首段必须等于当前用户，且 realpath 落在用户目录下。"""
    parts = [p for p in (path or "").replace("\\", "/").split("/") if p]
    if not parts or parts[0] != user_id:
        raise HTTPException(status_code=404, detail="附件不存在")
    # 首段用户段对齐后，剩余段逐段过 safe 校验（去 .. 防穿越）
    rel_parts = parts[1:]
    if any(p in ("..", ".") or not p for p in rel_parts):
        raise HTTPException(status_code=404, detail="附件不存在")
    try:
        return _safe_join_user_dir(user_id, *rel_parts)
    except (ValueError, OSError):
        raise HTTPException(status_code=404, detail="附件不存在")


_TEXT_ATTACHMENT_EXTS = {
    ".txt", ".log", ".md", ".csv", ".json", ".xml", ".html", ".htm",
    ".yaml", ".yml", ".sh", ".sql", ".out", ".conf", ".ini",
}


def _mime_for(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in _TEXT_ATTACHMENT_EXTS:
        return "text/plain"
    mime, _ = mimetypes.guess_type(str(path))
    return mime or "application/octet-stream"


def _attachment_augmented_message(user_id: str, message: str,
                                  attachments: Optional[list[dict]]) -> str:
    """21 号 §3.3：附件只注入路径引用，不内联全文。"""
    hints = []
    for a in (attachments or [])[:8]:
        if not isinstance(a, dict):
            continue
        name = str(a.get("name") or "").strip()
        rel = str(a.get("path") or "").strip()
        if not name or not rel:
            continue
        try:
            target = _attachment_authorized_path(user_id, rel)
        except HTTPException:
            continue
        if not target.is_file():
            continue
        size = target.stat().st_size
        hints.append(f"[附件] {name} → {target}（{size} bytes，可用 read_file / logaudit 工具读取）")
    if not hints:
        return message
    return f"{message}\n\n" + "\n".join(hints)


@app.get("/api/attachments/file")
async def get_attachment_file(path: str, user: dict = Depends(require_user)):
    """21 号 §3.6：下载原始字节流。path={userId}/{convId}/{name}，非本人 404。"""
    target = _attachment_authorized_path(user["id"], path)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="附件不存在")
    name = target.name
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{name}",
        "X-Content-Type-Options": "nosniff",
    }
    return FileResponse(str(target), media_type=_mime_for(target), headers=headers)


@app.get("/api/attachments/preview")
async def preview_attachment(path: str, max_bytes: int = 65536,
                             user: dict = Depends(require_user)):
    """21 号 §3.6：文本类附件回前 N 字节预览；二进制 415；非本人 404。"""
    max_bytes = min(max(max_bytes, 1), 256 * 1024)  # 上限 256KB
    target = _attachment_authorized_path(user["id"], path)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="附件不存在")
    mime = _mime_for(target)
    if mime.startswith("image/"):
        # 图片直接走 file 端点 <img>，preview 返回可下载信息
        return {"text": None, "truncated": False, "size": target.stat().st_size, "mime": mime}
    if mime != "text/plain" and not mime.startswith("text/"):
        # 二进制（pcap/压缩包等）不可预览
        raise HTTPException(status_code=415, detail=f"{mime} 不可预览")
    size = target.stat().st_size
    with open(target, "rb") as fh:
        chunk = fh.read(max_bytes)
    text = chunk.decode("utf-8", errors="replace")
    return {"text": text, "truncated": size > max_bytes, "size": size, "mime": mime}


@app.get("/api/rag/search")
async def rag_search(q: str, k: int = 5):
    """RAG 知识检索（演示用，只读 Chroma）。返回命中的安全知识条目 + 相似度分数。

    用法：GET /api/rag/search?q=SQL注入怎么防御&k=5
    q 为空或库空时返回空 hits，不影响调用方。无写库、不调 LLM，零成本。
    """
    q = (q or "").strip()
    if not q:
        return {"query": q, "k": k, "hits": []}
    try:
        from rag import get_knowledge_base
        hits = get_knowledge_base().search_with_scores(q, k=max(1, min(k, 20)))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"检索失败: {e}")
    return {"query": q, "k": k, "hits": hits}


# ---- 认证（15 号契约 §4） ----

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_register(req: RegisterRequest) -> None:
    if not _USERNAME_RE.match(req.username):
        raise HTTPException(status_code=422, detail="用户名需 3-20 位字母/数字/下划线",
                            headers={"X-Error-Code": "INVALID_USERNAME"})
    if not _EMAIL_RE.match(req.email):
        raise HTTPException(status_code=422, detail="邮箱格式不正确",
                            headers={"X-Error-Code": "INVALID_EMAIL"})
    if len(req.password) < 6:
        raise HTTPException(status_code=422, detail="密码至少 6 位",
                            headers={"X-Error-Code": "WEAK_PASSWORD"})
    if req.password != req.confirmPassword:
        raise HTTPException(status_code=422, detail="两次密码不一致",
                            headers={"X-Error-Code": "PASSWORD_MISMATCH"})


@app.post("/api/auth/register", status_code=201)
async def auth_register(req: RegisterRequest):
    _validate_register(req)
    user = account.create_user(req.username, req.email, req.password, req.phone)
    session = account.create_session(user["id"], remember=False)
    return {"user": user, "token": session["token"]}


@app.post("/api/auth/login")
async def auth_login(req: LoginRequest):
    user = account.authenticate_user(req.identifier, req.password)
    if user is None:
        raise HTTPException(status_code=401, detail="用户名或密码错误",
                            headers={"X-Error-Code": "INVALID_CREDENTIALS"})
    if user.status == "suspended":
        raise HTTPException(status_code=403, detail="账户已封禁",
                            headers={"X-Error-Code": "ACCOUNT_SUSPENDED"})
    session = account.create_session(user.id, req.remember)
    return {
        "user": {
            "id": user.id, "username": user.username, "email": user.email,
            "phone": user.phone, "createdAt": user.created_at,
        },
        "token": session["token"],
        "expiresAt": session["expiresAt"],
    }


@app.post("/api/auth/logout")
async def auth_logout(authorization: Optional[str] = Header(default=None)):
    token = _bearer_token(authorization)
    account.revoke_session(token or "")
    return {"ok": True}


@app.get("/api/auth/me")
async def auth_me(user: dict = Depends(require_user)):
    return user


@app.put("/api/auth/password")
async def auth_change_password(req: PasswordChangeRequest, user: dict = Depends(require_user)):
    if len(req.newPassword) < 6:
        raise HTTPException(status_code=422, detail="新密码至少 6 位",
                            headers={"X-Error-Code": "WEAK_PASSWORD"})
    account.change_password(user["id"], req.oldPassword, req.newPassword)
    return {"ok": True}


# ---- 历史对话（15 号契约 §5） ----

@app.get("/api/conversations")
async def list_conversations(page: int = 1, pageSize: int = 50, domain: Optional[str] = None,
                             pinned: Optional[bool] = None, search: Optional[str] = None,
                             project_id: Optional[str] = None,
                             user: dict = Depends(require_user)):
    items, total = account.list_conversations(user["id"], page, pageSize, domain, pinned, search, project_id)
    return {"items": items, "total": total, "page": page, "pageSize": pageSize}


@app.post("/api/conversations", status_code=201)
async def create_conversation(req: ConversationCreateRequest, user: dict = Depends(require_user)):
    return account.create_conversation(user["id"], req.title, req.domain, req.tabId,
                                       req.projectId or req.project_id)


@app.get("/api/conversations/{conversation_id}/messages")
async def get_conversation_messages(conversation_id: str, limit: int = 100, offset: int = 0,
                                    order: str = "desc", user: dict = Depends(require_user)):
    result = account.list_messages(user["id"], conversation_id, limit, offset, order)
    if result is None:
        raise HTTPException(status_code=404, detail="对话不存在", headers={"X-Error-Code": "NOT_FOUND"})
    return result


@app.post("/api/conversations/{conversation_id}/messages")
async def append_conversation_message(conversation_id: str, req: MessageAppendRequest,
                                      user: dict = Depends(require_user)):
    msg = account.append_message(
        user["id"], conversation_id, req.role, req.content, req.reasoning,
        req.toolName, req.toolArgs, req.toolOutput, req.toolExitCode, req.model,
    )
    if msg is None:
        raise HTTPException(status_code=404, detail="对话不存在", headers={"X-Error-Code": "NOT_FOUND"})
    return msg


@app.put("/api/conversations/{conversation_id}")
async def update_conversation(conversation_id: str, req: ConversationUpdateRequest,
                              user: dict = Depends(require_user)):
    conv = account.update_conversation(user["id"], conversation_id, req.title, req.pinned, req.status,
                                       req.projectId if req.projectId is not None else req.project_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="对话不存在", headers={"X-Error-Code": "NOT_FOUND"})
    return conv


@app.delete("/api/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str, user: dict = Depends(require_user)):
    if not account.delete_conversation(user["id"], conversation_id):
        raise HTTPException(status_code=404, detail="对话不存在", headers={"X-Error-Code": "NOT_FOUND"})
    # 21 号 §3.4：级联删除该会话的附件目录
    try:
        conv_dir = _safe_join_user_dir(user["id"], conversation_id)
        if conv_dir.exists():
            shutil.rmtree(conv_dir, ignore_errors=True)
    except (ValueError, OSError):
        logger.warning(f"[api] 删除会话附件目录失败（忽略）: {conversation_id}")
    return {"ok": True}


# ---- 长期记忆（15 号契约 §10 / 16 号方案 B2） ----

@app.get("/api/memory")
async def list_memory(type: Optional[str] = None, q: Optional[str] = None,
                      minImportance: int = 0, page: int = 1, pageSize: int = 20,
                      user: dict = Depends(require_user)):
    items, total = account.list_memories(user["id"], type, q, minImportance, page, pageSize)
    return {"items": items, "total": total, "page": page, "pageSize": pageSize}


@app.post("/api/memory", status_code=201)
async def create_memory(req: MemoryCreateRequest, user: dict = Depends(require_user)):
    return account.create_memory(user["id"], req.content, req.type, req.importance, req.keywords)


@app.patch("/api/memory/{memory_id}")
async def update_memory(memory_id: str, req: MemoryUpdateRequest, user: dict = Depends(require_user)):
    m = account.update_memory(user["id"], memory_id, req.content, req.type, req.importance, req.keywords)
    if m is None:
        raise HTTPException(status_code=404, detail="记忆不存在", headers={"X-Error-Code": "NOT_FOUND"})
    return m


@app.delete("/api/memory/{memory_id}")
async def delete_memory(memory_id: str, user: dict = Depends(require_user)):
    if not account.delete_memory(user["id"], memory_id):
        raise HTTPException(status_code=404, detail="记忆不存在", headers={"X-Error-Code": "NOT_FOUND"})
    return {"ok": True}


@app.post("/api/memory/forget-all")
async def forget_all_memory(user: dict = Depends(require_user)):
    count = account.forget_all_memories(user["id"])
    return {"ok": True, "count": count}


# ---- 项目（前端"添加新项目"） ----

class ProjectCreateRequest(BaseModel):
    name: str = Field(description="项目名称，1-200 字")
    target: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)
    color: Optional[str] = Field(default=None)


class ProjectUpdateRequest(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None
    pinned: Optional[bool] = None
    order: Optional[int] = None
    status: Optional[str] = None


@app.get("/api/projects")
async def list_projects(page: int = 1, page_size: int = 50, q: Optional[str] = None,
                        status: Optional[str] = None, user: dict = Depends(require_user)):
    items, total = account.list_projects(user["id"], page, page_size, q, status)
    return {"items": items, "total": total, "page": page, "pageSize": page_size}


def _validate_project_uuid(project_id: str) -> None:
    """17 号 §5.6：非法 project_id UUID 返回 422。"""
    try:
        uuid.UUID(project_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail="project_id 必须是合法 UUID",
                            headers={"X-Error-Code": "INVALID_PROJECT_ID"})


@app.post("/api/projects", status_code=201)
async def create_project(req: ProjectCreateRequest, user: dict = Depends(require_user)):
    return account.create_project(user["id"], req.name, req.target, req.description, req.color)


@app.get("/api/projects/{project_id}")
async def get_project(project_id: str, user: dict = Depends(require_user)):
    _validate_project_uuid(project_id)
    p = account.get_project(user["id"], project_id)
    if p is None:
        raise HTTPException(status_code=404, detail="项目不存在", headers={"X-Error-Code": "NOT_FOUND"})
    return p


@app.patch("/api/projects/{project_id}")
async def update_project(project_id: str, req: ProjectUpdateRequest, user: dict = Depends(require_user)):
    _validate_project_uuid(project_id)
    fields = req.model_fields_set
    p = account.update_project(
        user["id"], project_id,
        name=req.name if "name" in fields else account._UNSET,
        target=req.target if "target" in fields else account._UNSET,
        description=req.description if "description" in fields else account._UNSET,
        color=req.color if "color" in fields else account._UNSET,
        pinned=req.pinned if "pinned" in fields else None,
        order=req.order if "order" in fields else None,
        status=req.status if "status" in fields else None,
    )
    if p is None:
        raise HTTPException(status_code=404, detail="项目不存在", headers={"X-Error-Code": "NOT_FOUND"})
    return p


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str, user: dict = Depends(require_user)):
    _validate_project_uuid(project_id)
    result = account.delete_project(user["id"], project_id)
    if result is None:
        raise HTTPException(status_code=404, detail="项目不存在", headers={"X-Error-Code": "NOT_FOUND"})
    pid, unbound = result
    return {"ok": True, "id": pid, "unboundConversations": unbound}


def _is_user_attachment_target(target: str, user_id: str) -> bool:
    """L-4：附件绝对路径作为 logaudit 的 target 时，属于当前用户附件目录即放行。"""
    if not target or not user_id:
        return False
    try:
        base = _attachment_user_dir(user_id).resolve()
        p = Path(target).resolve()
        return str(p).startswith(str(base) + os.sep)
    except Exception:
        return False


def _prepare_task(domain: Domain, target: str, params: dict, tools: list[str],
                  pipeline: Optional[str] = None, user_id: str = "") -> dict:
    """创建任务记录（不启动后台线程），供 relay 场景先订阅部件流再派活。"""
    if not _is_user_attachment_target(target, user_id) and not check_target_whitelisted(target):
        raise HTTPException(status_code=403, detail=f"目标不在授权白名单内: {target}")

    part = get_registry().get(domain)  # 部件必须已注册（快速失败）

    task_id = new_task_id()
    store = get_store()
    task_domain = "all" if pipeline else domain.value
    store.create_task(task_id, task_domain, target, user_id=user_id or "")
    get_hub().publish(task_id, task_domain, "task_created", {"target": target, "pipeline": pipeline or domain.value})
    logger.info(f"[api] 收到任务 {task_id} domain={task_domain} target={target} user={user_id or '-'}")
    return {
        "task_id": task_id, "domain": domain, "target": target,
        "pipeline": pipeline, "task_domain": task_domain, "part": part,
    }


def _start_task_thread(domain: Domain, target: str, params: dict, tools: list[str],
                       task_id: str, pipeline: Optional[str] = None,
                       session_id: Optional[str] = None):
    """后台执行 run_task。"""
    store = get_store()

    def _run():
        try:
            run_task(domain, target, params, tools, task_id=task_id, pipeline=pipeline,
                     session_id=session_id)
        except Exception as e:
            logger.exception(f"[api] 后台任务 {task_id} 异常")
            store.transition(task_id, TaskStatus.FAILED, error=str(e))

    threading.Thread(target=_run, daemon=True).start()


def _create_and_run(domain: Domain, target: str, params: dict, tools: list[str],
                    pipeline: Optional[str] = None,
                    session_id: Optional[str] = None, user_id: str = "") -> dict:
    """创建任务并后台派活（/api/tasks 与 /api/assess 共用）。"""
    info = _prepare_task(domain, target, params, tools, pipeline, user_id=user_id)
    _start_task_thread(domain, target, params, tools, info["task_id"], pipeline, session_id)
    return {"task_id": info["task_id"], "status": "pending", "domain": info["task_domain"]}


@app.post("/api/tasks", status_code=202)
async def create_task(req: TaskRequest, user: dict = Depends(require_user)):
    """创建任务：鉴权 → 白名单校验 → 落库（归属当前用户）→ 后台派活（单域或管道）。

    req.task（自然语言任务描述）会并入 params["task"] 一并下发部件，
    与 /api/assess、/api/chat 的意图路由行为保持一致，否则部件只收到
    目标收不到用户要求；调用方若已显式传 req.params["task"]，以显式
    值为准（不覆盖）。
    """
    try:
        domain = Domain(req.domain)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"未知 domain: {req.domain}，可选 {[d.value for d in Domain]}")

    if req.pipeline and req.pipeline not in PIPELINES:
        raise HTTPException(status_code=400, detail=f"未知 pipeline: {req.pipeline}，可选 {list(PIPELINES)}")

    params = dict(req.params)
    if req.task:
        params.setdefault("task", req.task)

    return _create_and_run(domain, req.target, params, req.tools, req.pipeline, req.session_id, user_id=user["id"])


@app.post("/api/assess")
async def assess(req: ChatRequest, user: dict = Depends(require_user)):
    """自然语言一句话 → 自动编排子智能体（chat 转 task）。

    流程：解析意图(域/目标/管道) → 白名单校验 → 创建任务 → 返回 task_id。
    前端拿到 task_id 后，用 /api/stream 和 /api/tasks/{id} 回显进度与结果。
    """
    intent = await asyncio.to_thread(parse_task_intent, req.message)
    if not intent.get("target"):
        return {
            "status": "need_target",
            "reply": "请告诉我目标 IP 或域名，例如：扫描 8.215.92.252",
        }
    if not check_target_whitelisted(intent["target"]):
        return {
            "status": "rejected",
            "reply": f"目标 {intent['target']} 不在授权白名单内，拒绝执行。",
        }
    try:
        result = _create_and_run(intent["domain"], intent["target"], {"task": req.message}, [], intent["pipeline"], req.session_id, user_id=user["id"])
    except HTTPException as e:
        return {"status": "error", "reply": str(e.detail)}

    domain_label = result["domain"]
    pipeline_text = f"，管道 {intent['pipeline']}" if intent["pipeline"] else ""
    return {
        "status": "task_created",
        "task_id": result["task_id"],
        "domain": intent["domain"].value,
        "target": intent["target"],
        "pipeline": intent["pipeline"],
        "reply": f"已创建任务 {result['task_id']}（{domain_label}，目标 {intent['target']}{pipeline_text}），正在执行。",
    }


@app.get("/api/tasks")
async def list_tasks(limit: int = 50, user: dict = Depends(require_user)):
    """当前登录用户的最近任务列表（仪表盘用，用户隔离）。"""
    store = get_store()
    tasks = store.list_tasks(limit=limit, user_id=user["id"])
    for t in tasks:
        t["findings_count"] = len(store.list_findings(t["id"]))
        stages = store.list_stages(t["id"])
        t["stages"] = stages
        running = next((s for s in stages if s["status"] == "running"), None)
        t["current_stage"] = running["stage"] if running else (stages[-1]["stage"] if stages else "")
    return {"tasks": tasks}


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: str, user: dict = Depends(require_user)):
    store = get_store()
    task = store.get_task(task_id)
    if not task or (task.get("user_id") and task["user_id"] != user["id"]):
        raise HTTPException(status_code=404, detail="任务不存在")
    stages = store.list_stages(task_id)
    running = next((s for s in stages if s["status"] == "running"), None)
    current_stage = running["stage"] if running else (stages[-1]["stage"] if stages else "")
    return {
        **task,
        "findings_count": len(store.list_findings(task_id)),
        "stages": stages,
        "current_stage": current_stage,
        "thought_chain": store.list_ledger(task_id),
    }


@app.get("/api/agents/status")
async def agents_status():
    """各身体部件忙闲状态（前端 Agent 状态墙）。"""
    parts = get_registry().list()
    for p in parts:
        p["busy"] = part_busy(p["domain"])
        p.pop("token", None)  # 脱敏

    # 应急响应（TIR）是 REST 子 Agent，不走 reasonix 部件协议，单独探测
    tir_status = "offline"
    try:
        r = httpx.get(f"{settings.TIR_BASE_URL}/api/tir/health", timeout=2)
        tir_status = "ok" if r.status_code == 200 else "offline"
    except Exception:
        tir_status = "offline"

    return {
        "brain": {"status": "ok", "service": "aisoc-brain"},
        "parts": parts,
        "services": {
            "tir": {"name": "应急响应 Agent", "port": 8090, "status": tir_status},
        },
    }


@app.get("/api/tasks/{task_id}/export")
async def export_task(task_id: str, user: dict = Depends(require_user)):
    """审计导出（JSON）：任务 + 证据 + 账本 + 报告。"""
    store = get_store()
    task = store.get_task(task_id)
    if not task or (task.get("user_id") and task["user_id"] != user["id"]):
        raise HTTPException(status_code=404, detail="任务不存在")
    data = store.export_task(task_id)
    if not data:
        raise HTTPException(status_code=404, detail="任务不存在")
    return data


@app.get("/api/findings")
async def list_findings(task_id: str, user: dict = Depends(require_user)):
    store = get_store()
    task = store.get_task(task_id)
    if not task or (task.get("user_id") and task["user_id"] != user["id"]):
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"task_id": task_id, "findings": store.list_findings(task_id)}


@app.get("/api/reports/{task_id}")
async def get_report(task_id: str, user: dict = Depends(require_user)):
    store = get_store()
    task = store.get_task(task_id)
    if not task or (task.get("user_id") and task["user_id"] != user["id"]):
        raise HTTPException(status_code=404, detail="任务不存在")
    report = store.get_report(task_id)
    if not report:
        # 任务存在但报告未生成（运行中/排队）→ 200 + 空 report，避免误导性 404
        return {"task_id": task_id, "report": None,
                "status": task.get("status"), "detail": "报告尚未生成，任务可能仍在运行"}
    return {"task_id": task_id, "report": report["content"]}


@app.get("/api/registry")
async def registry():
    parts = get_registry().list()
    for p in parts:
        p["token"] = "***"  # 脱敏，aisoc-docs 06：token 不落日志/不外泄
    return {"parts": parts}


@app.get("/api/whitelist")
async def get_whitelist():
    """授权白名单（前端管理按钮）。"""
    return whitelist.get()


@app.post("/api/whitelist")
async def update_whitelist(body: WhitelistBody):
    """编辑白名单：add（加目标）/ remove（删目标）/ set_enabled（开关）。"""
    if body.action == "add":
        if not body.target:
            raise HTTPException(status_code=400, detail="add 需要 target")
        return whitelist.add(body.target)
    if body.action == "remove":
        if not body.target:
            raise HTTPException(status_code=400, detail="remove 需要 target")
        return whitelist.remove(body.target)
    if body.action == "set_enabled":
        if body.enabled is None:
            raise HTTPException(status_code=400, detail="set_enabled 需要 enabled")
        return whitelist.set_enabled(body.enabled)
    raise HTTPException(status_code=400, detail="action 只支持 add / remove / set_enabled")


@app.get("/api/data/alarms")
async def data_alarms(limit: int = 50, source: str = "auto", user: dict = Depends(require_user)):
    """深信服 XDR 告警数据（默认样例模式，配置联动码后可切 live）。"""
    if source == "live":
        if not live_enabled():
            raise HTTPException(status_code=503, detail="XDR live 未配置：请设置 XDR_BASE_URL + XDR_AUTH_CODE")
        raise HTTPException(status_code=501, detail="live 拉取需真实 XDR 环境，当前请用样例模式")
    alarms = get_sample_loader().list(limit=limit)
    return {"source": "sample", "count": len(alarms), "alarms": alarms}


@app.get("/api/data/alarms/summary")
async def data_alarms_summary(user: dict = Depends(require_user)):
    alarms = get_sample_loader().list()
    summary: dict[str, int] = {}
    verdict_hint: dict[str, int] = {}
    for a in alarms:
        summary[a["severity"]] = summary.get(a["severity"], 0) + 1
        verdict_hint[a["verdict_hint"]] = verdict_hint.get(a["verdict_hint"], 0) + 1
    return {"total": len(alarms), "by_severity": summary, "by_verdict_hint": verdict_hint}


@app.get("/api/stream")
async def stream():
    """实时事件流（SSE）—— 前端实时面板数据源。"""
    hub = get_hub()
    q = hub.subscribe()

    async def gen():
        try:
            while True:
                try:
                    event = await asyncio.to_thread(q.get, timeout=15)
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                except Exception:
                    yield ": ping\n\n"
        finally:
            hub.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/api/approve")
async def approve(req: ApproveRequest):
    """审批应答（阶段 4 记录账本；审批门控在处置流程接入时启用）。"""
    store = get_store()
    if not store.get_task(req.task_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    store.add_ledger(req.task_id, "human", f"approval_{req.decision}", {"action": req.action})
    return {"task_id": req.task_id, "action": req.action, "decision": req.decision, "status": "recorded"}


# ---- TIR 查询代理（L-1：大脑 6657 → 8090，鉴权 + 用户隔离） ----

def _tir_proxy_list(kind: str, task_id: Optional[str], user_id: str) -> dict:
    """拉 8090 的 alerts/playbooks/reports 并按 task_id 过滤（8090 不做过滤）。"""
    store = get_store()
    if not task_id:
        return {kind: []}
    task = store.get_task(task_id)
    if not task or (task.get("user_id") and task["user_id"] != user_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.get("verdict") != "real_threat":
        return {kind: []}
    try:
        r = httpx.get(f"{settings.TIR_BASE_URL}/api/tir/{kind}", timeout=8)
        r.raise_for_status()
        items = r.json().get(kind, [])
        mine = [a for a in items if str(a.get("task_id")) == str(task_id)]
        if kind == "playbooks":
            # P2-1：同一 alert 可能生成多份 playbook，按 alert_id 去重只保留首份
            seen: set[str] = set()
            deduped = []
            for p in mine:
                aid = str(p.get("alert_id", ""))
                if aid and aid in seen:
                    continue
                seen.add(aid)
                deduped.append(p)
            mine = deduped
        return {kind: mine}
    except Exception as e:
        logger.warning(f"[tir] {kind} 代理失败: {e}")
        return {kind: []}


@app.get("/api/tir/alerts")
async def tir_alerts(task_id: Optional[str] = None, user: dict = Depends(require_user)):
    return _tir_proxy_list("alerts", task_id, user["id"])


@app.get("/api/tir/playbooks")
async def tir_playbooks(task_id: Optional[str] = None, user: dict = Depends(require_user)):
    return _tir_proxy_list("playbooks", task_id, user["id"])


@app.get("/api/tir/reports")
async def tir_reports(task_id: Optional[str] = None, user: dict = Depends(require_user)):
    return _tir_proxy_list("reports", task_id, user["id"])


@app.post("/api/tir/playbooks/{playbook_id}/decision")
async def tir_playbook_decision(playbook_id: str, req: TirDecisionRequest,
                                user: dict = Depends(require_user)):
    """P0-1：预案审批代理 → 8090 生成 TIR report（responded/recorded）。

    用户隔离：先按 playbook_id 找到其 task_id，校验任务归属当前用户。
    """
    try:
        r = httpx.get(f"{settings.TIR_BASE_URL}/api/tir/playbooks", timeout=8)
        r.raise_for_status()
        pb = next((p for p in r.json().get("playbooks", [])
                   if str(p.get("playbook_id")) == str(playbook_id)), None)
    except Exception:
        pb = None
    if pb is None:
        raise HTTPException(status_code=404, detail="预案不存在")
    tid = str(pb.get("task_id", ""))
    task = get_store().get_task(tid)
    if not task or (task.get("user_id") and task["user_id"] != user["id"]):
        raise HTTPException(status_code=404, detail="预案不存在")
    try:
        r = httpx.post(f"{settings.TIR_BASE_URL}/api/tir/playbooks/{playbook_id}/decision",
                       json={"decision": req.decision, "operator": req.operator,
                             "reject_reason": req.reject_reason},
                       timeout=15)
        r.raise_for_status()
        body = r.json()
        # 记录账本（recorded 形态，供报告思维链/审批留档）
        get_store().add_ledger(tid, "human", f"tir_decision_{req.decision}",
                               {"playbook_id": playbook_id, "resp": body})
        return body
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code,
                            detail=f"TIR decision 失败: {e.response.text[:200]}")
    except Exception as e:
        logger.warning(f"[tir] decision 代理失败: {e}")
        raise HTTPException(status_code=502, detail="TIR 服务不可达")


# ---- 模拟 WAF 代理（L-2：大脑 6657 → 8788，处置回注演示） ----

@app.post("/api/mock/waf/{path:path}")
async def mock_waf_proxy(path: str, req: Request, user: dict = Depends(require_user)):
    """转发模拟 WAF 指令到 8788（logaudit 部件），保留响应体。"""
    try:
        part = get_registry().get(Domain.LOGAUDIT)
    except Exception:
        raise HTTPException(status_code=502, detail="日志审计部件未注册")
    try:
        body = await req.body()
        headers = _auth_headers(part.token, part.auth)
        headers["Content-Type"] = "application/json"
        r = httpx.post(f"{part.base_url}/mock/waf/{path}", content=body or b"{}",
                       headers=headers, timeout=10)
        return JSONResponse(status_code=r.status_code, content=r.json())
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="模拟 WAF 服务超时")
    except Exception as e:
        logger.warning(f"[api] mock waf 代理失败: {e}")
        raise HTTPException(status_code=502, detail="模拟 WAF 服务不可达")


def _rag_augmented_system(system: str, message: str, k: int = 3) -> str:
    """若本地知识库已就绪，检索与问题相关的知识，把摘要追加到 system 提示后。

    幂等安全：库空 / chroma 未装 / 检索无命中 → 原样返回 system（RAG 不生效=无扰动）。
    命中才返回扩充后的 system，供 chat 逻辑嵌入 messages。
    """
    try:
        from rag import get_knowledge_base
        hits = get_knowledge_base().search_with_scores(message, k=k)
        if hits:
            ctx = "\n".join(f"- {h['content']}" for h in hits)
            return (f"{system}\n\n[以下为本机构建的安全知识库检索结果，可据此给出基于本库的建议，"
                    f"仅作参考，勿逐字照抄]\n{ctx}")
    except Exception as e:
        logger.warning(f"[RAG] 检索失败，跳过注入: {e}")
    return system


def _memory_augmented_system(system: str, entries: list[dict]) -> str:
    """把命中的用户长期记忆以固定段落注入 system prompt（16 号方案 B3.3）。"""
    if not entries:
        return system
    lines = "\n".join(f"- [{e.get('type', 'fact')}] {e.get('content', '')}" for e in entries)
    return (f"{system}\n\n[用户长期记忆]\n以下是系统记录的、关于该用户的长期信息，"
            f"若与当前问题相关请自然使用，不要逐字复述：\n{lines}")


def _memory_enabled() -> bool:
    """长期记忆总开关（16 号方案 B7：memoryCompilerEnabled 真正被对话管线读取）。"""
    try:
        return bool(runtime_settings.get_all().get("memoryCompilerEnabled", False))
    except Exception:
        return False


def _chat_or_task(message: str, system: str, start: bool = True,
                  session_id: Optional[str] = None, use_rag: bool = True,
                  user_id: str = "", domain: Optional[str] = None,
                  target: Optional[str] = None, pipeline: Optional[str] = None) -> dict:
    """聊天入口的意图路由：任务意图 → 创建任务；闲聊 → 正常回复。

    start=False 时只创建任务记录、不启动后台线程（供 chat/stream 先订阅部件流再派活）。

    session_id 不为空时，任务意图会透传到下游 run_task，使同会话内多个任务复用部件上下文。
    user_id 不为空时，任务归属该登录用户（16 号方案 B8 用户隔离）。

    L-3：显式传 domain/target/pipeline 时优先于 parse_task_intent 的推断结果，
    并对 domain/pipeline 做合法性校验。
    """
    intent = parse_task_intent(message)
    explicit_task = False
    if domain:
        try:
            intent["domain"] = Domain(domain)
        except ValueError:
            return {"kind": "reply", "reply": f"未知 domain: {domain}，可选 {[d.value for d in Domain]}"}
    if target:
        intent["target"] = target
        explicit_task = True
    if pipeline:
        if pipeline not in PIPELINES:
            return {"kind": "reply", "reply": f"未知 pipeline: {pipeline}，可选 {list(PIPELINES)}"}
        intent["pipeline"] = pipeline
        explicit_task = True
    if intent_is_task(message, intent) or explicit_task:
        if not intent.get("target"):
            return {"kind": "reply", "reply": "请告诉我目标 IP 或域名，例如：扫描 8.215.92.252"}
        if not _is_user_attachment_target(intent["target"], user_id) and not check_target_whitelisted(intent["target"]):
            return {"kind": "reply", "reply": f"目标 {intent['target']} 不在授权白名单内，拒绝执行。"}
        try:
            info = _prepare_task(intent["domain"], intent["target"], {"task": message}, [], intent["pipeline"],
                                 user_id=user_id)
        except HTTPException as e:
            return {"kind": "reply", "reply": str(e.detail)}
        if start:
            _start_task_thread(intent["domain"], intent["target"], {"task": message}, [],
                               info["task_id"], intent["pipeline"], session_id)
        pipeline_text = f"，管道 {intent['pipeline']}" if intent["pipeline"] else ""
        result = {
            "kind": "task",
            "task_id": info["task_id"],
            "domain": intent["domain"].value,
            "target": intent["target"],
            "pipeline": intent["pipeline"],
            "part": info["part"],
            "reply": (f"已创建任务 {info['task_id']}（{intent['domain'].value}，"
                      f"目标 {intent['target']}{pipeline_text}），正在执行。"),
        }
        if not start:
            return result
        result.pop("part", None)  # 非 relay 场景不外泄 part 对象
        return result
    if use_rag:
        system = _rag_augmented_system(system, message)
    return {
        "kind": "chat",
        "reply": chat_text([
            {"role": "system", "content": system},
            {"role": "user", "content": message},
        ]),
    }


@app.post("/api/chat")
async def chat(req: ChatRequest, user: Optional[dict] = Depends(optional_user)):
    """通用聊天接口（DeepSeek，非流式）；任务意图会自动转成任务。"""
    system = req.system
    if user is not None and req.use_memory and _memory_enabled():
        try:
            entries = await asyncio.to_thread(account.retrieve_memories, user["id"], req.message, 5, 40)
            system = _memory_augmented_system(system, entries)
        except Exception as e:
            logger.warning(f"[memory] 召回失败（忽略）: {e}")
    return _chat_or_task(req.message, system, session_id=req.session_id, use_rag=req.use_rag,
                         user_id=(user["id"] if user else ""),
                         domain=req.domain, target=req.target, pipeline=req.pipeline)


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


def _map_part_event(ev: dict, task_id: str) -> Optional[dict]:
    """部件 /events 原生事件 → chat 帧（07-chat-stream-adaptive-relay §6.2，兼容 adapter 小写 kind）。"""
    k = str(ev.get("kind") or ev.get("type") or "").lower()
    if k in ("reasoning", "thinking"):
        return {"thinking": ev.get("text") or ev.get("reasoning") or "", "task_id": task_id}
    if k in ("tool_call", "tool_dispatch"):
        tool = ev.get("tool") or {}
        name = tool.get("name") if isinstance(tool, dict) else tool
        return {"tool_call": {"tool": name or "", "args": ev.get("args") or {}}, "task_id": task_id}
    if k == "tool_result":
        tool = ev.get("tool") or {}
        name = tool.get("name") if isinstance(tool, dict) else tool
        return {
            "tool_result": {
                "tool": name or "",
                "output": ev.get("output") or ev.get("text") or "",
                "exit_code": ev.get("exit_code"),
            },
            "task_id": task_id,
        }
    if k in ("message", "text", "answer"):
        return {"answer": {"text": ev.get("text") or ""}, "task_id": task_id}
    if k in ("turn_phase", "phase", "stage_start"):
        return {"stage_start": ev.get("phase") or ev.get("stage") or "", "task_id": task_id}
    if k == "turn_started":
        return {"stage_start": "turn", "task_id": task_id}
    return None


@app.post("/api/chat/stream")
async def chat_stream_endpoint(req: ChatRequest, user: Optional[dict] = Depends(optional_user)):
    """自适应接力流（07-chat-stream-adaptive-relay）。

    普通对话：data: {"delta": ...} → [DONE]
    任务意图：delta 确认 → task_created → 部件完整流接力（thinking/tool_call/tool_result/answer/stage_*）
              → report_ready → [DONE]

    15 号契约 §5.7：已登录用户（Bearer token）会在流结束后自动把本轮对话写入
    conversations / messages 表。不带 token 时行为与旧版完全一致。
    """
    # 登录用户：解析/创建历史对话（可选认证）
    conv_id: Optional[str] = None
    conv_created = False
    # 登录用户：解析/创建历史对话（可选认证）
    conv_id: Optional[str] = None
    conv_created = False
    bound_project_id: Optional[str] = None  # conversation_bound 帧要回填的 projectId
    if user is not None:
        # 17 号 §5.8 规则 1：传了 project_id 先校验归属，不属于当前用户 → 宽容忽略置 None
        project_id = req.project_id
        if project_id:
            if account.get_project(user["id"], project_id) is None:
                project_id = None
        if req.conversation_id:
            conv = account.get_conversation(user["id"], req.conversation_id)
            if conv is None:
                raise HTTPException(status_code=404, detail="对话不存在",
                                    headers={"X-Error-Code": "NOT_FOUND"})
            conv_id = req.conversation_id
            # 17 号 §5.8 规则 3：续接会话以现有 project_id 为准，不覆盖
            bound_project_id = getattr(conv, "project_id", None)
        else:
            conv = account.create_conversation(user["id"], title=(req.message or "新对话")[:30],
                                               project_id=project_id)
            conv_id = conv["id"]
            conv_created = True
            bound_project_id = project_id

    # 长期记忆召回（16 号方案 B3.2：任务意图/普通问答都检索；失败不阻断；总开关 B7）
    memory_entries: list[dict] = []
    if user is not None and req.use_memory and _memory_enabled():
        try:
            memory_entries = await asyncio.to_thread(
                account.retrieve_memories, user["id"], req.message, 5, 40)
        except Exception as e:
            logger.warning(f"[memory] 召回失败（忽略）: {e}")
            memory_entries = []
    system_with_memory = _memory_augmented_system(req.system, memory_entries)

    # 21 号 §3.3：附件只注入路径引用（prompt 不内联全文）
    message = req.message
    if user is not None and req.attachments:
        message = _attachment_augmented_message(user["id"], req.message, req.attachments)

    async def gen():
        # T0-2/T0-3：先建连发帧（会话绑定 + 心跳），意图分类放线程池，不阻塞事件循环
        if user is not None and conv_id:
            yield _sse({"kind": "conversation", "id": conv_id, "created": conv_created})
            # 17 号 §5.9：conversation_bound 帧带 projectId（新建=请求值，续接=DB 现值）
            yield _sse({"kind": "conversation_bound", "conversationId": conv_id,
                        "projectId": bound_project_id})
        yield ": ping\n\n"
        result = await asyncio.to_thread(
            _chat_or_task, message, system_with_memory,
            False, req.session_id, req.use_rag, (user["id"] if user else ""),
            req.domain, req.target, req.pipeline)
        if memory_entries:
            yield _sse({"kind": "memory_retrieved",
                        "entries": [
                            {"id": e["id"], "content": e["content"], "type": e["type"],
                             "importance": e["importance"], "matchedBy": e.get("matchedBy", "keyword")}
                            for e in memory_entries
                        ],
                        "injected": True})

        if result["kind"] == "chat":
            sys_aug = (_rag_augmented_system(system_with_memory, req.message) if req.use_rag else system_with_memory)
            full: list[str] = []
            reasoning_parts: list[str] = []
            if req.pass_through:
                # pass_through 纯聊天：发 reasonix 风格原始帧（无 delta）
                chat_task_id = new_task_id()
                yield _sse({"turn_started": {}, "task_id": chat_task_id})
                for ev in chat_stream_events([
                    {"role": "system", "content": sys_aug},
                    {"role": "user", "content": message},
                ]):
                    if "error" in ev:
                        yield _sse({"kind": "stream_error",
                                    "err": str(ev["error"].get("message", ""))[:500],
                                    "task_id": chat_task_id})
                        break
                    yield _sse({**ev, "task_id": chat_task_id})
                    if ev.get("reasoning"):
                        reasoning_parts.append(ev["reasoning"])
                    if ev.get("text"):
                        full.append(ev["text"])
                yield _sse({"message": {"text": "".join(full)}, "task_id": chat_task_id})
                yield _sse({"turn_done": {}, "task_id": chat_task_id})
            else:
                for delta in chat_stream([
                    {"role": "system", "content": sys_aug},
                    {"role": "user", "content": message},
                ]):
                    full.append(delta)
                    yield _sse({"delta": delta})

            if user is not None and conv_id:
                account.append_message(user["id"], conv_id, "user", req.message)
                account.append_message(
                    user["id"], conv_id, "assistant", "".join(full),
                    reasoning="".join(reasoning_parts) or None,
                    model=settings.DEEPSEEK_MODEL,
                )
            yield "data: [DONE]\n\n"
            return

        if result["kind"] == "reply":
            if req.pass_through:
                yield _sse({"error": {"code": "task_create_failed", "message": result["reply"]}})
            else:
                yield _sse({"delta": result["reply"]})
            if user is not None and conv_id:
                account.append_message(user["id"], conv_id, "user", req.message)
                account.append_message(user["id"], conv_id, "assistant", result["reply"],
                                       model=settings.DEEPSEEK_MODEL)
            yield "data: [DONE]\n\n"
            return

        # ---- 任务意图：先订阅部件流，再派活，然后接力 ----
        task_id = result["task_id"]
        part = result["part"]
        if not req.pass_through:
            yield _sse({"delta": result["reply"]})
            yield _sse({"task_id": task_id, "domain": result["domain"]})

        events: queue.Queue = queue.Queue()
        stop = threading.Event()

        def _listen():
            try:
                with httpx.stream(
                    "GET", f"{part.base_url}/events",
                    headers=_auth_headers(part.token, part.auth),
                    timeout=30,
                ) as r:
                    for line in r.iter_lines():
                        if stop.is_set():
                            break
                        if not line.startswith("data:"):
                            continue
                        try:
                            events.put(json.loads(line[5:].strip()))
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                events.put({"kind": "stream_error", "err": str(e)})

        threading.Thread(target=_listen, daemon=True).start()
        await asyncio.sleep(0.5)  # 等订阅 TCP 就绪
        # 现在才启动后台执行（它内部会再次订阅并 submit）
        _start_task_thread(Domain(result["domain"]), result["target"],
                           {"task": message}, [], task_id, result["pipeline"],
                           req.session_id)

        deadline = time.monotonic() + settings.PART_TURN_TIMEOUT_S
        saw_done = False
        pass_through = req.pass_through
        tool_events: list[dict] = []
        while not saw_done:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                ev = await asyncio.to_thread(events.get, timeout=min(remaining, 15))
            except Exception:
                continue
            k = str(ev.get("kind") or "").lower()

            if pass_through:
                # 10 号契约：原样透传 reasonix 事件（只补 task_id）
                yield _sse({**ev, "task_id": ev.get("task_id") or task_id})
                if k == "turn_done":
                    saw_done = True
                    break
                if k == "stream_error":
                    break
                continue

            if k == "turn_done":
                saw_done = True
                if ev.get("err"):
                    yield _sse({"error": {"code": "part_failed", "message": str(ev.get("err")), "task_id": task_id}})
                else:
                    yield _sse({"stage_finished": {"stage": result["domain"], "ok": True}, "task_id": task_id})
                break
            if k == "stream_error":
                yield _sse({"error": {"code": "part_unreachable", "message": ev.get("err", ""), "task_id": task_id}})
                break
            mapped = _map_part_event(ev, task_id)
            if mapped:
                if "tool_call" in mapped:
                    tool_events.append({
                        "tool_name": mapped["tool_call"].get("tool", ""),
                        "tool_args": mapped["tool_call"].get("args", {}),
                        "tool_output": None,
                    })
                elif "tool_result" in mapped:
                    name = mapped["tool_result"].get("tool", "")
                    merged = False
                    for t in reversed(tool_events):
                        if t.get("tool_output") is None and t.get("tool_name") == name:
                            t["tool_output"] = mapped["tool_result"].get("output", "")
                            merged = True
                            break
                    if not merged:
                        tool_events.append({
                            "tool_name": name, "tool_args": {},
                            "tool_output": mapped["tool_result"].get("output", ""),
                        })
                yield _sse(mapped)
        stop.set()

        # 流结束后落库（15 号契约 §5.7）
        if user is not None and conv_id:
            account.append_message(user["id"], conv_id, "user", req.message)
            for t in tool_events:
                account.append_message(
                    user["id"], conv_id, "tool",
                    content=(t.get("tool_output") or f"调用工具 {t.get('tool_name')}")[:2000],
                    tool_name=t.get("tool_name"),
                    tool_args=t.get("tool_args"),
                    tool_output=t.get("tool_output"),
                )
            account.append_message(
                user["id"], conv_id, "assistant",
                result["reply"] + f"\n\n任务编号：{task_id}",
                model=settings.DEEPSEEK_MODEL,
            )

        if not pass_through:
            yield _sse({"report_ready": {"task_id": task_id, "report_url": f"/api/tasks/{task_id}/export"}})
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/settings/runtime")
async def get_runtime_settings():
    """运行时行为设置（后端权威值，全量 7 字段）。"""
    return runtime_settings.get_all()


@app.post("/api/settings/runtime")
async def save_runtime_settings(body: RuntimeSettingsBody):
    """保存运行时行为设置（部分字段即可），返回更新后的全量值。"""
    try:
        return runtime_settings.update(body.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---- 前端静态面板（放在所有 API 路由之后，避免覆盖） ----
_static_dir = Path(__file__).resolve().parent.parent / "static"
_static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")
app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="panel")
