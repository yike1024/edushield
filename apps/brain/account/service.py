"""账户认证 + 对话历史服务（15 号契约 Part A §2-§5）。"""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from sqlalchemy import cast, func, or_, select, Text, update

from account.db import session_scope
from account.models import Conversation, MemoryEntry, Message, Project, Session, User
from config.settings import settings
from protocol import utc_now_iso


class AccountError(Exception):
    """业务错误：code 对齐 15 号契约（USERNAME_TAKEN / EMAIL_TAKEN / ...）。"""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


# ---------------- 密码 ----------------

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=settings.AUTH_BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


# ---------------- Token ----------------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, _hash_token(token)


def _session_expires_at(remember: bool) -> Optional[str]:
    if remember:
        return None
    exp = datetime.now(timezone.utc) + timedelta(days=settings.AUTH_SESSION_TTL_DAYS)
    return exp.isoformat()


def _is_expired(expires_at: Optional[str]) -> bool:
    if not expires_at:
        return False
    try:
        return datetime.now(timezone.utc) > datetime.fromisoformat(expires_at)
    except Exception:
        return True


# ---------------- 用户 ----------------

def _user_dict(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "phone": u.phone,
        "role": u.role,
        "createdAt": u.created_at,
        "lastLoginAt": u.last_login_at,
    }


def create_user(username: str, email: str, password: str, phone: Optional[str] = None) -> dict:
    with session_scope() as s:
        exists = s.execute(
            select(User).where(
                (func.lower(User.username) == username.lower())
                | (func.lower(User.email) == email.lower())
            )
        ).scalars().first()
        if exists is not None:
            if exists.username.lower() == username.lower():
                raise AccountError("USERNAME_TAKEN", "用户名已存在", 409)
            raise AccountError("EMAIL_TAKEN", "邮箱已存在", 409)

        user = User(
            id=str(uuid.uuid4()),
            username=username,
            email=email,
            phone=phone,
            password_hash=hash_password(password),
            status="active",
            email_verified=False,
            role="user",
            created_at=utc_now_iso(),
            preferences="{}",
        )
        s.add(user)
        s.flush()
        return _user_dict(user)


def authenticate_user(identifier: str, password: str) -> Optional[User]:
    with session_scope() as s:
        user = s.execute(
            select(User).where(
                (func.lower(User.username) == identifier.lower())
                | (func.lower(User.email) == identifier.lower())
            )
        ).scalars().first()
        if user is None:
            return None
        if not verify_password(password, user.password_hash):
            return None
        # 返回脱离 session 的字段副本，避免 DetachedInstanceError
        return User(
            id=user.id, username=user.username, email=user.email, phone=user.phone,
            password_hash=user.password_hash, status=user.status, role=user.role,
            email_verified=user.email_verified, created_at=user.created_at,
            last_login_at=user.last_login_at, last_login_ip=user.last_login_ip,
            preferences=user.preferences, deleted_at=user.deleted_at,
        )


def get_user_by_id(user_id: str) -> Optional[dict]:
    with session_scope() as s:
        u = s.get(User, user_id)
        return _user_dict(u) if u else None


def touch_login(user_id: str, ip: Optional[str] = None) -> None:
    with session_scope() as s:
        s.execute(
            update(User).where(User.id == user_id).values(
                last_login_at=utc_now_iso(), last_login_ip=ip or ""
            )
        )


# ---------------- 会话（Session） ----------------

def create_session(user_id: str, remember: bool, ip: Optional[str] = None) -> dict:
    token, token_hash = _new_token()
    now = utc_now_iso()
    with session_scope() as s:
        sess = Session(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token_hash=token_hash,
            remember=remember,
            expires_at=_session_expires_at(remember),
            created_at=now,
        )
        s.add(sess)
        s.execute(
            update(User).where(User.id == user_id).values(
                last_login_at=now, last_login_ip=ip or ""
            )
        )
    expires_ms = 0
    if not remember:
        exp = datetime.now(timezone.utc) + timedelta(days=settings.AUTH_SESSION_TTL_DAYS)
        expires_ms = int(exp.timestamp() * 1000)
    return {"token": token, "expiresAt": expires_ms}


def get_user_by_token(token: str) -> Optional[dict]:
    if not token:
        return None
    token_hash = _hash_token(token)
    with session_scope() as s:
        sess = s.execute(
            select(Session).where(Session.token_hash == token_hash)
        ).scalars().first()
        if sess is None or sess.revoked_at:
            return None
        if _is_expired(sess.expires_at):
            return None
        u = s.get(User, sess.user_id)
        if u is None or u.status != "active" or u.deleted_at:
            return None
        return _user_dict(u)


def revoke_session(token: str) -> bool:
    if not token:
        return False
    with session_scope() as s:
        sess = s.execute(
            select(Session).where(Session.token_hash == _hash_token(token))
        ).scalars().first()
        if sess is None:
            return False
        sess.revoked_at = utc_now_iso()
        return True


def change_password(user_id: str, old_password: str, new_password: str) -> None:
    with session_scope() as s:
        u = s.get(User, user_id)
        if u is None:
            raise AccountError("USER_NOT_FOUND", "用户不存在", 404)
        if not verify_password(old_password, u.password_hash):
            raise AccountError("INVALID_CREDENTIALS", "旧密码不正确", 401)
        u.password_hash = hash_password(new_password)


# ---------------- 对话 ----------------

def _conv_dict(c: Conversation) -> dict:
    return {
        "id": c.id,
        "title": c.title,
        "domain": c.domain,
        "projectId": c.project_id,
        "pinned": bool(c.pinned),
        "status": c.status,
        "summary": c.summary,
        "messageCount": c.message_count,
        "tokenCount": c.token_count,
        "createdAt": c.created_at,
        "updatedAt": c.updated_at,
    }


def create_conversation(user_id: str, title: Optional[str] = None,
                        domain: Optional[str] = None, tab_id: Optional[str] = None,
                        project_id: Optional[str] = None) -> dict:
    now = utc_now_iso()
    with session_scope() as s:
        c = Conversation(
            id=str(uuid.uuid4()),
            user_id=user_id,
            title=(title or "新对话")[:500],
            domain=domain,
            tab_id=tab_id,
            project_id=project_id,
            status="active",
            pinned=False,
            message_count=0,
            token_count=0,
            created_at=now,
            updated_at=now,
        )
        s.add(c)
        s.flush()
        return _conv_dict(c)


def get_conversation(user_id: str, conversation_id: str) -> Optional[Conversation]:
    with session_scope() as s:
        c = s.execute(
            select(Conversation).where(
                Conversation.id == conversation_id,
                Conversation.user_id == user_id,
                Conversation.status != "deleted",
            )
        ).scalars().first()
        if c is None:
            return None
        return Conversation(
            id=c.id, user_id=c.user_id, title=c.title, domain=c.domain,
            tab_id=c.tab_id, project_id=c.project_id, status=c.status, pinned=c.pinned,
            summary=c.summary, summary_updated_at=c.summary_updated_at,
            message_count=c.message_count, token_count=c.token_count,
            created_at=c.created_at, updated_at=c.updated_at,
        )


def list_conversations(user_id: str, page: int = 1, page_size: int = 50,
                       domain: Optional[str] = None, pinned: Optional[bool] = None,
                       search: Optional[str] = None, project_id: Optional[str] = None) -> tuple[list[dict], int]:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 100)
    with session_scope() as s:
        q = select(Conversation).where(
            Conversation.user_id == user_id,
            Conversation.status != "deleted",
        )
        if domain:
            q = q.where(Conversation.domain == domain)
        if pinned is not None:
            q = q.where(Conversation.pinned == pinned)
        if project_id is not None:
            q = q.where(Conversation.project_id == project_id)
        if search:
            q = q.where(Conversation.title.like(f"%{search}%"))

        total = len(s.execute(q).scalars().all())
        q = q.order_by(Conversation.pinned.desc(), Conversation.updated_at.desc())
        q = q.offset((page - 1) * page_size).limit(page_size)
        rows = s.execute(q).scalars().all()
        return [_conv_dict(c) for c in rows], total


def update_conversation(user_id: str, conversation_id: str, title: Optional[str] = None,
                        pinned: Optional[bool] = None, status: Optional[str] = None,
                        project_id: Optional[str] = None) -> Optional[dict]:
    with session_scope() as s:
        c = s.execute(
            select(Conversation).where(
                Conversation.id == conversation_id, Conversation.user_id == user_id
            )
        ).scalars().first()
        if c is None:
            return None
        if title is not None:
            c.title = title[:500]
        if pinned is not None:
            c.pinned = pinned
        if project_id is not None:
            c.project_id = project_id or None
        if status is not None:
            if status not in ("active", "archived", "deleted"):
                raise AccountError("INVALID_STATUS", "status 只支持 active/archived/deleted")
            c.status = status
        c.updated_at = utc_now_iso()
        s.flush()
        return _conv_dict(c)


def delete_conversation(user_id: str, conversation_id: str) -> bool:
    """软删除：status -> deleted。"""
    return update_conversation(user_id, conversation_id, status="deleted") is not None


# ---------------- 消息 ----------------

def _msg_dict(m: Message) -> dict:
    d = {
        "id": m.id,
        "role": m.role,
        "content": m.content,
        "reasoning": m.reasoning,
        "toolName": m.tool_name,
        "toolOutput": m.tool_output,
        "model": m.model,
        "tokenCount": m.token_count,
        "sequenceNum": m.sequence_num,
        "createdAt": m.created_at,
    }
    if m.tool_args:
        try:
            d["toolArgs"] = json.loads(m.tool_args)
        except json.JSONDecodeError:
            d["toolArgs"] = m.tool_args
    if m.tool_exit_code is not None:
        d["toolExitCode"] = m.tool_exit_code
    return d


def _estimate_tokens(text: Optional[str]) -> int:
    if not text:
        return 0
    return max(1, len(text) // 4)


def append_message(user_id: str, conversation_id: str, role: str, content: str,
                   reasoning: Optional[str] = None, tool_name: Optional[str] = None,
                   tool_args: Optional[dict] = None, tool_output: Optional[str] = None,
                   tool_exit_code: Optional[int] = None, model: Optional[str] = None) -> Optional[dict]:
    if role not in ("user", "assistant", "tool", "system"):
        raise AccountError("INVALID_ROLE", "role 只支持 user/assistant/tool/system")
    now = utc_now_iso()
    tokens = _estimate_tokens(content) + _estimate_tokens(reasoning)
    with session_scope() as s:
        c = s.execute(
            select(Conversation).where(
                Conversation.id == conversation_id,
                Conversation.user_id == user_id,
                Conversation.status != "deleted",
            )
        ).scalars().first()
        if c is None:
            return None
        next_seq = c.message_count  # 以对话内累计消息数作为序号，简单且幂等
        m = Message(
            id=str(uuid.uuid4()),
            conversation_id=conversation_id,
            user_id=user_id,
            role=role,
            content=content or "",
            reasoning=reasoning,
            tool_name=tool_name,
            tool_args=json.dumps(tool_args, ensure_ascii=False) if tool_args is not None else None,
            tool_output=tool_output,
            tool_exit_code=tool_exit_code,
            token_count=tokens,
            model=model,
            importance=0,
            created_at=now,
            sequence_num=next_seq,
        )
        s.add(m)
        c.message_count = next_seq + 1
        c.token_count = (c.token_count or 0) + tokens
        c.updated_at = now
        s.flush()
        return _msg_dict(m)


def list_messages(user_id: str, conversation_id: str, limit: int = 100,
                  offset: int = 0, order: str = "desc") -> Optional[dict]:
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)
    with session_scope() as s:
        c = s.execute(
            select(Conversation).where(
                Conversation.id == conversation_id,
                Conversation.user_id == user_id,
            )
        ).scalars().first()
        if c is None:
            return None
        q = select(Message).where(Message.conversation_id == conversation_id)
        q = q.order_by(Message.sequence_num.desc() if order == "desc" else Message.sequence_num.asc())
        q = q.offset(offset).limit(limit)
        rows = s.execute(q).scalars().all()
        total = c.message_count
        return {"items": [_msg_dict(m) for m in rows], "total": total}


# ---------------- 长期记忆（15 号契约 §10 / 16 号方案 B2） ----------------

_MEM_TYPES = {"fact", "preference", "goal", "entity", "skill"}

# 项目颜色白名单（17 号 §4.1，对齐前端 projectColorValue 色板）
_PROJECT_COLORS = {"red", "orange", "amber", "green", "teal", "blue", "purple", "pink"}

# PATCH 语义 sentinel：区分"未传字段"与"显式传 null 清空"
_UNSET = object()


def _mem_keywords(m: MemoryEntry) -> list[str]:
    kw = m.keywords
    if isinstance(kw, str):
        try:
            kw = json.loads(kw)
        except json.JSONDecodeError:
            kw = []
    if not isinstance(kw, list):
        return []
    return [str(x) for x in kw if str(x).strip()][:20]


def _mem_dict(m: MemoryEntry) -> dict:
    return {
        "id": m.id,
        "content": m.content,
        "type": m.type,
        "importance": m.importance,
        "keywords": _mem_keywords(m),
        "source": m.source,
        "scope": m.scope,
        "createdAt": m.created_at,
        "updatedAt": m.updated_at,
        "lastAccessedAt": m.last_accessed_at,
        "accessCount": m.access_count,
    }


def _normalize_mem_content(content: str) -> str:
    content = (content or "").strip()
    if not content:
        raise AccountError("VALIDATION_ERROR", "记忆内容不能为空", 422)
    if len(content) > 2000:
        raise AccountError("VALIDATION_ERROR", "记忆内容超过 2000 字上限", 422)
    return content


def _normalize_mem_keywords(keywords: Optional[list[str]]) -> list[str]:
    if not keywords:
        return []
    seen = set()
    out = []
    for k in keywords:
        k = str(k).strip()
        if k and k not in seen:
            seen.add(k)
            out.append(k[:50])
        if len(out) >= 20:
            break
    return out


def create_memory(user_id: str, content: str, type: Optional[str] = None,
                  importance: Optional[int] = None, keywords: Optional[list[str]] = None) -> dict:
    content = _normalize_mem_content(content)
    mem_type = type or "fact"
    if mem_type not in _MEM_TYPES:
        raise AccountError("VALIDATION_ERROR", f"type 只支持 {'/'.join(sorted(_MEM_TYPES))}", 422)
    imp = int(importance or 0)
    imp = max(0, min(100, imp))
    if imp < 80:
        imp = 80  # 用户手动标记的记忆一律高重要度（16 号方案 B2）
    now = utc_now_iso()
    with session_scope() as s:
        m = MemoryEntry(
            id=str(uuid.uuid4()),
            user_id=user_id,
            content=content,
            type=mem_type,
            importance=imp,
            keywords=_normalize_mem_keywords(keywords),
            created_at=now,
            updated_at=now,
            last_accessed_at=now,
            access_count=0,
            decay_score=1.0,
            status="active",
            source="user_marked",
            scope="global",
        )
        s.add(m)
        s.flush()
        return _mem_dict(m)


def list_memories(user_id: str, type: Optional[str] = None, q: Optional[str] = None,
                  min_importance: int = 0, page: int = 1, page_size: int = 20) -> tuple[list[dict], int]:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 100)
    with session_scope() as s:
        stmt = select(MemoryEntry).where(
            MemoryEntry.user_id == user_id,
            MemoryEntry.status == "active",
        )
        if type:
            stmt = stmt.where(MemoryEntry.type == type)
        if min_importance:
            stmt = stmt.where(MemoryEntry.importance >= min_importance)
        if q:
            like = f"%{q.strip()}%"
            stmt = stmt.where(
                or_(
                    MemoryEntry.content.ilike(like),
                    cast(MemoryEntry.keywords, Text).ilike(like),
                )
            )
        total = len(s.execute(stmt).scalars().all())
        stmt = stmt.order_by(MemoryEntry.importance.desc(), MemoryEntry.updated_at.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        rows = s.execute(stmt).scalars().all()
        return [_mem_dict(m) for m in rows], total


def get_memory(user_id: str, memory_id: str) -> Optional[dict]:
    with session_scope() as s:
        m = s.execute(
            select(MemoryEntry).where(
                MemoryEntry.id == memory_id,
                MemoryEntry.user_id == user_id,
                MemoryEntry.status == "active",
            )
        ).scalars().first()
        if m is None:
            return None
        return _mem_dict(m)


def update_memory(user_id: str, memory_id: str, content: Optional[str] = None,
                  type: Optional[str] = None, importance: Optional[int] = None,
                  keywords: Optional[list[str]] = None) -> Optional[dict]:
    with session_scope() as s:
        m = s.execute(
            select(MemoryEntry).where(
                MemoryEntry.id == memory_id,
                MemoryEntry.user_id == user_id,
                MemoryEntry.status == "active",
            )
        ).scalars().first()
        if m is None:
            return None
        if content is not None:
            m.content = _normalize_mem_content(content)
        if type is not None:
            if type not in _MEM_TYPES:
                raise AccountError("VALIDATION_ERROR", f"type 只支持 {'/'.join(sorted(_MEM_TYPES))}", 422)
            m.type = type
        if importance is not None:
            m.importance = max(0, min(100, int(importance)))
        if keywords is not None:
            m.keywords = _normalize_mem_keywords(keywords)
        m.updated_at = utc_now_iso()
        s.flush()
        return _mem_dict(m)


def delete_memory(user_id: str, memory_id: str) -> bool:
    """显式遗忘：软删除 status -> forgotten。不属于本人返回 False（不暴露存在性）。"""
    with session_scope() as s:
        m = s.execute(
            select(MemoryEntry).where(
                MemoryEntry.id == memory_id,
                MemoryEntry.user_id == user_id,
                MemoryEntry.status == "active",
            )
        ).scalars().first()
        if m is None:
            return False
        m.status = "forgotten"
        m.updated_at = utc_now_iso()
        return True


def forget_all_memories(user_id: str) -> int:
    with session_scope() as s:
        rows = s.execute(
            select(MemoryEntry).where(
                MemoryEntry.user_id == user_id,
                MemoryEntry.status == "active",
            )
        ).scalars().all()
        now = utc_now_iso()
        for m in rows:
            m.status = "forgotten"
            m.updated_at = now
        return len(rows)


def touch_memories(user_id: str, memory_ids: list[str]) -> None:
    """命中反馈：更新 last_accessed_at / access_count（16 号方案 B3.4）。"""
    if not memory_ids:
        return
    now = utc_now_iso()
    with session_scope() as s:
        for mid in memory_ids:
            s.execute(
                update(MemoryEntry).where(
                    MemoryEntry.id == mid,
                    MemoryEntry.user_id == user_id,
                    MemoryEntry.status == "active",
                ).values(
                    last_accessed_at=now,
                    access_count=MemoryEntry.access_count + 1,
                )
            )


def _tokenize(text: str) -> list[str]:
    """M1 关键词检索的粗分词：中文字段 + 英文/数字/域名 token。

    - 连续中文 2-12 字一段
    - 连续 [A-Za-z0-9_.:-] 一段（域名/IP/工具名）
    """
    import re
    tokens: list[str] = []
    for m in re.findall(r"[\u4e00-\u9fff]{2,12}|[A-Za-z0-9_.:-]{2,40}", text or ""):
        t = m.strip()
        if t and t.lower() not in tokens:
            tokens.append(t)
    return tokens


def retrieve_memories(user_id: str, query: str, top_k: int = 5,
                      min_importance: int = 40) -> list[dict]:
    """M1 关键词召回（16 号方案 B3.2：无向量时退化关键词检索）。

    策略：取该用户全部 active 记忆（记忆量小，M1 在进程内打分），
    命中分 = 记忆侧 token 出现在用户消息中的数量 ×3 + 用户消息 token 出现在记忆中的数量 ×2；
    按 (分数, importance) 降序取 top_k，只返回 importance >= min_importance 的条目。
    命中条目同时 touch（last_accessed_at / access_count）。
    不抛异常：任何失败返回空列表（召回失败不阻断对话）。
    """
    if not query or not query.strip():
        return []
    try:
        query_l = query.strip().lower()
        q_tokens = _tokenize(query)
        with session_scope() as s:
            rows = s.execute(
                select(MemoryEntry).where(
                    MemoryEntry.user_id == user_id,
                    MemoryEntry.status == "active",
                )
            ).scalars().all()
        scored: list[tuple[float, MemoryEntry]] = []
        for m in rows:
            if m.importance < min_importance:
                continue
            content_l = (m.content or "").lower()
            mem_tokens = _tokenize(m.content) + [str(k).lower() for k in _mem_keywords(m)]
            score = 0.0
            for t in mem_tokens:
                if t and t.lower() in query_l:
                    score += 3
            for t in q_tokens:
                if t and t.lower() in content_l:
                    score += 2
            if score > 0:
                scored.append((score, m))
        scored.sort(key=lambda x: (x[0], x[1].importance), reverse=True)
        picked = [m for _, m in scored[:top_k]]
        touch_memories(user_id, [m.id for m in picked])
        return [{"matchedBy": "keyword", **_mem_dict(m)} for m in picked]
    except Exception as e:
        logger.warning(f"[account] 记忆召回失败（忽略）: {e}")
        return []


# ---------------- 项目（前端"添加新项目"，16 号方案后续对接） ----------------

def _project_dict(p: Project, conversation_count: int = 0) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "target": p.target,
        "description": p.description,
        "color": p.color,
        "pinned": bool(p.pinned),
        "order": p.order,
        "status": p.status,
        "createdAt": p.created_at,
        "updatedAt": p.updated_at,
        "conversationCount": conversation_count,
        "taskCount": 0,
        "findingCount": 0,
    }


def _project_conversation_counts(s, user_id: str, project_ids: list[str]) -> dict[str, int]:
    """按 project_id 统计会话数（用于 conversationCount 聚合）。"""
    if not project_ids:
        return {}
    rows = s.execute(
        select(Conversation.project_id, func.count(Conversation.id))
        .where(Conversation.user_id == user_id,
               Conversation.project_id.in_(project_ids),
               Conversation.status != "deleted")
        .group_by(Conversation.project_id)
    ).all()
    return {pid: int(cnt) for pid, cnt in rows}


def list_projects(user_id: str, page: int = 1, page_size: int = 50,
                  q: Optional[str] = None, status: Optional[str] = None) -> tuple[list[dict], int]:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    with session_scope() as s:
        stmt = select(Project).where(Project.user_id == user_id)
        if status:
            stmt = stmt.where(Project.status == status)
        else:
            stmt = stmt.where(Project.status != "deleted")
        if q:
            stmt = stmt.where(Project.name.ilike(f"%{q.strip()}%"))
        total = len(s.execute(stmt).scalars().all())
        stmt = stmt.order_by(Project.pinned.desc(), Project.updated_at.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        rows = s.execute(stmt).scalars().all()
        counts = _project_conversation_counts(s, user_id, [p.id for p in rows])
        return [_project_dict(p, counts.get(p.id, 0)) for p in rows], total


def _norm_color(color: Optional[str]) -> Optional[str]:
    if color is None:
        return None
    color = color.strip().lower()
    if not color:
        return None
    if color not in _PROJECT_COLORS:
        raise AccountError("VALIDATION_ERROR",
                           f"color 只支持 {'/'.join(sorted(_PROJECT_COLORS))}", 422)
    return color


def create_project(user_id: str, name: str, target: Optional[str] = None,
                   description: Optional[str] = None, color: Optional[str] = None) -> dict:
    name = (name or "").strip()
    if not name:
        raise AccountError("VALIDATION_ERROR", "项目名称不能为空", 422)
    if len(name) > 200:
        raise AccountError("VALIDATION_ERROR", "项目名称超过 200 字上限", 422)
    color = _norm_color(color)
    now = utc_now_iso()
    with session_scope() as s:
        p = Project(
            id=str(uuid.uuid4()),
            user_id=user_id,
            name=name,
            target=(target or "").strip() or None,
            description=(description or "").strip() or None,
            color=color,
            pinned=False,
            order=None,
            status="active",
            created_at=now,
            updated_at=now,
        )
        s.add(p)
        s.flush()
        return _project_dict(p)


def get_project(user_id: str, project_id: str) -> Optional[dict]:
    with session_scope() as s:
        p = s.execute(
            select(Project).where(
                Project.id == project_id,
                Project.user_id == user_id,
                Project.status != "deleted",
            )
        ).scalars().first()
        if p is None:
            return None
        counts = _project_conversation_counts(s, user_id, [p.id])
        return _project_dict(p, counts.get(p.id, 0))


def update_project(user_id: str, project_id: str, name: object = _UNSET,
                   target: object = _UNSET, description: object = _UNSET,
                   color: object = _UNSET, pinned: Optional[bool] = None,
                   order: Optional[int] = None, status: Optional[str] = None) -> Optional[dict]:
    with session_scope() as s:
        p = s.execute(
            select(Project).where(
                Project.id == project_id,
                Project.user_id == user_id,
                Project.status != "deleted",
            )
        ).scalars().first()
        if p is None:
            return None
        if name is not _UNSET:
            name = (name or "").strip()
            if not name:
                raise AccountError("VALIDATION_ERROR", "项目名称不能为空", 422)
            p.name = name[:200]
        if target is not _UNSET:
            # 显式传 null → 清空（17 号 §5.4）
            p.target = (target or "").strip() or None
        if description is not _UNSET:
            p.description = (description or "").strip() or None
        if color is not _UNSET:
            p.color = _norm_color(color)
        if pinned is not None:
            p.pinned = bool(pinned)
        if order is not None:
            p.order = int(order)
        if status is not None:
            if status not in ("active", "archived", "deleted"):
                raise AccountError("VALIDATION_ERROR", "status 只支持 active/archived/deleted", 422)
            p.status = status
        p.updated_at = utc_now_iso()
        s.flush()
        return _project_dict(p)


def delete_project(user_id: str, project_id: str) -> Optional[tuple[str, int]]:
    """软删除项目，并解绑属于该项目的会话（project_id -> NULL）。

    返回 (project_id, unbound_conversations)；项目不存在/非本人返回 None。
    """
    with session_scope() as s:
        p = s.execute(
            select(Project).where(
                Project.id == project_id,
                Project.user_id == user_id,
                Project.status != "deleted",
            )
        ).scalars().first()
        if p is None:
            return None
        now = utc_now_iso()
        p.status = "deleted"
        p.updated_at = now
        # 解绑会话（17 号 §5.5）
        rows = s.execute(
            select(Conversation).where(
                Conversation.user_id == user_id,
                Conversation.project_id == project_id,
            )
        ).scalars().all()
        for c in rows:
            c.project_id = None
            c.updated_at = now
        s.flush()
        return project_id, len(rows)
