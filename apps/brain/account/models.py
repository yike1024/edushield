"""账户与会话记忆 —— SQLAlchemy 模型（15 号契约 Part A）。

表结构对齐《15-后端数据库与记忆架构设计.md》，SQLite 先行：
    - UUID 存 TEXT
    - 时间存 ISO 8601 字符串（与 protocol.utc_now_iso 一致）
    - JSON 存 TEXT
将来迁 PostgreSQL 只改连接串与少量字段类型，业务代码不动。
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, Float, ForeignKey, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    username = Column(String(20), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    phone = Column(String(20), unique=True)
    password_hash = Column(String(255), nullable=False)
    status = Column(String(16), nullable=False, default="active")  # active | suspended | deleted
    email_verified = Column(Boolean, nullable=False, default=False)
    role = Column(String(16), nullable=False, default="user")      # user | admin
    created_at = Column(Text, nullable=False)
    last_login_at = Column(Text)
    last_login_ip = Column(Text)
    preferences = Column(Text, nullable=False, default="{}")       # JSON
    deleted_at = Column(Text)

    __table_args__ = (
        Index("idx_users_status", "status"),
    )


# 用户名/邮箱大小写不敏感唯一（与文档 idx_users_username_lower / email_lower 对齐）
Index("idx_users_username_lower", func.lower(User.username), unique=True)
Index("idx_users_email_lower", func.lower(User.email), unique=True)


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)
    remember = Column(Boolean, nullable=False, default=False)
    expires_at = Column(Text)          # NULL = 永久
    created_at = Column(Text, nullable=False)
    revoked_at = Column(Text)

    __table_args__ = (
        Index("idx_sessions_user", "user_id"),
    )


class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=False)
    title = Column(String(500), nullable=False, default="新对话")
    domain = Column(String(32))
    tab_id = Column(String(64))
    project_id = Column(String(36))                        # 所属项目（前端 projectTree）
    status = Column(String(16), nullable=False, default="active")  # active | archived | deleted
    pinned = Column(Boolean, nullable=False, default=False)
    summary = Column(Text)
    summary_updated_at = Column(Text)
    message_count = Column(Integer, nullable=False, default=0)
    token_count = Column(Integer, nullable=False, default=0)
    created_at = Column(Text, nullable=False)
    updated_at = Column(Text, nullable=False)

    __table_args__ = (
        Index("idx_conv_user", "user_id", "updated_at"),
        Index("idx_conv_user_pinned", "user_id", "pinned", "updated_at"),
        Index("idx_conv_tab", "tab_id"),
        Index("idx_conv_project", "user_id", "project_id"),
    )


class Message(Base):
    __tablename__ = "messages"

    id = Column(String(36), primary_key=True)
    conversation_id = Column(String(36), nullable=False)
    user_id = Column(String(36), nullable=False)
    role = Column(String(16), nullable=False)     # user | assistant | tool | system
    content = Column(Text, nullable=False)
    reasoning = Column(Text)
    tool_name = Column(String(128))
    tool_args = Column(Text)                       # JSON
    tool_output = Column(Text)
    tool_exit_code = Column(Integer)
    token_count = Column(Integer)
    model = Column(String(64))
    embedding_id = Column(Integer)
    importance = Column(Integer, nullable=False, default=0)
    created_at = Column(Text, nullable=False)
    sequence_num = Column(Integer, nullable=False)

    __table_args__ = (
        Index("idx_msg_conv_seq", "conversation_id", "sequence_num"),
        Index("idx_msg_user_time", "user_id", "created_at"),
        Index("idx_msg_importance", "user_id", "importance"),
    )


class MemoryEntry(Base):
    """长期记忆条目（15 号契约 Part B §7.1，16 号方案 B1 落地）。

    M1 务实调整：
    - embedding 列不建：服务器 pgvector 未 CREATE EXTENSION（B0 盘点结论），
      M2 装好扩展后执行 ALTER TABLE memory_entries ADD COLUMN embedding vector(768) 再回填。
    - keywords 用 JSON（PostgreSQL 为 JSON，SQLite 为 TEXT），跨库一致，M1 用 ILIKE 检索。
    - 时间沿用 ISO 8601 文本（与 account 其它表一致）。
    """

    __tablename__ = "memory_entries"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    conversation_id = Column(String(36), ForeignKey("conversations.id", ondelete="SET NULL"))
    content = Column(Text, nullable=False)
    type = Column(String(16), nullable=False)              # fact | preference | goal | entity | skill
    importance = Column(Integer, nullable=False, default=50)  # 0-100
    keywords = Column(JSON)                                # 关键词数组
    created_at = Column(Text, nullable=False)
    updated_at = Column(Text, nullable=False)
    last_accessed_at = Column(Text, nullable=False)
    access_count = Column(Integer, nullable=False, default=0)
    decay_score = Column(Float, nullable=False, default=1.0)
    status = Column(String(16), nullable=False, default="active")  # active | forgotten | merged
    superseded_by = Column(String(36))
    source = Column(String(32), nullable=False, default="extracted")  # extracted | user_marked | system
    scope = Column(String(16), nullable=False, default="global")      # global | project

    __table_args__ = (
        Index("idx_mem_user_type", "user_id", "status", "type", "importance"),
        Index("idx_mem_user_recent", "user_id", "status", "last_accessed_at"),
    )


class Project(Base):
    """项目（前端"添加新项目"），按用户隔离。

    前端 DTO（camelCase）：id / name / target / description / color /
    pinned / order / status / createdAt / updatedAt /
    conversationCount / taskCount / findingCount。
    """

    __tablename__ = "projects"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(200), nullable=False)
    target = Column(Text)                                   # 项目目标/靶标描述（可空）
    description = Column(Text)                              # 项目说明（可空）
    color = Column(String(32))                              # 前端色板（可空）
    pinned = Column(Boolean, nullable=False, default=False)
    order = Column(Integer)                                 # 排序权重（可空）
    status = Column(String(16), nullable=False, default="active")  # active | archived | deleted
    created_at = Column(Text, nullable=False)
    updated_at = Column(Text, nullable=False)

    __table_args__ = (
        Index("idx_proj_user_status", "user_id", "status", "updated_at"),
        Index("idx_proj_user_pinned", "user_id", "pinned", "updated_at"),
    )
