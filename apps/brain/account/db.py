"""账户/对话数据层 —— SQLAlchemy 2.x。

数据库按 settings.DATABASE_URL 选择（15 号契约：生产用 PostgreSQL）：
    - 配了 DATABASE_URL（postgresql+psycopg://...）→ 用 PostgreSQL
    - 没配 → 回退 SQLite（settings.BRAIN_DB_PATH），本地开发零依赖

任务表（tasks/findings/...）仍由 session.SessionStore 用 SQLite 管理，
两套存储互不重叠；将来若要把任务表也迁 PG，替换 SessionStore 即可。
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from account.models import Base

logger = logging.getLogger(__name__)

_engine = None
_session_factory = None
_lock = threading.Lock()


def _database_url() -> str:
    from config.settings import settings
    if settings.DATABASE_URL:
        return settings.DATABASE_URL
    p = str(Path(settings.BRAIN_DB_PATH).as_posix())
    return f"sqlite:///{p}"


def _make_engine():
    url = _database_url()
    if url.startswith("sqlite"):
        path_raw = url[len("sqlite:///"):] if url.startswith("sqlite:///") else url[len("sqlite://"):]
        db_path = Path(path_raw.replace("\\", "/"))
        db_path.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            f"sqlite:///{db_path.as_posix()}",
            connect_args={"check_same_thread": False, "timeout": 30},
            future=True,
        )
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.execute(text("PRAGMA foreign_keys=ON"))
    else:
        # PostgreSQL（或其它服务型数据库）：连接池 + 断线自愈
        engine = create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10, future=True)
    logger.info("[account] 数据库就绪: %s", url.split("@")[-1] if "@" in url else url)
    return engine


def get_engine():
    global _engine
    if _engine is None:
        with _lock:
            if _engine is None:
                _engine = _make_engine()
                # 只建 account 自己的表；tasks/findings 等由 session.SessionStore 建
                Base.metadata.create_all(_engine)
                _migrate(_engine)
    return _engine


def _migrate(engine):
    """轻量迁移：老库补 conversations.project_id 列（前端 projectTree）。"""
    from sqlalchemy import inspect
    insp = inspect(engine)
    if "conversations" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("conversations")}
    if "project_id" in cols:
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE conversations ADD COLUMN project_id VARCHAR(36)"))
    logger.info("[account] 迁移：conversations 增加 project_id 列")


def get_session_factory():
    global _session_factory
    if _session_factory is None:
        engine = get_engine()  # 先取 engine（内部有锁），避免持锁后重入死锁
        with _lock:
            if _session_factory is None:
                _session_factory = sessionmaker(
                    bind=engine, autoflush=False, expire_on_commit=False, future=True
                )
    return _session_factory


@contextmanager
def session_scope():
    """事务性 Session 上下文：正常提交，异常回滚。"""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
