"""EduShield configuration — single source of truth for all settings.

阶段 1（大脑地基）新增：
    - 大脑服务端口 6657（aisoc-docs 01）
    - SQLite 路径、授权白名单、部件注册表、部件下发超时/轮询
"""

import os
from dotenv import load_dotenv

load_dotenv()


def _split_env(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


class Settings:
    # ---- LLM（阶段 2/3 使用，阶段 1 保留） ----
    DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_API_BASE: str = os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com/v1")
    DEEPSEEK_MODEL: str = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.3"))

    # ---- RAG / ChromaDB（阶段 2 使用） ----
    CHROMA_PERSIST_DIR: str = os.getenv("CHROMA_PERSIST_DIR", "./chroma_data")
    CHROMA_COLLECTION_NAME: str = os.getenv("CHROMA_COLLECTION_NAME", "edushield_knowledge")

    # ---- Logging ----
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ---- Server（大脑端口 = 6657，aisoc-docs 01） ----
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "6657"))

    # ---- 会话存储（SQLite：任务表） ----
    BRAIN_DB_PATH: str = os.getenv("BRAIN_DB_PATH", "./data/brain.sqlite3")

    # ---- 账号/对话表数据库（15 号契约：生产用 PostgreSQL） ----
    # 为空 → 回退 SQLite（BRAIN_DB_PATH），本地开发零依赖。
    # 示例：postgresql+psycopg://edushield:密码@127.0.0.1:5432/edushield
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")

    # ---- 部件注册表 ----
    REGISTRY_FILE: str = os.getenv("REGISTRY_FILE", "")  # 为空 = 用内置默认

    # ---- 授权白名单（计划书第一步：只有名单上的目标才能扫） ----
    TARGET_WHITELIST_ENABLED: bool = os.getenv("TARGET_WHITELIST_ENABLED", "true").lower() in ("1", "true", "yes")
    AUTHORIZED_TARGETS: list[str] = _split_env(
        "AUTHORIZED_TARGETS",
        "127.0.0.1,10.21.16.116,demo-campus.edu.cn,http://demo-campus.edu.cn",
    )

    # ---- 部件下发（HTTP） ----
    PART_SUBMIT_TIMEOUT_S: float = float(os.getenv("PART_SUBMIT_TIMEOUT_S", "10"))
    PART_TURN_TIMEOUT_S: float = float(os.getenv("PART_TURN_TIMEOUT_S", "1800"))  # SSE 等待 turn_done 总超时（秒）
    PART_POLL_INTERVAL_S: float = float(os.getenv("PART_POLL_INTERVAL_S", "0.5"))
    PART_POLL_MAX_ATTEMPTS: int = int(os.getenv("PART_POLL_MAX_ATTEMPTS", "60"))

    # ---- 深信服 XDR 数据接入（阶段 2） ----
    XDR_LIVE_ENABLED: bool = os.getenv("XDR_LIVE_ENABLED", "false").lower() in ("1", "true", "yes")
    XDR_BASE_URL: str = os.getenv("XDR_BASE_URL", "")
    XDR_AUTH_CODE: str = os.getenv("XDR_AUTH_CODE", "")      # 联动码
    XDR_AK: str = os.getenv("XDR_AK", "")                    # 或直接 AK/SK
    XDR_SK: str = os.getenv("XDR_SK", "")
    XDR_SAMPLE_FILE: str = os.getenv("XDR_SAMPLE_FILE", "./data/samples/xdr_alerts_sample.json")

    # ---- 应急响应子 Agent（TIR，计划书身体部件 D，端口 8090） ----
    TIR_ENABLED: bool = os.getenv("TIR_ENABLED", "true").lower() in ("1", "true", "yes")
    TIR_BASE_URL: str = os.getenv("TIR_BASE_URL", "http://127.0.0.1:8090")

    # ---- 认证与对话记忆（15 号契约） ----
    AUTH_SESSION_TTL_DAYS: int = int(os.getenv("AUTH_SESSION_TTL_DAYS", "7"))  # 非 remember 会话有效期（天）
    AUTH_BCRYPT_ROUNDS: int = int(os.getenv("AUTH_BCRYPT_ROUNDS", "12"))


settings = Settings()
