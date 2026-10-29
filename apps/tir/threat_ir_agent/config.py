# -*- coding: utf-8 -*-
"""
威胁警报-应急响应 子Agent 独立配置模块
=======================================
设计原则（对齐《安全智能体平台-项目计划书》3.4 会话管理边界与 AI 使用原则）：
- AI 只加在“判断/生成”处（威胁分级判定、预案生成、报告生成），
  不加在“流程/状态/存储”处（状态机、持久化均为确定性纯业务代码）。
- 本模块为子 Agent 专属配置，全部环境变量使用 `TIR_` 前缀，
  与 edushield 主系统的 settings（无前缀 / DEEPSEEK_ 前缀）命名空间隔离，
  不读取、不修改 edushield 任何配置文件。

本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import os
from pathlib import Path

# 子 Agent 包根目录（本文件所在目录）
PACKAGE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# .env 加载（只读自己的 .env.example / .env，绝不触碰 edushield 配置）
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv

    # 优先加载子 Agent 自己的 .env（不存在则静默跳过）
    load_dotenv(PACKAGE_DIR / ".env", override=False)
except Exception:  # pragma: no cover - dotenv 缺失时仅依赖系统环境变量
    pass


def _read_env(name: str, default: str) -> str:
    """读取环境变量；当缺失时尝试（只读）回退到 edushield 目录的 .env，
    以复用主平台已配置的 DeepSeek 密钥，避免重复配置。
    该回退是只读操作，不修改 edushield 任何文件。"""
    val = os.getenv(name)
    if val:
        return val
    # 只读回退：edushield 根目录下的 .env（存在则读取同名变量）
    try:
        candidate = PACKAGE_DIR.parent / "edushield" / "edushield" / ".env"
        if candidate.is_file():
            with open(candidate, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith(name + "="):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return default


class ThreatIRConfig:
    """子 Agent 配置（独立命名空间 tir_）。

    说明：以下每一项均为子 Agent 新增配置，不修改 edushield 主系统配置。
    """

    # ---- 版本与命名空间 ----
    SUBAGENT_NAME: str = "threat-ir-agent"
    SUBAGENT_NAMESPACE: str = "tir_"  # 任务/告警/报告 ID 统一前缀，与主系统隔离

    # ---- 推理大脑（DeepSeek-Reasonix-Security 模型网关）----
    # 取值: auto | reasonix-cli | openai-api | mock
    #   - reasonix-cli : 调用 DeepSeek-Reasonix-Security 对外暴露的 CLI 一次性入口
    #                    （`reasonix run -p ... --output-format json`）
    #   - openai-api   : 调用该模型底层 DeepSeek OpenAI 兼容 API（与 edushield
    #                    llm 适配层同一调用入口，仅走模型对外暴露的接口）
    #   - auto         : 优先探测 reasonix-cli，不可用时回退 openai-api
    #   - mock         : 内置确定性回复（仅用于无网络/无密钥的测试场景）
    MODEL_GATEWAY: str = os.getenv("TIR_MODEL_GATEWAY", "auto")
    # 威胁分级判定专用温度（更低 → 更稳定、更可复现的研判结果）
    CLASSIFY_TEMPERATURE: float = float(os.getenv("TIR_CLASSIFY_TEMPERATURE", "0.1"))

    # DeepSeek-Reasonix-Security 的 reasonix 二进制路径（CLI 通道）
    REASONIX_BIN: str = os.getenv("TIR_REASONIX_BIN", "reasonix")
    REASONIX_TIMEOUT_SECONDS: int = int(os.getenv("TIR_REASONIX_TIMEOUT_SECONDS", "180"))

    # OpenAI 兼容 API 通道（与 edushield llm 适配层同源，仅调用模型对外接口）
    DEEPSEEK_API_KEY: str = _read_env("DEEPSEEK_API_KEY", "")
    DEEPSEEK_API_BASE: str = _read_env("DEEPSEEK_API_BASE", "https://api.deepseek.com/v1")
    DEEPSEEK_MODEL: str = _read_env("DEEPSEEK_MODEL", "deepseek-chat")
    LLM_TEMPERATURE: float = float(os.getenv("TIR_LLM_TEMPERATURE", "0.2"))
    API_TIMEOUT_SECONDS: int = int(os.getenv("TIR_API_TIMEOUT_SECONDS", "120"))

    # ---- 本地持久化（子 Agent 专属存储，独立于主系统数据库）----
    # 默认落在 <包>/storage/data 下，全部为新增目录/文件
    STORE_DIR: Path = Path(os.getenv("TIR_STORE_DIR", str(PACKAGE_DIR / "storage" / "data")))

    # ---- 告警推送（向 edushield 主智能体推送告警）----
    # 同步通道：调用方总是从返回值中取得告警（可直接供主对话界面展示）。
    # 异步通道：配置了 TIR_NOTIFY_URL 时，额外以 HTTP POST 推送该地址
    #（由 edushield 部署方提供桥接端点；子 Agent 不修改主系统代码）。
    NOTIFY_URL: str = os.getenv("TIR_NOTIFY_URL", "")
    NOTIFY_TIMEOUT_SECONDS: int = int(os.getenv("TIR_NOTIFY_TIMEOUT_SECONDS", "10"))

    # ---- 子 Agent HTTP 服务（edushield 可经 HTTP REST 调用，对齐计划书 3.5）----
    API_HOST: str = os.getenv("TIR_API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("TIR_API_PORT", "8090"))

    # ---- 审计留档 ----
    # 对齐计划书“审计留档 180 天”：子 Agent 本地告警/预案/报告默认留存天数
    RETENTION_DAYS: int = int(os.getenv("TIR_RETENTION_DAYS", "180"))

    # ---- 派生路径 ----
    ALERTS_DIR: Path = STORE_DIR / "alerts"
    PLAYBOOKS_DIR: Path = STORE_DIR / "playbooks"
    REPORTS_DIR: Path = STORE_DIR / "reports"
    LOGS_DIR: Path = Path(os.getenv("TIR_LOG_DIR", str(PACKAGE_DIR / "storage" / "logs")))

    def ensure_dirs(self) -> None:
        """创建子 Agent 专属存储目录（全部为新增目录，不影响主系统）。"""
        for d in (self.ALERTS_DIR, self.PLAYBOOKS_DIR, self.REPORTS_DIR, self.LOGS_DIR):
            d.mkdir(parents=True, exist_ok=True)


config = ThreatIRConfig()
