"""部件注册表 —— domain → {host, port, token}。

权威来源：aisoc-docs 01 §2.1 端口规划、03 §8。
- 大脑启动时加载；新增部件 = 注册表加一行（或改 registry.json）
- 下发任务时按 domain 取 host/port/token
- 阶段 1：默认内置两个一期部件（pentest 8787 / logaudit 8788），
  可通过 REGISTRY_FILE 指向 JSON 覆盖。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from protocol import Domain

logger = logging.getLogger(__name__)

# 默认注册表基线（aisoc-docs 01 §2.1）
_DEFAULT_PARTS: dict[str, dict] = {
    "pentest": {"host": "127.0.0.1", "port": 8786, "token": "tk_pentest_dev", "auth": "bearer"},
    "logaudit": {"host": "127.0.0.1", "port": 8788, "token": "tk_logaudit_dev", "auth": "cookie"},
    "intel": {"host": "127.0.0.1", "port": 8789, "token": "tk_intel_dev", "auth": "bearer"},
}


class PartSpec(BaseModel):
    domain: str
    host: str
    port: int
    token: str = ""
    auth: str = Field(default="token", description="鉴权方式，预留：token / aksk")
    enabled: bool = True

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class Registry:
    """部件注册表（线程内只读，启动时加载一次）。"""

    def __init__(self, parts: list[PartSpec]):
        self._parts = {p.domain: p for p in parts}

    @classmethod
    def load(cls, registry_file: Optional[str] = None) -> "Registry":
        """加载注册表：显式 JSON 文件 > 默认内置。"""
        if registry_file:
            path = Path(registry_file)
            if path.exists():
                raw = json.loads(path.read_text(encoding="utf-8"))
                parts = [PartSpec(domain=k, **v) for k, v in raw.items()]
                logger.info(f"[registry] 从 {path} 加载 {len(parts)} 个部件")
                return cls(parts)
            logger.warning(f"[registry] 注册表文件不存在，回退默认: {registry_file}")

        parts = [PartSpec(domain=k, **v) for k, v in _DEFAULT_PARTS.items()]
        logger.info(f"[registry] 使用默认注册表（{len(parts)} 个部件）")
        return cls(parts)

    def get(self, domain: str | Domain) -> PartSpec:
        key = domain.value if isinstance(domain, Domain) else domain
        part = self._parts.get(key)
        if part is None:
            raise KeyError(f"未知部件域: {key}（注册表: {sorted(self._parts)}）")
        if not part.enabled:
            raise RuntimeError(f"部件已禁用: {key}")
        return part

    def list(self) -> list[dict]:
        return [p.model_dump() for p in self._parts.values()]
