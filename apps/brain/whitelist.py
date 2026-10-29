"""授权白名单 —— 运行时读写 + 持久化（前端白名单管理按钮用）。

- 默认值来自 .env（settings.AUTHORIZED_TARGETS）
- 前端修改后写入 data/whitelist.json，重启不丢
- check_target_whitelisted 优先读本文件，其次 .env 默认值
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from config.settings import settings

_lock = threading.Lock()
_path = Path(settings.BRAIN_DB_PATH).parent / "whitelist.json"


def _defaults() -> dict:
    return {
        "enabled": settings.TARGET_WHITELIST_ENABLED,
        "targets": list(settings.AUTHORIZED_TARGETS),
    }


def get() -> dict:
    """当前白名单：{enabled, targets}。"""
    data = _defaults()
    with _lock:
        if _path.exists():
            try:
                saved = json.loads(_path.read_text(encoding="utf-8"))
                if isinstance(saved.get("targets"), list):
                    data["targets"] = saved["targets"]
                if isinstance(saved.get("enabled"), bool):
                    data["enabled"] = saved["enabled"]
            except Exception:
                pass
    return data


def _save(data: dict) -> dict:
    with _lock:
        _path.parent.mkdir(parents=True, exist_ok=True)
        _path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def contains(target: str) -> bool:
    data = get()
    if not data["enabled"]:
        return True  # 白名单关闭 = 全部放行
    return target in data["targets"]


def add(target: str) -> dict:
    data = get()
    t = target.strip()
    if t and t not in data["targets"]:
        data["targets"].append(t)
        _save(data)
    return data


def remove(target: str) -> dict:
    data = get()
    data["targets"] = [t for t in data["targets"] if t != target.strip()]
    _save(data)
    return data


def set_enabled(enabled: bool) -> dict:
    data = get()
    data["enabled"] = bool(enabled)
    _save(data)
    return data
