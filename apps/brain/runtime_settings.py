"""运行时行为设置 —— 后端权威值持久化（前端设置面板对接）。

前端契约见 runtime-settings-api.md：
- GET  /api/settings/runtime  返回全量 7 字段
- POST /api/settings/runtime  可选写入（实现后，改动再次 GET 值一致）
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from config.settings import settings

DEFAULTS: dict = {
    "defaultToolApprovalMode": "auto",
    "autoPlan": "off",
    "memoryCompilerEnabled": False,
    "subagentEffort": "medium",
    "maxSubagentDepth": 2,
    "coldResumePrune": True,
    "reasoningLanguage": "auto",
}

_ALLOWED: dict[str, set] = {
    "defaultToolApprovalMode": {"ask", "auto", "yolo"},
    "autoPlan": {"off", "on"},
    "subagentEffort": {"low", "medium", "high", "auto"},
    "reasoningLanguage": {"auto", "zh", "en"},
}

_lock = threading.Lock()
_path = Path(settings.BRAIN_DB_PATH).parent / "runtime_settings.json"


def get_all() -> dict:
    """读取全量字段：持久化值覆盖默认值，保证字段齐全。"""
    data = dict(DEFAULTS)
    with _lock:
        if _path.exists():
            try:
                data.update(json.loads(_path.read_text(encoding="utf-8")))
            except Exception:
                pass
    return data


def update(partial: dict) -> dict:
    """校验并持久化部分字段，返回更新后的全量值。"""
    data = get_all()
    for k, v in partial.items():
        if k not in DEFAULTS:
            continue
        if k in _ALLOWED and v not in _ALLOWED[k]:
            raise ValueError(f"{k} 非法值: {v}（允许 {sorted(_ALLOWED[k])}）")
        if k == "maxSubagentDepth":
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise ValueError("maxSubagentDepth 必须是正整数")
            if v < 1:
                raise ValueError("maxSubagentDepth 必须是正整数")
        if k in ("memoryCompilerEnabled", "coldResumePrune") and not isinstance(v, bool):
            raise ValueError(f"{k} 必须是布尔值")
        data[k] = v

    with _lock:
        _path.parent.mkdir(parents=True, exist_ok=True)
        _path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data
