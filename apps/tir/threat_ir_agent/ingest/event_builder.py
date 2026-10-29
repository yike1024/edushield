# -*- coding: utf-8 -*-
"""
NormalizedRecord → DetectionEvent 生成逻辑
===========================================
把解析器产出的规范化记录映射为与现有 DetectionEvent JSON Schema 完全兼容的事件：
- 可映射字段 → 标准字段（event_type/target/source_ip/severity_hint/description/raw/context）
- 无法映射字段 → raw.raw_data / raw.extra_context（不丢失原始信息）
- 溯源字段 → context.source_file / context.record_index
- parse_error 标记事件也在此生成（交由应急响应模块降级处理）

不修改 models.py 中 DetectionEvent 的 Schema 定义。本文件为【新增文件】。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

# severity 归一：任意输入 → critical/high/medium/low/info
_SEV_MAP = {
    "critical": "critical", "危": "critical", "5": "critical", "10": "critical",
    "high": "high", "高": "high", "4": "high", "9": "high", "8": "high", "7": "high",
    "medium": "medium", "中": "medium", "3": "medium", "6": "medium", "5": "medium",
    "low": "low", "低": "low", "2": "low", "4": "low", "3": "low",
    "info": "info", "信息": "info", "1": "info", "0": "info", "2": "info", "1": "info",
}

# 严重度排序（越小越严重），用于 min_severity 过滤
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_rank(sev: Optional[str]) -> int:
    """严重度 → 排序值（critical=0 ... info=4）。"""
    return _SEVERITY_RANK.get(str(sev or "").strip().lower(), 4)


def filter_by_min_severity(events: list[dict], min_severity: str) -> list[dict]:
    """只保留严重度 ≥ 阈值的普通事件；parse_error 事件不受过滤影响（始终保留）。

    min_severity ∈ {critical, high, medium, low, info}
    例：min_severity="medium" → 仅保留 critical/high/medium。
    """
    min_rank = severity_rank(min_severity)
    return [e for e in events
            if e.get("raw", {}).get("parse_error") or severity_rank(e.get("severity_hint")) <= min_rank]


def _norm_severity(sev: Optional[str]) -> str:
    if not sev:
        return "info"
    s = str(sev).strip().lower()
    if s in _SEV_MAP:
        return _SEV_MAP[s]
    try:
        n = float(s)
    except ValueError:
        return "info"
    if n >= 9:
        return "critical"
    if n >= 7:
        return "high"
    if n >= 4:
        return "medium"
    if n >= 2:
        return "low"
    return "info"


def _short_id() -> str:
    import uuid
    return f"tir_event_{uuid.uuid4().hex[:8]}"


def _deterministic_event_id(source_file: str, record_index: int) -> str:
    """确定性事件ID：由 source_file + record_index 派生（同一输入重复运行结果稳定，便于溯源/去重）。"""
    digest = hashlib.sha1(f"{source_file}#{record_index}".encode("utf-8")).hexdigest()[:8]
    return f"tir_event_{digest}"


def record_to_event(record: dict, source_file: str, record_index: int,
                    parser_name: str) -> dict:
    """规范化记录 → DetectionEvent dict（与现有 Schema 兼容）。"""
    extra = dict(record.get("extra") or {})
    raw_data = record.get("raw_data") or ""
    src_ip = record.get("src_ip")
    dst_ip = record.get("dst_ip")
    dport = record.get("dst_port")
    target = ""
    if dst_ip:
        target = f"{dst_ip}:{dport}" if dport else dst_ip

    # 事件类型归一：优先取 event_type，其次从 IOC/摘要推断
    event_type = record.get("event_type") or "security_detection"

    ioc = record.get("ioc") or []
    extra.setdefault("ioc", ioc)

    evt = {
        "event_id": _deterministic_event_id(source_file, record_index),
        "source": f"ingest:{parser_name}",
        "domain": "threat-alert",
        "event_type": event_type,
        "target": target,
        "source_ip": src_ip,
        "severity_hint": _norm_severity(record.get("severity")),
        "description": record.get("summary") or f"{parser_name} 解析到一条安全记录",
        "raw": {
            "raw_data": raw_data[:4000],           # 原始日志片段/证据摘要（保真）
            "extra_context": extra,                 # 无法映射的原始关键信息（不丢失）
            "format": parser_name,
            "parse_error": False,
            "record": {k: v for k, v in record.items()
                       if k not in ("raw_data", "extra", "summary")},
        },
        "context": {
            "source_file": source_file,
            "record_index": record_index,
            "pipeline": "ingest",
            "tool": "ingest-layer",
            "task_id": f"ingest:{Path(source_file).name}#{record_index}",
        },
    }
    # 仅在记录带时间戳时写入 occurred_at（避免 None 触发下游 Schema 校验失败）
    if record.get("timestamp"):
        evt["occurred_at"] = record["timestamp"]
    return evt


def parse_error_event(path: Path, error: BaseException | str,
                      parser_name: Optional[str], raw_summary: str = "") -> dict:
    """解析失败/无法识别 → 带 parse_error 标记的 DetectionEvent（降级处理）。

    该事件按正常流程进入威胁警报 + 应急响应（降级处置），并保留错误详情。
    """
    err_text = str(error)
    return {
        "event_id": _short_id(),
        "source": f"ingest:{parser_name or 'unknown-format'}",
        "domain": "threat-alert",
        "event_type": "parse_error",
        "target": str(path),
        "source_ip": None,
        "severity_hint": "low",
        "description": f"[parse_error] 数据文件处理失败: {err_text}",
        "raw": {
            "raw_data": (raw_summary or "")[:4000],
            "extra_context": {"error": err_text, "file": str(path)},
            "format": parser_name or "unknown",
            "parse_error": True,
        },
        "context": {
            "source_file": str(path),
            "record_index": 0,
            "pipeline": "ingest",
            "tool": "ingest-layer",
            "task_id": f"ingest:{Path(path).name}#parse_error",
        },
    }


def file_fingerprint(path: Path, size: int) -> str:
    """文件指纹（用于 parse_error 事件溯源）。"""
    return f"{path.name}|{size}|{hashlib.md5(path.name.encode('utf-8')).hexdigest()[:8]}"
