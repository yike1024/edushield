"""深信服数据接入（阶段 2）。

两条数据通道（自动降级）：
    1. sample —— 官方《安全告警日志规范》配套的 10 条脱敏样例（默认，离线可用）
    2. live   —— XDR OpenAPI（配置 XDR_BASE_URL + 联动码/aksk 后启用）

告警字段规范见《DataOpenDocument》：
    uuId / srcIp / dstIp / threatClass / threatType / threatSubType /
    riskLevel / dealStatus / analysisInfo / threatDefine / extensions ...
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from config.settings import settings

logger = logging.getLogger(__name__)

# severity(0-100) 与协议 Severity 的映射阈值
_SEVERITY_MAP = [
    (90, "critical"),
    (70, "high"),
    (40, "medium"),
    (20, "low"),
]


def normalize_alarm(raw: dict[str, Any]) -> dict[str, Any]:
    """把 XDR 原始告警归一化成平台通用结构（供判定/报告/部件使用）。"""
    score = 0
    if raw.get("riskLevel"):
        try:
            score = int(raw["riskLevel"]) * 10
        except (TypeError, ValueError):
            score = 0
    elif raw.get("severity") is not None:
        try:
            score = int(raw["severity"])
        except (TypeError, ValueError):
            score = 0

    severity = "info"
    for threshold, name in _SEVERITY_MAP:
        if score >= threshold:
            severity = name
            break

    threat_define = raw.get("threatDefine") or []
    if threat_define:
        if 100 in threat_define:
            verdict_hint = "false_positive"
        elif 1000 in threat_define:
            verdict_hint = "real_threat"
        else:
            verdict_hint = "pending_review"
    else:
        verdict_hint = "pending_review"

    return {
        "id": raw.get("uuId", ""),
        "source": "xdr",
        "severity": severity,
        "severity_score": score,
        "verdict_hint": verdict_hint,
        "source_ip": raw.get("srcIp") or raw.get("xffClientIp") or "",
        "dest_ip": raw.get("dstIp") or "",
        "src_port": raw.get("srcPort"),
        "dst_port": raw.get("dstPort"),
        "direction": raw.get("direction"),
        "protocol": raw.get("protocol", ""),
        "threat_class": raw.get("threatClass"),
        "threat_type": raw.get("threatType"),
        "threat_sub_type": raw.get("threatSubType"),
        "rule_id": raw.get("alertRuleId", ""),
        "engine": raw.get("alertEngine", ""),
        "deal_status": raw.get("dealStatus"),
        "title": raw.get("name") or raw.get("description") or "未知告警",
        "description": raw.get("description", ""),
        "analysis": raw.get("analysisInfo", ""),
        "url": raw.get("url", ""),
        "host": raw.get("host", ""),
        "user_agent": raw.get("userAgent", ""),
        "first_time": raw.get("firstTimestamp"),
        "last_time": raw.get("lastTimestamp"),
        "occur_time": raw.get("occurTimestamp"),
        "raw": raw,
    }


class SampleAlarmLoader:
    """官方 10 条脱敏告警样例（离线模式）。"""

    def __init__(self, sample_file: str = settings.XDR_SAMPLE_FILE):
        self._path = Path(sample_file)
        self._cache: Optional[list[dict]] = None

    def load(self) -> list[dict]:
        if self._cache is None:
            if not self._path.exists():
                logger.warning(f"[data_source] 样例文件不存在: {self._path}")
                self._cache = []
            else:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                self._cache = [normalize_alarm(r) for r in raw]
                logger.info(f"[data_source] 加载 {len(self._cache)} 条 XDR 告警样例")
        return self._cache

    def list(self, limit: int = 50) -> list[dict]:
        return self.load()[:limit]


def get_sample_loader() -> SampleAlarmLoader:
    return SampleAlarmLoader()
