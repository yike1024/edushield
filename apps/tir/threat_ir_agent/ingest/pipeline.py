# -*- coding: utf-8 -*-
"""
ingest 流水线：文件 → 格式识别 → 解析 → DetectionEvent → 下游分析
=================================================================
流程：
  接收数据文件 → 格式识别 → 选择对应解析器 → 提取安全字段
  → 生成 DetectionEvent JSON → 调用现有威胁报警与应急响应逻辑
异常路径：
  格式识别失败 / 解析异常 → 生成 parse_error 标记的 DetectionEvent，
  同样送入下游应急响应模块做降级处理（不中断整个流水线）。
批量：
  多记录文件拆分为多个事件，逐条送入下游；context 保留 source_file+record_index 溯源。

对接现有模块：本层只调用 ThreatIRSubAgent.handle_event()（现有门面），
DetectionEvent Schema 零改动，现有威胁报警/应急响应核心逻辑零改动。
本文件为【新增文件】。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Optional

from ..models import DetectionEvent
from .base import ParseError
from .detector import FormatDetector, detector as default_detector
from .event_builder import (
    filter_by_min_severity,
    parse_error_event,
    record_to_event,
)

logger = logging.getLogger(__name__)


class IngestPipeline:
    """数据文件摄入流水线。"""

    def __init__(self, detector: Optional[FormatDetector] = None,
                 agent: Optional[object] = None) -> None:
        self.detector = detector or default_detector
        self.agent = agent  # 下游分析门面（ThreatIRSubAgent）；None 则只转换不分析

    # ------------------------------------------------------------------
    def ingest_file(self, path: str | Path, feed: bool = True,
                    max_events: Optional[int] = None,
                    min_severity: Optional[str] = None) -> dict:
        """处理单个数据文件。

        参数：
          path         数据文件路径
          feed         是否送入下游（威胁警报 + 应急响应）
          max_events   最多生成事件数（大文件先按严重度排序再截断）
          min_severity 只处理严重度 ≥ 阈值的普通事件（critical/high/medium/low/info）；
                       parse_error 事件不受过滤影响，始终保留

        返回结构：
        {
          "source_file", "format"(parser name/None), "detect_note",
          "records": n,
          "events_total": 过滤前事件总数,
          "events_filtered_out": 因 min_severity 被过滤的事件数,
          "events": [DetectionEvent dict...],
          "results": [下游返回...] (feed=True 时),
          "parse_error": bool, "error": str|None
        }
        """
        p = Path(path)
        if not p.is_file():
            return self._fail(p, f"文件不存在: {p}", None)

        # 1) 格式识别
        parser, score = self.detector.detect(p)
        note = self.detector.explain(p, parser, score)

        # 2) 无法识别 → parse_error 降级
        if parser is None:
            evt = parse_error_event(p, f"格式无法识别（{note}）", None,
                                    raw_summary=self._head_text(p))
            return self._emit(p, None, 0, [evt], feed, note, parse_error=True)

        # 3) 解析
        try:
            records = parser.parse(p)
        except ParseError as e:
            evt = parse_error_event(p, e, parser.name, e.raw_summary or self._head_text(p))
            return self._emit(p, parser.name, 0, [evt], feed, note, parse_error=True,
                              error=str(e))
        except Exception as e:  # noqa: BLE001 - 任何解析异常都降级而非中断
            logger.exception("[Ingest] %s 解析异常", p.name)
            evt = parse_error_event(p, e, parser.name, self._head_text(p))
            return self._emit(p, parser.name, 0, [evt], feed, note, parse_error=True,
                              error=str(e))

        # 4) 规范化记录 → DetectionEvent（批量，保留 source_file+record_index 溯源）
        events = []
        for idx, rec in enumerate(records, 1):
            events.append(record_to_event(rec, str(p), idx, parser.name))
            if max_events and len(events) >= max_events:
                logger.info("[Ingest] 达到 max_events=%d，截断", max_events)
                break

        # 5) 严重度过滤（只处理 high/medium 及以上；parse_error 始终保留）
        events_total = len(events)
        events_filtered_out = 0
        if min_severity:
            kept = filter_by_min_severity(events, min_severity)
            events_filtered_out = events_total - len(kept)
            events = kept
            logger.info("[Ingest] min_severity=%s 过滤：%d/%d 条保留",
                        min_severity, len(events), events_total)

        # 6) 送入下游（威胁警报 + 应急响应；min_severity 同时作为输出最低告警级别门槛）
        return self._emit(p, parser.name, len(records), events, feed, note,
                          events_total=events_total,
                          events_filtered_out=events_filtered_out,
                          min_severity=min_severity)

    # ------------------------------------------------------------------
    def _emit(self, path: Path, fmt: Optional[str], records: int,
              events: list[dict], feed: bool, note: str,
              parse_error: bool = False, error: Optional[str] = None,
              events_total: Optional[int] = None,
              events_filtered_out: int = 0,
              min_severity: Optional[str] = None) -> dict:
        results = []
        alerts_filtered_by_verdict = 0
        if feed and self.agent is not None:
            for i, evt in enumerate(events, 1):
                try:
                    res = self.agent.handle_event(
                        DetectionEvent.from_dict(evt),
                        task_id=evt["context"]["task_id"],
                        min_alert_level=min_severity,  # 输出最低告警级别门槛
                    )
                    if res.get("skipped_by_level"):
                        alerts_filtered_by_verdict += 1
                    results.append(res)
                except Exception as e:  # noqa: BLE001 - 单条失败不中断批量
                    logger.warning("[Ingest] 下游处理第 %d 条失败: %s", i, e)
                    results.append({"error": str(e)})
        return {
            "source_file": str(path),
            "format": fmt,
            "detect_note": note,
            "records": records,
            "events": events,
            "events_total": events_total if events_total is not None else len(events),
            "events_filtered_out": events_filtered_out,
            "alerts_filtered_by_verdict": alerts_filtered_by_verdict,
            "results": results,
            "parse_error": parse_error,
            "error": error,
        }

    def _fail(self, path: Path, msg: str, fmt: Optional[str]) -> dict:
        evt = parse_error_event(path, msg, fmt)
        return self._emit(path, fmt, 0, [evt], feed=False, note=msg, parse_error=True,
                          error=msg)

    @staticmethod
    def _head_text(path: Path, limit: int = 2000) -> str:
        try:
            data = path.read_bytes()[:4096]
            return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)[:limit]
        except OSError:
            return ""


pipeline = IngestPipeline()


def ingest_file(path: str | Path, feed: bool = True, max_events: Optional[int] = None,
                min_severity: Optional[str] = None,
                agent: Optional[object] = None) -> dict:
    """便捷入口：默认使用全局 pipeline（agent 为 None 时仅转换不分析）。

    min_severity：只处理严重度 ≥ 阈值的普通事件（critical/high/medium/low/info），
    parse_error 事件始终保留。
    """
    if agent is not None:
        return IngestPipeline(agent=agent).ingest_file(
            path, feed=feed, max_events=max_events, min_severity=min_severity)
    return pipeline.ingest_file(path, feed=feed, max_events=max_events,
                                min_severity=min_severity)
