# -*- coding: utf-8 -*-
"""
格式识别器（多策略融合）
========================
对输入文件做格式识别：文件扩展名 + Magic Number + 内容特征正则 + 已知Schema校验，
取各解析器置信度最高者（≥ 阈值）为最终格式；无法识别返回 None，
由流水线生成 parse_error 标记的 DetectionEvent。

本文件为【新增文件】。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .base import BaseParser
from .registry import all_parsers

logger = logging.getLogger(__name__)

DETECT_THRESHOLD = 0.45  # 低于该置信度视为"无法识别"
HEAD_SIZE = 4096         # 识别采样字节数


class FormatDetector:
    """多策略格式识别器。"""

    def __init__(self, parsers: Optional[list[BaseParser]] = None) -> None:
        self.parsers = parsers if parsers is not None else all_parsers()

    # ------------------------------------------------------------------
    def detect(self, path: Path) -> tuple[Optional[BaseParser], float]:
        """识别文件格式，返回 (parser, 置信度)；无法识别返回 (None, 0.0)。"""
        if not path.is_file():
            return None, 0.0
        try:
            with open(path, "rb") as fh:
                head = fh.read(HEAD_SIZE)
        except OSError as e:
            logger.warning("[Detector] 读取文件头失败 %s: %s", path, e)
            return None, 0.0

        best_parser: Optional[BaseParser] = None
        best_score = 0.0
        for p in self.parsers:
            try:
                score = p.detect(path, head)
            except Exception as e:  # noqa: BLE001 - 单个解析器识别异常不影响整体
                logger.debug("[Detector] %s 识别异常: %s", p.name, e)
                continue
            if score > best_score:
                best_score, best_parser = score, p

        if best_parser is None or best_score < DETECT_THRESHOLD:
            return None, best_score
        return best_parser, best_score

    # ------------------------------------------------------------------
    @staticmethod
    def explain(path: Path, parser: Optional[BaseParser], score: float) -> str:
        """识别结果说明（供日志/parse_error 事件描述）。"""
        if parser is None:
            return f"无法识别文件格式（最高置信度 {score:.2f} < 阈值 {DETECT_THRESHOLD}）"
        return f"识别为 {parser.display_name}（{parser.name}，置信度 {score:.2f}）"


detector = FormatDetector()
