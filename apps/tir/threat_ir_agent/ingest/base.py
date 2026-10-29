# -*- coding: utf-8 -*-
"""
解析器抽象基类 + 规范化记录约定
================================
NormalizedRecord：解析器产出的"规范化安全字段"字典，约定键如下
（全部可选，event_builder 负责映射到 DetectionEvent）：

  timestamp   : 时间戳（ISO 字符串或原始字符串）
  event_type  : 事件类型/告警名称（如 brute_force / sql_injection / scan / malware）
  severity    : critical|high|medium|low|info
  src_ip / dst_ip / src_port / dst_port : 源/目的 IP 与端口
  protocol    : 协议（tcp/udp/icmp/http/ssh...）
  host / user : 主机 / 用户信息
  file_name / file_hash : 文件名 / 哈希
  ioc         : 威胁指标列表（IP/域名/哈希）
  summary     : 事件摘要（中文/英文均可）
  raw_data    : 原始日志片段 / 证据摘要（尽量保留原文）
  extra       : 无法映射到标准字段的额外键值（dict）

本文件为【新增文件】。
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Pattern


class ParseError(Exception):
    """解析失败（格式识别成功但解析异常时抛出，由流水线转 parse_error 事件）。"""

    def __init__(self, message: str, raw_summary: str = "") -> None:
        super().__init__(message)
        self.raw_summary = raw_summary[:2000]  # 原始数据摘要（防超大）


class BaseParser(ABC):
    """所有格式解析器的抽象基类。

    子类需声明识别特征（extensions/magics/content_patterns/schema_keys）
    并实现 parse()。识别特征供 FormatDetector 多策略打分使用。
    """

    # ---- 元信息 ----
    name: str = "base"                 # 唯一标识（registry 用）
    display_name: str = "Base Parser"
    category: str = "generic"          # network | host | intel | generic | alert

    # ---- 识别特征（多策略）----
    extensions: set[str] = set()       # 文件扩展名（弱信号，0.3 分）
    magics: list[tuple[bytes, float]] = []       # (文件头魔数, 置信度0~1)
    content_patterns: list[tuple[Pattern, float]] = []  # (首4KB内正则, 置信度)
    schema_keys: Optional[dict] = None # JSON/CSV 首条记录的必含键（Schema 校验）

    # ---- 解析入口 ----
    @abstractmethod
    def parse(self, path: Path) -> list[dict]:
        """解析文件，返回 NormalizedRecord 列表（每个 dict 遵循上述键约定）。"""

    # ==================================================================
    # 识别打分（框架调用，子类一般无需重写；也可重写做特殊识别）
    # ==================================================================
    def detect(self, path: Path, head: bytes) -> float:
        """多策略融合打分，返回 0~1 置信度。"""
        score = 0.0
        ext = path.suffix.lower()
        if ext in self.extensions:
            score = max(score, 0.3)
        for magic, conf in self.magics:
            if head.startswith(magic):
                score = max(score, conf)
        sample = head[:4096]
        try:
            text = sample.decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            text = ""
        for pat, conf in self.content_patterns:
            if pat.search(text):
                score = max(score, conf)
        return score

    # ==================================================================
    # 工具函数（子类复用）
    # ==================================================================
    @staticmethod
    def _sniff_delimiter(head: bytes) -> Optional[str]:
        """CSV/TSV 分隔符嗅探：优先制表符，其次逗号，再分号。"""
        sample = head[:4096].decode("utf-8", "ignore")
        counts = {d: sample.count(d) for d in ("\t", ",", ";")}
        best = max(counts, key=counts.get)
        return best if counts[best] > 0 else None

    @staticmethod
    def _strip_bom(text: str) -> str:
        return text.lstrip("\ufeff")

    @staticmethod
    def _hash_file(path: Path, algo: str = "sha256") -> str:
        import hashlib
        h = hashlib.new(algo)
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _safe_text(data: bytes, limit: int = 2000) -> str:
        """二进制 → 可打印文本（不可打印字符转 .），供 raw_data 摘要。"""
        out = []
        for b in data[:limit]:
            if 32 <= b < 127 or b in (9, 10, 13):
                out.append(chr(b))
            else:
                out.append(".")
        return "".join(out)
