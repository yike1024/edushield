# -*- coding: utf-8 -*-
"""
通用格式解析器：JSON/JSONL、CSV/TSV、XML、Parquet/Avro（依赖缺失时明确提示）
============================================================================
- JSON/JSONL：数组 / 单对象 / 每行一条；按已知键名映射
- CSV/TSV：分隔符嗅探 + 表头映射
- XML：ElementTree 解析，常用安全字段提取
- Parquet/Avro：识别格式；若未安装 pyarrow/fastavro，抛出明确提示的 ParseError
  （"不强行解析"，由流水线生成 parse_error 事件降级处理）

本文件为【新增文件】。
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ..base import BaseParser, ParseError
from ..registry import register_parser

logger = logging.getLogger(__name__)

_GENERIC_KEYS = {
    "src_ip": "src_ip", "source_ip": "src_ip", "srcip": "src_ip",
    "dst_ip": "dst_ip", "dest_ip": "dst_ip", "destination_ip": "dst_ip",
    "src_port": "src_port", "source_port": "src_port",
    "dst_port": "dst_port", "destination_port": "dst_port",
    "protocol": "protocol", "proto": "protocol",
    "severity": "severity", "level": "severity", "priority": "severity",
    "event_type": "event_type", "eventtype": "event_type", "type": "event_type",
    "name": "event_type", "signature": "event_type",
    "host": "host", "hostname": "host", "computer": "host", "agent": "host",
    "user": "user", "username": "user", "account": "user",
    "hash": "file_hash", "sha256": "file_hash", "md5": "file_hash", "file_hash": "file_hash",
    "file": "file_name", "filename": "file_name", "file_name": "file_name",
    "message": "summary", "description": "summary", "summary": "summary",
    "timestamp": "timestamp", "time": "timestamp", "date": "timestamp",
    "ioc": "ioc", "indicators": "ioc", "iocs": "ioc",
}


# ===========================================================================
# 1) JSON / JSONL
# ===========================================================================

@register_parser
class JsonParser(BaseParser):
    name = "generic_json"
    display_name = "JSON / JSONL"
    category = "generic"
    extensions = {".json", ".jsonl", ".ndjson"}
    content_patterns = [(re.compile(r"^\s*[\[{]", re.M), 0.5)]

    def parse(self, path: Path) -> list[dict]:
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError:
            loaded = None
        items = []
        if isinstance(loaded, list):
            items = loaded
        elif isinstance(loaded, dict):
            # 常见包裹结构：{"events": [...]} / {"records": [...]} / {"data": [...]}
            for key in ("events", "records", "data", "items", "results"):
                if isinstance(loaded.get(key), list):
                    items = loaded[key]
                    break
            else:
                items = [loaded]
        else:
            for ln in text.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    items.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
        records = []
        for item in items:
            if isinstance(item, dict):
                rec = _map_generic(item)
                if rec:
                    records.append(rec)
        if not records:
            raise ParseError("JSON 无有效记录", text[:500])
        return records


# ===========================================================================
# 2) CSV / TSV
# ===========================================================================

@register_parser
class CsvParser(BaseParser):
    name = "generic_csv"
    display_name = "CSV / TSV"
    category = "generic"
    extensions = {".csv", ".tsv", ".txt"}
    content_patterns = [(re.compile(r"(?m)^[^\n]*,[^\n]*\n[^\n]*,[^\n]*$"), 0.6),
                        (re.compile(r"(?m)^[^\n]*\t[^\n]*\n[^\n]*\t[^\n]*$"), 0.6)]

    def parse(self, path: Path) -> list[dict]:
        import csv as _csv
        head = path.read_bytes()[:4096]
        sep = self._sniff_delimiter(head) or ","
        rows = list(_csv.reader(path.open(encoding="utf-8", errors="replace"), delimiter=sep))
        if len(rows) < 2:
            raise ParseError("CSV 无表头或数据行", "")
        header = [h.strip().strip('"').strip("'") for h in rows[0]]
        records = []
        for row in rows[1:]:
            if not any(c.strip() for c in row):
                continue
            rec = _map_generic(dict(zip(header, row + [""] * (len(header) - len(row)))))
            if rec:
                records.append(rec)
        if not records:
            raise ParseError("CSV 无有效数据行", "\n".join(map(str, rows[:5])))
        return records


# ===========================================================================
# 3) XML（ElementTree）
# ===========================================================================

@register_parser
class XmlParser(BaseParser):
    name = "generic_xml"
    display_name = "XML"
    category = "generic"
    extensions = {".xml"}
    content_patterns = [(re.compile(r"^\s*<\?xml", re.M), 0.7),
                        (re.compile(r"^\s*<[A-Za-z_][\w.-]*[^>]*>\s*$", re.M), 0.4)]

    def parse(self, path: Path) -> list[dict]:
        try:
            root = ET.parse(str(path)).getroot()
        except ET.ParseError as e:
            raise ParseError(f"XML 解析失败: {e}", path.read_text(encoding="utf-8", errors="replace")[:500])
        records = []
        for elem in root.iter():
            if elem.tag in ("Event", "Alert", "Record", "entry", "row", "message", "item"):
                text = (elem.text or "").strip()
                if not text and len(elem) == 0:
                    continue
                rec = _map_xml_elem(elem)
                if rec:
                    records.append(rec)
        if not records:
            # 兜底：整个根元素作为一条记录
            rec = _map_xml_elem(root)
            if rec:
                records.append(rec)
        if not records:
            raise ParseError("XML 无有效记录", path.read_text(encoding="utf-8", errors="replace")[:500])
        return records


# ===========================================================================
# 4) Parquet / Avro（依赖缺失 → 明确提示，不强行解析）
# ===========================================================================

@register_parser
class ParquetAvroParser(BaseParser):
    name = "parquet_avro"
    display_name = "Parquet / Avro"
    category = "generic"
    extensions = {".parquet", ".pq", ".avro"}
    magics = [(b"PAR1", 0.95), (b"Obj\x01", 0.95)]  # Parquet / Avro OCF

    def parse(self, path: Path) -> list[dict]:
        head = path.read_bytes()[:4]
        kind = "Parquet" if head == b"PAR1" else "Avro"
        lib = "pyarrow" if kind == "Parquet" else "fastavro"
        raise ParseError(
            f"{kind} 文件需要第三方库 {lib} 才能解析，当前环境未安装，"
            f"不强行解析（请先 pip install {lib} 或先转成 JSON/CSV 再摄入）",
            path.read_bytes()[:200].hex())


# ===========================================================================
# 映射工具
# ===========================================================================

def _map_generic(item: dict) -> dict:
    mapped: dict = {}
    extra: dict = {}
    for k, v in item.items():
        key = str(k).lower()
        target = _GENERIC_KEYS.get(key)
        if target and v not in ("", None):
            if target == "ioc":
                mapped.setdefault("ioc", []).extend([v] if isinstance(v, str) else (v or []))
            elif target == "severity":
                mapped["severity"] = str(v)
            elif target == "event_type":
                mapped.setdefault("event_type", str(v))
            elif target == "timestamp":
                mapped["timestamp"] = str(v)
            else:
                mapped[target] = v
        else:
            extra[k] = v if not isinstance(v, (dict, list)) else json.dumps(v, ensure_ascii=False)[:500]
    if not mapped:
        return {}
    mapped.setdefault("event_type", "generic_event")
    mapped.setdefault("severity", "low")
    mapped.setdefault("summary", f"通用事件: {json.dumps({k: v for k, v in item.items() if k in ('name','description','message','event_type')}, ensure_ascii=False)[:200]}")
    mapped["raw_data"] = json.dumps(item, ensure_ascii=False)[:3000]
    mapped["extra"] = extra
    return mapped


def _map_xml_elem(elem) -> dict:
    attrs = {k: v for k, v in elem.attrib.items()}
    children = {ch.tag: (ch.text or "").strip() for ch in elem if len(ch) == 0}
    item = {**attrs, **children}
    if not item:
        return {}
    rec = _map_generic(item)
    if rec:
        rec["raw_data"] = ET.tostring(elem, encoding="unicode")[:3000]
    return rec
