# -*- coding: utf-8 -*-
"""
告警聚合格式解析器：CEF / LEEF / IDMEF
=======================================
- CEF ：CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|扩展键值
- LEEF：LEEF:1.0|Vendor|Product|Version|EventID|key=value 对
- IDMEF：XML（Alert/Classification/Analyzer/Source/Destination）

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

_CEF_SEV = {"0": "info", "1": "info", "2": "low", "3": "medium", "4": "medium",
            "5": "medium", "6": "high", "7": "high", "8": "high", "9": "critical", "10": "critical"}


def _kv_parse(ext: str) -> dict:
    r"""CEF/LEEF 扩展段键值解析（处理 \= 转义）。"""
    out: dict = {}
    for m in re.finditer(r"(\w+)=((?:[^=\s]|\s(?!\w+=)|\\=)+)", ext):
        k, v = m.group(1), m.group(2).strip()
        if k in out:
            continue
        out[k] = v
    return out


# ===========================================================================
# 1) CEF
# ===========================================================================

@register_parser
class CefParser(BaseParser):
    name = "cef"
    display_name = "CEF 告警"
    category = "alert"
    extensions = {".cef", ".log", ".txt"}
    content_patterns = [(re.compile(r"^CEF:\d\|", re.M), 0.95)]

    def parse(self, path: Path) -> list[dict]:
        records = []
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not ln.startswith("CEF:"):
                continue
            body = ln[4:]
            parts = body.split("|")
            if len(parts) < 8:
                continue
            # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
            version, vendor, product, dev_version, sig_id, name, sev, ext = (
                parts[0], parts[1], parts[2], parts[3], parts[4], parts[5],
                parts[6], "|".join(parts[7:]))
            kv = _kv_parse(ext)
            records.append({
                "timestamp": kv.get("rt") or kv.get("end") or None,
                "event_type": sig_id or "cef_alert",
                "severity": _CEF_SEV.get(sev, "medium"),
                "src_ip": kv.get("src") or kv.get("sourceAddress"),
                "dst_ip": kv.get("dst") or kv.get("destinationAddress"),
                "src_port": kv.get("spt"), "dst_port": kv.get("dpt"),
                "protocol": kv.get("proto"),
                "user": kv.get("suser") or kv.get("duser"),
                "file_name": kv.get("fname"),
                "summary": f"[CEF:{sev}] {name} (sig={sig_id}) {vendor}/{product}",
                "raw_data": ln[:3000],
                "extra": {"version": version, "vendor": vendor, "product": product,
                          "device_version": dev_version,
                          "cef_severity": sev, "extensions": kv},
            })
        if not records:
            raise ParseError("CEF 无有效告警行", "")
        return records


# ===========================================================================
# 2) LEEF
# ===========================================================================

@register_parser
class LeefParser(BaseParser):
    name = "leef"
    display_name = "LEEF 告警"
    category = "alert"
    extensions = {".leef", ".log", ".txt"}
    content_patterns = [(re.compile(r"^LEEF:1\.0\|", re.M), 0.95)]

    def parse(self, path: Path) -> list[dict]:
        records = []
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not ln.startswith("LEEF:"):
                continue
            body = ln[5:]
            parts = body.split("|")
            if len(parts) < 6:
                continue
            version, vendor, product, _v, event_id, rest = (parts[0], parts[1], parts[2],
                                                            parts[3], parts[4], "|".join(parts[5:]))
            kv = _kv_parse(rest)
            records.append({
                "timestamp": kv.get("devTime") or None,
                "event_type": event_id or "leef_alert",
                "severity": kv.get("sev", "medium").lower() if kv.get("sev") in ("low", "medium", "high", "critical", "info") else "medium",
                "src_ip": kv.get("src"), "dst_ip": kv.get("dst"),
                "src_port": kv.get("srcPort"), "dst_port": kv.get("dstPort"),
                "protocol": kv.get("proto"),
                "user": kv.get("usrName"),
                "summary": f"LEEF 告警: {event_id} ({vendor}/{product})",
                "raw_data": ln[:3000],
                "extra": {"version": version, "vendor": vendor, "product": product,
                          "event_id": event_id, "extensions": kv},
            })
        if not records:
            raise ParseError("LEEF 无有效告警行", "")
        return records


# ===========================================================================
# 3) IDMEF（XML）
# ===========================================================================

@register_parser
class IdmefParser(BaseParser):
    name = "idmef"
    display_name = "IDMEF 告警 (XML)"
    category = "alert"
    extensions = {".xml", ".idmef"}
    content_patterns = [(re.compile(r"<(?:IDMEF-Message|Alert)\b"), 0.9)]

    def parse(self, path: Path) -> list[dict]:
        try:
            root = ET.parse(str(path)).getroot()
        except ET.ParseError as e:
            raise ParseError(f"IDMEF XML 解析失败: {e}",
                             path.read_text(encoding="utf-8", errors="replace")[:500])
        records = []
        for alert in root.iter("Alert"):
            def _text(tag: str) -> str:
                el = alert.find(tag)
                return (el.text or "").strip() if el is not None and el.text else ""

            def _attr(tag: str, name: str) -> str:
                el = alert.find(tag)
                return (el.get(name) or "").strip() if el is not None else ""

            src = alert.find("Source")
            dst = alert.find("Target")
            src_ip = _attr("Source/Node/Address", "address") or (src.find("Node/Address").get("address") if src is not None and src.find("Node/Address") is not None else "")
            dst_ip = _attr("Target/Node/Address", "address") or (dst.find("Node/Address").get("address") if dst is not None and dst.find("Node/Address") is not None else "")
            records.append({
                "timestamp": _text("DetectTime"),
                "event_type": _text("Classification") or "idmef_alert",
                "severity": "high",
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": _attr("Source/Service/port", "value") or "",
                "dst_port": _attr("Target/Service/port", "value") or "",
                "protocol": _text("Target/Service/protocol") or "",
                "summary": f"IDMEF 告警: {_text('Classification') or '?'} "
                           f"{src_ip}->{dst_ip}",
                "raw_data": ET.tostring(alert, encoding="unicode")[:3000],
                "extra": {"analyzer": _text("Analyzer/name"),
                          "message_id": _attr(".", "messageid") or alert.get("messageid"),
                          "impact": _text("Impact")},
            })
        if not records:
            raise ParseError("IDMEF 无 Alert 节点", "")
        return records
