# -*- coding: utf-8 -*-
"""
主机行为解析器：Syslog / Windows EVTX / Linux Auditd / EDR·OSQuery·Beats 遥测
============================================================================
本文件为【新增文件】。
"""

from __future__ import annotations

import json
import logging
import re
import struct
from pathlib import Path

from ..base import BaseParser, ParseError
from ..registry import register_parser

logger = logging.getLogger(__name__)

# ===========================================================================
# 1) Syslog（RFC3164 / RFC5424）
# ===========================================================================

# RFC3164: <PRI>Mmm dd hh:mm:ss host tag[pid]: msg
_R3164 = re.compile(
    r"^<(\d{1,3})>(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+?)(?:\[\d+\])?:\s?(.*)$"
)
# RFC5424: <PRI>1 YYYY-MM-DDTHH:MM:SSZ host app procid msgid msg
_R5424 = re.compile(
    r"^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$"
)
_PRI_SEV = {0: "critical", 1: "critical", 2: "critical", 3: "high", 4: "medium",
            5: "medium", 6: "low", 7: "info"}


@register_parser
class SyslogParser(BaseParser):
    name = "syslog"
    display_name = "Syslog"
    category = "host"
    extensions = {".log", ".syslog", ".txt"}
    content_patterns = [(re.compile(r"^<\d{1,3}>(?:\d\s|\w{3}\s)", re.M), 0.85)]

    def parse(self, path: Path) -> list[dict]:
        records = []
        for idx, ln in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            ln = ln.strip()
            if not ln:
                continue
            m5424 = _R5424.match(ln)
            m3164 = _R3164.match(ln)
            if m5424:
                pri, ts, host, app, _, _, msg = m5424.groups()
                tag, body = app, msg
            elif m3164:
                pri, host, tag, body = m3164.groups()
                ts, msg = None, body
            else:
                continue
            try:
                sev = _PRI_SEV[int(pri) % 8]
            except (ValueError, TypeError):
                sev = "info"
            records.append({
                "timestamp": ts,
                "event_type": "syslog",
                "severity": sev,
                "host": host,
                "user": None,
                "summary": f"[syslog:{sev}] {host} {tag}: {body[:200]}",
                "raw_data": ln[:2000],
                "extra": {"priority": pri, "tag": tag, "facility": int(pri) // 8},
            })
        if not records:
            raise ParseError("Syslog 格式无法识别（非 RFC3164/5424）", "")
        return records


# ===========================================================================
# 2) Windows Event Log (EVTX) —— 基础解析（不依赖第三方库）
# ===========================================================================
# EVTX 结构：文件头(ElfFile) → 64KB Chunk(ElfChnk) → EventRecord(二进制XML UTF-16LE)
# 本解析器提取每条 EventRecord 的 XML 并正则提取关键字段；
# 不做模板解码/属性反序列化（完整能力依赖 python-evtx，未安装时给出明确提示）。

_EVTX_LEVEL_SEV = {"1": "critical", "2": "critical", "3": "high", "4": "medium", "5": "low"}


@register_parser
class EvtxParser(BaseParser):
    name = "evtx"
    display_name = "Windows 事件日志 (EVTX)"
    category = "host"
    extensions = {".evtx"}
    magics = [(b"ElfFile\x00", 0.95)]

    def parse(self, path: Path) -> list[dict]:
        data = path.read_bytes()
        if not data.startswith(b"ElfFile\x00"):
            raise ParseError("不是有效 EVTX 文件（缺少 ElfFile 魔数）")
        records = []
        pos = 0
        n = len(data)
        # 逐 Chunk（64KB）扫描 EventRecord
        while pos + 4096 <= n:
            if data[pos:pos + 8] == b"ElfChnk\x00":
                rec_pos = pos + 512  # Chunk 头 512 字节
                while rec_pos + 120 <= pos + 65536 and rec_pos + 120 <= n:
                    rec_len = struct.unpack("<I", data[rec_pos + 4:rec_pos + 8])[0]
                    if rec_len < 120 or rec_pos + rec_len > pos + 65536 or rec_pos + rec_len > n:
                        break
                    xml_bytes = data[rec_pos + 24: rec_pos + rec_len - 24]
                    xml_text = xml_bytes.decode("utf-16-le", "ignore")
                    rec = self._extract_xml(xml_text, rec_pos)
                    if rec:
                        records.append(rec)
                    rec_pos += rec_len
            pos += 65536
        if not records:
            raise ParseError(
                "EVTX 中未提取到事件记录（如需完整模板解码，请安装 python-evtx 后重试）",
                data[:200].hex())
        return records

    @staticmethod
    def _extract_xml(xml_text: str, offset: int) -> dict:
        m = re.search(r"<EventID[^>]*>\s*(\d+)\s*</EventID>", xml_text, re.S)
        evt_id = m.group(1) if m else "?"
        provider = computer = channel = level = time_created = user_sid = None
        data_pairs = []
        mp = re.search(r"<Provider Name=['\"]([^'\"]+)['\"]", xml_text, re.S)
        if mp:
            provider = mp.group(1)
        ml = re.search(r"<Level>(\d+)</Level>", xml_text, re.S)
        if ml:
            level = ml.group(1)
        mc = re.search(r"<Computer>([^<]+)</Computer>", xml_text, re.S)
        if mc:
            computer = mc.group(1)
        mch = re.search(r"<Channel>([^<]+)</Channel>", xml_text, re.S)
        if mch:
            channel = mch.group(1)
        mt = re.search(r"<TimeCreated SystemTime=['\"]([^'\"]+)['\"]", xml_text, re.S)
        if mt:
            time_created = mt.group(1)
        ms = re.search(r"<Security UserID=['\"]([^'\"]+)['\"]", xml_text, re.S)
        if ms:
            user_sid = ms.group(1)
        for md in re.finditer(r"<Data Name=['\"]([^'\"]+)['\"]>([^<]*)</Data>", xml_text, re.S):
            data_pairs.append((md.group(1), md.group(2).strip()[:200]))
        sev = _EVTX_LEVEL_SEV.get(level or "", "info")
        return {
            "timestamp": time_created,
            "event_type": f"windows_event_{evt_id}",
            "severity": sev,
            "host": computer,
            "user": user_sid,
            "summary": f"Windows 事件 {evt_id} ({provider or '未知来源'}) @ {computer or '?'} "
                       f"通道={channel or '?'}",
            "raw_data": xml_text[:4000],
            "extra": {"event_id": evt_id, "provider": provider, "channel": channel,
                      "level": level, "user_sid": user_sid,
                      "data": dict(data_pairs[:20]), "record_offset": offset},
        }


# ===========================================================================
# 3) Linux Auditd（/var/log/audit/audit.log）
# ===========================================================================

_AUDIT_RE = re.compile(r"type=(\S+)\s+msg=audit\((\d+\.\d+):\d+\):\s*(.*)", re.S)
_AUDIT_KEY = re.compile(r'key="?([^"]+)"?', re.S)
_AUDIT_ACCT = re.compile(r'acct="?([^"]+)"?', re.S)
_AUDIT_ADDR = re.compile(r"addr=([0-9a-fA-F:.]+)", re.S)
_AUDIT_EXE = re.compile(r'exe="?([^"]+)"?', re.S)


@register_parser
class AuditdParser(BaseParser):
    name = "auditd"
    display_name = "Linux Auditd 日志"
    category = "host"
    extensions = {".log", ".audit"}
    content_patterns = [(re.compile(r"^type=\S+\s+msg=audit\(\d+\.\d+:\d+\)"), 0.9)]

    def parse(self, path: Path) -> list[dict]:
        records = []
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _AUDIT_RE.match(ln.strip())
            if not m:
                continue
            atype, ts, detail = m.groups()
            key_m = _AUDIT_KEY.search(detail)
            acct_m = _AUDIT_ACCT.search(detail)
            addr_m = _AUDIT_ADDR.search(detail)
            exe_m = _AUDIT_EXE.search(detail)
            key_val = key_m.group(1) if key_m else None
            acct_val = acct_m.group(1) if acct_m else None
            addr_val = addr_m.group(1) if addr_m else None
            exe_val = exe_m.group(1) if exe_m else None
            sev = "high" if atype in ("AVC", "USER_AUTH", "CRED_ACQ") else "low"
            records.append({
                "timestamp": ts,
                "event_type": f"auditd_{atype}",
                "severity": sev,
                "host": None,
                "user": acct_val,
                "src_ip": addr_val,
                "summary": f"auditd[{atype}]{' 用户=' + acct_val if acct_val else ''}"
                           f"{' 来源=' + addr_val if addr_val else ''}"
                           f"{' 程序=' + exe_val if exe_val else ''}"
                           f"{' key=' + key_val if key_val else ''}",
                "raw_data": ln[:2000],
                "extra": {"audit_type": atype, "key": key_val, "exe": exe_val,
                          "detail": detail[:500]},
            })
        if not records:
            raise ParseError("Auditd 日志无有效记录", "")
        return records


# ===========================================================================
# 4) EDR / XDR / OSQuery / Auditbeat / Winlogbeat 遥测（JSON/JSONL/CSV）
# ===========================================================================
# 内置常见字段映射；未知字段进入 extra_context 不丢失。

_TELEMETRY_MAP = {
    "timestamp": "timestamp", "@timestamp": "timestamp", "time": "timestamp",
    "event.type": "event_type", "event_type": "event_type", "category": "event_type",
    "event.category": "event_type", "name": "event_type", "event.name": "event_type",
    "severity": "severity", "event.severity": "severity", "risk_score": "severity",
    "src_ip": "src_ip", "source_ip": "src_ip", "srcip": "src_ip", "src": "src_ip",
    "source.ip": "src_ip", "ip": "src_ip", "src_addr": "src_ip",
    "dst_ip": "dst_ip", "dest_ip": "dst_ip", "destination.ip": "dst_ip",
    "src_port": "src_port", "source.port": "src_port",
    "dst_port": "dst_port", "destination.port": "dst_port",
    "protocol": "protocol", "network.protocol": "protocol",
    "host": "host", "host.name": "host", "hostname": "host", "computer": "host",
    "user": "user", "user.name": "user", "username": "user",
    "file.hash.sha256": "file_hash", "sha256": "file_hash", "hash": "file_hash",
    "file.name": "file_name", "filename": "file_name",
    "message": "summary", "description": "summary", "event.description": "summary",
    "ioc": "ioc",
}


@register_parser
class TelemetryParser(BaseParser):
    name = "edr_telemetry"
    display_name = "EDR/XDR/OSQuery/Beats 遥测 (JSON/CSV)"
    category = "host"
    extensions = {".json", ".jsonl", ".csv", ".tsv", ".log"}
    content_patterns = [(re.compile(r'"@timestamp"\s*:'), 0.7),
                        (re.compile(r'"event"\s*:\s*\{'), 0.6)]

    def parse(self, path: Path) -> list[dict]:
        head = path.read_bytes()[:4096]
        text = head.decode("utf-8", "ignore").lstrip("\ufeff").lstrip()
        if text.startswith("[") or text.startswith("{"):
            return self._parse_json(path)
        return self._parse_csv(path)

    # ---- JSON / JSONL ----
    def _parse_json(self, path: Path) -> list[dict]:
        records = []
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        try:
            loaded = json.loads(raw_text)
            items = loaded if isinstance(loaded, list) else [loaded]
        except json.JSONDecodeError:
            items = []
            for ln in raw_text.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    items.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
        for item in items:
            if not isinstance(item, dict):
                continue
            rec = self._map_fields(item)
            if rec:
                records.append(rec)
        if not records:
            raise ParseError("EDR/遥测 JSON 无有效记录", raw_text[:500])
        return records

    # ---- CSV / TSV ----
    def _parse_csv(self, path: Path) -> list[dict]:
        import csv as _csv
        sep = self._sniff_delimiter(path.read_bytes()[:4096]) or ","
        rows = list(_csv.reader(path.open(encoding="utf-8", errors="replace"),
                                delimiter=sep))
        if not rows:
            raise ParseError("CSV 为空", "")
        header = [h.strip().strip('"').strip("'") for h in rows[0]]
        records = []
        for row in rows[1:]:
            item = dict(zip(header, row))
            rec = self._map_fields(item)
            if rec:
                records.append(rec)
        if not records:
            raise ParseError("CSV 无有效数据行", "\n".join(map(str, rows[:5])))
        return records

    def _map_fields(self, item: dict) -> dict:
        # 先把嵌套对象按点号扁平化（Beats/EDR 常见："host":{"name":...} → "host.name"）
        flat: dict = {}

        def _flatten(obj: dict, prefix: str = "") -> None:
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, dict):
                    _flatten(v, key)
                else:
                    flat.setdefault(key, v)

        _flatten(item)
        mapped: dict = {}
        extra: dict = {}
        for k, v in flat.items():
            target = _TELEMETRY_MAP.get(k)
            if target and v not in ("", None):
                if target == "ioc":
                    mapped.setdefault("ioc", []).extend(
                        [v] if isinstance(v, str) else v)
                elif target in ("src_ip", "dst_ip", "host", "user", "file_hash",
                                "file_name", "protocol", "src_port", "dst_port"):
                    mapped[target] = v
                elif target == "summary":
                    mapped.setdefault("summary", str(v)[:500])
                elif target == "event_type":
                    mapped.setdefault("event_type", str(v))
                elif target == "severity":
                    mapped["severity"] = str(v)
                elif target == "timestamp":
                    mapped["timestamp"] = str(v)
            else:
                extra[k] = v if not isinstance(v, (dict, list)) else json.dumps(v, ensure_ascii=False)[:500]
        if not mapped:
            return {}
        event_type = mapped.get("event_type") or "edr_event"
        mapped.setdefault("event_type", event_type)
        mapped.setdefault("severity", "low")
        mapped.setdefault("summary", f"EDR/遥测事件 {event_type}")
        mapped["raw_data"] = json.dumps(item, ensure_ascii=False)[:3000]
        mapped["extra"] = extra
        return mapped
