# -*- coding: utf-8 -*-
"""
情报类解析器：文件哈希列表 / MISP JSON·CSV / STIX 2.x / YARA 命中报告 / 恶意样本元数据
=====================================================================================
- 哈希列表：每行一个哈希（或 CSV/空格分隔），自动识别 MD5/SHA1/SHA256
- MISP：Event/Attribute 结构（JSON）或 type,value 列（CSV）
- STIX 2.x：objects[] 中 indicator / observed-data / malware / ipv4-addr 等
- YARA 命中：文本报告（rule ... file）或 JSON（rules/matches）
- 恶意样本：PE/ELF/OLE(OFFICE)/PDF/脚本 —— 仅提取元数据与哈希，不执行、不解压

本文件为【新增文件】。
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..base import BaseParser, ParseError
from ..registry import register_parser

logger = logging.getLogger(__name__)

_HASH_RE = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_SUSPECT_SCRIPT_KEYWORDS = ("eval(", "base64", "powershell", "-enc", "fromCharCode",
                            "cmd.exe", "rundll32", "wscript", "cscript", "certutil",
                            "mshta", "IEX(")


def _hash_type(h: str) -> str:
    return {64: "SHA256", 40: "SHA1", 32: "MD5"}.get(len(h), "unknown")


# ===========================================================================
# 1) 文件哈希列表
# ===========================================================================

@register_parser
class HashListParser(BaseParser):
    name = "hash_list"
    display_name = "文件哈希列表"
    category = "intel"
    extensions = {".txt", ".hashes", ".md5", ".sha1", ".sha256", ".csv", ".tsv"}
    content_patterns = [(re.compile(r"^\s*[a-fA-F0-9]{32,64}(\s+\S+)?\s*$", re.M), 0.9)]

    def parse(self, path: Path) -> list[dict]:
        hashes = []
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            # 兼容 "hash filename" 两列
            first = ln.split()[0].strip().lower()
            if _HASH_RE.fullmatch(first):
                hashes.append({"hash": first, "file_name": " ".join(ln.split()[1:]) or None})
        if not hashes:
            raise ParseError("未识别到哈希条目（MD5/SHA1/SHA256）", "")
        records = []
        for h in hashes:
            records.append({
                "timestamp": None,
                "event_type": "ioc_hash",
                "severity": "medium",
                "file_hash": h["hash"],
                "file_name": h.get("file_name"),
                "summary": f"哈希IOC: {_hash_type(h['hash'])} {h['hash'][:16]}... "
                           f"{'(' + h['file_name'] + ')' if h.get('file_name') else ''}",
                "raw_data": h["hash"] + ((" " + h["file_name"]) if h.get("file_name") else ""),
                "extra": {"hash_type": _hash_type(h["hash"]), "ioc": [h["hash"]]},
            })
        return records


# ===========================================================================
# 2) MISP（JSON Event / CSV）
# ===========================================================================

@register_parser
class MispParser(BaseParser):
    name = "misp"
    display_name = "MISP 情报"
    category = "intel"
    extensions = {".json", ".csv", ".misp"}
    content_patterns = [(re.compile(r'"Event"\s*:\s*\{'), 0.9),
                        (re.compile(r'"uuid"\s*:\s*"[0-9a-f-]{36}"', re.I), 0.6)]

    def parse(self, path: Path) -> list[dict]:
        head = path.read_bytes()[:1024].decode("utf-8", "ignore").lstrip("\ufeff").lstrip()
        if head.startswith("{"):
            return self._parse_json(path)
        return self._parse_csv(path)

    def _parse_json(self, path: Path) -> list[dict]:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        event = obj.get("Event") or obj
        attrs = event.get("Attribute") or []
        records = []
        for a in attrs:
            if not isinstance(a, dict):
                continue
            val = str(a.get("value", ""))
            atype = a.get("type", "")
            records.append({
                "timestamp": a.get("timestamp") or event.get("date"),
                "event_type": "misp_ioc",
                "severity": "medium" if a.get("to_ids", False) else "low",
                "src_ip": val if atype in ("ip-src", "ip-dst") else None,
                "file_hash": val if _HASH_RE.fullmatch(val) else None,
                "summary": f"MISP IOC [{atype}]: {val}",
                "raw_data": json.dumps(a, ensure_ascii=False)[:2000],
                "extra": {"uuid": a.get("uuid"), "category": a.get("category"),
                          "type": atype, "to_ids": a.get("to_ids"),
                          "event_uuid": event.get("uuid"), "ioc": [val]},
            })
        if not records:
            raise ParseError("MISP JSON 无 Attribute", path.read_text(encoding="utf-8", errors="replace")[:500])
        return records

    def _parse_csv(self, path: Path) -> list[dict]:
        import csv as _csv
        rows = list(_csv.reader(path.open(encoding="utf-8", errors="replace")))
        if not rows:
            raise ParseError("MISP CSV 为空", "")
        header = [h.strip().lower() for h in rows[0]]
        records = []
        for row in rows[1:]:
            item = dict(zip(header, row))
            val = item.get("value") or item.get("ioc") or ""
            if not val:
                continue
            records.append({
                "event_type": "misp_ioc",
                "severity": "medium",
                "file_hash": val if _HASH_RE.fullmatch(str(val)) else None,
                "summary": f"MISP IOC [{item.get('type','?')}]: {val}",
                "raw_data": ",".join(row)[:2000],
                "extra": {k: v for k, v in item.items() if k not in ("value", "type")},
            })
        if not records:
            raise ParseError("MISP CSV 无数据行", "")
        return records


# ===========================================================================
# 3) STIX 2.x
# ===========================================================================

@register_parser
class StixParser(BaseParser):
    name = "stix2"
    display_name = "STIX 2.x"
    category = "intel"
    extensions = {".json"}
    content_patterns = [(re.compile(r'"type"\s*:\s*"bundle"'), 0.7),
                        (re.compile(r'"spec_version"\s*:\s*"2\.'), 0.9)]

    def parse(self, path: Path) -> list[dict]:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        objects = obj.get("objects", []) if isinstance(obj, dict) else obj
        records = []
        for o in objects:
            if not isinstance(o, dict):
                continue
            otype = o.get("type", "")
            if otype in ("indicator", "observed-data", "malware", "ipv4-addr",
                         "domain-name", "url", "file", "attack-pattern", "campaign"):
                pattern = o.get("pattern") or ""
                iocs = re.findall(r"\[?(?:ipv4-addr|domain-name|url|file:hashes\.'SHA-256'|file:name)"
                                  r":value\s*=\s*'([^']+)'", pattern)
                records.append({
                    "timestamp": o.get("modified") or o.get("created"),
                    "event_type": f"stix_{otype}",
                    "severity": "medium" if o.get("pattern") else "low",
                    "file_hash": o.get("hashes", {}).get("SHA-256") if isinstance(o.get("hashes"), dict) else None,
                    "summary": f"STIX {otype}: {o.get('name') or o.get('value') or o.get('id','?')}",
                    "raw_data": json.dumps(o, ensure_ascii=False)[:2000],
                    "extra": {"stix_id": o.get("id"), "pattern": pattern,
                              "labels": o.get("labels", []), "ioc": iocs},
                })
        if not records:
            raise ParseError("STIX 无相关对象", path.read_text(encoding="utf-8", errors="replace")[:500])
        return records


# ===========================================================================
# 4) YARA 命中报告（文本 / JSON）
# ===========================================================================

_YARA_TEXT = re.compile(r"^([A-Za-z0-9_\-]+)\s+([^\s]+)\s*$", re.M)


@register_parser
class YaraParser(BaseParser):
    name = "yara_report"
    display_name = "YARA 命中报告"
    category = "intel"
    extensions = {".txt", ".json", ".yara_report"}
    content_patterns = [
        (re.compile(r"(?:rule|matched|match)\s+[A-Za-z0-9_\-]+\s+(?:file|path|target)", re.I), 0.8),
        # 文本报告常见行："规则名 绝对路径"
        (re.compile(r"^[A-Za-z0-9_\-]{3,64}\s+(?:/|[A-Za-z]:[\\/])", re.M), 0.75),
    ]

    def parse(self, path: Path) -> list[dict]:
        text = path.read_text(encoding="utf-8", errors="replace")
        head = text.lstrip()
        if head.startswith("{"):
            obj = json.loads(text)
            rules = obj.get("rules") or [obj]
            records = []
            for r in rules:
                if isinstance(r, dict):
                    fname = r.get("file") or r.get("path") or r.get("target") or r.get("filename")
                    records.append({
                        "event_type": "yara_hit",
                        "severity": "high",
                        "file_name": fname,
                        "summary": f"YARA 规则命中: {r.get('rule') or r.get('name')} @ {fname or '?'}",
                        "raw_data": json.dumps(r, ensure_ascii=False)[:2000],
                        "extra": {"rule": r.get("rule") or r.get("name"),
                                  "strings": r.get("strings", []), "ioc": [str(fname)] if fname else []},
                    })
            if not records:
                raise ParseError("YARA JSON 无命中条目", text[:500])
            return records
        # 文本报告：每行 "rule_name file_path"
        records = []
        for m in _YARA_TEXT.finditer(text):
            rule, fname = m.groups()
            records.append({
                "event_type": "yara_hit",
                "severity": "high",
                "file_name": fname,
                "summary": f"YARA 规则命中: {rule} @ {fname}",
                "raw_data": m.group(0),
                "extra": {"rule": rule, "ioc": [fname]},
            })
        if not records:
            raise ParseError("YARA 文本报告无命中行", text[:500])
        return records


# ===========================================================================
# 5) 恶意文件样本元数据（PE/ELF/OLE·Office/PDF/脚本）—— 只读提取，不执行
# ===========================================================================

@register_parser
class SampleParser(BaseParser):
    name = "malware_sample"
    display_name = "恶意文件样本 (PE/ELF/OLE/PDF/脚本)"
    category = "intel"
    extensions = {".exe", ".dll", ".elf", ".bin", ".doc", ".docx", ".xls", ".xlsx",
                  ".ppt", ".pptx", ".pdf", ".js", ".vbs", ".ps1", ".bat", ".sh", ".py", ".scr"}
    magics = [(b"MZ", 0.8), (b"\x7fELF", 0.8), (b"%PDF-", 0.8),
              (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0.9)]  # OLE

    def parse(self, path: Path) -> list[dict]:
        data = path.read_bytes()
        head = data[:4096]
        sha256 = self._hash_file(path, "sha256")
        sha1 = self._hash_file(path, "sha1")
        md5 = self._hash_file(path, "md5")
        fmt, info, sev = self._identify(head, path.suffix, data)
        summary = f"样本文件: {path.name} | 格式={fmt} | SHA256={sha256[:16]}..."
        if info:
            summary += " | " + info
        return [{
            "timestamp": None,
            "event_type": "malicious_sample",
            "severity": sev,
            "file_name": path.name,
            "file_hash": sha256,
            "summary": summary,
            "raw_data": self._safe_text(head, 800),
            "extra": {"format": fmt, "sha256": sha256, "sha1": sha1, "md5": md5,
                      "size_bytes": len(data), "info": info, "ioc": [sha256]},
        }]

    @staticmethod
    def _identify(head: bytes, ext: str, data: bytes) -> tuple[str, str, str]:
        """返回 (格式, 附加信息, 严重度)。仅元数据，不解压不执行。"""
        if head.startswith(b"MZ"):
            # PE：读取 e_lfanew 处的 PE 签名
            try:
                e_lfanew = struct_unpack_pe(head)
                info = f"PE 可执行文件 (入口偏移 {e_lfanew:#x})"
            except Exception:  # noqa: BLE001
                info = "PE 可执行文件"
            return "PE", info, "high"
        if head.startswith(b"\x7fELF"):
            cls = "64位" if head[4] == 2 else "32位"
            etype = {1: "可重定位", 2: "可执行", 3: "共享库"}.get(head[16], "?")
            machine = {0x3E: "x86-64", 0x03: "x86", 0xB7: "AArch64"}.get(
                int.from_bytes(head[18:20], "little"), "?")
            return "ELF", f"{cls} {etype} {machine}", "high"
        if head.startswith(b"%PDF-"):
            ver = head[5:8].decode("ascii", "ignore")
            return "PDF", f"PDF {ver} 文档", "medium"
        if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "OLE", "OLE 复合文档 (Office 老格式 doc/xls/ppt)", "medium"
        if head[:4] == b"PK\x03\x04":
            low = head.decode("utf-8", "ignore").lower()
            kind = "Office OOXML (docx/xlsx/pptx)" if ("[content_types].xml" in low or "word/" in low or "xl/" in low) else "ZIP 压缩包(需解压后分析，不强行解析)"
            return "ZIP/OOXML", kind, "medium"
        if ext in (".js", ".vbs", ".ps1", ".bat", ".sh", ".py", ".scr"):
            text = head.decode("utf-8", "ignore")
            hits = [k for k in _SUSPECT_SCRIPT_KEYWORDS if k.lower() in text.lower()]
            sev = "high" if hits else "low"
            info = f"脚本 {ext}；可疑特征: {hits}" if hits else f"脚本 {ext}（未发现明显可疑特征）"
            return "SCRIPT", info, sev
        return "UNKNOWN", "未知文件格式（仅记录哈希）", "low"


def struct_unpack_pe(head: bytes) -> int:
    """读取 PE 可选头中的入口点偏移（仅元数据）。"""
    import struct
    e_lfanew = struct.unpack("<I", head[0x3C:0x40])[0]
    return e_lfanew
