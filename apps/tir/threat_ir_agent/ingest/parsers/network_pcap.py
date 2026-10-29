# -*- coding: utf-8 -*-
"""
网络流量解析器：PCAP / PCAPNG / Zeek / Suricata EVE / NetFlow v5 / sFlow / IPFIX
================================================================================
- pcap  ：经典 libpcap（Ethernet+IPv4/IPv6 TCP/UDP），提取流与关键应用层特征
- pcapng：基础块解析（SHB/IDB/EPB），与 pcap 相同的记录产出
- Zeek  ：制表符分隔日志（#fields/#types 头）
- Suricata/Snort EVE：JSONL（event_type 字段）
- NetFlow v5：二进制记录
- sFlow v5：头部 + 基础采样信息（不做深度 per-sample 解码，明确标注）
- IPFIX (v9/v10)：导出头部信息（模板集深度解码为后续扩展，明确标注）
- TLS 加密流量：仅提取元数据并明确提示"加密流量，不强行解密"

本文件为【新增文件】。
"""

from __future__ import annotations

import json
import logging
import re
import struct
from pathlib import Path
from typing import Optional

from ..base import BaseParser, ParseError
from ..registry import register_parser

logger = logging.getLogger(__name__)

_SEV_BY_EVENT = {
    "alert": "high", "scan": "medium", "http": "info", "dns": "info",
    "ssh": "medium", "tls": "low", "smb": "medium", "flow": "low",
    "anomaly": "medium", "suspicious": "medium", "malware": "high",
    "brute_force": "high", "sql_injection": "high", "xss": "medium",
    "webshell": "critical", "data_exfiltration": "critical",
}


def _sev_for(event_type: str) -> str:
    return _SEV_BY_EVENT.get(str(event_type).lower(), "low")


# ===========================================================================
# 1) PCAP（经典 libpcap）
# ===========================================================================

_SERVER_PORTS = {22, 80, 443, 445, 8080, 8000, 8443, 3389, 3306, 6379, 27017, 25, 110, 143}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_WEB_PORTS = {80, 8080, 8000, 8888, 8443, 443}
_SQLI_KEYWORDS = ("union select", "union%20select", "or 1=1", "or%201=1",
                  "sleep(", "benchmark(", "'--", "1=1--", "information_schema")
_XSS_KEYWORDS = ("<script", "onerror=", "alert(", "javascript:", "%3cscript")
_TOMCAT_PATHS = ("/manager", "/examples", "/host-manager", "/docs")


@register_parser
class PcapParser(BaseParser):
    name = "pcap"
    display_name = "PCAP 网络抓包"
    category = "network"
    extensions = {".pcap", ".cap"}
    magics = [(b"\xd4\xc3\xb2\xa1", 0.95), (b"\xa1\xb2\xc3\xd4", 0.95),
              (b"\x4d\x3c\xb2\xa1", 0.95), (b"\xa1\xb2\x3c\x4d", 0.95)]  # us/ns 时间戳变体

    def parse(self, path: Path) -> list[dict]:
        with open(path, "rb") as fh:
            magic = fh.read(4)
            endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            gh = fh.read(20)
            linktype = struct.unpack(endian + "I", gh[16:20])[0]
            if linktype != 1:
                raise ParseError(f"仅支持 Ethernet(linktype=1)，当前 linktype={linktype}")
            flows: dict = {}
            while True:
                ph = fh.read(16)
                if len(ph) < 16:
                    break
                ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + "IIII", ph)
                data = fh.read(incl_len)
                if len(data) < incl_len:
                    break
                if incl_len < 14:
                    continue
                ethtype = struct.unpack(">H", data[12:14])[0]
                if ethtype not in (0x0800, 0x86DD):
                    continue
                meta = _parse_tcp_udp(data[14:], ethtype)
                if meta is None:
                    continue
                _accumulate_flow(meta, ts_sec + ts_usec / 1e6, flows)
        # 双向合并 + 完整统计产出（按严重度排序，供 max_events 截断保留高价值流）
        merged = _merge_flows(flows)
        records = [_emit_flow(f) for f in merged]
        if not records:
            raise ParseError("PCAP 中未提取到 IPv4/IPv6 TCP/UDP 记录", "无可用网络记录")
        # 精细化启发式：SSH 单连接不判定为爆破（多连接才升级）
        _refine_ssh_heuristic(records)
        records.sort(key=lambda r: (_SEV_RANK.get(r["severity"], 4),
                                    -int(r.get("extra", {}).get("bytes", 0))))
        return records


def _parse_tcp_udp(ip_payload: bytes, ethtype: int) -> Optional[dict]:
    """IPv4/IPv6 + TCP/UDP → 元数据 dict。"""
    if ethtype == 0x0800:  # IPv4
        if len(ip_payload) < 20:
            return None
        ihl = (ip_payload[0] & 0x0F) * 4
        if len(ip_payload) < ihl:
            return None
        src = ".".join(str(b) for b in ip_payload[12:16])
        dst = ".".join(str(b) for b in ip_payload[16:20])
        proto = ip_payload[9]
        rest = ip_payload[ihl:]
    else:  # IPv6
        if len(ip_payload) < 40:
            return None
        src = ":".join(f"{int.from_bytes(ip_payload[8+i*2:10+i*2],'big'):x}" for i in range(8))
        dst = ":".join(f"{int.from_bytes(ip_payload[24+i*2:26+i*2],'big'):x}" for i in range(8))
        proto = ip_payload[6]
        rest = ip_payload[40:]

    if proto == 6 and len(rest) >= 20:  # TCP
        sport, dport = struct.unpack(">HH", rest[0:4])
        flags = rest[13]
        tcp_off = ((rest[12] >> 4) * 4)
        payload = rest[tcp_off:]
        return {"src": src, "dst": dst, "sport": sport, "dport": dport,
                "proto": "tcp", "flags": flags, "payload": payload}
    if proto == 17 and len(rest) >= 8:  # UDP
        sport, dport = struct.unpack(">HH", rest[0:4])
        return {"src": src, "dst": dst, "sport": sport, "dport": dport,
                "proto": "udp", "flags": 0, "payload": rest[8:]}
    return None


def _accumulate_flow(meta: dict, ts: float, flows: dict) -> None:
    """按流聚合所有包（完整统计）。"""
    key = (meta["src"], meta["dst"], meta["sport"], meta["dport"], meta["proto"])
    f = flows.setdefault(key, {
        "src": meta["src"], "dst": meta["dst"],
        "sport": meta["sport"], "dport": meta["dport"], "proto": meta["proto"],
        "pkts": 0, "bytes": 0, "syn": 0, "first": ts, "last": ts,
        "http_reqs": [], "http_401": 0, "http_404": 0, "susp": [], "tls": False,
        "smb": 0,
    })
    f["pkts"] += 1
    f["bytes"] += len(meta["payload"])
    f["last"] = ts
    if meta["flags"] & 0x02:
        f["syn"] += 1
    payload = meta["payload"]
    if meta["proto"] == "tcp":
        # HTTP 请求行（客户端方向）
        if payload[:4] in (b"GET ", b"POST ", b"HEAD ", b"PUT "):
            line = payload.split(b"\r\n")[0].decode("utf-8", "replace")
            f["http_reqs"].append(line)
            low = line.lower()
            for kw in _SQLI_KEYWORDS:
                if kw in low:
                    f["susp"].append(("sql_injection", line[:120]))
                    break
            for kw in _XSS_KEYWORDS:
                if kw in low:
                    f["susp"].append(("xss", line[:120]))
                    break
        # HTTP 响应状态码（服务器方向，记到服务端口所在流）
        if meta["sport"] in _WEB_PORTS and payload.startswith(b"HTTP/"):
            parts = payload.split(b" ")
            if len(parts) >= 2:
                code = parts[1].decode("utf-8", "replace")
                if code == "401":
                    f["http_401"] += 1
                elif code == "404":
                    f["http_404"] += 1
        # TLS 记录头（0x16 0x03）
        if payload[:2] == b"\x16\x03":
            f["tls"] = True
    if meta["dport"] == 445:
        f["smb"] += 1


def _merge_flows(flows: dict) -> list[dict]:
    """双向流合并：同一连接的请求/响应方向合并为一条，保留服务端方向。"""
    merged: dict = {}
    for f in flows.values():
        canon = (tuple(sorted((f["src"], f["dst"]))),
                 tuple(sorted((f["sport"], f["dport"]))), f["proto"])
        if canon in merged:
            base = merged[canon]
            base["pkts"] += f["pkts"]
            base["bytes"] += f["bytes"]
            base["syn"] += f["syn"]
            base["tls"] = base["tls"] or f["tls"]
            base["smb"] += f["smb"]
            base["http_401"] += f["http_401"]
            base["http_404"] += f["http_404"]
            base["http_reqs"].extend(f["http_reqs"])
            base["susp"].extend(f["susp"])
            base["first"] = min(base["first"], f["first"])
            base["last"] = max(base["last"], f["last"])
            if _is_server_port(f["dport"]):
                base.update(src=f["src"], dst=f["dst"],
                            sport=f["sport"], dport=f["dport"])
        else:
            merged[canon] = dict(f)
    return list(merged.values())


def _is_server_port(port: int) -> bool:
    return port in _SERVER_PORTS


def _refine_ssh_heuristic(records: list[dict]) -> None:
    """SSH 启发式精细化：仅当同一来源对 22 端口建立多条连接时才判为爆破。

    单条 SSH 连接（即使数据量大）更可能是正常会话，标为 ssh_access/low，
    避免与模型研判产生无谓分歧。
    """
    ssh_by_src: dict[str, int] = {}
    for r in records:
        if r.get("dst_port") == 22:
            ssh_by_src[r.get("src_ip", "")] = ssh_by_src.get(r.get("src_ip", ""), 0) + 1
    for r in records:
        if r.get("dst_port") != 22:
            continue
        n = ssh_by_src.get(r.get("src_ip", ""), 0)
        if n >= 20:
            r["event_type"], r["severity"] = "brute_force", "high"
            r["summary"] = r["summary"].replace("SSH 端口连接", f"SSH 爆破（同源 {n} 条连接）")
        elif n >= 5:
            r["event_type"], r["severity"] = "brute_force", "medium"
            r["summary"] = r["summary"].replace("SSH 端口连接", f"SSH 爆破（同源 {n} 条连接）")
        else:
            r["event_type"], r["severity"] = "ssh_access", "low"
            r["summary"] = r["summary"].replace("SSH 端口连接", "SSH 访问")


def _emit_flow(f: dict) -> dict:
    """完整统计的流 → NormalizedRecord。"""
    evt_type = "network_flow"
    sev = "info"
    note = []
    dport = f["dport"]
    if dport == 22:
        evt_type, sev = "ssh_access", "low"   # 是否升级为爆破由 _refine_ssh_heuristic 决定
        note.append("SSH 端口连接")
    elif dport == 445:
        evt_type, sev = "smb_access", "low"
        note.append("SMB 访问")
    elif f["http_reqs"]:
        if f["susp"]:
            atype, line = f["susp"][0]
            evt_type, sev = atype, ("high" if atype == "sql_injection" else "medium")
            note.append(f"{atype} 特征: {line}")
        elif f["http_401"] >= 3:
            evt_type, sev = "brute_force", "high" if f["http_401"] >= 10 else "medium"
            note.append(f"HTTP 401 x{f['http_401']}，疑似弱口令爆破")
        elif f["http_404"] >= 20:
            evt_type, sev = "directory_scan", "medium"
            note.append(f"HTTP 404 x{f['http_404']}，疑似路径探测")
        else:
            evt_type, sev = "http_request", "info"
            note.append("HTTP: " + f["http_reqs"][0][:80])
    if f["tls"]:
        note.append("⚠ TLS 加密流量，仅提取元数据，不强行解密")
    return {
        "timestamp": f"{f['first']:.3f}",
        "event_type": evt_type,
        "severity": sev,
        "src_ip": f["src"], "dst_ip": f["dst"],
        "src_port": f["sport"], "dst_port": dport,
        "protocol": f["proto"],
        "summary": f"网络流: {f['src']}:{f['sport']} → {f['dst']}:{dport} "
                   f"({f['pkts']} 包 / {f['bytes']} 字节) " + "；".join(note),
        "raw_data": f"flow={f['src']}:{f['sport']}->{f['dst']}:{dport} "
                    f"proto={f['proto']} pkts={f['pkts']} bytes={f['bytes']} "
                    f"syn={f['syn']} tls={f['tls']} http401={f['http_401']} http404={f['http_404']}",
        "extra": {"pkts": f["pkts"], "bytes": f["bytes"], "syn": f["syn"],
                  "duration_sec": round(f["last"] - f["first"], 3),
                  "tls_encrypted": f["tls"], "http_requests": f["http_reqs"][:5],
                  "http_401": f["http_401"], "http_404": f["http_404"],
                  "suspicious_uris": f["susp"][:3]},
    }


# ===========================================================================
# 2) PCAPNG（基础块解析）
# ===========================================================================

@register_parser
class PcapngParser(BaseParser):
    name = "pcapng"
    display_name = "PCAPNG 网络抓包"
    category = "network"
    extensions = {".pcapng"}
    magics = [(b"\x0a\x0d\x0d\x0a", 0.95)]  # Section Header Block

    def parse(self, path: Path) -> list[dict]:
        records: list[dict] = []
        flows: dict = {}
        with open(path, "rb") as fh:
            data = fh.read()
        pos = 0
        linktype = None
        n = len(data)
        while pos + 12 <= n:
            btype, blen = struct.unpack("<II", data[pos:pos + 8])
            if blen < 12 or pos + blen > n:
                break
            body = data[pos + 8: pos + blen - 4]
            if btype == 0x0A0D0D0A:  # SHB
                if len(body) >= 8:
                    linktype = struct.unpack("<H", body[8:10])[0]
            elif btype == 0x00000001:  # IDB
                linktype = struct.unpack("<H", body[0:2])[0]
            elif btype == 0x00000006 and linktype == 1:  # EPB
                ts_hi, ts_lo, caplen, _ = struct.unpack("<IIII", body[0:16])
                pkt = body[16:16 + caplen]
                ts = ts_hi * (2 ** 32) / 1e6 + ts_lo / 1e6
                if len(pkt) >= 14:
                    ethtype = struct.unpack(">H", pkt[12:14])[0]
                    meta = _parse_tcp_udp(pkt[14:], ethtype)
                    if meta:
                        _accumulate_flow(meta, ts, flows)
            pos += blen
        for f in _merge_flows(flows):
            records.append(_emit_flow(f))
        if not records:
            raise ParseError("PCAPNG 中未提取到网络记录", "无可用记录")
        return records


# ===========================================================================
# 3) Zeek / Bro 日志（制表符分隔，带 #fields / #types 头）
# ===========================================================================

_ZEK_FIELD_HINTS = {
    "id.orig_h": "src_ip", "id.resp_h": "dst_ip",
    "id.orig_p": "src_port", "id.resp_p": "dst_port",
    "proto": "protocol", "uid": "extra.uid", "conn_state": "extra.conn_state",
    "service": "extra.service", "duration": "extra.duration",
    "orig_bytes": "extra.orig_bytes", "resp_bytes": "extra.resp_bytes",
}


@register_parser
class ZeekParser(BaseParser):
    name = "zeek"
    display_name = "Zeek/Bro 日志"
    category = "network"
    extensions = {".log"}
    content_patterns = [(re.compile(r"^#separator\s+\\x[0-9a-fA-F]{2}", re.M), 0.9),
                        (re.compile(r"^#fields\t", re.M), 0.85)]

    def parse(self, path: Path) -> list[dict]:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        sep, fields, types = "\t", [], []
        body: list[str] = []
        for ln in lines:
            if ln.startswith("#separator"):
                sep = ln.split("#separator", 1)[1].strip().encode().decode("unicode_escape")
            elif ln.startswith("#fields"):
                fields = ln.split("#fields", 1)[1].strip().split(sep)
            elif ln.startswith("#types"):
                types = ln.split("#types", 1)[1].strip().split(sep)
            elif ln and not ln.startswith("#"):
                body.append(ln)
        if not fields:
            raise ParseError("Zeek 日志缺少 #fields 头", "\n".join(lines[:5]))
        records = []
        for idx, ln in enumerate(body, 1):
            vals = ln.split(sep)
            row = dict(zip(fields, vals + [""] * (len(fields) - len(vals))))
            rec = {"timestamp": row.get("ts"), "event_type": row.get("event_type") or "zeek_event",
                   "severity": _sev_for(row.get("event_type", "")),
                   "src_ip": row.get("id.orig_h"), "dst_ip": row.get("id.resp_h"),
                   "src_port": row.get("id.orig_p"), "dst_port": row.get("id.resp_p"),
                   "protocol": row.get("proto"),
                   "summary": f"Zeek {row.get('event_type','event')}: {row.get('id.orig_h','?')} -> {row.get('id.resp_h','?')}",
                   "raw_data": ln[:2000],
                   "extra": {k: v for k, v in row.items()
                             if k not in ("ts", "id.orig_h", "id.resp_h",
                                          "id.orig_p", "id.resp_p", "proto")}}
            records.append(rec)
        if not records:
            raise ParseError("Zeek 日志无数据行", "\n".join(lines[:5]))
        return records


# ===========================================================================
# 4) Suricata / Snort EVE JSON（JSONL）
# ===========================================================================

@register_parser
class SuricataParser(BaseParser):
    name = "suricata_eve"
    display_name = "Suricata/Snort EVE JSON"
    category = "network"
    extensions = {".json", ".jsonl", ".eve", ".log"}
    content_patterns = [(re.compile(r'"event_type"\s*:\s*"(alert|flow|dns|http|tls|ssh|smb)"'), 0.9)]

    def parse(self, path: Path) -> list[dict]:
        records = []
        for idx, ln in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or "event_type" not in obj:
                continue
            et = obj.get("event_type", "unknown")
            alert = obj.get("alert") or {}
            flow = obj.get("flow") or {}
            src_ip = obj.get("src_ip") or flow.get("src_ip")
            dst_ip = obj.get("dest_ip") or flow.get("dest_ip")
            records.append({
                "timestamp": obj.get("timestamp"),
                "event_type": et if et != "alert" else (alert.get("signature_id") and "ids_alert" or "ids_alert"),
                "severity": _sev_for(et),
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": obj.get("src_port"), "dst_port": obj.get("dest_port"),
                "protocol": obj.get("proto"),
                "summary": (alert.get("signature") or alert.get("category") or f"Suricata {et}"),
                "raw_data": ln[:3000],
                "extra": {"signature": alert.get("signature"), "category": alert.get("category"),
                          "severity_raw": alert.get("severity"), "eve_type": et},
            })
        if not records:
            raise ParseError("Suricata EVE JSON 无有效事件行", "")
        return records


# ===========================================================================
# 5) NetFlow v5（二进制）
# ===========================================================================

@register_parser
class NetflowParser(BaseParser):
    name = "netflow_v5"
    display_name = "NetFlow v5 记录"
    category = "network"
    extensions = {".nflow", ".nf", ".bin", ".dat"}
    magics = [(b"\x00\x05", 0.85)]  # version=5 + count

    def parse(self, path: Path) -> list[dict]:
        data = path.read_bytes()
        if len(data) < 24:
            raise ParseError("NetFlow v5 文件过短", data[:200].hex())
        records = []
        pos = 0
        while pos + 24 <= len(data):
            version, count = struct.unpack(">HH", data[pos:pos + 4])
            if version != 5:
                break
            sys_uptime, unix_secs = struct.unpack(">II", data[pos + 4:pos + 12])
            for i in range(count):
                off = pos + 24 + i * 48
                if off + 48 > len(data):
                    break
                r = data[off:off + 48]
                src = ".".join(str(b) for b in r[0:4])
                dst = ".".join(str(b) for b in r[4:8])
                pkts, octets = struct.unpack(">II", r[16:24])
                sport, dport = struct.unpack(">HH", r[32:36])
                tcp_flags, prot, tos = r[36], r[37], r[38]
                records.append({
                    "timestamp": unix_secs,
                    "event_type": "netflow",
                    "severity": "low",
                    "src_ip": src, "dst_ip": dst,
                    "src_port": sport, "dst_port": dport,
                    "protocol": str(prot),
                    "summary": f"NetFlow: {src}:{sport} -> {dst}:{dport} "
                               f"({pkts} 包/{octets} 字节) prot={prot} flags={tcp_flags:#x}",
                    "raw_data": r.hex(),
                    "extra": {"pkts": pkts, "octets": octets, "tcp_flags": tcp_flags,
                              "tos": tos, "sys_uptime_ms": sys_uptime},
                })
            pos += 24 + count * 48
        if not records:
            raise ParseError("NetFlow v5 无有效记录", data[:200].hex())
        return records


# ===========================================================================
# 6) sFlow v5（头部 + 基础信息，不做深度 per-sample 解码）
# ===========================================================================

@register_parser
class SflowParser(BaseParser):
    name = "sflow_v5"
    display_name = "sFlow v5 采样"
    category = "network"
    extensions = {".sflow", ".sf"}
    magics = [(b"\x00\x00\x00\x05", 0.85)]  # sFlow version 5

    def parse(self, path: Path) -> list[dict]:
        data = path.read_bytes()
        if len(data) < 28:
            raise ParseError("sFlow 文件过短", data[:200].hex())
        version, agent = struct.unpack(">II", data[0:8])
        if version != 5:
            raise ParseError(f"仅支持 sFlow v5，当前 version={version}")
        agent_ip = ".".join(str(b) for b in data[8:12]) if (data[4] >> 24) == 0 else "IPv6(跳过)"
        sub_agent, seq, uptime, num_samples = struct.unpack(">IIII", data[12:28])
        records = [{
            "timestamp": None,
            "event_type": "sflow_sampling",
            "severity": "info",
            "src_ip": agent_ip,
            "summary": f"sFlow v5 导出：agent={agent_ip} 采样数={num_samples} uptime={uptime}ms",
            "raw_data": data[:200].hex(),
            "extra": {"sub_agent": sub_agent, "sequence": seq, "samples": num_samples,
                      "note": "仅解析导出头，per-sample 深度解码为后续扩展"},
        }]
        return records


# ===========================================================================
# 7) IPFIX v9/v10（导出头部信息，模板深度解码为后续扩展）
# ===========================================================================

@register_parser
class IpfixParser(BaseParser):
    name = "ipfix"
    display_name = "IPFIX 导出"
    category = "network"
    extensions = {".ipfix", ".nf9"}
    magics = [(b"\x00\x09", 0.8), (b"\x00\x0a", 0.8)]  # version 9 / 10

    def parse(self, path: Path) -> list[dict]:
        data = path.read_bytes()
        if len(data) < 16:
            raise ParseError("IPFIX 文件过短", data[:200].hex())
        version, length = struct.unpack(">HH", data[0:4])
        export_time, seq, domain = struct.unpack(">III", data[4:16])
        return [{
            "timestamp": export_time,
            "event_type": "ipfix_export",
            "severity": "info",
            "summary": f"IPFIX v{version} 导出：域={domain} 序列={seq} 长度={length} 字节",
            "raw_data": data[:400].hex(),
            "extra": {"version": version, "export_time": export_time,
                      "sequence": seq, "domain_id": domain,
                      "note": "模板集(Template Set)深度解码为后续扩展"},
        }]
