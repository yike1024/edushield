# -*- coding: utf-8 -*-
"""
ingest 前置层测试：格式识别 / 各解析器 / 批量转换 / parse_error 降级 / 下游对接
==============================================================================
运行：
  python -m pytest tests/test_ingest.py -v
  或直接：python tests/test_ingest.py
"""

import os
import struct
import sys
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="tir_ingest_")
os.environ["TIR_MODEL_GATEWAY"] = "mock"
os.environ["TIR_STORE_DIR"] = _TMP
os.environ["TIR_NOTIFY_URL"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from threat_ir_agent.ingest import IngestPipeline, ingest_file  # noqa: E402
from threat_ir_agent.ingest.detector import FormatDetector  # noqa: E402
from threat_ir_agent.ingest.registry import parser_names  # noqa: E402

pipeline = IngestPipeline()
T = Path(_TMP)


# ===========================================================================
# 样例文件生成
# ===========================================================================

def _write(name: str, content: bytes | str) -> Path:
    p = T / name
    if isinstance(content, str):
        p.write_text(content, encoding="utf-8")
    else:
        p.write_bytes(content)
    return p


def _zeek_log() -> Path:
    return _write("conn.log", (
        "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n"
        "#unset_field\t-\n#path\tconn\n#open\t2026-08-26-00-00-00\n"
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\tlocal_orig\n"
        "#types\ttime\taddr\tport\taddr\tport\tenum\tstring\tbool\n"
        "1756170000.123456\t10.0.0.5\t50001\t10.0.0.112\t22\ttcp\tSF\tT\n"
        "1756170001.654321\t10.0.0.5\t50002\t10.0.0.112\t8080\ttcp\tSF\tT\n"
    ))


def _suricata_eve() -> Path:
    import json as _json
    lines = [
        _json.dumps({"timestamp": "2026-08-26T10:00:00.000Z", "event_type": "alert",
                     "src_ip": "203.0.113.9", "dest_ip": "10.0.0.112", "src_port": 44555,
                     "dest_port": 8080, "proto": "TCP",
                     "alert": {"signature": "ET POLICY Suspicious inbound to Tomcat",
                               "category": "Attempted Administrator Privilege Gain",
                               "severity": 2}}),
        _json.dumps({"timestamp": "2026-08-26T10:00:01.000Z", "event_type": "flow",
                     "src_ip": "203.0.113.9", "dest_ip": "10.0.0.112", "proto": "TCP"}),
    ]
    return _write("eve.json", "\n".join(lines) + "\n")


def _syslog() -> Path:
    return _write("auth.log", (
        "<34>Aug 26 10:00:00 webserver sshd[1234]: Failed password for root from 203.0.113.9 port 55555 ssh2\n"
        "<34>Aug 26 10:00:01 webserver sshd[1234]: Failed password for root from 203.0.113.9 port 55556 ssh2\n"
        "<14>1 2026-08-26T10:00:02Z host01 sudo 1234 - - user root : command failed\n"
    ))


def _auditd() -> Path:
    return _write("audit.log", (
        "type=USER_AUTH msg=audit(1756170000.123:456): pid=123 uid=0 auid=1000 ses=1 "
        "msg='op=PAM:authentication grantors=pam_unix acct=\"root\" exe=\"/usr/sbin/sshd\" "
        "hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=failed'\n"
        "type=AVC msg=audit(1756170001.456:457): avc: denied { exec } for pid=456 comm=\"nginx\" "
        "name=\"shell.php\" dev=\"dm-0\" ino=789 scontext=system_u:object_r:httpd_sys_content_t "
        "tcontext=system_u:object_r:bin_t\n"
    ))


def _cef() -> Path:
    return _write("alert.cef", (
        "CEF:0|Fortinet|FortiGate|v6.0|081905|Brute force login attempt blocked|7|"
        "src=203.0.113.9 spt=55555 dst=10.0.0.112 dpt=443 proto=tcp rt=1756170000 "
        "cs1Label=attack cs1=SSH\n"
    ))


def _leef() -> Path:
    return _write("alert.leef", (
        "LEEF:1.0|IBM|QRadar|7.4|1001|devTime=1756170000 sev=high src=203.0.113.9 "
        "dst=10.0.0.112 srcPort=55555 dstPort=8080 proto=tcp\n"
    ))


def _csv() -> Path:
    return _write("events.csv", (
        "timestamp,src_ip,dst_ip,event_type,severity,message\n"
        "2026-08-26T10:00:00,203.0.113.9,10.0.0.112,sql_injection,high,SQL injection probe in URL\n"
        "2026-08-26T10:00:01,203.0.113.10,10.0.0.112,xss,medium,XSS attempt\n"
    ))


def _jsonl() -> Path:
    return _write("edr.jsonl", (
        '{"@timestamp":"2026-08-26T10:00:00Z","event":{"category":"process"},"host":{"name":"win01"}'
        ',"user":{"name":"admin"},"process":{"executable":"cmd.exe","args":"/c whoami"}}\n'
        '{"@timestamp":"2026-08-26T10:00:01Z","event":{"category":"network"},"source":{"ip":"203.0.113.9"}'
        ',"destination":{"ip":"10.0.0.112","port":8080},"host":{"name":"win01"}}\n'
    ))


def _misp_json() -> Path:
    import json as _json
    md5hash = "a" * 32
    data = {"Event": {
        "uuid": "11111111-2222-3333-4444-555555555555", "date": "2026-08-26",
        "Attribute": [
            {"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "type": "ip-src",
             "category": "Network activity", "value": "203.0.113.9", "to_ids": True},
            {"uuid": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "type": "md5",
             "category": "Artifacts dropped", "value": md5hash, "to_ids": True},
        ]}}
    return _write("misp.json", _json.dumps(data))


def _stix_json() -> Path:
    import json as _json
    sha = "b" * 64
    data = {"type": "bundle", "id": "bundle--1", "spec_version": "2.1", "objects": [
        {"type": "indicator", "id": "indicator--1", "name": "Malicious IP",
         "pattern": "[ipv4-addr:value = '203.0.113.9']",
         "valid_from": "2026-08-26T00:00:00Z", "labels": ["malicious-activity"]},
        {"type": "file", "id": "file--2", "hashes": {"SHA-256": sha}},
    ]}
    return _write("stix.json", _json.dumps(data))


def _yara_txt() -> Path:
    return _write("yara_report.txt", (
        "Ransomware_CryptoLocker /tmp/sample.exe\n"
        "Mimikatz_Detect C:/Users/Public/tools/mimikatz.exe\n"
    ))


def _hash_list() -> Path:
    return _write("hashes.txt", (
        "a" * 32 + "  suspect_md5.bin\n"
        + "b" * 40 + "  suspect_sha1.bin\n"
        + "c" * 64 + "  suspect_sha256.bin\n"
    ))


def _pe_sample() -> Path:
    # 构造最小 PE 头（仅元数据提取用）
    mz = b"MZ" + b"\x00" * 60 + struct.pack("<I", 0x80)  # e_lfanew=0x80
    pe = b"PE\x00\x00" + b"\x00" * 100
    return _write("sample.exe", mz + pe)


def _small_pcap() -> Path:
    """构造 2 包 mini pcap：一个 SSH SYN、一个 HTTP GET。"""
    def ipv4_tcp(smac_src: str, smac_dst: str, src: str, dst: str, sport: int,
                 dport: int, flags: int, payload: bytes = b"") -> bytes:
        s = bytes(map(int, src.split(".")))
        d = bytes(map(int, dst.split(".")))
        ip_hl = 5
        tcp_len = 20 + len(payload)
        tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
        total = 20 + len(tcp)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0, s, d)
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        return eth + ip + tcp

    pkt1 = ipv4_tcp("", "", "10.0.0.115", "10.0.0.105", 50001, 22, 0x02)
    pkt2 = ipv4_tcp("", "", "203.0.113.9", "10.0.0.112", 50002, 8080, 0x18,
                    b"GET /manager/html HTTP/1.1\r\nHost: t\r\n\r\n")
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    out = gh
    for ts, pkt in ((1756170000, pkt1), (1756170001, pkt2)):
        out += struct.pack("<IIII", ts, 0, len(pkt), len(pkt)) + pkt
    return _write("mini.pcap", out)


def _netflow_v5() -> Path:
    def rec(src: str, dst: str, sport: int, dport: int, pkts: int, octets: int, prot: int) -> bytes:
        s = bytes(map(int, src.split(".")))
        d = bytes(map(int, dst.split(".")))
        return (s + d + b"\x00" * 4 + struct.pack(">HHII", 0, 0, pkts, octets)
                + struct.pack(">II", 0, 0) + struct.pack(">HH", sport, dport)
                + bytes([0, prot, 0]) + b"\x00" * 9)
    # NetFlow v5 头部共 24 字节：version(2) count(2) sys_uptime(4) unix_secs(4)
    #                        unix_nsecs(4) flow_seq(4) engine_type(1) engine_id(1) sampling(2)
    header = (struct.pack(">HHII", 5, 2, 1000, 1756170000)
              + struct.pack(">II", 0, 0) + b"\x00\x00\x00\x00")
    body = rec("10.0.0.115", "10.0.0.105", 50001, 22, 100, 5000, 6) + \
           rec("203.0.113.9", "10.0.0.112", 50002, 8080, 50, 20000, 6)
    return _write("nf5.dat", header + body)


# ===========================================================================
# 测试：格式识别
# ===========================================================================

def test_detector_identifies_formats():
    det = FormatDetector()
    cases = {
        _zeek_log(): "zeek",
        _suricata_eve(): "suricata_eve",
        _syslog(): "syslog",
        _auditd(): "auditd",
        _cef(): "cef",
        _leef(): "leef",
        _csv(): "generic_csv",
        _small_pcap(): "pcap",
        _netflow_v5(): "netflow_v5",
        _hash_list(): "hash_list",
    }
    for path, expect in cases.items():
        parser, score = det.detect(path)
        assert parser is not None, f"{path.name} 未被识别"
        assert parser.name == expect, f"{path.name} 识别为 {parser.name}，期望 {expect}"
    # 无法识别
    p = _write("unknown.bin", b"\x99\x88\x77\x66random")
    parser, _ = det.detect(p)
    assert parser is None


def test_parser_registry_plugin():
    names = parser_names()
    for required in ("pcap", "pcapng", "zeek", "suricata_eve", "netflow_v5",
                     "sflow_v5", "ipfix", "syslog", "evtx", "auditd",
                     "edr_telemetry", "hash_list", "misp", "stix2", "yara_report",
                     "malware_sample", "generic_json", "generic_csv", "generic_xml",
                     "parquet_avro", "cef", "leef", "idmef"):
        assert required in names, f"缺少解析器 {required}"


# ===========================================================================
# 测试：各解析器转换结果
# ===========================================================================

def test_zeek_parse():
    r = pipeline.ingest_file(_zeek_log(), feed=False)
    assert r["parse_error"] is False
    assert len(r["events"]) == 2
    e = r["events"][0]
    assert e["source_ip"] == "10.0.0.5" and e["raw"]["record"]["protocol"] == "tcp"
    assert e["context"]["source_file"].endswith("conn.log")
    assert e["context"]["record_index"] == 1


def test_suricata_parse():
    r = pipeline.ingest_file(_suricata_eve(), feed=False)
    assert len(r["events"]) == 2
    assert r["events"][0]["event_type"] == "ids_alert"
    assert r["events"][0]["severity_hint"] == "high"
    assert r["events"][0]["source_ip"] == "203.0.113.9"


def test_syslog_parse():
    r = pipeline.ingest_file(_syslog(), feed=False)
    assert len(r["events"]) == 3
    assert all(e["severity_hint"] == "critical" for e in r["events"][:2])  # PRI 34 → crit
    assert r["events"][0]["raw"]["extra_context"]["tag"] == "sshd"


def test_auditd_parse():
    r = pipeline.ingest_file(_auditd(), feed=False)
    assert len(r["events"]) == 2
    assert r["events"][0]["event_type"] == "auditd_USER_AUTH"
    assert r["events"][0]["severity_hint"] == "high"


def test_cef_leef_parse():
    rc = pipeline.ingest_file(_cef(), feed=False)
    assert rc["events"][0]["event_type"] == "081905"
    assert rc["events"][0]["severity_hint"] == "high"  # CEF 7
    assert rc["events"][0]["source_ip"] == "203.0.113.9"
    rl = pipeline.ingest_file(_leef(), feed=False)
    assert rl["events"][0]["severity_hint"] == "high"
    assert rl["events"][0]["raw"]["record"]["dst_port"] == "8080"


def test_csv_and_jsonl_parse():
    rc = pipeline.ingest_file(_csv(), feed=False)
    assert len(rc["events"]) == 2
    assert rc["events"][0]["event_type"] == "sql_injection"
    assert rc["events"][0]["severity_hint"] == "high"
    rj = pipeline.ingest_file(_jsonl(), feed=False)
    assert len(rj["events"]) == 2
    assert rj["events"][0]["raw"]["record"]["host"] == "win01"
    assert rj["events"][1]["raw"]["record"]["dst_ip"] == "10.0.0.112"


def test_intel_parse():
    rm = pipeline.ingest_file(_misp_json(), feed=False)
    assert len(rm["events"]) == 2
    assert rm["events"][0]["event_type"] == "misp_ioc"
    assert rm["events"][0]["source_ip"] == "203.0.113.9" or rm["events"][0]["raw"]["extra_context"]["ioc"]
    rs = pipeline.ingest_file(_stix_json(), feed=False)
    assert len(rs["events"]) == 2
    assert rs["events"][0]["event_type"] == "stix_indicator"
    ry = pipeline.ingest_file(_yara_txt(), feed=False)
    assert len(ry["events"]) == 2
    assert ry["events"][0]["event_type"] == "yara_hit"
    assert ry["events"][0]["severity_hint"] == "high"
    rh = pipeline.ingest_file(_hash_list(), feed=False)
    assert len(rh["events"]) == 3
    assert rh["events"][2]["raw"]["extra_context"]["hash_type"] == "SHA256"


def test_sample_parse():
    r = pipeline.ingest_file(_pe_sample(), feed=False)
    assert r["parse_error"] is False
    e = r["events"][0]
    assert e["event_type"] == "malicious_sample"
    assert e["severity_hint"] == "high"
    assert e["raw"]["extra_context"]["sha256"]


def test_pcap_and_netflow_parse():
    r = pipeline.ingest_file(_small_pcap(), feed=False)
    assert r["parse_error"] is False, r.get("error")
    types = {e["event_type"] for e in r["events"]}
    # 单条 SSH 连接不再误判为爆破（启发式精细化）
    assert "ssh_access" in types
    assert "http_request" in types
    assert "brute_force" not in types
    rn = pipeline.ingest_file(_netflow_v5(), feed=False)
    assert len(rn["events"]) == 2
    assert rn["events"][0]["event_type"] == "netflow"
    assert rn["events"][0]["source_ip"] == "10.0.0.115"


def _pkt(src: str, dst: str, sport: int, dport: int, flags: int,
         payload: bytes = b"", proto: int = 6) -> bytes:
    """构造以太网+IPv4+TCP 包。"""
    s = bytes(map(int, src.split(".")))
    d = bytes(map(int, dst.split(".")))
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, s, d)
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip + tcp


def _pcap_from_pkts(pkts: list[tuple[int, bytes]], name: str = "mini2.pcap") -> Path:
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    out = gh
    for i, (ts, pkt) in enumerate(pkts):
        out += struct.pack("<IIII", ts, 0, len(pkt), len(pkt)) + pkt
    return _write(name, out)


def test_pcap_http_brute_force_heuristic():
    """HTTP 401 ≥3（同一条连接内）→ 判定弱口令爆破（与 DeepSeek 研判一致性强）。"""
    pkts = []
    for i in range(4):  # 同一客户端端口 50000，4 次请求+401 响应（同一连接）
        ts = 1756170000 + i
        pkts.append((ts, _pkt("203.0.113.9", "10.0.0.112", 50000, 8080, 0x18,
                              b"GET /manager/html HTTP/1.1\r\nHost: t\r\n\r\n")))
        pkts.append((ts + 1, _pkt("10.0.0.112", "203.0.113.9", 8080, 50000, 0x18,
                                  b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")))
    r = pipeline.ingest_file(_pcap_from_pkts(pkts), feed=False)
    types = {e["event_type"] for e in r["events"]}
    assert "brute_force" in types
    assert any(e["severity_hint"] == "medium" for e in r["events"] if e["event_type"] == "brute_force")


def test_event_id_deterministic():
    """同一输入重复转换 → event_id 稳定（修复重复检测结果不一致问题）。"""
    p = _csv()
    r1 = pipeline.ingest_file(p, feed=False)
    r2 = pipeline.ingest_file(p, feed=False)
    assert r1["events"][0]["event_id"] == r2["events"][0]["event_id"]
    assert r1["events"][0]["event_id"].startswith("tir_event_")


def test_event_without_timestamp_ok():
    """无时间戳事件（如哈希列表）不再触发下游 Schema 校验失败。"""
    from threat_ir_agent import ThreatIRSubAgent
    r = IngestPipeline(agent=ThreatIRSubAgent()).ingest_file(_hash_list(), feed=True)
    assert r["parse_error"] is False
    assert len(r["events"]) == 3
    assert all("error" not in res for res in r["results"])


def test_min_alert_level_floor():
    """输出最低告警级别门槛：最终研判低于门槛 → skipped_by_level，不产生告警。"""
    from threat_ir_agent import ThreatIRSubAgent
    agent = ThreatIRSubAgent()
    # 低风险事件（校园误报规则直接定级 low）+ 门槛 medium → 被拦截
    low_evt = {"source": "pcap:test", "event_type": "directory_scan",
               "target": "10.0.0.112:8080", "source_ip": "203.0.113.9",
               "severity_hint": "medium",
               "description": "搜索引擎爬虫密集访问页面",
               "context": {"source_file": "x.pcap", "record_index": 1}}
    res = agent.handle_event(low_evt, task_id="t1", min_alert_level="medium")
    assert res.get("skipped_by_level") is True
    assert res["notification"] is None
    # 同一事件不设门槛 → 正常产生告警
    res2 = agent.handle_event(low_evt, task_id="t1")
    assert res2.get("skipped_by_level") is None
    assert res2["alert"]["level"] == "low"


def test_min_alert_level_keeps_medium():
    """中危事件 + 门槛 medium → 正常产生告警（不被拦截）。"""
    from threat_ir_agent import ThreatIRSubAgent
    agent = ThreatIRSubAgent()
    med_evt = {"source": "pcap:test", "event_type": "brute_force",
               "target": "10.0.0.112:22", "source_ip": "10.0.0.115",
               "severity_hint": "medium", "description": "SSH 暴力破解尝试",
               "context": {"source_file": "x.pcap", "record_index": 2}}
    res = agent.handle_event(med_evt, task_id="t2", min_alert_level="medium")
    assert res.get("skipped_by_level") is None
    assert res["alert"]["level"] == "medium"
    assert res["notification"] is not None


# ===========================================================================
# 测试：parse_error 降级 + 批量 + 下游对接
# ===========================================================================

def test_parse_error_event():
    bad = _write("broken.evtx", b"ElfFile\x00" + b"\x00" * 100)  # 魔数正确但无记录
    r = pipeline.ingest_file(bad, feed=False)
    assert r["parse_error"] is True
    e = r["events"][0]
    assert e["event_type"] == "parse_error"
    assert e["raw"]["parse_error"] is True
    assert "error" in e["raw"]["extra_context"]


def test_unknown_format_parse_error():
    p = _write("mystery.data", b"\xde\xad\xbe\xef" * 10)
    r = pipeline.ingest_file(p, feed=False)
    assert r["parse_error"] is True
    assert r["format"] is None


def test_parquet_avro_hint():
    p = _write("data.parquet", b"PAR1" + b"\x00" * 50)
    r = pipeline.ingest_file(p, feed=False)
    assert r["parse_error"] is True
    assert "pyarrow" in r["error"]


def test_min_severity_filter():
    """min_severity 过滤：只保留 ≥ 阈值的事件；parse_error 不受影响。"""
    # CSV 样例：sql_injection=high, xss=medium
    r = pipeline.ingest_file(_csv(), feed=False, min_severity="high")
    assert len(r["events"]) == 1
    assert r["events"][0]["event_type"] == "sql_injection"
    assert r["events_total"] == 2
    assert r["events_filtered_out"] == 1

    r2 = pipeline.ingest_file(_csv(), feed=False, min_severity="medium")
    assert len(r2["events"]) == 2
    assert r2["events_filtered_out"] == 0

    # parse_error 事件（severity=low）不受 high 过滤影响，始终保留
    bad = _write("broken2.evtx", b"ElfFile\x00" + b"\x00" * 100)
    r3 = pipeline.ingest_file(bad, feed=False, min_severity="high")
    assert r3["parse_error"] is True
    assert len(r3["events"]) == 1
    assert r3["events"][0]["event_type"] == "parse_error"


def test_feed_into_agent_end_to_end():
    """转换 → 送入现有威胁警报+应急响应（mock 通道），保持原有行为一致。"""
    from threat_ir_agent import ThreatIRSubAgent
    from threat_ir_agent.models import DetectionEvent
    agent = ThreatIRSubAgent()
    result = ingest_file(_csv(), feed=True, agent=agent)
    assert len(result["results"]) == 2
    for res in result["results"]:
        assert res["alert"]["alert_id"].startswith("tir_alert_")
        assert res["notification"]["display_md"]
        assert res["playbook"]["playbook_id"].startswith("tir_playbook_")
    # 事件 Schema 与原有 DetectionEvent 完全兼容
    evt = result["events"][0]
    de = DetectionEvent.from_dict(evt)
    assert de.event_type == "sql_injection"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: [{type(e).__name__}] {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
