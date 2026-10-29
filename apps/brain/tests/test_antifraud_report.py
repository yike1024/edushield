"""L-5 反诈研判报告段测试。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from report import build_report  # noqa: E402


class AntiFraudReportTest(unittest.TestCase):
    def test_section_present_with_iocs_and_evidence(self):
        findings = [{
            "id": "F-T001-1", "task_id": "T001", "domain": "logaudit", "target": "x",
            "tool": "email_parse", "severity": "high", "title": "钓鱼邮件：冒充校长",
            "description": "Return-Path 与显示名不符，SPF 软失败，仿冒域 xynu-edu.top，账号 zhangsan",
            "evidence": "Return-Path: <spoof@xynu-edu.top>; SPF: softfail; 恶意链接 http://xynu-edu.top/login; 附件 hash a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "remediation": "拉黑 xynu-edu.top，账号强制改密", "confidence": 0.92, "mitre": [],
        }]
        assessment = {"verdict": "real_threat", "confidence": 0.92,
                      "threats": findings, "false_positives": [], "reason": "test",
                      "rules_fired": []}
        md = build_report({"id": "T001", "domain": "logaudit", "target": "x", "status": "done"},
                          findings, assessment, [])
        self.assertIn("## 反诈研判", md)
        self.assertIn("xynu-edu.top", md)
        self.assertIn("zhangsan", md)
        self.assertIn("IOC 清单", md)
        self.assertIn("误报排除", md)

    def test_no_section_when_no_antifraud(self):
        findings = [{"id": "F-1", "task_id": "T", "domain": "pentest", "target": "x",
                     "tool": "nmap", "severity": "medium", "title": "开放端口",
                     "description": "22 开放", "evidence": "22/tcp", "confidence": 0.5}]
        md = build_report({"id": "T", "domain": "pentest", "target": "x", "status": "done"},
                          findings, {"verdict": "pending_review", "confidence": 0.5,
                                     "threats": findings, "false_positives": [], "reason": "t"},
                          [])
        self.assertNotIn("## 反诈研判", md)

    def test_12_digit_accounts_extracted(self):
        findings = [{"id": "F-1", "task_id": "T", "domain": "logaudit", "target": "x",
                     "tool": "ioc_extract", "severity": "critical",
                     "title": "仿冒站收割 12 个账号",
                     "description": "12 个不同 account_id（202311010101、202311010201、202212020301）",
                     "evidence": "count 12", "remediation": "改密", "confidence": 0.95}]
        md = build_report({"id": "T", "domain": "logaudit", "target": "x", "status": "done"},
                          findings, {"verdict": "real_threat", "confidence": 0.95,
                                     "threats": findings, "false_positives": [], "reason": "t"},
                          [])
        self.assertIn("202311010101", md)
        self.assertIn("202311010201", md)
        self.assertIn("202212020301", md)
        self.assertNotIn("待与 CAS/VPN 登录日志关联", md)


if __name__ == "__main__":
    unittest.main()
