# -*- coding: utf-8 -*-
"""
威胁分级判定模块
================
需求：接收 edushield 主平台传递的安全检测事件数据，完成威胁分级判定
（高/中/低风险），生成标准化威胁告警报文。

实现（双轨判定，对齐计划书八、风险对策“判定走规则引擎+LLM双轨”）：
1. 规则引擎预筛（确定性纯业务，不加 AI）：依据事件类型/攻击类型/严重度提示/
   置信度提示快速给出初判，并应用校园误报抑制规则
   （爬虫≠攻击、选课/查分高并发≠DDoS —— 对齐 edushield 知识库与计划书 2.2）。
2. 模型研判（推理大脑 DeepSeek-Reasonix-Security）：由模型给出
   level/attack_type/mitre/confidence/verdict/recommended_action/reasoning。
3. 合并规则：显式误报 → LOW；模型与规则冲突时以模型为准但记录分歧；
   模型不可用时回退规则初判。

借鉴点（仅设计思想，见 docs/GITHUB_RESEARCH.md）：
- 计划书 2.2 EduShield 威胁判定模型（verdict/confidence/AnalyzedThreat）设计可移植；
- TheHive 的 Alert 分级与 Tracecat 规则+AI 双轨判定思想。
本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import logging
from typing import Optional

from ..config import config
from ..model_gateway import gateway
from ..models import (
    DetectionEvent,
    ThreatAlert,
    ThreatLevel,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 校园误报抑制规则（对齐 edushield 知识库内容与计划书 2.2，可迁移规则）
# ---------------------------------------------------------------------------
_FALSE_POSITIVE_RULES: list[tuple[str, str]] = [
    ("爬虫", "搜索引擎爬虫(Googlebot/Bingbot/BaiduSpider)密集访问 ≠ 攻击"),
    ("选课", "选课/查分时段高并发 ≠ DDoS"),
    ("查分", "选课/查分时段高并发 ≠ DDoS"),
    ("刷网课", "学生宿舍晚间集中刷网课导致流量高 ≠ 攻击"),
    ("图书馆", "图书馆开馆时段集中检索书目 ≠ 目录扫描"),
    ("远程办公", "教师远程办公从外网登录 ≠ 异常登录（需看IP归属地）"),
]

# 高/中风险事件类型（与 edushield AttackType 词汇对齐）
_HIGH_RISK_TYPES = {
    "webshell", "sql_injection", "command_injection", "rce", "cve_exploit",
    "data_exfiltration", "data_exfil", "ransomware", "privilege_escalation",
}
_MEDIUM_RISK_TYPES = {
    "brute_force", "xss", "csrf", "file_upload", "ddos", "credential_stuffing",
    "phishing", "port_scan", "directory_scan",
}

_CLASSIFY_SYSTEM_PROMPT = """你是校园网络安全威胁研判专家（威胁警报子Agent的分级判定大脑）。
你的任务：对一条安全检测事件进行威胁分级判定，输出 JSON（不要输出其他内容）。

分级标准（严格三档）：
- "high"   高风险：明确攻击特征/正在进行的攻击/数据泄露/RCE/webshell/勒索等
- "medium" 中风险：可疑但特征不完全明确，需要关注的异常行为
- "low"    低风险：误报、无害行为、信息性事件

校园误报抑制原则（务必执行）：
- 搜索引擎爬虫的密集访问 ≠ 攻击；选课/查分高并发 ≠ DDoS；
- 学生宿舍晚间集中刷网课 ≠ 攻击；图书馆集中检索 ≠ 目录扫描。
- 判断原则：结合时间、User-Agent、行为基线、IP归属地综合判断。

输出 JSON 字段：
{
  "level": "high|medium|low",
  "title": "告警标题(中文)",
  "attack_type": "攻击类型英文标识，如 sql_injection",
  "mitre_technique": "MITRE ATT&CK 技术ID或null",
  "confidence": 0.0到1.0,
  "verdict": "true_positive|false_positive|benign|uncertain",
  "summary": "告警摘要(中文)",
  "evidence": "关键证据(中文)",
  "recommended_action": "建议处置(中文，一句话)",
  "reasoning": "分级判定依据(中文，说明为什么是这个等级)"
}"""


class ThreatClassifier:
    """威胁分级判定器（规则预筛 + 模型研判双轨）。"""

    # ------------------------------------------------------------------
    # 1) 规则引擎预筛
    # ------------------------------------------------------------------
    def rule_precheck(self, event: DetectionEvent) -> dict:
        """确定性初判：返回 {level, attack_type, confidence, verdict, reason}。"""
        attack = (event.attack_type_hint or event.event_type or "").lower()
        sev = (event.severity_hint or "").lower()
        conf = event.confidence_hint if event.confidence_hint is not None else 0.5
        desc = (event.description or "").lower()

        # 校园误报抑制：命中即 LOW（显式误报排除）
        for kw, reason in _FALSE_POSITIVE_RULES:
            if kw in desc or kw in (event.description or ""):
                return {
                    "level": ThreatLevel.LOW,
                    "attack_type": "benign",
                    "confidence": min(conf, 0.9),
                    "verdict": "false_positive",
                    "reason": f"命中校园误报抑制规则[{kw}]：{reason}",
                }

        # 高/中风险事件类型映射
        if attack in _HIGH_RISK_TYPES or sev in ("critical", "high"):
            return {
                "level": ThreatLevel.HIGH,
                "attack_type": attack or "unknown",
                "confidence": max(conf, 0.7),
                "verdict": "true_positive",
                "reason": f"事件类型/严重度提示命中高风险档（{attack or sev}）",
            }
        if attack in _MEDIUM_RISK_TYPES or sev in ("medium",):
            return {
                "level": ThreatLevel.MEDIUM,
                "attack_type": attack or "unknown",
                "confidence": conf,
                "verdict": "uncertain",
                "reason": f"事件类型/严重度提示命中中风险档（{attack or sev}）",
            }
        return {
            "level": ThreatLevel.LOW,
            "attack_type": attack or "unknown",
            "confidence": conf,
            "verdict": "benign",
            "reason": "未命中明确攻击特征，按低风险处理",
        }

    # ------------------------------------------------------------------
    # 2) 模型研判（DeepSeek-Reasonix-Security 推理大脑）
    # ------------------------------------------------------------------
    def model_verdict(self, event: DetectionEvent) -> dict:
        """调用推理大脑完成分级判定，返回 JSON dict；失败返回空 dict。

        确定性设计：提示词中排除每次运行都会变化的易变字段
        （event_id / occurred_at / received_at），保证同一输入重复研判结果稳定；
        使用较低温度（TIR_CLASSIFY_TEMPERATURE，默认 0.1）。
        """
        event_dump = event.model_dump(
            mode="json",
            exclude={"raw", "context", "event_id", "occurred_at", "received_at"},
        )
        user_prompt = (
            "## 安全检测事件\n"
            f"{event_dump}\n\n"
            "## 原始数据\n"
            f"{event.raw if event.raw else '（无）'}\n\n"
            "请对该事件进行威胁分级判定，只输出 JSON。"
        )
        return gateway.complete(_CLASSIFY_SYSTEM_PROMPT, user_prompt,
                                temperature=config.CLASSIFY_TEMPERATURE)

    # ------------------------------------------------------------------
    # 3) 合并与告警生成
    # ------------------------------------------------------------------
    def classify(self, event: DetectionEvent) -> ThreatAlert:
        """完整分级流程：预筛 → 模型研判 → 合并 → 生成标准化告警报文。"""
        rule = self.rule_precheck(event)

        # 显式误报：规则直接定级 LOW，不再劳烦模型
        if rule["verdict"] == "false_positive":
            return self._build_alert(event, rule)

        model = self.model_verdict(event) or {}
        if not model:
            # 模型不可用 → 回退规则初判（保证子 Agent 在断网/无密钥时可运行）
            logger.warning("[Classifier] 模型研判不可用，回退规则初判: %s", rule["reason"])
            return self._build_alert(event, rule)

        level = ThreatLevel(model.get("level", rule["level"].value)) \
            if model.get("level") in ("high", "medium", "low") else rule["level"]
        merged = {
            "level": level,
            "attack_type": model.get("attack_type") or rule["attack_type"],
            "confidence": float(model.get("confidence", rule["confidence"])),
            "verdict": model.get("verdict") or rule["verdict"],
            "reason": model.get("reasoning") or rule["reason"],
            "title": model.get("title") or "",
            "summary": model.get("summary") or "",
            "evidence": model.get("evidence") or "",
            "recommended_action": model.get("recommended_action") or "",
            "mitre": model.get("mitre_technique"),
        }
        # 模型与规则分歧时记录（以模型为准，规则作为兜底参考）
        if merged["level"] != rule["level"]:
            merged["reason"] = (
                f"模型判定={merged['level'].value}；规则初判={rule['level'].value}；"
                f"以模型为准。规则依据：{rule['reason']}"
            )
        return self._build_alert(event, merged)

    @staticmethod
    def _build_alert(event: DetectionEvent, v: dict) -> ThreatAlert:
        return ThreatAlert(
            event_ref=event.event_id,
            title=v.get("title") or f"威胁事件：{event.event_type}",
            level=v["level"],
            attack_type=v.get("attack_type", "unknown"),
            mitre_technique=v.get("mitre"),
            confidence=max(0.0, min(1.0, float(v.get("confidence", 0.5)))),
            source_ip=event.source_ip,
            target=event.target,
            summary=v.get("summary") or v.get("reason", ""),
            evidence=v.get("evidence", ""),
            recommended_action=v.get("recommended_action", ""),
            reasoning=v.get("reason", ""),
            verdict=v.get("verdict", "uncertain"),
        )


classifier = ThreatClassifier()
