"""报告生成（阶段 3）。

- 按任务生成 Markdown 报告，引用 Finding id（可追溯）
- 附录：判定理由、规则命中、思维链
- 后续阶段：等保合规检查、docx 导出
"""

from __future__ import annotations

import json
import re
from typing import Any


_ANTIFRAUD_HINTS = ("钓鱼", "仿冒", "举报", "诈骗", "助学金", "冒充", "垃圾邮件", "phishing")


def _is_antifraud_finding(f: dict) -> bool:
    text = " ".join(str(f.get(k, "")) for k in ("title", "description", "evidence", "domain", "tool"))
    return any(h in text.lower() for h in _ANTIFRAUD_HINTS)


def _extract_iocs(text: str) -> list[str]:
    iocs: list[str] = []
    for pat in (r"\d{1,3}(?:\.\d{1,3}){3}",
                r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+(?:edu\.cn|com\.cn|com|cn|net|org|top)",
                r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b"):
        for m in re.findall(pat, text, flags=re.IGNORECASE):
            if m not in iocs:
                iocs.append(m)
    return iocs[:20]


def _antifraud_section(findings: list[dict], assessment: dict) -> list[str]:
    """L-5：反诈研判段（邮件头证据/IOC/受害面/处置/误报排除，与 Finding 可追溯）。"""
    af = [f for f in findings if _is_antifraud_finding(f)]
    if not af:
        return []
    lines = ["## 反诈研判"]
    lines.append("")
    seen_iocs: list[str] = []
    for i, f in enumerate(af, 1):
        lines.append(f"### {i}. [{f.get('severity', 'info').upper()}] {f.get('title', '')}")
        lines.append(f"- Finding: `{f.get('id', '')}`（可追溯原始证据）")
        lines.append(f"- 置信度: {float(f.get('confidence', 0) or 0):.0%}　产出工具: {f.get('tool', '')}")
        evidence = str(f.get("evidence", ""))
        if evidence:
            lines.append(f"- 邮件头/证据: {evidence[:600]}")
        desc = str(f.get("description", ""))
        if desc:
            lines.append(f"- 研判结论: {desc[:400]}")
        for ioc in _extract_iocs(evidence + " " + desc):
            if ioc not in seen_iocs:
                seen_iocs.append(ioc)
        rem = f.get("remediation")
        if rem:
            lines.append(f"- 处置建议: {rem}")
        lines.append("")
    if seen_iocs:
        lines.append("**IOC 清单**：" + "、".join(f"`{x}`" for x in seen_iocs))
        lines.append("")
    # 受害面：从 finding 描述中提取账号线索，没有则标注待关联（合成样本）
    accounts: list[str] = []
    for f in af:
        text = " ".join(str(f.get(k, "")) for k in ("evidence", "description"))
        for m in re.findall(r"(?:账号|账户|用户)\s*[:：]?\s*([0-9a-zA-Z_@.\-]{3,30})", text):
            if m not in accounts:
                accounts.append(m)
        # 学号格式账号（12 位连续数字，如 202311010101）
        for m in re.findall(r"\b\d{12}\b", text):
            if m not in accounts:
                accounts.append(m)
    if accounts:
        lines.append(f"**受害面账号**：{', '.join(f'`{a}`' for a in accounts[:20])}（合成样本，按需与 CAS/VPN 日志关联）")
    else:
        lines.append("**受害面账号**：待与 CAS/VPN 登录日志关联（样本待注入）")
    lines.append("")
    fps = assessment.get("false_positives", [])
    if fps:
        lines.append(f"**误报排除**：{len(fps)} 条命中抑制规则（{', '.join(f.get('false_positive_rules', ['—'])[0] for f in fps)}），详见上文误报排除节。")
    else:
        lines.append("**误报排除**：本轮未命中误报抑制规则。")
    lines.append("")
    return lines


def build_report(task: dict, findings: list[dict], assessment: dict, ledger: list[dict],
                 tir: dict | None = None) -> str:
    lines = [
        "# AiSOC 安全分析报告",
        "",
        f"- task_id: {task.get('id', '')}",
        f"- domain: {task.get('domain', '')}",
        f"- target: {task.get('target', '')}",
        f"- status: {task.get('status', '')}",
        f"- verdict: **{assessment.get('verdict', '')}**",
        f"- confidence: {assessment.get('confidence', 0):.0%}",
        f"- findings: {len(findings)}（确认威胁 {len(assessment.get('threats', []))} / 误报 {len(assessment.get('false_positives', []))}）",
        "",
        f"## 判定理由",
        "",
        f"{assessment.get('reason', '')}",
        "",
    ]

    if assessment.get("rules_fired"):
        lines.append("## 命中规则")
        for r in assessment["rules_fired"]:
            lines.append(f"- {r['name']}：{r['description']}")
        lines.append("")

    threats = assessment.get("threats", [])
    if threats:
        lines.append("## 确认威胁")
        for i, f in enumerate(threats, 1):
            lines.append(f"### {i}. [{f.get('severity', 'info').upper()}] {f.get('title', '')}")
            lines.append(f"- Finding: `{f.get('id', '')}`")
            lines.append(f"- 工具: {f.get('tool', '')}　置信度: {float(f.get('confidence', 0) or 0):.0%}")
            if f.get("mitre"):
                lines.append(f"- MITRE: {', '.join(f['mitre'])}")
            if f.get("cve"):
                lines.append(f"- CVE: {f['cve']}")
            lines.append(f"- 描述: {f.get('description', '')}")
            lines.append(f"- 证据: {f.get('evidence', '')}")
            if f.get("remediation"):
                lines.append(f"- 建议: {f['remediation']}")
            lines.append("")

    fps = assessment.get("false_positives", [])
    if fps:
        lines.append("## 误报排除")
        for f in fps:
            lines.append(f"- [{f.get('severity', 'info').upper()}] {f.get('title', '')}（`{f.get('id', '')}`，规则：{', '.join(f.get('false_positive_rules', []))}）")
        lines.append("")

    # L-5：反诈研判段（有反诈相关 finding 时才输出）
    lines.extend(_antifraud_section(findings, assessment))

    if tir:
        lines.append("## 应急响应（TIR）")
        alerts = tir.get("alerts", [])
        playbooks = tir.get("playbooks", [])
        if alerts:
            lines.append(f"- 已生成告警 {len(alerts)} 条：{', '.join(f'`{a}`' for a in alerts)}")
        if playbooks:
            lines.append(f"- 已生成应急预案 {len(playbooks)} 份：{', '.join(f'`{p}`' for p in playbooks)}")
        if not alerts and not playbooks:
            lines.append("- 未生成告警/预案（TIR 子 Agent 不可用或无真实威胁）")
        lines.append("")

    lines.append("## 思维链摘要")
    for evt in ledger[-20:]:
        lines.append(f"- [{evt.get('ts', '')}] {evt.get('actor', '')} / {evt.get('action', '')}")
    lines.append("")
    lines.append("---")
    lines.append("本报告由 AiSOC 大脑自动生成，Finding 可追溯至部件原始证据。")
    return "\n".join(lines)


def export_json(task: dict, findings: list[dict], assessment: dict, ledger: list[dict]) -> dict[str, Any]:
    """审计导出用 JSON（≥180 天留档、可机器复核）。"""
    return {
        "task": task,
        "findings": findings,
        "assessment": assessment,
        "ledger": ledger,
        "export_note": "AiSOC 审计导出",
    }
