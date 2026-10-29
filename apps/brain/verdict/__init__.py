"""威胁判定引擎（阶段 3）—— 规则 + LLM 双轨。

权威来源：aisoc-docs 03 §3。
- 规则轨：校园误报抑制（爬虫≠攻击、选课高并发≠DDoS 等），确定性、可解释
- LLM 轨：DeepSeek 结构化判定（未配 key 时自动只走规则轨）
- 输出：verdict + confidence + threats + false_positives + reason（可复核）
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from llm import chat_json
from protocol import Verdict

logger = logging.getLogger(__name__)

# ---- 规则轨：校园误报抑制（每条规则可解释、可复核） ----

_FALSE_POSITIVE_RULES: list[dict[str, Any]] = [
    {
        "name": "rule:爬虫排除",
        "description": "搜索引擎爬虫的密集访问/大量404不是攻击",
        "applies": lambda f: (
            any(k in str(f.get("title", "")) + str(f.get("description", "")) + str(f.get("evidence", ""))
                for k in ["爬虫", "Googlebot", "Bingbot", "BaiduSpider", "Yandex"])
            and f.get("severity") in ("low", "info")
        ),
    },
    {
        "name": "rule:高并发排除",
        "description": "选课/查分时段高并发不是DDoS",
        "applies": lambda f: (
            any(k in str(f.get("title", "")) + str(f.get("description", ""))
                for k in ["高并发", "选课", "查分", "刷课"])
        ),
    },
    {
        "name": "rule:校园时段排除",
        "description": "宿舍/图书馆等校园正常行为基线不计为攻击",
        "applies": lambda f: (
            any(k in str(f.get("title", "")) + str(f.get("description", ""))
                for k in ["图书馆", "宿舍", "在线课程", "教务系统登录"])
            and f.get("severity") in ("low", "info")
        ),
    },
]

_LOW_RISK_RULES: list[dict[str, Any]] = [
    {
        "name": "rule:端口扫描-低危",
        "description": "仅端口扫描无后续利用，风险降级",
        "applies": lambda f: f.get("severity") in ("low", "info") and "扫描" in str(f.get("title", "")),
        "new_severity": "low",
    },
]


def _rule_fire(finding: dict, rules: list[dict]) -> list[dict]:
    fired = []
    for rule in rules:
        try:
            if rule["applies"](finding):
                fired.append({"name": rule["name"], "description": rule["description"]})
        except Exception:
            continue
    return fired


def evaluate(findings: list[dict]) -> dict[str, Any]:
    """输入 Finding 列表（dict），输出威胁判定结果。"""
    false_positives: list[dict] = []
    threats: list[dict] = []
    rules_fired: list[dict] = []

    for f in findings:
        fp_rules = _rule_fire(f, _FALSE_POSITIVE_RULES)
        if fp_rules:
            f = dict(f)
            f["false_positive_rules"] = [r["name"] for r in fp_rules]
            false_positives.append(f)
            rules_fired.extend(fp_rules)
            continue

        low_rules = _rule_fire(f, _LOW_RISK_RULES)
        if low_rules:
            f = dict(f)
            f["severity"] = low_rules[0].get("new_severity", f["severity"])
            rules_fired.extend(low_rules)

        threats.append(f)

    # 规则轨结论
    if not threats:
        verdict = Verdict.FALSE_POSITIVE
        reason = "全部发现命中误报抑制规则"
    elif any(f.get("severity") in ("critical", "high") and float(f.get("confidence", 0) or 0) >= 0.7 for f in threats):
        verdict = Verdict.REAL_THREAT
        reason = "存在高危/严重发现且部件置信度≥0.7"
    else:
        verdict = Verdict.PENDING_REVIEW
        reason = "存在可疑发现，需人工复核或跨域印证"

    max_conf = max([float(f.get("confidence", 0) or 0) for f in threats], default=0.0)

    # LLM 轨（未配 key 自动跳过；失败回退规则轨）
    llm_used = False
    rag_hits: list[str] = []
    user_doc: dict[str, Any] = {"findings": findings, "rules_fired": rules_fired}
    # RAG：拼 findings 关键词做一次性检索，命中知识并入判定依据（增强校园业务与攻防语境）
    try:
        from rag import get_knowledge_base
        _q_terms = " ".join(
            str(f.get("title", "")) + " " + str(f.get("description", "")) + " "
            + str(f.get("evidence", ""))
            for f in findings
        )
        if _q_terms.strip():
            rag_hits = [h.get("content", "") for h in get_knowledge_base().search_with_scores(_q_terms, k=4)]
    except Exception:
        rag_hits = []
    if rag_hits:
        user_doc["rag_knowledge"] = rag_hits

    llm_result = chat_json(
        system_prompt=(
            "你是安全运营研判专家。基于给定 Findings 输出 JSON："
            '{"verdict": "real_threat|false_positive|pending_review", "confidence": 0.0-1.0, "reason": "一句话理由"}'
        ),
        user_prompt=json.dumps(user_doc, ensure_ascii=False),
    )
    if llm_result:
        try:
            v = Verdict(str(llm_result.get("verdict", "")))
            verdict = v
            max_conf = max(0.0, min(1.0, float(llm_result.get("confidence", max_conf))))
            reason = f"{reason}；LLM补充：{llm_result.get('reason', '')}"
            llm_used = True
        except (ValueError, TypeError):
            logger.warning("[verdict] LLM 返回非法 verdict，回退规则轨")

    return {
        "verdict": verdict.value,
        "confidence": round(max_conf, 3),
        "threats": threats,
        "false_positives": false_positives,
        "reason": reason,
        "rules_fired": rules_fired,
        "llm_used": llm_used,
        "rag_hits": rag_hits,
    }
