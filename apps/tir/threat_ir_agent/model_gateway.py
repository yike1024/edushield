# -*- coding: utf-8 -*-
"""
DeepSeek-Reasonix-Security 推理大脑调用网关
===========================================
子 Agent 的“推理大脑”复用现有 DeepSeek-Reasonix-Security 模型，本模块
**只调用该模型对外暴露的调用入口**，绝不修改模型任何文件（权重/配置/调用逻辑）。

对外暴露的调用入口（两个通道，互不修改）：
1. reasonix-cli 通道 —— 调用 DeepSeek-Reasonix-Security 二进制自带的
   一次性自动化入口：`reasonix run -p "<prompt>" --output-format json`
   （参考其 docs/CLI.zh-CN.md 的一次性运行与自动化章节）。
   只用于获取模型推理文本，不向其授予任何工具权限（--permission-mode dontAsk
   + 不配置工具），保证子 Agent 不会借由模型执行任何真实系统操作。
2. openai-api 通道 —— 调用该模型底层的 DeepSeek OpenAI 兼容 API
   （/chat/completions），与 edushield 主系统 llm 适配层使用同一类调用入口
   （同 base_url/model 配置来源），仅作为 reasonix-cli 在目标机器上不可用时的
   等价推理通道。
3. mock 通道 —— 无网络/无密钥的确定性测试通道（仅测试用，非生产）。

所有威胁研判、预案生成均由该模型推理完成；本网关不实现任何“业务逻辑替代”，
只负责把提示词送达模型并把结构化结果解析回来。

设计参考：
- 《安全智能体平台-项目计划书》3.5：FastAPI 平台层 ↔ reasonix serve/CLI 通信。
- DeepSeek-Reasonix docs/CLI.zh-CN.md 一次性运行与结构化输出格式。
本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import re
from typing import Optional

import httpx

from .config import config

logger = logging.getLogger(__name__)


# ===========================================================================
# 结构化解析工具
# ===========================================================================

def extract_json(text: str) -> dict:
    """从模型回复中稳健提取 JSON 对象（容忍 ```json 代码块与前后缀文本）。"""
    if not text:
        return {}
    text = text.strip()
    # 去除 markdown 代码块围栏
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()
    # 直接尝试
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # 截取首个 { 到最后一个 }
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return {}


# ===========================================================================
# 通道1：reasonix CLI（DeepSeek-Reasonix-Security 对外暴露的 CLI 入口）
# ===========================================================================

class ReasonixCliTransport:
    """调用 DeepSeek-Reasonix-Security 的 reasonix 一次性运行入口。

    注意：仅发起 `reasonix run -p` 文本推理请求（无工具、dontAsk 权限模式），
    不会执行也不允许模型执行任何真实系统命令。
    """

    name = "reasonix-cli"

    def available(self) -> bool:
        """探测 reasonix 二进制是否可用（PATH 或显式路径）。"""
        if config.REASONIX_BIN and shutil.which(config.REASONIX_BIN):
            return True
        return False

    def complete(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        cmd = [
            config.REASONIX_BIN,
            "run",
            "-p",
            f"{system_prompt}\n\n---\n\n{user_prompt}",
            "--output-format", "json",
            "--permission-mode", "dontAsk",
            "--max-steps", "1",
        ]
        logger.info("[ModelGateway] 调用 DeepSeek-Reasonix-Security CLI 推理")
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.REASONIX_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
        )
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        # 结构化结果对象中的 result 字段即最终回答（见 CLI.zh-CN.md 输出格式）
        data = extract_json(out)
        if isinstance(data, dict) and data.get("result"):
            return str(data["result"])
        if isinstance(data, dict) and data.get("type") == "result":
            return json.dumps(data, ensure_ascii=False)
        return out


# ===========================================================================
# 通道2：DeepSeek OpenAI 兼容 API（模型对外暴露的 API 入口）
# ===========================================================================

class OpenAICompatTransport:
    """调用 DeepSeek-Reasonix-Security 底层模型的 OpenAI 兼容 API。

    与 edushield llm 适配层同源（同一 base_url/model），仅调用模型对外接口。
    """

    name = "openai-api"

    def available(self) -> bool:
        return bool(config.DEEPSEEK_API_KEY)

    def complete(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        url = config.DEEPSEEK_API_BASE.rstrip("/") + "/chat/completions"
        payload = {
            "model": config.DEEPSEEK_MODEL,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        headers = {
            "Authorization": f"Bearer {config.DEEPSEEK_API_KEY}",
            "Content-Type": "application/json",
        }
        logger.info("[ModelGateway] 调用 DeepSeek OpenAI 兼容 API 推理")
        resp = httpx.post(url, json=payload, headers=headers,
                          timeout=config.API_TIMEOUT_SECONDS)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


# ===========================================================================
# 通道3：mock（确定性测试通道）
# ===========================================================================

class MockTransport:
    """内置确定性回复 —— 仅用于无网络/无密钥时的功能测试，非生产通道。"""

    name = "mock"

    def available(self) -> bool:
        return True

    @staticmethod
    def _has(text: str, kw: str) -> bool:
        """词边界匹配（避免 'rce' 误命中 'source' 等子串）。"""
        return re.search(rf"\b{re.escape(kw)}\b", text) is not None

    def complete(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        # ---- 预案生成场景：返回确定性步骤 ----
        if "应急处置预案" in system_prompt:
            return json.dumps({
                "objective": "遏制威胁并完成加固（模拟）",
                "summary": "mock 通道生成的标准处置预案（仅测试）",
                "steps": [
                    {"phase": "遏制(Containment)", "action": "隔离受影响目标并阻断来源IP",
                     "expected_command": "示例：block 111.1.216.150（仅文本，不执行）",
                     "risk_level": "high", "requires_approval": True,
                     "rationale": "先遏制再调查，防止扩散"},
                    {"phase": "根除(Eradication)", "action": "清除恶意文件/后门并修复入口",
                     "expected_command": "示例：删除 webshell 文件（仅文本，不执行）",
                     "risk_level": "high", "requires_approval": True,
                     "rationale": "彻底移除攻击载体"},
                    {"phase": "恢复(Recovery)", "action": "恢复服务并验证业务可用",
                     "expected_command": "示例：重启服务并监控（仅文本，不执行）",
                     "risk_level": "medium", "requires_approval": True,
                     "rationale": "确认恢复后再回线"},
                    {"phase": "复盘(Lessons)", "action": "复盘攻击链并输出改进建议",
                     "expected_command": "", "risk_level": "low",
                     "requires_approval": False, "rationale": "沉淀经验"},
                ],
            })
        # ---- 威胁分级场景：基于内置关键字规则给出确定性结果 ----
        low = {"爬虫", "选课", "查分", "搜索引擎", "正常访问", "误报", "info"}
        high = {"webshell", "sql_injection", "data_exfiltration", "数据窃取",
                "数据泄露", "勒索", "命令执行", "critical"}
        if any(self._has(user_prompt, k) for k in high):
            level, atype, conf, verdict = "high", "webshell", 0.92, "true_positive"
            title = "检测到高危威胁（模拟研判）"
        elif any(self._has(user_prompt, k) for k in low):
            level, atype, conf, verdict = "low", "benign", 0.85, "false_positive"
            title = "判定为误报/低风险行为（模拟研判）"
        else:
            level, atype, conf, verdict = "medium", "suspicious", 0.6, "uncertain"
            title = "检测到中风险可疑行为（模拟研判）"
        return json.dumps({
            "level": level,
            "title": title,
            "attack_type": atype,
            "mitre_technique": "T1059" if level == "high" else None,
            "confidence": conf,
            "verdict": verdict,
            "summary": "由 mock 通道生成的确定性研判结果（仅测试）",
            "evidence": "模拟证据：命中内置关键字规则",
            "recommended_action": "建议按预案执行隔离与加固（模拟）",
            "reasoning": "mock 通道基于内置关键字规则给出确定性结果，供离线测试。",
        })


# ===========================================================================
# 网关门面
# ===========================================================================

class ModelGateway:
    """推理大脑网关：统一入口，自动选择可用通道。

    容错原则（对齐计划书“判定走规则引擎+LLM双轨”风险对策）：
    模型通道失败/不可达时返回空 dict，由调用方（分类器/预案生成器）
    自动回退到规则引擎，保证子 Agent 在断网/欠费/密钥失效时仍可运行。
    """

    _transports = [
        ReasonixCliTransport(),
        OpenAICompatTransport(),
        MockTransport(),
    ]

    def __init__(self) -> None:
        self._forced: Optional[str] = None

    def set_mode(self, mode: str) -> None:
        """运行时切换推理通道（测试/演示用）。"""
        mode = mode.strip().lower()
        self._forced = mode if mode in ("reasonix-cli", "openai-api", "mock") else None

    def _select(self) -> object:
        if self._forced:
            for t in self._transports:
                if t.name == self._forced:
                    return t
        # 配置指定通道（reasonix-cli / openai-api / mock）
        mode = config.MODEL_GATEWAY.strip().lower()
        if mode in ("reasonix-cli", "openai-api", "mock"):
            for t in self._transports:
                if t.name == mode:
                    return t
        # auto：优先 reasonix-cli（DeepSeek-Reasonix-Security 原生入口），
        # 不可用则回退 openai-api，最后兜底 mock（保证离线可演示）。
        for t in self._transports:
            if t.available():
                return t
        return self._transports[-1]

    def complete(self, system_prompt: str, user_prompt: str,
                 temperature: Optional[float] = None) -> dict:
        """调用推理大脑，返回解析后的 JSON dict（失败返回 {}）。

        所有威胁研判、预案生成、报告生成均经由此入口交由模型完成。
        任何通道异常都被捕获并降级为空结果，交由调用方规则回退。
        """
        t = self._select()
        temp = temperature if temperature is not None else config.LLM_TEMPERATURE
        try:
            raw = t.complete(system_prompt, user_prompt, temp)
        except Exception as e:  # noqa: BLE001 - 通道失败必须降级而非中断
            logger.warning("[ModelGateway] 推理通道 %s 调用失败，降级为空结果: %s", t.name, e)
            return {}
        result = extract_json(raw)
        result.setdefault("_transport", t.name)
        logger.info("[ModelGateway] 推理通道=%s", t.name)
        return result

    def current_transport(self) -> str:
        return self._select().name


gateway = ModelGateway()
