"""LLM 适配层。

- chat_json()：阶段 3 判定用的 OpenAI 兼容 JSON 调用（httpx，重试 2 次）
- get_llm()：历史 langchain 封装（后续报告/编排需要时用，按需 import）

切换模型：改 .env 的 DEEPSEEK_API_BASE / DEEPSEEK_MODEL 即可。
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

from config.settings import settings

logger = logging.getLogger(__name__)

# 分段超时：connect 10s 快速失败；read 300s 覆盖长 reasoning（DeepSeek reasoning 模型
# 思考可达数十秒，单一 timeout=60 会在流中途掐断）；write/pool 保守值。
_HTTPX_TIMEOUT = httpx.Timeout(connect=10, read=300, write=30, pool=10)


def chat_text(messages: list[dict], temperature: float = 0.3) -> str:
    """通用聊天（非流式），返回文本。无 key 时返回提示。"""
    if not settings.DEEPSEEK_API_KEY:
        return "未配置 DEEPSEEK_API_KEY，聊天不可用"
    url = settings.DEEPSEEK_API_BASE.rstrip("/") + "/chat/completions"
    payload = {
        "model": settings.DEEPSEEK_MODEL,
        "temperature": temperature,
        "messages": messages,
    }
    headers = {"Authorization": f"Bearer {settings.DEEPSEEK_API_KEY}"}
    try:
        resp = httpx.post(url, json=payload, headers=headers, timeout=_HTTPX_TIMEOUT)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logger.warning(f"[llm] chat 失败: {e}")
        return f"聊天请求失败: {e}"


def chat_stream(messages: list[dict], temperature: float = 0.3):
    """通用聊天（流式），逐段 yield 文本增量。"""
    if not settings.DEEPSEEK_API_KEY:
        yield "未配置 DEEPSEEK_API_KEY，聊天不可用"
        return
    url = settings.DEEPSEEK_API_BASE.rstrip("/") + "/chat/completions"
    payload = {
        "model": settings.DEEPSEEK_MODEL,
        "temperature": temperature,
        "messages": messages,
        "stream": True,
    }
    headers = {"Authorization": f"Bearer {settings.DEEPSEEK_API_KEY}"}
    try:
        with httpx.stream("POST", url, json=payload, headers=headers, timeout=_HTTPX_TIMEOUT) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    obj = json.loads(data)
                    delta = obj["choices"][0].get("delta", {}).get("content")
                    if delta:
                        yield delta
                except Exception:
                    continue
    except Exception as e:
        logger.warning(f"[llm] chat stream 失败: {e}")
        yield f"聊天请求失败: {e}"


def chat_stream_events(messages: list[dict], temperature: float = 0.3):
    """pass_through 模式：输出 reasonix 风格事件（reasoning/text/usage）。"""
    if not settings.DEEPSEEK_API_KEY:
        yield {"text": "未配置 DEEPSEEK_API_KEY，聊天不可用"}
        return
    url = settings.DEEPSEEK_API_BASE.rstrip("/") + "/chat/completions"
    payload = {
        "model": settings.DEEPSEEK_MODEL,
        "temperature": temperature,
        "messages": messages,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    headers = {"Authorization": f"Bearer {settings.DEEPSEEK_API_KEY}"}
    try:
        with httpx.stream("POST", url, json=payload, headers=headers, timeout=_HTTPX_TIMEOUT) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    continue
                choices = obj.get("choices") or []
                if choices:
                    delta = choices[0].get("delta") or {}
                    if delta.get("reasoning_content"):
                        yield {"reasoning": delta["reasoning_content"]}
                    if delta.get("content"):
                        yield {"text": delta["content"]}
                if obj.get("usage"):
                    yield {"usage": obj["usage"]}
    except Exception as e:
        logger.warning(f"[llm] chat stream events 失败: {e}")
        yield {"error": {"code": "brain_think_failed", "message": str(e)}}


def chat_json(system_prompt: str, user_prompt: str, temperature: float = 0.2,
              max_retries: int = 2, timeout: Optional[float] = None) -> Optional[dict[str, Any]]:
    """调用 OpenAI 兼容 chat/completions，要求模型只输出 JSON。

    失败/无 key/JSON 解析失败 → 返回 None（调用方回退规则轨）。
    timeout 秒：None=默认分段超时；意图分类等场景传 8 表示收紧到 8s。
    """
    if not settings.DEEPSEEK_API_KEY:
        logger.info("[llm] 未配置 DEEPSEEK_API_KEY，跳过 LLM 轨")
        return None

    url = settings.DEEPSEEK_API_BASE.rstrip("/") + "/chat/completions"
    payload = {
        "model": settings.DEEPSEEK_MODEL,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": f"Bearer {settings.DEEPSEEK_API_KEY}"}
    httpx_timeout: httpx.Timeout = _HTTPX_TIMEOUT
    if timeout is not None:
        httpx_timeout = httpx.Timeout(connect=5, read=timeout, write=10, pool=5)

    for attempt in range(max_retries + 1):
        try:
            resp = httpx.post(url, json=payload, headers=headers, timeout=httpx_timeout)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            return json.loads(content)
        except Exception as e:
            logger.warning(f"[llm] 调用失败(第{attempt + 1}次): {e}")
    return None


def get_llm(temperature: float | None = None):
    """历史 langchain 封装（需要时再装 langchain-openai）。"""
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(
        model=settings.DEEPSEEK_MODEL,
        api_key=settings.DEEPSEEK_API_KEY,
        base_url=settings.DEEPSEEK_API_BASE,
        temperature=temperature if temperature is not None else settings.LLM_TEMPERATURE,
    )
