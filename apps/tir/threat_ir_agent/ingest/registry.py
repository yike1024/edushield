# -*- coding: utf-8 -*-
"""
解析器注册表（插件化机制）
==========================
新增格式解析器：实现 BaseParser 子类 + 用 @register_parser 装饰即可自动注册，
无需修改框架与流水线代码。本文件为【新增文件】。
"""

from __future__ import annotations

from typing import Optional

from .base import BaseParser

_REGISTRY: dict[str, BaseParser] = {}


def register_parser(cls: type[BaseParser]) -> type[BaseParser]:
    """类装饰器：把解析器实例注册进全局注册表。"""
    inst = cls()
    _REGISTRY[inst.name] = inst
    return cls


def get_parser(name: str) -> Optional[BaseParser]:
    return _REGISTRY.get(name)


def all_parsers() -> list[BaseParser]:
    return list(_REGISTRY.values())


def parser_names() -> list[str]:
    return sorted(_REGISTRY.keys())


# 触发 parsers 包内的注册（import 即完成注册）
from . import parsers as _parsers  # noqa: E402,F401  (确保所有 @register_parser 生效)
