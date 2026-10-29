# -*- coding: utf-8 -*-
"""
ingest 前置层 —— 数据文件 → 标准 DetectionEvent 转换层
======================================================
本层是"前置处理/格式适配"独立层：接收多种安全数据文件格式，自动识别并解析，
输出与现有 DetectionEvent JSON Schema 完全兼容的事件，再调用现有
威胁警报 + 应急响应逻辑。不修改现有 Schema、不改变现有核心逻辑。

设计原则：
1. 插件化解析器：新增格式 = 新增一个 Parser 子类并注册，零改动框架。
2. 多策略格式识别：文件扩展名 + Magic Number + 内容特征正则 + 已知Schema校验。
3. 信息不丢失：无法映射的字段放入 raw.raw_data / raw.extra_context。
4. 解析失败降级：生成 parse_error 标记的 DetectionEvent，交由应急响应处理。
5. 批量 + 溯源：多记录文件拆分多个事件，context 保留 source_file + record_index。
"""

from .pipeline import IngestPipeline, ingest_file

__all__ = ["IngestPipeline", "ingest_file"]