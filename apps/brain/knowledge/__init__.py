"""安全知识库（阶段 3）—— 复用 EduShield ChromaDB 资产。

实现放在 rag/（历史模块名），这里提供大脑架构名 knowledge 的入口：
    search / search_with_scores / seed_default_knowledge / get_knowledge_base
"""

from rag import SecurityKnowledgeBase, get_knowledge_base  # noqa: F401

__all__ = ["SecurityKnowledgeBase", "get_knowledge_base"]
