"""对话 RAG 接线回归测试：_rag_augmented_system 命中/未命中行为。

运行：python -m unittest tests.test_rag_chat
不碰网络、不依赖真实 ./chroma_data；用临时 Chroma 库 monkeypatch rag.get_knowledge_base。
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

_APP = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, _APP)

from rag import SecurityKnowledgeBase  # noqa: E402


class RagInjectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import rag
        import api
        cls.api = api
        tmp = cls.tmp = tempfile.mkdtemp(prefix="rag_ut_")
        kb = SecurityKnowledgeBase(persist_dir=tmp, collection_name="ragtest")
        kb.ensure_seeded()
        assert kb.count() > 0
        cls._gkb = rag.get_knowledge_base
        rag.get_knowledge_base = lambda: kb

    @classmethod
    def tearDownClass(cls):
        import rag
        rag.get_knowledge_base = cls._gkb

    def test_hit_injects(self):
        s = self.api._rag_augmented_system("你是助手", "如何防御SQL注入和XSS")
        self.assertIn("SQL注入", s)
        self.assertIn("安全知识库", s)

    def test_miss_passthrough(self):
        s = self.api._rag_augmented_system("你是助手", "今天午饭想吃什么")
        self.assertEqual(s, "你是助手")


if __name__ == "__main__":
    unittest.main(verbosity=2)
