"""verdict RAG 接线回归测试：evaluate 内把知识检索并入 user_doc 并返回 rag_hits。

运行：python -m unittest tests.test_rag_verdict
不触发真实 DeepSeek（mock llm.chat_json）+ 不落真实 chroma_data（mock rag.get_knowledge_base）。
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

_APP = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, _APP)


class RagVerdictTest(unittest.TestCase):
    def test_rag_hits_returned(self):
        _captured = {}

        # 1) mock llm.chat_json：拦截其 user_prompt 记录并给一个合法 JSON
        def _fake_chat_json(**kwargs):
            _captured["user_prompt"] = kwargs.get("user_prompt", "")
            return {"verdict": "real_threat", "confidence": 0.9, "reason": "mock判定"}

        # 2) mock rag 单例检索：返回固定知识
        class _FakeKB:
            def search_with_scores(self, query, k=4):
                return [{"content": "SQL注入：参数化查询与输入校验是关键防御。", "score": 1.0}]

        from verdict import evaluate
        import verdict as verdict_mod
        with mock.patch.object(verdict_mod, "chat_json", side_effect=_fake_chat_json), \
             mock.patch("rag.get_knowledge_base", return_value=_FakeKB()):
            res = evaluate([{
                "title": "SQL注入攻击尝试", "description": "发现注入payload", "evidence": "1 or 1=1",
                "severity": "high", "confidence": 0.9,
            }])

        self.assertTrue(res.get("rag_hits"))
        self.assertIn("SQL注入", res["rag_hits"][0])
        # user_prompt 里应带 rag_knowledge 段
        self.assertIn("rag_knowledge", _captured.get("user_prompt", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
