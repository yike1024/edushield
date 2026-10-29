"""L-3 显式 domain/target/pipeline 路由测试（ChatRequest 三字段生效）。"""
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

_U = uuid.uuid4().hex[:8]
TEST_DIR = tempfile.mkdtemp(prefix="l3-")
os.environ["BRAIN_ATTACHMENT_DIR"] = TEST_DIR

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from unittest.mock import patch  # noqa: E402
import api  # noqa: E402
from api import _chat_or_task  # noqa: E402


class ExplicitRoutingTest(unittest.TestCase):
    def setUp(self):
        # discover 下白名单开关由别的测试固化，这里直接 patch 校验函数
        self.patcher = patch.object(api, "check_target_whitelisted", return_value=True)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
    def test_explicit_target_builds_task_without_keywords(self):
        r = _chat_or_task("你好", "sys", start=False, user_id="u1",
                          target="8.215.92.252", domain="logaudit")
        self.assertEqual(r["kind"], "task", r)
        self.assertEqual(r["domain"], "logaudit")
        self.assertEqual(r["target"], "8.215.92.252")

    def test_invalid_domain_rejected(self):
        r = _chat_or_task("你好", "sys", start=False, user_id="u1",
                          target="8.215.92.252", domain="nope")
        self.assertEqual(r["kind"], "reply")
        self.assertIn("未知 domain", r["reply"])

    def test_invalid_pipeline_rejected(self):
        r = _chat_or_task("你好", "sys", start=False, user_id="u1",
                          target="8.215.92.252", domain="logaudit", pipeline="bad")
        self.assertEqual(r["kind"], "reply")
        self.assertIn("未知 pipeline", r["reply"])

    def test_pipeline_ok(self):
        r = _chat_or_task("你好", "sys", start=False, user_id="u1",
                          target="8.215.92.252", domain="logaudit", pipeline="data_leak")
        self.assertEqual(r["kind"], "task", r)
        self.assertEqual(r["pipeline"], "data_leak")


if __name__ == "__main__":
    unittest.main()
