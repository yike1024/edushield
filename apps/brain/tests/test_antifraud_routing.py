"""L-4 反诈关键词 + 附件路径 target 测试。"""
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

_U = uuid.uuid4().hex[:8]
TEST_DIR = tempfile.mkdtemp(prefix="l4-")
os.environ["BRAIN_ATTACHMENT_DIR"] = TEST_DIR
os.environ["TARGET_WHITELIST_ENABLED"] = "true"  # 开启白名单，验证附件路径放行
os.environ.setdefault("AUTHORIZED_TARGETS", "127.0.0.1,8.215.92.252")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import _chat_or_task, _is_user_attachment_target  # noqa: E402
from orchestrator import parse_task_intent  # noqa: E402


class AntiFraudRoutingTest(unittest.TestCase):
    def setUp(self):
        # discover 时其它测试模块会改 BRAIN_ATTACHMENT_DIR，重置回本模块目录
        os.environ["BRAIN_ATTACHMENT_DIR"] = TEST_DIR

    def test_keyword_phishing_routes_logaudit(self):
        intent = parse_task_intent("帮我研判这封钓鱼举报邮件")
        self.assertEqual(intent["domain"].value, "logaudit", intent)

    def test_attachment_path_as_target_builds_task(self):
        user_id = "u_" + _U
        att_dir = Path(TEST_DIR) / user_id / "conv1"
        att_dir.mkdir(parents=True, exist_ok=True)
        eml = att_dir / "举报邮件.eml"
        eml.write_bytes(b"From: fake")
        path_str = eml.as_posix()
        msg = f"帮我研判这封举报邮件\n\n[附件] 举报邮件.eml → {path_str}"
        self.assertTrue(_is_user_attachment_target(str(eml), user_id))
        r = _chat_or_task(msg, "sys", start=False, user_id=user_id)
        self.assertEqual(r["kind"], "task", r)
        self.assertEqual(r["domain"], "logaudit")
        self.assertEqual(r["target"], path_str)

    def test_other_users_attachment_rejected(self):
        user_id = "u_" + _U
        other = "other_" + _U
        eml = Path(TEST_DIR) / other / "c" / "x.eml"
        eml.parent.mkdir(parents=True, exist_ok=True)
        eml.write_bytes(b"x")
        self.assertFalse(_is_user_attachment_target(str(eml), user_id))


if __name__ == "__main__":
    unittest.main()
