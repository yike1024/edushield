"""21 号方案 save-attachment 回归测试（新契约：鉴权 + 会话目录/pending + 50MB）。

运行：python -m unittest tests.test_save_attachment
覆盖：未带 token 401；无会话落 _pending 返 upload_id；带会话落 {userId}/{convId}/；
      /api 别名；51MB->413；空字段->400；非法 base64->400；0 字节->413；
      纯 base64 容错；路径穿越安全；safe-name 保留原名。
"""

import base64
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

_U = uuid.uuid4().hex[:8]

# 必须在导入 api 之前设置，让 ATTACHMENT_DIR 指向临时目录
TEST_DIR = tempfile.mkdtemp(prefix="brain-att-")
os.environ["BRAIN_ATTACHMENT_DIR"] = TEST_DIR

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from api import _safe_attachment_name, app  # noqa: E402


class SaveAttachmentTest(unittest.TestCase):
    M = "data:text/plain;base64,"

    @classmethod
    def setUpClass(cls):
        # discover 时其它测试模块可能改过 BRAIN_ATTACHMENT_DIR，重新指回本模块目录
        os.environ["BRAIN_ATTACHMENT_DIR"] = TEST_DIR
        cls.client = TestClient(app)
        # 注册用户拿 token
        r = cls.client.post("/api/auth/register", json={
            "username": f"att_{_U}", "email": f"att{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        assert r.status_code == 201, r.text
        cls.token = r.json()["token"]
        cls.user_id = r.json()["user"]["id"]
        cls.auth = {"Authorization": f"Bearer {cls.token}"}

    def test_requires_auth(self):
        r = self.client.post("/save-attachment",
                             json={"name": "hi.txt", "dataUrl": self.M + "aGk="})
        self.assertEqual(r.status_code, 401, r.text)

    def test_upload_without_conversation_goes_pending(self):
        r = self.client.post("/save-attachment", headers=self.auth,
                             json={"name": "hi.txt", "dataUrl": self.M + base64.b64encode(b"hello attachment").decode()})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertFalse(body["conversation_bound"])
        uid = body["upload_id"]
        # 21 号 path 相对根：{userId}/_pending/{uploadId}_{safeName}
        self.assertEqual(body["path"], f"{self.user_id}/_pending/{uid}_hi.txt", body)
        f = Path(TEST_DIR) / self.user_id / "_pending" / f"{uid}_hi.txt"
        self.assertTrue(f.exists(), f"文件未落盘到 {f}")
        self.assertEqual(f.read_bytes(), b"hello attachment")

    def test_upload_with_conversation_goes_session_dir(self):
        r = self.client.post("/api/conversations", headers=self.auth, json={"title": "附件会话"})
        cid = r.json()["id"]
        r = self.client.post("/save-attachment", headers=self.auth, json={
            "name": "b.txt", "dataUrl": self.M + "Yg==", "conversation_id": cid})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["conversation_bound"])
        self.assertEqual(body["path"], f"{self.user_id}/{cid}/b.txt", body)
        f = Path(TEST_DIR) / self.user_id / cid / "b.txt"
        self.assertTrue(f.exists())

    def test_api_alias(self):
        r = self.client.post("/api/save-attachment", headers=self.auth,
                             json={"name": "c.txt", "dataUrl": self.M + "Yw=="})
        self.assertEqual(r.status_code, 200, r.text)

    def test_oversize_413(self):
        big = base64.b64encode(b"a" * (51 * 1024 * 1024)).decode()
        r = self.client.post("/save-attachment", headers=self.auth,
                             json={"name": "big.bin", "dataUrl": "data:application/octet-stream;base64," + big})
        self.assertEqual(r.status_code, 413)
        self.assertIn("exceeds 50MB limit", r.text)

    def test_empty_fields_400(self):
        self.assertEqual(self.client.post("/save-attachment", headers=self.auth,
                                          json={"name": "", "dataUrl": self.M}).status_code, 400)
        self.assertEqual(self.client.post("/save-attachment", headers=self.auth,
                                          json={"name": "x.log"}).status_code, 400)

    def test_invalid_base64_400(self):
        r = self.client.post("/save-attachment", headers=self.auth,
                             json={"name": "x.log", "dataUrl": self.M + "@@@"})
        self.assertIn(r.status_code, (400, 422))

    def test_zero_byte_413(self):
        self.assertEqual(self.client.post("/save-attachment", headers=self.auth,
                                          json={"name": "e.txt", "dataUrl": self.M}).status_code, 413)

    def test_raw_base64_ok(self):
        r = self.client.post("/save-attachment", headers=self.auth,
                             json={"name": "raw.bin", "dataUrl": base64.b64encode(b"raw").decode()})
        self.assertEqual(r.status_code, 200, r.text)

    def test_path_traversal_sanitized(self):
        r = self.client.post("/save-attachment", headers=self.auth,
                             json={"name": "../../../etc/passwd", "dataUrl": self.M + "eA=="})
        self.assertEqual(r.status_code, 200, r.text)
        fn = Path(r.json().get("path", "")).name
        self.assertNotIn("..", fn)
        self.assertNotIn("/", fn)

    def test_safe_name_keeps_original(self):
        # 21 号 §2：safe-name 保留原名，去路径穿越与非法字符
        self.assertEqual(_safe_attachment_name("hi.txt"), "hi.txt")
        n2 = _safe_attachment_name("../../etc/passwd")
        self.assertNotIn("..", n2)
        self.assertNotIn("/", n2)
        self.assertNotIn("\\", n2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
