"""21 号方案 save-attachment 扩展测试：会话目录 / pending / 50MB / 鉴权 / 归属校验。"""
import base64
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

_U = uuid.uuid4().hex[:8]

TEST_DIR = tempfile.mkdtemp(prefix="att21-")
os.environ["BRAIN_ATTACHMENT_DIR"] = TEST_DIR

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
import api  # noqa: E402

client = TestClient(api.app)


class SaveAttachment21Test(unittest.TestCase):
    M = "data:text/plain;base64,"

    @classmethod
    def setUpClass(cls):
        # discover 时其它测试模块可能改过 BRAIN_ATTACHMENT_DIR，重新指回本模块目录
        os.environ["BRAIN_ATTACHMENT_DIR"] = TEST_DIR
        r = client.post("/api/auth/register", json={
            "username": f"a21_{_U}", "email": f"a21{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        assert r.status_code == 201, r.text
        cls.token = r.json()["token"]
        cls.uid = r.json()["user"]["id"]
        cls.auth = {"Authorization": f"Bearer {cls.token}"}

    def test_requires_auth(self):
        r = client.post("/api/save-attachment",
                        json={"name": "a.txt", "dataUrl": self.M + "eA=="})
        self.assertEqual(r.status_code, 401)

    def test_with_conversation_writes_session_dir(self):
        r = client.post("/api/conversations", headers=self.auth, json={"title": "会话A"})
        cid = r.json()["id"]
        raw = b"hello 21"
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "OpenSSH_2k.log",
            "dataUrl": self.M + base64.b64encode(raw).decode(),
            "conversation_id": cid})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        # path 相对 ATTACHMENT_ROOT：{userId}/{convId}/{safeName}
        self.assertEqual(body["path"], f"{self.uid}/{cid}/OpenSSH_2k.log", body)
        self.assertTrue(body["conversation_bound"])
        self.assertEqual(body["size"], len(raw))
        f = Path(TEST_DIR) / self.uid / cid / "OpenSSH_2k.log"
        self.assertTrue(f.exists(), f"文件未落盘到 {f}")
        self.assertEqual(f.read_bytes(), raw)

    def test_without_conversation_writes_pending(self):
        raw = b"pending-data"
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "note.txt",
            "dataUrl": self.M + base64.b64encode(raw).decode()})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertFalse(body["conversation_bound"])
        self.assertIn("upload_id", body)
        self.assertTrue(body["path"].startswith(f"{self.uid}/_pending/{body['upload_id']}_"), body)
        f = Path(TEST_DIR) / self.uid / "_pending" / f"{body['upload_id']}_note.txt"
        self.assertTrue(f.exists(), f"文件未落盘到 {f}")

    def test_other_users_conversation_404(self):
        # B 用户建会话，A 传文件挂到 B 的会话 → 404
        r = client.post("/api/auth/register", json={
            "username": f"b21_{_U}", "email": f"b21{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        tb = r.json()["token"]
        r = client.post("/api/conversations",
                        headers={"Authorization": f"Bearer {tb}"}, json={"title": "B的会话"})
        cid_b = r.json()["id"]
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "x.txt", "dataUrl": self.M + "eA==", "conversation_id": cid_b})
        self.assertEqual(r.status_code, 404, r.text)

    def test_oversize_413(self):
        # 51MB 超限；用 51MB 原始数据 base64 太大，直接发纯 base64 字符串验证上限判断
        big = base64.b64encode(b"a" * (51 * 1024 * 1024)).decode()
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "big.bin", "dataUrl": "data:application/octet-stream;base64," + big})
        self.assertEqual(r.status_code, 413)
        self.assertIn("exceeds 50MB limit", r.text)

    def test_path_traversal_sanitized(self):
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "../../etc/passwd", "dataUrl": self.M + "eA=="})
        self.assertEqual(r.status_code, 200, r.text)
        name = Path(r.json()["path"]).name
        self.assertNotIn("..", name)
        self.assertNotIn("/", name)

    def test_bind_moves_pending_into_session(self):
        # 无会话上传 → pending 拿 upload_id
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "audit.log", "dataUrl": self.M + base64.b64encode(b"LOG-LINE").decode()})
        up = r.json()
        # 建会话
        r = client.post("/api/conversations", headers=self.auth, json={"title": "绑定会话"})
        cid = r.json()["id"]
        # bind
        r = client.post("/api/attachments/bind", headers=self.auth, json={
            "upload_ids": [up["upload_id"]], "conversation_id": cid})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["bound"], [f"{self.uid}/{cid}/audit.log"], r.text)
        # 文件已 move 到会话目录
        f = Path(TEST_DIR) / self.uid / cid / "audit.log"
        self.assertTrue(f.exists(), f)
        self.assertEqual(f.read_bytes(), b"LOG-LINE")
        # pending 目录已空
        leftovers = list((Path(TEST_DIR) / self.uid / "_pending").iterdir())
        self.assertEqual(leftovers, [])

    def test_bind_other_conversation_404(self):
        r = client.post("/api/auth/register", json={
            "username": f"c21_{_U}", "email": f"c21{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        tb = r.json()["token"]
        r = client.post("/api/conversations",
                        headers={"Authorization": f"Bearer {tb}"}, json={"title": "他人会话"})
        cid = r.json()["id"]
        r = client.post("/api/attachments/bind", headers=self.auth, json={
            "upload_ids": ["whatever"], "conversation_id": cid})
        self.assertEqual(r.status_code, 404)

    def test_file_download_and_other_user_404(self):
        # 上传文本到会话
        r = client.post("/api/conversations", headers=self.auth, json={"title": "下载会话"})
        cid = r.json()["id"]
        raw = b"download-me-123"
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "dl.txt",
            "dataUrl": self.M + base64.b64encode(raw).decode(),
            "conversation_id": cid})
        path = r.json()["path"]
        # 下载
        r = client.get("/api/attachments/file", headers=self.auth, params={"path": path})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.content, raw)
        self.assertIn("attachment", r.headers.get("content-disposition", ""))
        # 他人下载 → 404
        r = client.post("/api/auth/register", json={
            "username": f"d21_{_U}", "email": f"d21{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        tb = r.json()["token"]
        r = client.get("/api/attachments/file",
                       headers={"Authorization": f"Bearer {tb}"}, params={"path": path})
        self.assertEqual(r.status_code, 404)
        # 穿越 → 404
        r = client.get("/api/attachments/file", headers=self.auth,
                       params={"path": f"{self.uid}/../../etc/passwd"})
        self.assertEqual(r.status_code, 404)

    def test_preview_text_and_binary(self):
        r = client.post("/api/conversations", headers=self.auth, json={"title": "预览会话"})
        cid = r.json()["id"]
        # 文本 > max_bytes → truncated
        raw = b"x" * 2000
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "big.txt",
            "dataUrl": self.M + base64.b64encode(raw).decode(),
            "conversation_id": cid})
        path = r.json()["path"]
        r = client.get("/api/attachments/preview", headers=self.auth,
                       params={"path": path, "max_bytes": 100})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(len(body["text"]), 100)
        self.assertTrue(body["truncated"])
        self.assertEqual(body["size"], 2000)
        # 二进制（pcap）→ 415
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "t.pcap",
            "dataUrl": self.M + base64.b64encode(b"\x00\x01\x02").decode(),
            "conversation_id": cid})
        pcap_path = r.json()["path"]
        r = client.get("/api/attachments/preview", headers=self.auth,
                       params={"path": pcap_path})
        self.assertEqual(r.status_code, 415, r.text)

    def test_delete_conversation_removes_dir(self):
        r = client.post("/api/conversations", headers=self.auth, json={"title": "待删会话"})
        cid = r.json()["id"]
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "gone.txt",
            "dataUrl": self.M + base64.b64encode(b"BYE").decode(),
            "conversation_id": cid})
        conv_dir = Path(TEST_DIR) / self.uid / cid
        self.assertTrue(conv_dir.exists())
        r = client.delete(f"/api/conversations/{cid}", headers=self.auth)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(conv_dir.exists(), "删除会话后附件目录应消失")

    def test_chat_message_augmented_with_attachment_path_only(self):
        # 建会话 + 上传，然后验证注入结果只含路径不含文件全文
        r = client.post("/api/conversations", headers=self.auth, json={"title": "注入会话"})
        cid = r.json()["id"]
        secret = "TOP-SECRET-CONTENT-XYZ"
        r = client.post("/api/save-attachment", headers=self.auth, json={
            "name": "a.log",
            "dataUrl": self.M + base64.b64encode(secret.encode()).decode(),
            "conversation_id": cid})
        path = r.json()["path"]
        msg = api._attachment_augmented_message(
            self.uid, "审计这个日志", [{"name": "a.log", "path": path}])
        self.assertIn("[附件] a.log →", msg)
        self.assertIn("审计这个日志", msg)
        self.assertNotIn(secret, msg, "prompt 不得内联文件全文")


if __name__ == "__main__":
    unittest.main()
