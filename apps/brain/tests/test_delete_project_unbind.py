"""P0-2: DELETE 项目后会话解绑 + 响应字段。"""
import os
import sys
import tempfile
import unittest
import uuid

_U = uuid.uuid4().hex[:8]

_tmp = tempfile.mkdtemp(prefix="unbind_")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/t.db"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402
import api  # noqa: E402

client = TestClient(api.app)


class DeleteProjectUnbindTest(unittest.TestCase):
    def test_delete_project_unbinds_conversations(self):
        r = client.post("/api/auth/register", json={
            "username": f"unb_{_U}", "email": f"unb{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        self.assertEqual(r.status_code, 201, r.text)
        token = r.json()["token"]
        auth = {"Authorization": f"Bearer {token}"}

        r = client.post("/api/projects", headers=auth, json={"name": "项目Z"})
        pid = r.json()["id"]

        # 两个会话挂到该项目
        for t in ["会话1", "会话2"]:
            r = client.post("/api/conversations", headers=auth, json={"title": t, "projectId": pid})
            self.assertEqual(r.status_code, 201, r.text)

        # 删除项目
        r = client.delete(f"/api/projects/{pid}", headers=auth)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["id"], pid)
        self.assertEqual(body["unboundConversations"], 2, body)

        # 会话已解绑
        r = client.get("/api/conversations", headers=auth, params={"pageSize": 50})
        for c in r.json()["items"]:
            self.assertIsNone(c["projectId"], c)

        # 项目列表不可见（软删除）
        r = client.get("/api/projects", headers=auth, params={"status": "active"})
        self.assertEqual(r.json()["total"], 0)


if __name__ == "__main__":
    unittest.main()
