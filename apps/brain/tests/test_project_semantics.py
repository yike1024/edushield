"""P1 项目语义测试：target=null 清空、color 白名单 422、project_id UUID 422。"""
import os
import sys
import tempfile
import unittest
import uuid

_U = uuid.uuid4().hex[:8]

_tmp = tempfile.mkdtemp(prefix="projp1_")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/t.db"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402
import api  # noqa: E402

client = TestClient(api.app)


class ProjectSemanticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r = client.post("/api/auth/register", json={
            "username": f"p1_{_U}", "email": f"p1{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        assert r.status_code == 201, r.text
        cls.token = r.json()["token"]
        cls.auth = {"Authorization": f"Bearer {cls.token}"}

    def test_patch_target_null_clears(self):
        r = client.post("/api/projects", headers=self.auth,
                        json={"name": "P", "target": "8.215.92.252"})
        self.assertEqual(r.status_code, 201, r.text)
        pid = r.json()["id"]
        self.assertEqual(r.json()["target"], "8.215.92.252")

        # 显式传 null 清空
        r = client.patch(f"/api/projects/{pid}", headers=self.auth, json={"target": None})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(r.json()["target"])

        # 未传 target 不改动其它字段
        r = client.patch(f"/api/projects/{pid}", headers=self.auth, json={"pinned": True})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(r.json()["target"])
        self.assertTrue(r.json()["pinned"])

    def test_invalid_color_422(self):
        r = client.post("/api/projects", headers=self.auth, json={"name": "C", "color": "not-a-color"})
        self.assertEqual(r.status_code, 422, r.text)
        r = client.post("/api/projects", headers=self.auth, json={"name": "C2", "color": "blue"})
        self.assertEqual(r.status_code, 201, r.text)

    def test_invalid_project_uuid_422(self):
        # GET / DELETE 无 body
        r = client.get("/api/projects/not-a-uuid", headers=self.auth)
        self.assertEqual(r.status_code, 422, r.text)
        r = client.delete("/api/projects/not-a-uuid", headers=self.auth)
        self.assertEqual(r.status_code, 422, r.text)
        # PATCH 带 body
        r = client.patch("/api/projects/not-a-uuid", headers=self.auth, json={"pinned": True})
        self.assertEqual(r.status_code, 422, r.text)


if __name__ == "__main__":
    unittest.main()
