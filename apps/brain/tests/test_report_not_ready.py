"""L-8 补充测试：任务存在但报告未生成 → 200 + report:null（非 404）。"""
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

_U = uuid.uuid4().hex[:8]
TEST_DIR = tempfile.mkdtemp(prefix="rep-")
os.environ["BRAIN_DB_PATH"] = str(Path(TEST_DIR) / "brain.sqlite3")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DIR}/t.db"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
import api  # noqa: E402
from session import get_store  # noqa: E402

client = TestClient(api.app)


class ReportNotReadyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r = client.post("/api/auth/register", json={
            "username": f"rep_{_U}", "email": f"rep{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        assert r.status_code == 201, r.text
        cls.token = r.json()["token"]
        cls.uid = r.json()["user"]["id"]
        cls.auth = {"Authorization": f"Bearer {cls.token}"}

    def test_running_task_report_200_null(self):
        import time as _t
        store = get_store()
        tid = "REP" + uuid.uuid4().hex[:8]
        store.create_task(tid, "logaudit", "8.8.8.8", user_id=self.uid)
        r = client.get(f"/api/reports/{tid}", headers=self.auth)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIsNone(body["report"])
        self.assertEqual(body["task_id"], tid)
        self.assertIn("报告尚未生成", body.get("detail", ""))

    def test_unknown_task_404(self):
        r = client.get("/api/reports/nope", headers=self.auth)
        self.assertEqual(r.status_code, 404, r.text)


if __name__ == "__main__":
    unittest.main()
