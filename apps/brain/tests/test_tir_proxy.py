"""L-1/L-7 TIR 代理逻辑测试：鉴权、用户隔离、verdict 过滤。"""
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

_U = uuid.uuid4().hex[:8]
TEST_DIR = tempfile.mkdtemp(prefix="tir-")
os.environ["BRAIN_DB_PATH"] = str(Path(TEST_DIR) / "brain.sqlite3")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DIR}/t.db"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
import api  # noqa: E402
from session import get_store  # noqa: E402

client = TestClient(api.app)


class TirProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r = client.post("/api/auth/register", json={
            "username": f"tir_{_U}", "email": f"tir{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        assert r.status_code == 201, r.text
        cls.token = r.json()["token"]
        cls.uid = r.json()["user"]["id"]
        cls.auth = {"Authorization": f"Bearer {cls.token}"}

    def _make_task(self, verdict):
        import time as _t
        store = get_store()
        tid = "TIR" + uuid.uuid4().hex[:8]
        store.create_task(tid, "logaudit", "8.8.8.8", user_id=self.uid)
        store.set_verdict(tid, verdict, 0.9)
        return tid

    def test_no_token_401(self):
        r = client.get("/api/tir/alerts")
        self.assertEqual(r.status_code, 401, r.text)

    def test_unknown_task_404(self):
        r = client.get("/api/tir/alerts", headers=self.auth,
                       params={"task_id": "nope"})
        self.assertEqual(r.status_code, 404, r.text)

    def test_not_real_threat_returns_empty(self):
        tid = self._make_task("pending_review")
        r = client.get("/api/tir/alerts", headers=self.auth, params={"task_id": tid})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"alerts": []})

    def test_real_threat_filters_by_task(self):
        tid = self._make_task("real_threat")
        fake = {"alerts": [
            {"alert_id": "a1", "task_id": tid, "title": "钓鱼"},
            {"alert_id": "a2", "task_id": "other", "title": "无关"},
        ]}
        with patch.object(api.httpx, "get") as mock_get:
            mock_get.return_value.raise_for_status.return_value = None
            mock_get.return_value.json.return_value = fake
            r = client.get("/api/tir/alerts", headers=self.auth, params={"task_id": tid})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual([a["alert_id"] for a in r.json()["alerts"]], ["a1"])

    def test_8090_down_degrades_empty(self):
        tid = self._make_task("real_threat")
        with patch.object(api.httpx, "get", side_effect=RuntimeError("down")):
            r = client.get("/api/tir/alerts", headers=self.auth, params={"task_id": tid})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"alerts": []})

    def test_playbooks_dedup_by_alert(self):
        tid = self._make_task("real_threat")
        fake = {"playbooks": [
            {"playbook_id": "p1", "alert_id": "a1", "task_id": tid},
            {"playbook_id": "p2", "alert_id": "a1", "task_id": tid},  # 同 alert 重复
            {"playbook_id": "p3", "alert_id": "a2", "task_id": tid},
        ]}
        with patch.object(api.httpx, "get") as mock_get:
            mock_get.return_value.raise_for_status.return_value = None
            mock_get.return_value.json.return_value = fake
            r = client.get("/api/tir/playbooks", headers=self.auth, params={"task_id": tid})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual([p["playbook_id"] for p in r.json()["playbooks"]], ["p1", "p3"])


if __name__ == "__main__":
    unittest.main()
