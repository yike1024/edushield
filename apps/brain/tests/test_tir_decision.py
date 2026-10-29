"""P0-1 TIR decision 代理测试：鉴权、用户隔离、转发、账本。"""
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

_U = uuid.uuid4().hex[:8]
TEST_DIR = tempfile.mkdtemp(prefix="tird-")
os.environ["BRAIN_DB_PATH"] = str(Path(TEST_DIR) / "brain.sqlite3")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DIR}/t.db"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
import api  # noqa: E402
from session import get_store  # noqa: E402

client = TestClient(api.app)


class TirDecisionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r = client.post("/api/auth/register", json={
            "username": f"td_{_U}", "email": f"td{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        assert r.status_code == 201, r.text
        cls.token = r.json()["token"]
        cls.uid = r.json()["user"]["id"]
        cls.auth = {"Authorization": f"Bearer {cls.token}"}
        cls.tid = "TD" + uuid.uuid4().hex[:8]
        get_store().create_task(cls.tid, "logaudit", "8.8.8.8", user_id=cls.uid)

    def test_no_token_401(self):
        r = client.post("/api/tir/playbooks/pb1/decision", json={"decision": "approve"})
        self.assertEqual(r.status_code, 401, r.text)

    def test_unknown_playbook_404(self):
        with patch.object(api.httpx, "get") as g:
            g.return_value.raise_for_status.return_value = None
            g.return_value.json.return_value = {"playbooks": []}
            r = client.post("/api/tir/playbooks/pbx/decision", headers=self.auth,
                            json={"decision": "approve"})
        self.assertEqual(r.status_code, 404, r.text)

    def test_other_users_playbook_404(self):
        # 建 B 用户与 B 的任务，A 审 B 的 playbook → 404
        r = client.post("/api/auth/register", json={
            "username": f"tdb_{_U}", "email": f"tdb{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        tb = r.json()["token"]
        tid_b = "TD" + uuid.uuid4().hex[:8]
        get_store().create_task(tid_b, "logaudit", "8.8.8.8",
                                user_id=r.json()["user"]["id"])
        with patch.object(api.httpx, "get") as g:
            g.return_value.raise_for_status.return_value = None
            g.return_value.json.return_value = {"playbooks": [
                {"playbook_id": "pb_b", "alert_id": "a_b", "task_id": tid_b}]}
            r = client.post("/api/tir/playbooks/pb_b/decision", headers=self.auth,
                            json={"decision": "approve"})
        self.assertEqual(r.status_code, 404, r.text)

    def test_approve_forwards_and_records_ledger(self):
        resp = {"status": "responded", "report_id": "tir_report_1", "report_md": "# TIR"}
        with patch.object(api.httpx, "get") as g, patch.object(api.httpx, "post") as p:
            g.return_value.raise_for_status.return_value = None
            g.return_value.json.return_value = {"playbooks": [
                {"playbook_id": "pb1", "alert_id": "a1", "task_id": self.tid}]}
            p.return_value.raise_for_status.return_value = None
            p.return_value.json.return_value = resp
            r = client.post("/api/tir/playbooks/pb1/decision", headers=self.auth,
                            json={"decision": "approve", "operator": "tester"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "responded")
        # 账本 recorded
        ledger = get_store().list_ledger(self.tid)
        self.assertTrue(any("tir_decision_approve" in str(e.get("action", ""))
                            for e in ledger), ledger)


if __name__ == "__main__":
    unittest.main()
