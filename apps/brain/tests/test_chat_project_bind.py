"""P0-1: chat/stream 携带 project_id 时，会话必须绑定项目。"""
import json
import os
import sys
import tempfile
import unittest
import uuid

_U = uuid.uuid4().hex[:8]

_tmp = tempfile.mkdtemp(prefix="projbind_")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/t.db"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402
import api  # noqa: E402

client = TestClient(api.app)


def _frames(response):
    out = []
    for line in response.iter_lines():
        if not line or not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            continue
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            continue
        out.append((obj.get("kind"), obj))
    return out


class ChatStreamProjectBindTest(unittest.TestCase):
    def test_chat_stream_binds_project(self):
        r = client.post("/api/auth/register", json={
            "username": f"bind_{_U}", "email": f"bind{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        self.assertEqual(r.status_code, 201, r.text)
        token = r.json()["token"]
        auth = {"Authorization": f"Bearer {token}"}

        r = client.post("/api/projects", headers=auth, json={"name": "项目X"})
        self.assertEqual(r.status_code, 201, r.text)
        pid = r.json()["id"]

        # 新建会话并绑定项目
        with client.stream("POST", "/api/chat/stream", headers=auth, json={
                "message": "你好", "project_id": pid, "use_rag": False}) as resp:
            self.assertEqual(resp.status_code, 200)
            frames = _frames(resp)

        # conversation_bound 帧带 projectId（17 号 §5.9）
        bound = [o for k, o in frames if k == "conversation_bound"][0]
        self.assertEqual(bound["projectId"], pid, bound)

        r = client.get("/api/conversations", headers=auth, params={"pageSize": 50})
        convs = r.json()["items"]
        self.assertEqual(len(convs), 1)
        self.assertEqual(convs[0]["projectId"], pid, convs[0])

    def test_chat_stream_binds_existing_conversation(self):
        r = client.post("/api/auth/register", json={
            "username": f"bind2_{_U}", "email": f"bind2{_U}@x.com",
            "password": "pass1234", "confirmPassword": "pass1234"})
        self.assertEqual(r.status_code, 201, r.text)
        token = r.json()["token"]
        auth = {"Authorization": f"Bearer {token}"}

        r = client.post("/api/projects", headers=auth, json={"name": "项目Y"})
        pid = r.json()["id"]

        # 先建一个会话（不绑定）
        r = client.post("/api/conversations", headers=auth, json={"title": "旧会话"})
        cid = r.json()["id"]

        # 再带 conversation_id + project_id 发流，应把会话绑定到项目
        with client.stream("POST", "/api/chat/stream", headers=auth, json={
                "message": "你好", "conversation_id": cid,
                "project_id": pid, "use_rag": False}) as resp:
            self.assertEqual(resp.status_code, 200)
            for line in resp.iter_lines():
                pass

        r = client.get("/api/conversations", headers=auth, params={"pageSize": 50})
        conv = [c for c in r.json()["items"] if c["id"] == cid][0]
        self.assertEqual(conv["projectId"], pid)


if __name__ == "__main__":
    unittest.main()
