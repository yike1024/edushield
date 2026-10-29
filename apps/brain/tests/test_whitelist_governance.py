"""P1-2 白名单治理测试：enabled=true 时校园合法域放行、仿冒域拒绝。"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TEST_DIR = tempfile.mkdtemp(prefix="wl-")
os.environ["BRAIN_DB_PATH"] = str(Path(TEST_DIR) / "brain.sqlite3")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist  # noqa: E402

# 模拟服务器配置：enabled=true，含校园合法域，不含仿冒域 xynu-edu.top
Path(TEST_DIR, "whitelist.json").write_text(json.dumps({
    "enabled": True,
    "targets": ["xynu.edu.cn", "cas.xynu.edu.cn", "8.215.92.252"],
}), encoding="utf-8")


class WhitelistGovernanceTest(unittest.TestCase):
    def setUp(self):
        # discover 时 whitelist._path 已被其它测试模块固化，这里显式指向本模块配置
        self.patcher = patch.object(whitelist, "_path", Path(TEST_DIR, "whitelist.json"))
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_enabled(self):
        self.assertTrue(whitelist.get()["enabled"])

    def test_campus_domain_allowed(self):
        self.assertTrue(whitelist.contains("xynu.edu.cn"))
        self.assertTrue(whitelist.contains("cas.xynu.edu.cn"))

    def test_spoof_domain_rejected(self):
        self.assertFalse(whitelist.contains("xynu-edu.top"))


if __name__ == "__main__":
    unittest.main()
