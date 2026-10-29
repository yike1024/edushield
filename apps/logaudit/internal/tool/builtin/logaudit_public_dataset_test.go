package builtin

// 公开数据集验证（方案5）：以 loghub（IEEE ISSRE 2023）OpenSSH 真实
// 暴力破解日志驱动全链路。数据集缺失时跳过（可通过网络重新获取）。
// 来源: https://github.com/logpai/loghub/tree/master/OpenSSH

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reasonix/internal/evidence"
)

const openSSH2kRel = "../../../../../logaudit-training/datasets/OpenSSH_2k.log"

func TestPublicDatasetOpenSSH(t *testing.T) {
	path, err := filepath.Abs(openSSH2kRel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("dataset missing (re-download from loghub): %v", err)
	}
	globalLogStore.clear()
	evidence.Global.Clear()

	out := runTool(t, logIngest{}, map[string]any{"path": path, "format": "syslog"})
	t.Logf("[log_ingest]\n%s", out)
	if !strings.Contains(out, "Skipped: 0") {
		t.Errorf("真实 syslog 数据集出现解析丢弃:\n%s", out)
	}

	out = runTool(t, anomalyDetect{}, map[string]any{})
	t.Logf("[anomaly_detect]\n%s", out)

	// loghub OpenSSH 数据集为真实爆破流量：必须检出暴力破解，
	// 且源 IP 提取（句中 from <IP> / rhost=<IP>）全部生效。
	bruteForce := false
	missingIP := false
	for _, f := range evidence.Global.All() {
		if strings.Contains(f.ID, ":brute_force") {
			bruteForce = true
			if f.Target == "" || !strings.Contains(f.Target, ".") {
				missingIP = true
			}
		}
	}
	if !bruteForce {
		t.Errorf("公开数据集未检出暴力破解:\n%s", out)
	}
	if missingIP {
		t.Error("暴力破解 Finding 缺少有效源 IP（sshd 句中 IP 提取失效）")
	}
}
