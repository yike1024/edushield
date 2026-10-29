package builtin

// 流量包自检：以 AntSword2.pcap 还原的合成 nginx 访问日志驱动
// log_ingest(persist) -> anomaly_detect -> correlation -> log_query verify，
// 验证模块对 webshell 通信（JSP）与目录扫描的检测能力。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reasonix/internal/evidence"
)

const syntheticPcapLog = `d:\004-pocket\trea-1\.tools\pcap_synthetic_access.log`

func TestPcapSelfCheckWebshellAndScan(t *testing.T) {
	if _, err := os.Stat(syntheticPcapLog); err != nil {
		t.Skipf("synthetic log missing: %v", err)
	}
	globalLogStore.clear()
	evidence.Global.Clear()
	home := t.TempDir()
	t.Setenv("REASONIX_HOME", home)

	out := runTool(t, logIngest{}, map[string]any{"path": syntheticPcapLog, "format": "nginx", "persist": true})
	if !strings.Contains(out, "Parsed: 31") {
		t.Fatalf("expected 31 parsed records:\n%s", out)
	}

	out = runTool(t, anomalyDetect{}, map[string]any{"scan_threshold": 10})
	if !strings.Contains(out, "Potential webshell access from 203.0.113.200") {
		t.Errorf("webshell (JSP POST /shell/yesec.jsp) not detected:\n%s", out)
	}
	if !strings.Contains(out, "Reconnaissance / scanning activity from 198.51.100.88") {
		t.Errorf("directory scanning not detected:\n%s", out)
	}
	// 正常基线流量不得误报
	if strings.Contains(out, "10.20.0.50") || strings.Contains(out, "10.20.0.51") {
		t.Errorf("false positive on normal traffic:\n%s", out)
	}

	out = runTool(t, correlationTool{}, map[string]any{"window_minutes": 120, "min_events": 2})
	t.Logf("[correlation]\n%s", out)

	out = runTool(t, logQuery{}, map[string]any{"ip": "203.0.113.200"})
	if !strings.Contains(out, "16 matched / 31 stored") {
		t.Errorf("expected 16 webshell records queryable:\n%s", out)
	}

	out = runTool(t, logQuery{}, map[string]any{"verify": true})
	if !strings.Contains(out, "Chain verify: OK") {
		t.Errorf("hash chain verify failed:\n%s", out)
	}

	// 落盘分片存在性 + 总行数与解析数一致（31 条，按日期分布）
	n := 0
	matches, err := filepath.Glob(filepath.Join(home, "logaudit", "records-*.jsonl"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("shards missing: %v", err)
	}
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			t.Fatalf("shard read: %v", err)
		}
		n += len(strings.Split(strings.TrimSpace(string(data)), "\n"))
	}
	if n != 31 {
		t.Errorf("expected 31 persisted lines across shards, got %d", n)
	}
}
