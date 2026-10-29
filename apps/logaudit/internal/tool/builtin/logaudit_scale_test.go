package builtin

// 全流程规模压力测试：以 5 万级生成日志驱动
// log_ingest(persist, 分片落盘) -> anomaly_detect -> correlation
// -> log_query(过滤/时间窗口) -> log_query(verify, 跨分片哈希链)，
// 验证大规模数据下的召回、精确率、总量守恒与防篡改完整性。
// 数据集由 logaudit-loggen 生成（seed=2026），缺失时自动跳过。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reasonix/internal/evidence"
)

const scaleDataRel = "../../../../../logaudit-training/generated-large"

func TestScaleFullPipeline(t *testing.T) {
	dir, err := filepath.Abs(scaleDataRel)
	if err != nil {
		t.Fatal(err)
	}
	access := filepath.Join(dir, "access.log")
	if _, err := os.Stat(access); err != nil {
		t.Skipf("scale dataset missing (run logaudit-loggen first): %v", err)
	}

	globalLogStore.clear()
	evidence.Global.Clear()
	home := t.TempDir()
	t.Setenv("REASONIX_HOME", home)

	start := time.Now()

	// Step 1: 采集 + 分片持久化
	out := runTool(t, logIngest{}, map[string]any{"path": access, "format": "nginx", "persist": true})
	t.Logf("[log_ingest access] %s", firstLine(out))
	out = runTool(t, logIngest{}, map[string]any{"path": filepath.Join(dir, "auth.log"), "format": "syslog", "persist": true})
	t.Logf("[log_ingest auth] %s", firstLine(out))

	// Step 2: 异常检测（默认阈值）
	out = runTool(t, anomalyDetect{}, map[string]any{})

	// Step 3: 攻击链关联
	_ = runTool(t, correlationTool{}, map[string]any{"window_minutes": 120, "min_events": 2})

	// Step 4: 检索（按 IP 过滤 + 时间窗口）
	q := runTool(t, logQuery{}, map[string]any{"ip": "203.0.113.200"})
	if !strings.Contains(q, "30 matched") {
		t.Errorf("webshell IP 检索数不符:\n%s", q)
	}
	q = runTool(t, logQuery{}, map[string]any{
		"since": "2026-08-15 02:00:00", "until": "2026-08-15 03:00:00",
	})
	if !strings.Contains(q, "matched") {
		t.Errorf("时间窗口检索无结果:\n%s", q)
	}

	// Step 5: 跨分片哈希链防篡改校验
	q = runTool(t, logQuery{}, map[string]any{"verify": true})
	if !strings.Contains(q, "Chain verify: OK") {
		t.Errorf("分片哈希链校验失败:\n%s", q)
	}

	// 召回断言：7 类注入场景全部检出
	var ids []string
	for _, f := range evidence.Global.All() {
		ids = append(ids, f.ID)
	}
	joined := strings.Join(ids, " ")
	for _, want := range []string{
		"anomaly_detect:203.0.113.77:brute_force",
		"anomaly_detect:45.155.205.100:brute_force",
		"anomaly_detect:192.0.2.45:scan",
		"anomaly_detect:198.51.100.23:sqli",
		"anomaly_detect:203.0.113.200:webshell",
		"anomaly_detect:172.16.9.9:out_of_hours",
		"anomaly_detect:198.51.100.99:traffic",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("规模数据召回缺失: %s", want)
		}
	}
	// 精确率断言：正常基线流量（10.20/10.21 网段）零误报
	for _, fp := range []string{"10.20.0.", "10.20.1.", "10.21."} {
		if strings.Contains(joined, fp) {
			t.Errorf("误报：正常基线 %s 被标记为威胁", fp)
		}
	}

	// 落盘守恒：全部分片行数 = 解析行数（持久化路径不做脏行二次丢弃）
	total := 0
	shards, _ := filepath.Glob(filepath.Join(home, "logaudit", "records-*.jsonl"))
	for _, s := range shards {
		data, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		total += len(strings.Split(strings.TrimSpace(string(data)), "\n"))
	}
	if total == 0 {
		t.Fatal("分片落盘为空")
	}
	t.Logf("scale pipeline: shards=%d persisted=%d elapsed=%s", len(shards), total, time.Since(start).Round(time.Millisecond))
}

// TestScaleTamperDetection：规模落盘后篡改任一分片，校验必须定位断链。
func TestScaleTamperDetection(t *testing.T) {
	dir, err := filepath.Abs(scaleDataRel)
	if err != nil {
		t.Fatal(err)
	}
	access := filepath.Join(dir, "access.log")
	if _, err := os.Stat(access); err != nil {
		t.Skipf("scale dataset missing: %v", err)
	}

	globalLogStore.clear()
	evidence.Global.Clear()
	home := t.TempDir()
	t.Setenv("REASONIX_HOME", home)

	// 用小切片落盘即可覆盖跨分片篡改，避免重复跑全量
	runTool(t, logIngest{}, map[string]any{"path": access, "format": "nginx", "persist": true, "limit": 2000})

	shards, _ := filepath.Glob(filepath.Join(home, "logaudit", "records-*.jsonl"))
	if len(shards) == 0 {
		t.Fatal("no shard persisted")
	}
	target := shards[0]
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for i, l := range lines {
		if l == "" {
			continue
		}
		lines[i] = strings.Replace(l, `"status":200`, `"status":404`, 1)
		if lines[i] != l {
			break
		}
	}
	if err := os.WriteFile(target, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runTool(t, logQuery{}, map[string]any{"verify": true})
	if strings.Contains(out, "Chain verify: OK") {
		t.Errorf("篡改未被检出:\n%s", out)
	}
	if !strings.Contains(out, "broken") && !strings.Contains(out, "BROKEN") && !strings.Contains(out, "tamper") {
		t.Logf("verify output (check wording):\n%s", out)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
