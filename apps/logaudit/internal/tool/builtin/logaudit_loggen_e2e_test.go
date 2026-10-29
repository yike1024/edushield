package builtin

// 日志生成器驱动的已知答案测试（方案3）：
// 以确定性种子生成"正常基线 + 攻击注入 + 脏行 + 误报诱饵"日志，
// 驱动 log_ingest -> anomaly_detect 全链路，验证召回率、精确率与解析健壮性。
// 任一失败即为规则引擎或解析器缺陷的直接证据。

import (
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"reasonix/internal/evidence"
)

func loggenWriteFile(t *testing.T, dir, name string, lines []string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoggenRecallPrecision：全部注入场景必须检出，正常流量零误报。
func TestLoggenRecallPrecision(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()
	dir := t.TempDir()
	rnd := rand.New(rand.NewSource(42))
	start := time.Date(2026, 8, 15, 9, 0, 0, 0, time.FixedZone("CST", 8*3600))

	var accessLines, syslogLines []string
	injected := map[string]LoggenScenario{}
	for _, sc := range LoggenScenarios() {
		switch sc.Name {
		case "normal":
			accessLines = append(accessLines, sc.Gen(rnd, start, 200)...)
		case "bruteforce_ssh":
			syslogLines = append(syslogLines, sc.Gen(rnd, start, 12)...)
			injected[sc.Name] = sc
		case "bruteforce_nginx":
			accessLines = append(accessLines, sc.Gen(rnd, start, 8)...)
			injected[sc.Name] = sc
		case "scan":
			accessLines = append(accessLines, sc.Gen(rnd, start, 25)...)
			injected[sc.Name] = sc
		case "sqli":
			accessLines = append(accessLines, sc.Gen(rnd, start, 3)...)
			injected[sc.Name] = sc
		case "webshell":
			accessLines = append(accessLines, sc.Gen(rnd, start, 4)...)
			injected[sc.Name] = sc
		case "out_of_hours":
			accessLines = append(accessLines, sc.Gen(rnd, start, 12)...)
			injected[sc.Name] = sc
		case "high_traffic":
			accessLines = append(accessLines, sc.Gen(rnd, start, 0)...)
			injected[sc.Name] = sc
		}
	}
	access := loggenWriteFile(t, dir, "access.log", accessLines)
	auth := loggenWriteFile(t, dir, "auth.log", syslogLines)

	runTool(t, logIngest{}, map[string]any{"path": access, "format": "nginx"})
	runTool(t, logIngest{}, map[string]any{"path": auth, "format": "syslog"})
	runTool(t, anomalyDetect{}, map[string]any{})

	var ids []string
	for _, f := range evidence.Global.All() {
		ids = append(ids, f.ID)
	}
	joined := strings.Join(ids, " ")

	for name, sc := range injected {
		if !strings.Contains(joined, sc.ExpectedFinding) {
			t.Errorf("召回缺失 [%s]: 期望 Finding 含 %q\n全部 IDs:\n%s", name, sc.ExpectedFinding, joined)
		}
	}
	for _, fp := range []string{"10.20.0.", "10.20.1."} {
		if strings.Contains(joined, fp) {
			t.Errorf("误报：正常基线流量 %s 被标记为威胁", fp)
		}
	}
}

// TestLoggenFPProbes：误报诱饵行不得产生任何 Finding（探测正则过宽缺陷）。
func TestLoggenFPProbes(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()
	dir := t.TempDir()

	var lines []string
	for _, p := range LoggenFPProbes() {
		lines = append(lines, p.Line)
	}
	f := loggenWriteFile(t, dir, "fp_probes.log", lines)
	runTool(t, logIngest{}, map[string]any{"path": f, "format": "nginx"})
	runTool(t, anomalyDetect{}, map[string]any{"attack_threshold": 1, "scan_threshold": 1, "brute_force_threshold": 1})

	for _, f := range evidence.Global.All() {
		if f.Tool == "log_ingest" {
			continue
		}
		t.Errorf("误报缺陷：诱饵流量产生 Finding [%s] %s | Target=%s", f.Severity, f.Title, f.Target)
	}
}

// TestLoggenDirtyLineRobustness：脏行必须计入 Skipped，且总量守恒（解析+跳过=行数）。
func TestLoggenDirtyLineRobustness(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()
	dir := t.TempDir()
	rnd := rand.New(rand.NewSource(7))
	start := time.Date(2026, 8, 15, 9, 0, 0, 0, time.FixedZone("CST", 8*3600))

	normal := LoggenScenarios()[0].Gen(rnd, start, 60)
	dirty := LoggenDirtyLines()
	mixed := LoggenRender(normal, dirty, 10) // 每 10 行正常行插入 1 行脏行
	f := loggenWriteFile(t, dir, "dirty.log", mixed)

	out := runTool(t, logIngest{}, map[string]any{"path": f, "format": "nginx"})
	t.Logf("[log_ingest dirty]\n%s", out)

	// 无 IP 前缀且无可解析时间戳的行（空行/乱码）必须跳过；
	// 携带 IP 前缀的降级行（截断/坏时间戳/缺状态码/未闭合引号）允许按 generic 解析。
	dirtySkipped := 0
	for _, d := range dirty {
		switch d.Kind {
		case "empty", "garbage":
			dirtySkipped++
		}
	}
	if !strings.Contains(out, "Skipped: "+strconv.Itoa(dirtySkipped)) {
		t.Errorf("无效行跳过数不符：期望 Skipped=%d\n%s", dirtySkipped, out)
	}
	parsed := 60 + (len(dirty) - dirtySkipped)
	if !strings.Contains(out, "Parsed: "+strconv.Itoa(parsed)) {
		t.Errorf("解析数不符：期望 Parsed=%d\n%s", parsed, out)
	}
	// 总量守恒：解析 + 跳过 = 写入行数（空行位于文件中部，独立占一行）
	if parsed+dirtySkipped != len(mixed) {
		t.Errorf("总量不守恒：Parsed(%d)+Skipped(%d) != lines(%d)", parsed, dirtySkipped, len(mixed))
	}
}

// TestEncodedSQLiRecall：D4 修复回归——URL 编码的 SQLi payload（%20 分隔）
// 必须经百分号解码后被检出，同时解码不得引入新的误报。
func TestEncodedSQLiRecall(t *testing.T) {
	atk := LogRecord{SourceIP: "198.51.100.23", Request: "GET /q?id=1%20UNION%20SELECT%20user() HTTP/1.1", Path: "/q?id=1%20UNION%20SELECT%20user()"}
	if !isSQLiRecord(atk) {
		t.Error("URL 编码 UNION%20SELECT 未被检出（解码匹配失效）")
	}
	fp := LogRecord{SourceIP: "10.20.0.73", Request: "GET /search?q=it%27s%20fine HTTP/1.1", Path: "/search?q=it%27s%20fine"}
	if isSQLiRecord(fp) {
		t.Error("解码匹配引入误报：普通检索词被判为 SQLi")
	}
}
