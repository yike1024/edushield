package builtin

// 百万级全流程压力测试（环境变量门控，默认跳过）：
// 内存生成约 100 万条日志（正常基线 + 7 类攻击 + 脏行），写盘后驱动
// log_ingest(persist, 分卷采集) -> anomaly_detect -> correlation
// -> log_query(verify)，记录各阶段耗时与堆内存，暴露规模瓶颈。
//
// 运行方式：
//
//	set LOGAUDIT_MILLION=1 && go test ./internal/tool/builtin/ -run TestMillion -v -timeout 30m
//
// 已知约束（本测试即用于暴露其影响）：
//   - log_ingest 单次最多 50 万行，且同源路径重复采集会覆盖旧记录（D5 缺陷，
//     见项目缺陷清单），故大文件只能拆成多个源文件分批采集；
//   - 拆分后同一正常 IP 会命中关联规则"多源活动"造成大量告警噪声（预期行为），
//     故误报断言只针对 anomaly_detect。

import (
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"reasonix/internal/evidence"
)

func TestMillionFullPipeline(t *testing.T) {
	if os.Getenv("LOGAUDIT_MILLION") == "" {
		t.Skip("set LOGAUDIT_MILLION=1 to run the million-record stress test")
	}

	globalLogStore.clear()
	evidence.Global.Clear()
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("REASONIX_HOME", home)

	rnd := rand.New(rand.NewSource(1000000))
	start := time.Date(2026, 8, 15, 9, 0, 0, 0, time.FixedZone("CST", 8*3600))

	// ---- 生成：约 100 万条 ----
	genStart := time.Now()
	var accessLines, syslogLines []string
	for _, sc := range LoggenScenarios() {
		switch sc.Name {
		case "normal":
			accessLines = append(accessLines, sc.Gen(rnd, start, 995000)...)
		case "bruteforce_ssh":
			syslogLines = append(syslogLines, sc.Gen(rnd, start, 50)...)
		case "bruteforce_nginx":
			accessLines = append(accessLines, sc.Gen(rnd, start, 50)...)
		case "scan":
			accessLines = append(accessLines, sc.Gen(rnd, start, 60)...)
		case "sqli":
			accessLines = append(accessLines, sc.Gen(rnd, start, 10)...)
		case "webshell":
			accessLines = append(accessLines, sc.Gen(rnd, start, 20)...)
		case "out_of_hours":
			accessLines = append(accessLines, sc.Gen(rnd, start, 30)...)
		case "high_traffic":
			accessLines = append(accessLines, sc.Gen(rnd, start, 0)...)
		}
	}
	accessLines = LoggenRender(accessLines, LoggenDirtyLines(), 1000)
	t.Logf("generated %d access + %d syslog lines in %s", len(accessLines), len(syslogLines), time.Since(genStart).Round(time.Millisecond))

	// 分卷写盘（每卷 <= 50 万行：同源重复采集会覆盖，不能用单文件分批）
	partSize := 500000
	var parts []string
	for i := 0; i < len(accessLines); i += partSize {
		end := i + partSize
		if end > len(accessLines) {
			end = len(accessLines)
		}
		p := filepath.Join(dir, "access-part-"+string(rune('a'+len(parts)))+".log")
		if err := os.WriteFile(p, []byte(strings.Join(accessLines[i:end], "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, p)
	}
	authPath := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(authPath, []byte(strings.Join(syslogLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("heap before ingest: Alloc=%dMB Sys=%dMB", ms.Alloc/(1<<20), ms.Sys/(1<<20))

	// ---- Step 1: 采集 + 分片持久化（多源分卷，绕开 50 万行/次与同源覆盖限制）----
	ingestStart := time.Now()
	for _, p := range parts {
		out := runTool(t, logIngest{}, map[string]any{"path": p, "format": "nginx", "persist": true, "limit": 500000})
		t.Logf("[log_ingest %s] %s", filepath.Base(p), firstLine(out))
	}
	out := runTool(t, logIngest{}, map[string]any{"path": authPath, "format": "syslog", "persist": true})
	t.Logf("[log_ingest auth] %s", firstLine(out))
	t.Logf("ingest+persist elapsed: %s", time.Since(ingestStart).Round(time.Millisecond))
	runtime.ReadMemStats(&ms)
	t.Logf("heap after ingest: Alloc=%dMB Sys=%dMB", ms.Alloc/(1<<20), ms.Sys/(1<<20))

	// ---- Step 2: 异常检测 ----
	detectStart := time.Now()
	out = runTool(t, anomalyDetect{}, map[string]any{})
	t.Logf("anomaly_detect elapsed: %s", time.Since(detectStart).Round(time.Millisecond))

	// ---- Step 3: 攻击链关联 ----
	corrStart := time.Now()
	_ = runTool(t, correlationTool{}, map[string]any{"window_minutes": 120, "min_events": 2})
	t.Logf("correlation elapsed: %s", time.Since(corrStart).Round(time.Millisecond))

	// ---- Step 4: 检索 ----
	q := runTool(t, logQuery{}, map[string]any{"ip": "203.0.113.200"})
	if !strings.Contains(q, "20 matched") {
		t.Errorf("webshell IP 检索数不符:\n%s", q)
	}

	// ---- Step 5: 跨分片哈希链校验 ----
	verifyStart := time.Now()
	q = runTool(t, logQuery{}, map[string]any{"verify": true})
	t.Logf("verify elapsed: %s", time.Since(verifyStart).Round(time.Millisecond))
	if !strings.Contains(q, "Chain verify: OK") {
		t.Errorf("百万级哈希链校验失败:\n%s", q)
	}

	// ---- 断言：召回 + 精确率 ----
	// 多源分卷下正常 IP 会命中关联"多源活动"（预期行为）；误报断言只针对 anomaly_detect。
	var ids, anomalyIDs, corrIDs []string
	for _, f := range evidence.Global.All() {
		ids = append(ids, f.ID)
		if strings.HasPrefix(f.ID, "anomaly_detect:") {
			anomalyIDs = append(anomalyIDs, f.ID)
		} else {
			corrIDs = append(corrIDs, f.ID)
		}
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
			t.Errorf("百万级召回缺失: %s", want)
		}
	}
	anomalyJoined := strings.Join(anomalyIDs, " ")
	for _, fp := range []string{"10.20.0.", "10.20.1.", "10.21."} {
		if strings.Contains(anomalyJoined, fp) {
			t.Errorf("误报：正常基线 %s 被异常检测标记为威胁", fp)
		}
	}
	t.Logf("findings: anomaly=%d correlation=%d", len(anomalyIDs), len(corrIDs))

	// 落盘体积统计
	totalBytes, totalLines, shardN := int64(0), 0, 0
	shards, _ := filepath.Glob(filepath.Join(home, "logaudit", "records-*.jsonl"))
	for _, s := range shards {
		fi, err := os.Stat(s)
		if err != nil {
			t.Fatal(err)
		}
		totalBytes += fi.Size()
		data, _ := os.ReadFile(s)
		totalLines += len(strings.Split(strings.TrimSpace(string(data)), "\n"))
		shardN++
	}
	t.Logf("MILLION SUMMARY: lines=%d shards=%d store=%dMB persisted=%d",
		len(accessLines)+len(syslogLines), shardN, totalBytes/(1<<20), totalLines)
}
