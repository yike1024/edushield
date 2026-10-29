package builtin

// 日志审计模块端到端训练验证：以真实训练日志驱动
// log_ingest -> anomaly_detect -> correlation 全链路，
// 不依赖 LLM，直接验证部件检测能力（身体部件 B 交付前自检）。

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"reasonix/internal/evidence"
)

const trainingDirRel = "../../../../../logaudit-training"

func TestLogAuditTrainingE2E(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()

	dir, err := filepath.Abs(trainingDirRel)
	if err != nil {
		t.Fatal(err)
	}

	// Step 1: log_ingest 三个日志源
	sources := []struct {
		file   string
		format string
	}{
		{"access_normal.log", "nginx"},
		{"access_attack.log", "nginx"},
		{"auth.log", "syslog"},
	}
	for _, s := range sources {
		out := runTool(t, logIngest{}, map[string]any{
			"path":   filepath.Join(dir, s.file),
			"format": s.format,
		})
		t.Logf("[log_ingest %s]\n%s", s.file, out)
	}

	// Step 2: anomaly_detect 全项检测（默认阈值）
	out := runTool(t, anomalyDetect{}, map[string]any{})
	t.Logf("[anomaly_detect]\n%s", out)

	// Step 3: correlation 时间线关联
	out = runTool(t, correlationTool{}, map[string]any{
		"window_minutes": 120,
		"min_events":     2,
	})
	t.Logf("[correlation]\n%s", out)

	// Step 4: 汇总结构化 Finding（即上报大脑的证据）
	all := evidence.Global.All()
	t.Logf("[findings] total=%d", len(all))
	for _, f := range all {
		b, _ := json.MarshalIndent(f, "", "  ")
		t.Logf("Finding:\n%s", string(b))
	}

	// 验收断言：预期检出
	var joined []string
	for _, f := range all {
		joined = append(joined, f.ID)
	}
	ids := strings.Join(joined, " ")
	expect := []struct {
		substr string
		desc   string
	}{
		{"anomaly_detect:203.0.113.77:brute_force", "管理后台暴力破解"},
		{"anomaly_detect:198.51.100.23:sqli", "SQL 注入"},
		{"anomaly_detect:198.51.100.23:webshell", "Webshell 访问"},
		{"anomaly_detect:192.0.2.45:scan", "目录扫描"},
		{"anomaly_detect:45.155.205.100:brute_force", "SSH 暴力破解"},
		{"anomaly_detect:172.16.9.9:out_of_hours", "凌晨异常时段批量导出"},
		{"correlation:203.0.113.77:credential_stuffing_success", "爆破成功攻击链"},
	}
	for _, e := range expect {
		if !strings.Contains(ids, e.substr) {
			t.Errorf("缺少预期检出 [%s]: %s\n全部 Finding IDs:\n%s", e.desc, e.substr, ids)
		}
	}

	// 误报抑制断言：爬虫与正常校园流量不得产出 Finding
	for _, fpIP := range []string{"66.249.66.1", "114.114.8.9", "10.20.0.", "10.20.1."} {
		if strings.Contains(ids, fpIP) {
			t.Errorf("误报：正常流量/爬虫 %s 被标记为威胁", fpIP)
		}
	}

	fmt.Printf("TRAINING E2E PASS: %d findings, %d expected checks\n", len(all), len(expect))
}
