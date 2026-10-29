package builtin

// 日志持久化与检索测试：log_ingest persist=true 落盘后，
// log_query 按 IP / 状态码 / 关键字 / 时间窗口过滤命中。
// 使用隔离的 REASONIX_HOME，不影响回归基线与其他测试。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reasonix/internal/evidence"
)

// readAllShards concatenates the content of every records-*.jsonl shard.
func readAllShards(t *testing.T, home string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(home, "logaudit", "records-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
	}
	return sb.String()
}

func TestLogIngestPersistAndQuery(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()

	home := t.TempDir()
	t.Setenv("REASONIX_HOME", home)

	logPath := filepath.Join(t.TempDir(), "access.log")
	content := `1.2.3.4 - - [15/Aug/2026:10:00:00 +0800] "GET /admin/login HTTP/1.1" 401 123 "-" "curl/8.0"
1.2.3.4 - - [15/Aug/2026:10:00:01 +0800] "GET /admin/login HTTP/1.1" 200 456 "-" "Mozilla/5.0"
5.6.7.8 - - [15/Aug/2026:11:00:00 +0800] "GET /index.html HTTP/1.1" 200 789 "-" "Mozilla/5.0"
`
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runTool(t, logIngest{}, map[string]any{"path": logPath, "persist": true})
	if !strings.Contains(out, "Persist: 3 records appended") {
		t.Fatalf("expected persist confirmation:\n%s", out)
	}
	// 分片存储：同日记录进 records-2026-08-15.jsonl
	store := filepath.Join(home, "logaudit", "records-2026-08-15.jsonl")
	if _, err := os.Stat(store); err != nil {
		t.Fatalf("shard file missing: %v", err)
	}

	// 按 IP 精确过滤
	out = runTool(t, logQuery{}, map[string]any{"ip": "1.2.3.4"})
	if !strings.Contains(out, "2 matched / 3 stored") {
		t.Errorf("expected 2 matches for ip filter:\n%s", out)
	}

	// 按状态码过滤
	out = runTool(t, logQuery{}, map[string]any{"status": 401})
	if !strings.Contains(out, "1 matched / 3 stored") {
		t.Errorf("expected 1 match for status filter:\n%s", out)
	}

	// 关键字大小写不敏感
	out = runTool(t, logQuery{}, map[string]any{"keyword": "ADMIN"})
	if !strings.Contains(out, "2 matched / 3 stored") {
		t.Errorf("expected 2 matches for keyword filter:\n%s", out)
	}

	// 时间窗口过滤：日志时间戳带 +0800，11:00+08:00=03:00 UTC，
	// since 取 02:30 UTC 只保留 11 点那条；与存储时间同单位比较。
	out = runTool(t, logQuery{}, map[string]any{"since": "2026-08-15 02:30:00"})
	if !strings.Contains(out, "1 matched / 3 stored") {
		t.Errorf("expected 1 match for since filter:\n%s", out)
	}

	// 组合过滤无命中
	out = runTool(t, logQuery{}, map[string]any{"ip": "1.2.3.4", "status": 200, "keyword": "nonexistent"})
	if !strings.Contains(out, "No records matched") {
		t.Errorf("expected zero matches:\n%s", out)
	}
}

func TestLogQueryEmptyStore(t *testing.T) {
	t.Setenv("REASONIX_HOME", t.TempDir())

	out := runTool(t, logQuery{}, map[string]any{})
	if !strings.Contains(out, "Log store is empty") {
		t.Fatalf("expected empty-store hint:\n%s", out)
	}
}

func TestLogPersistRetentionAndChainVerify(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()

	home := t.TempDir()
	t.Setenv("REASONIX_HOME", home)
	oldShard := filepath.Join(home, "logaudit", "records-2026-07-19.jsonl")
	newShard := filepath.Join(home, "logaudit", "records-2026-08-28.jsonl")

	// 第一批：40 天前的旧日志（超出后续 30 天留存窗口）
	oldLog := filepath.Join(t.TempDir(), "old.log")
	oldContent := `9.9.9.9 - - [19/Jul/2026:10:00:00 +0800] "GET /old HTTP/1.1" 200 100 "-" "Mozilla/5.0"
`
	if err := os.WriteFile(oldLog, []byte(oldContent), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runTool(t, logIngest{}, map[string]any{"path": oldLog, "persist": true, "persist_retention_days": 0})
	if !strings.Contains(out, "1 records appended") {
		t.Fatalf("expected old record persisted:\n%s", out)
	}

	// 第二批：新日志，留存 30 天 → 旧记录应被清除（当前日期 2026-08-28，40 天前超期）
	newLog := filepath.Join(t.TempDir(), "new.log")
	newContent := `8.8.8.8 - - [28/Aug/2026:09:00:00 +0800] "GET /new HTTP/1.1" 200 100 "-" "Mozilla/5.0"
`
	if err := os.WriteFile(newLog, []byte(newContent), 0o644); err != nil {
		t.Fatal(err)
	}
	out = runTool(t, logIngest{}, map[string]any{"path": newLog, "persist": true, "persist_retention_days": 30})
	if !strings.Contains(out, "1 records appended, 1 expired purged") {
		t.Fatalf("expected retention purge:\n%s", out)
	}
	// 超期分片整片删除；新分片保留
	if _, err := os.Stat(oldShard); !os.IsNotExist(err) {
		t.Fatalf("expired shard should be removed: %v", err)
	}
	data, err := os.ReadFile(newShard)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "/old") || !strings.Contains(string(data), "/new") {
		t.Fatalf("store content wrong after retention purge:\n%s", string(data))
	}

	// 哈希链完整 → verify 通过
	out = runTool(t, logQuery{}, map[string]any{"verify": true})
	if !strings.Contains(out, "Chain verify: OK") {
		t.Fatalf("expected chain intact:\n%s", out)
	}

	// 篡改：改动分片文件中记录内容但不重算链哈希 → verify 必须定位断链（含分片名）
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	lines[0] = strings.Replace(lines[0], "8.8.8.8", "6.6.6.6", 1)
	if err := os.WriteFile(newShard, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	out = runTool(t, logQuery{}, map[string]any{"verify": true})
	if !strings.Contains(out, "BROKEN at line 1") || !strings.Contains(out, "records-2026-08-28.jsonl") {
		t.Fatalf("expected tamper detection at line 1 of the shard:\n%s", out)
	}
}

func TestLogChainVerifyEmptyStore(t *testing.T) {
	t.Setenv("REASONIX_HOME", t.TempDir())

	out := runTool(t, logQuery{}, map[string]any{"verify": true})
	if !strings.Contains(out, "nothing to verify") {
		t.Fatalf("expected empty-store verify hint:\n%s", out)
	}
}

// TestLogPersistMaskingSensitiveValues 验证落盘与证据片段对凭据类模式掩码，
// 且哈希链在掩码后的内容上仍然完整。
func TestLogPersistMaskingSensitiveValues(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()

	home := t.TempDir()
	t.Setenv("REASONIX_HOME", home)

	logPath := filepath.Join(t.TempDir(), "sensitive.log")
	content := `7.7.7.7 - - [28/Aug/2026:12:00:00 +0800] "POST /login?password=hunter2secret&user=bob HTTP/1.1" 200 55 "-" "Mozilla/5.0 Authorization: Bearer abc.def.ghi"
7.7.7.7 - - [28/Aug/2026:12:00:05 +0800] "GET /api HTTP/1.1" 200 66 "-" "curl/8.0 Cookie: SESSIONID=deadbeefcafe"
`
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runTool(t, logIngest{}, map[string]any{"path": logPath, "persist": true})
	if !strings.Contains(out, "Persist: 2 records appended") {
		t.Fatalf("expected persist:\n%s", out)
	}

	// 落盘内容不得含明文凭据；叙述性文本不被误掩码（边界直测）
	disk := readAllShards(t, home)
	for _, secret := range []string{"hunter2secret", "abc.def.ghi", "deadbeefcafe"} {
		if strings.Contains(disk, secret) {
			t.Errorf("plaintext secret %q persisted to disk", secret)
		}
	}
	if !strings.Contains(disk, "password=***") {
		t.Errorf("expected masked password in store:\n%s", disk)
	}
	if got := maskSensitiveString("Failed password for root from 1.1.1.1"); got != "Failed password for root from 1.1.1.1" {
		t.Errorf("sshd prose must not be masked, got: %s", got)
	}

	// 会话内记录保持原文（检测保真）
	session := globalLogStore.recordsFor(logPath)
	if len(session) != 2 || !strings.Contains(session[0].Request+session[0].Raw, "hunter2secret") {
		t.Errorf("session records must keep raw content for detection")
	}

	// 掩码后哈希链仍完整（链计算基于掩码后内容）
	out = runTool(t, logQuery{}, map[string]any{"verify": true})
	if !strings.Contains(out, "Chain verify: OK") {
		t.Fatalf("chain must stay intact after masking:\n%s", out)
	}

	// 检索输出同样不得回显凭据
	out = runTool(t, logQuery{}, map[string]any{"keyword": "login"})
	if strings.Contains(out, "hunter2secret") || strings.Contains(out, "abc.def.ghi") {
		t.Errorf("query output leaks secrets:\n%s", out)
	}
}

// TestLogPersistLegacyMigration 验证旧单文件存储迁移到分片后可查可验。
func TestLogPersistLegacyMigration(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()

	home := t.TempDir()
	t.Setenv("REASONIX_HOME", home)

	// 手工构造旧版单文件存储（旧格式为裸记录 JSON 行，无链无信封）
	dir := filepath.Join(home, "logaudit")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "records.jsonl")
	legacyLine := `{"source":"legacy","format":"nginx","timestamp":"2026-08-27T10:00:00+08:00","source_ip":"3.3.3.3","method":"GET","path":"/legacy","status":200}`
	if err := os.WriteFile(legacy, []byte(legacyLine+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	// 新写入触发迁移：旧记录进 2026-08-27 分片，新记录进 2026-08-28 分片
	newLog := filepath.Join(t.TempDir(), "new.log")
	newContent := `4.4.4.4 - - [28/Aug/2026:10:00:00 +0800] "GET /fresh HTTP/1.1" 200 10 "-" "Mozilla/5.0"
`
	if err := os.WriteFile(newLog, []byte(newContent), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runTool(t, logIngest{}, map[string]any{"path": newLog, "persist": true})
	if !strings.Contains(out, "1 records appended") {
		t.Fatalf("expected append:\n%s", out)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy file must be removed after migration")
	}
	if _, err := os.Stat(filepath.Join(dir, "records-2026-08-27.jsonl")); err != nil {
		t.Fatalf("legacy record shard missing: %v", err)
	}

	// 迁移后重链，验证应通过；旧记录仍可检索（无链行已重建为有链）
	out = runTool(t, logQuery{}, map[string]any{"verify": true})
	if !strings.Contains(out, "Chain verify: OK") {
		t.Fatalf("verify after migration failed:\n%s", out)
	}
	out = runTool(t, logQuery{}, map[string]any{"ip": "3.3.3.3"})
	if !strings.Contains(out, "1 matched / 2 stored") {
		t.Errorf("legacy record not queryable after migration:\n%s", out)
	}
}
