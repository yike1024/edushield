package builtin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reasonix/internal/evidence"
)

func TestLogIngestNginxCombined(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()

	path := filepath.Join(t.TempDir(), "access.log")
	content := `1.2.3.4 - - [15/Aug/2026:10:00:00 +0800] "GET /admin/login HTTP/1.1" 401 123 "-" "curl/8.0"
1.2.3.4 - - [15/Aug/2026:10:00:01 +0800] "GET /admin/login HTTP/1.1" 200 456 "-" "Mozilla/5.0"
5.6.7.8 - - [15/Aug/2026:11:00:00 +0800] "GET /index.html HTTP/1.1" 200 789 "-" "Mozilla/5.0"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runTool(t, logIngest{}, map[string]any{"path": path})
	for _, want := range []string{"Parsed: 3", "Unique source IPs: 2", "Session records: 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}

	records := globalLogStore.recordsFor("")
	if len(records) != 3 {
		t.Fatalf("expected 3 stored records, got %d", len(records))
	}
	if records[0].SourceIP != "1.2.3.4" || records[0].Status != 401 || records[0].Path != "/admin/login" {
		t.Errorf("unexpected first record: %+v", records[0])
	}
	if records[0].Timestamp.IsZero() {
		t.Error("timestamp was not parsed")
	}
}

func TestLogIngestJSONLines(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()

	path := filepath.Join(t.TempDir(), "app.log")
	content := `{"timestamp":"2026-08-15T10:00:00+08:00","client_ip":"10.0.0.9","method":"POST","path":"/api/login","status":403,"message":"blocked"}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runTool(t, logIngest{}, map[string]any{"path": path})
	if !strings.Contains(out, "Parsed: 1") {
		t.Fatalf("expected one parsed JSON record:\n%s", out)
	}
	records := globalLogStore.recordsFor("")
	if len(records) != 1 || records[0].SourceIP != "10.0.0.9" || records[0].Status != 403 {
		t.Fatalf("unexpected records: %+v", records)
	}
}

func TestAnomalyDetectBruteForce(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()

	var records []LogRecord
	for i := 0; i < 6; i++ {
		records = append(records, LogRecord{
			Source:   "/var/log/auth.log",
			Format:   "syslog",
			SourceIP: "203.0.113.7",
			Message:  "Failed password for root from 203.0.113.7 port 22 ssh2",
			Raw:      "Aug 15 10:00:00 host sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2",
		})
	}
	globalLogStore.replace("/var/log/auth.log", records)

	out := runTool(t, anomalyDetect{}, map[string]any{"brute_force_threshold": 5})
	if !strings.Contains(out, "Brute-force / credential stuffing from 203.0.113.7") {
		t.Fatalf("expected brute-force finding:\n%s", out)
	}
	if evidence.Global.Query("203.0.113.7", "anomaly_detect", "", 0) == nil {
		t.Fatal("expected anomaly finding in FindingStore")
	}
}

func TestCorrelationCredentialStuffingSuccess(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()

	base := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	records := []LogRecord{
		{Source: "/var/log/nginx/access.log", SourceIP: "198.51.100.20", Timestamp: base, Status: 401, Method: "POST", Request: "/login", Path: "/login", Raw: "401 /login"},
		{Source: "/var/log/nginx/access.log", SourceIP: "198.51.100.20", Timestamp: base.Add(time.Minute), Status: 401, Method: "POST", Request: "/login", Path: "/login", Raw: "401 /login"},
		{Source: "/var/log/nginx/access.log", SourceIP: "198.51.100.20", Timestamp: base.Add(2 * time.Minute), Status: 200, Method: "POST", Request: "/login", Path: "/login", Raw: "200 /login"},
	}
	globalLogStore.replace("/var/log/nginx/access.log", records)

	out := runTool(t, correlationTool{}, map[string]any{"window_minutes": 60, "min_events": 2})
	if !strings.Contains(out, "Credential-stuffing success chain from 198.51.100.20") {
		t.Fatalf("expected credential-stuffing chain:\n%s", out)
	}
	if evidence.Global.Query("198.51.100.20", "correlation", "", 0) == nil {
		t.Fatal("expected correlation finding in FindingStore")
	}
}
