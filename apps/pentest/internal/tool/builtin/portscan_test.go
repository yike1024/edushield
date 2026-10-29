package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// startGreetingListener accepts one connection and immediately writes a banner.
func startGreetingListener(t *testing.T, greeting string) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if greeting != "" {
				_, _ = conn.Write([]byte(greeting))
			}
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			conn.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func TestParsePortSpec(t *testing.T) {
	ports, err := parsePortSpec("80,443,8000-8002,80")
	if err != nil {
		t.Fatalf("parsePortSpec: %v", err)
	}
	want := []int{80, 443, 8000, 8001, 8002}
	if len(ports) != len(want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports = %v, want %v", ports, want)
		}
	}
	for _, bad := range []string{"abc", "80-", "-80", "0", "70000"} {
		if _, err := parsePortSpec(bad); err == nil {
			t.Fatalf("parsePortSpec(%q) accepted invalid input", bad)
		}
	}
}

func TestPortScanFindsOpenPortWithBanner(t *testing.T) {
	host, port := startGreetingListener(t, "SSH-2.0-TestServer\r\n")
	args, _ := json.Marshal(map[string]any{
		"host":       host,
		"ports":      fmt.Sprintf("%d,%d", port, port+1),
		"banner":     true,
		"timeout_ms": 2000,
	})
	out, err := portScan{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, fmt.Sprintf("%d open", port)) {
		t.Fatalf("output missing open port %d:\n%s", port, out)
	}
	if !strings.Contains(out, "SSH-2.0-TestServer") {
		t.Fatalf("output missing banner:\n%s", out)
	}
	if !strings.Contains(out, "2 ports probed, 1 open") {
		t.Fatalf("output missing summary:\n%s", out)
	}
}

func TestPortScanRejectsUnknownPreset(t *testing.T) {
	args, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "preset": "nope"})
	if _, err := (portScan{}).Execute(context.Background(), args); err == nil {
		t.Fatal("expected error for unknown preset")
	}
}

func TestPortScanRequiresHost(t *testing.T) {
	if _, err := (portScan{}).Execute(context.Background(), json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner([]byte("220 FTP\x00ready\r\nIGNORED"))
	if got != "220 FTP.ready" {
		t.Fatalf("sanitizeBanner = %q", got)
	}
	long := strings.Repeat("A", 300)
	if got := sanitizeBanner([]byte(long)); len(got) != 120 {
		t.Fatalf("long banner length = %d, want 120", len(got))
	}
}
