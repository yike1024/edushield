package builtin

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServiceProbeReadsSSHBanner(t *testing.T) {
	host, port := startGreetingListener(t, "SSH-2.0-OpenSSH_9.9\r\n")
	args, _ := json.Marshal(map[string]any{"host": host, "port": port, "timeout_ms": 2000})
	out, err := serviceProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "SSH-2.0-OpenSSH_9.9") {
		t.Fatalf("output missing banner:\n%s", out)
	}
	if !strings.Contains(out, "likely service: SSH") {
		t.Fatalf("output missing SSH guess:\n%s", out)
	}
}

// startEchoAfterReadListener answers only after the client sends a line.
func startEchoAfterReadListener(t *testing.T, reply string) (host string, port int) {
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
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 256)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write([]byte(reply))
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func TestServiceProbeSendsProbeLineToSilentService(t *testing.T) {
	host, port := startEchoAfterReadListener(t, "HTTP/1.0 200 OK\r\nServer: test\r\n\r\n")
	args, _ := json.Marshal(map[string]any{
		"host": host, "port": port,
		"probe": "HEAD / HTTP/1.0", "timeout_ms": 2000,
	})
	out, err := serviceProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "HTTP/1.0 200 OK") {
		t.Fatalf("output missing probe response:\n%s", out)
	}
	if !strings.Contains(out, "likely service: HTTP") {
		t.Fatalf("output missing HTTP guess:\n%s", out)
	}
}

func TestServiceProbeSilentServiceWithoutProbeReportsHint(t *testing.T) {
	host, port := startEchoAfterReadListener(t, "unused")
	args, _ := json.Marshal(map[string]any{"host": host, "port": port, "timeout_ms": 1000})
	out, err := serviceProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "no unprompted banner") {
		t.Fatalf("output missing silence hint:\n%s", out)
	}
}

func TestServiceProbeValidatesArgs(t *testing.T) {
	if _, err := (serviceProbe{}).Execute(context.Background(), json.RawMessage(`{"host":"x"}`)); err == nil {
		t.Fatal("expected error for missing port")
	}
	if _, err := (serviceProbe{}).Execute(context.Background(), json.RawMessage(`{"host":"","port":80}`)); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{
		0x0301: "TLS 1.0 (weak)",
		0x0303: "TLS 1.2",
		0x0304: "TLS 1.3",
	}
	for v, want := range cases {
		if got := tlsVersionName(v); got != want {
			t.Fatalf("tlsVersionName(0x%04x) = %q, want %q", v, got, want)
		}
	}
	if got := tlsVersionName(0x9999); !strings.HasPrefix(got, "0x") {
		t.Fatalf("unknown version = %q", got)
	}
}

func TestServiceProbeConnectError(t *testing.T) {
	// A listener closed immediately yields connection refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	args, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "port": port, "timeout_ms": 1000})
	if _, err := (serviceProbe{}).Execute(context.Background(), args); err == nil {
		t.Fatal("expected connect error for closed port")
	}
}
