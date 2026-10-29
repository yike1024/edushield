package builtin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(serviceProbe{}) }

// serviceProbe grabs a service banner on an authorized host:port, optionally
// exchanging a probe line, and can complete a TLS handshake to fingerprint the
// certificate. Service identification is heuristic prefix matching on the
// greeting.
type serviceProbe struct{}

func (serviceProbe) Name() string { return "service_probe" }

func (serviceProbe) Description() string {
	return "Fingerprint a service on an authorized host:port: read the greeting banner (optionally after sending a probe line such as \"HEAD / HTTP/1.0\"), or complete a TLS handshake and report certificate subject/issuer/expiry. Offensive action - only target hosts the user authorized."
}

func (serviceProbe) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"host":{"type":"string","description":"Target host (IP or hostname) authorized for this engagement"},"port":{"type":"integer","description":"Target TCP port"},"probe":{"type":"string","description":"Optional line to send before reading the banner, e.g. \"HEAD / HTTP/1.0\""},"tls":{"type":"boolean","description":"When true, perform a TLS handshake and report certificate details (default false)"},"timeout_ms":{"type":"integer","description":"Connect/read timeout in ms (default 3000)"}},"required":["host","port"]}`)
}

func (serviceProbe) ReadOnly() bool { return false }

// SnipHint: banners are short; keep the whole result.
func (serviceProbe) SnipHint() tool.SnipHint {
	return tool.SnipHint{Head: 60, Tail: 10, HeadChars: 8000, TailChars: 1000}
}

// serviceGuesses maps banner prefixes to likely services.
var serviceGuesses = []struct{ prefix, name string }{
	{"SSH-", "SSH"},
	{"220 ", "FTP/SMTP banner"},
	{"+OK", "POP3"},
	{"* OK", "IMAP"},
	{"HTTP/", "HTTP"},
	{"5.7.0", "MySQL auth error"},
	{"mysql_native_password", "MySQL"},
	{"-ERR unknown command", "Redis"},
	{"{\"error\"", "Elasticsearch/Memcached JSON"},
	{"KDC_ERR", "Kerberos"},
}

func (serviceProbe) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Host      string `json:"host"`
		Port      int    `json:"port"`
		Probe     string `json:"probe"`
		TLS       bool   `json:"tls"`
		TimeoutMs int    `json:"timeout_ms"`
	}{TimeoutMs: 3000}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if strings.TrimSpace(p.Host) == "" || p.Port < 1 || p.Port > 65535 {
		return "", fmt.Errorf("host and a valid port (1-65535) are required")
	}
	if p.TimeoutMs < 100 || p.TimeoutMs > 30000 {
		p.TimeoutMs = 3000
	}
	timeout := time.Duration(p.TimeoutMs) * time.Millisecond
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))

	if p.TLS {
		return probeTLS(addr, p.Probe, timeout)
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	banner := grabBanner(conn, timeout)
	if banner == "" && strings.TrimSpace(p.Probe) != "" {
		// grabBanner may have consumed the whole deadline waiting on a silent
		// service; refresh it before writing the probe.
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write([]byte(strings.TrimSpace(p.Probe) + "\r\n")); err != nil {
			return "", fmt.Errorf("write probe to %s: %w", addr, err)
		}
		banner = grabBanner(conn, timeout)
	} else if banner == "" {
		// Services like HTTP wait for the client first: send the probe if we
		// have one, otherwise note the silence.
		if strings.TrimSpace(p.Probe) == "" {
			return fmt.Sprintf("%s: connection opened, no unprompted banner (service waits for client input; retry with a probe line)\n", addr), nil
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "probe of %s\n", addr)
	if banner == "" {
		b.WriteString("banner: (none)\n")
	} else {
		fmt.Fprintf(&b, "banner: %s\n", banner)
		for _, g := range serviceGuesses {
			if strings.HasPrefix(banner, g.prefix) {
				fmt.Fprintf(&b, "likely service: %s\n", g.name)
				break
			}
		}
	}
	return b.String(), nil
}

// probeTLS completes a TLS handshake and reports certificate metadata. A probe
// line, when given, is sent after the handshake to read an over-TLS banner.
func probeTLS(addr, probe string, timeout time.Duration) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // fingerprinting self-signed/internal targets is the point
	})
	if err != nil {
		return "", fmt.Errorf("tls handshake %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var b strings.Builder
	state := conn.ConnectionState()
	fmt.Fprintf(&b, "TLS probe of %s: handshake ok, version %s\n", addr, tlsVersionName(state.Version))
	for i, cert := range state.PeerCertificates {
		if i > 0 {
			break // only the leaf cert keeps output tight
		}
		fmt.Fprintf(&b, "subject: %s\n", cert.Subject.String())
		fmt.Fprintf(&b, "issuer: %s\n", cert.Issuer.String())
		fmt.Fprintf(&b, "valid: %s -> %s\n", cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
		if len(cert.DNSNames) > 0 {
			names := cert.DNSNames
			if len(names) > 5 {
				names = names[:5]
			}
			fmt.Fprintf(&b, "SAN: %s\n", strings.Join(names, ", "))
		}
		if !cert.NotAfter.After(time.Now()) {
			b.WriteString("warning: certificate is EXPIRED\n")
		}
	}
	if strings.TrimSpace(probe) != "" {
		if _, err := conn.Write([]byte(strings.TrimSpace(probe) + "\r\n")); err == nil {
			if banner := grabBanner(conn, timeout); banner != "" {
				fmt.Fprintf(&b, "banner: %s\n", banner)
			}
		}
	}
	return b.String(), nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0 (weak)"
	case tls.VersionTLS11:
		return "TLS 1.1 (weak)"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionSSL30:
		return "SSL 3.0 (insecure)"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
