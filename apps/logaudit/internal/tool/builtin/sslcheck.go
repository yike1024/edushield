package builtin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(sslCheck{}) }

type sslCheck struct{}

func (sslCheck) Name() string { return "ssl_check" }

func (sslCheck) Description() string {
	return "Analyze SSL/TLS certificate of a host. Returns certificate chain details, validity period, issuer, subject, SANs, supported TLS versions, cipher suites, and security assessment (expiry warnings, weak ciphers, self-signed detection)."
}

func (sslCheck) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"host":{"type":"string","description":"Target hostname (e.g., example.com or example.com:443)"},
	"timeout_ms":{"type":"integer","description":"Connection timeout in milliseconds (default 5000)"}
},
"required":["host"]
}`)
}

func (sslCheck) ReadOnly() bool { return true }

func (sslCheck) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Host      string `json:"host"`
		TimeoutMs int    `json:"timeout_ms"`
	}{TimeoutMs: 5000}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Host == "" {
		return "", fmt.Errorf("host is required")
	}
	if p.TimeoutMs < 1000 {
		p.TimeoutMs = 1000
	}
	if p.TimeoutMs > 30000 {
		p.TimeoutMs = 30000
	}

	host, port := p.Host, "443"
	if h, p2, err := net.SplitHostPort(p.Host); err == nil {
		host, port = h, p2
	}

	// SSRF guard
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return "", fmt.Errorf("internal IP %s blocked for safety", host)
		}
	} else {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return "", fmt.Errorf("failed to resolve %s: %w", host, err)
		}
		for _, ip := range ips {
			if isPrivateIP(ip.IP) {
				return "", fmt.Errorf("host %s resolves to private IP %s; blocked for safety", host, ip.IP.String())
			}
		}
	}

	timeout := time.Duration(p.TimeoutMs) * time.Millisecond
	dialer := &net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, port)

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var b strings.Builder
	b.WriteString(fmt.Sprintf("SSL/TLS Analysis for %s\n\n", p.Host))

	// TLS version
	tlsVersion := tlsVersionString(state.Version)
	b.WriteString(fmt.Sprintf("TLS Version: %s\n", tlsVersion))
	if state.Version < tls.VersionTLS12 {
		b.WriteString("  ⚠ WARNING: TLS version is outdated and insecure!\n")
	}

	// Cipher suite
	b.WriteString(fmt.Sprintf("Cipher Suite: %s\n", tls.CipherSuiteName(state.CipherSuite)))
	if isWeakCipher(state.CipherSuite) {
		b.WriteString("  ⚠ WARNING: Weak/insecure cipher suite!\n")
	}

	// Negotiated protocol
	b.WriteString(fmt.Sprintf("Negotiated Protocol: %s\n", state.NegotiatedProtocol))

	// Server name
	b.WriteString(fmt.Sprintf("Server Name: %s\n", state.ServerName))

	// Certificate chain
	b.WriteString(fmt.Sprintf("\nCertificate Chain (%d certs):\n\n", len(state.PeerCertificates)))
	for i, cert := range state.PeerCertificates {
		b.WriteString(fmt.Sprintf("--- Certificate %d ---\n", i+1))
		b.WriteString(fmt.Sprintf("Subject: %s\n", cert.Subject.String()))
		b.WriteString(fmt.Sprintf("Issuer:  %s\n", cert.Issuer.String()))
		b.WriteString(fmt.Sprintf("Serial:  %s\n", cert.SerialNumber.String()))
		b.WriteString(fmt.Sprintf("Valid From: %s\n", cert.NotBefore.Format(time.RFC3339)))
		b.WriteString(fmt.Sprintf("Valid Until: %s\n", cert.NotAfter.Format(time.RFC3339)))

		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysLeft < 0 {
			b.WriteString(fmt.Sprintf("  🔴 EXPIRED (%d days ago)\n", -daysLeft))
		} else if daysLeft < 30 {
			b.WriteString(fmt.Sprintf("  🟡 Expires in %d days\n", daysLeft))
		} else {
			b.WriteString(fmt.Sprintf("  🟢 Valid for %d more days\n", daysLeft))
		}

		b.WriteString(fmt.Sprintf("Version: %d\n", cert.Version))
		b.WriteString(fmt.Sprintf("Sig Alg: %s\n", cert.SignatureAlgorithm.String()))
		b.WriteString(fmt.Sprintf("Public Key: %s (%d bits)\n", cert.PublicKeyAlgorithm.String(), publicKeyBits(cert)))
		b.WriteString(fmt.Sprintf("Is CA: %v\n", cert.IsCA))

		if len(cert.DNSNames) > 0 {
			b.WriteString(fmt.Sprintf("SANs (DNS): %s\n", strings.Join(cert.DNSNames, ", ")))
		}
		if len(cert.IPAddresses) > 0 {
			ips := make([]string, len(cert.IPAddresses))
			for j, ip := range cert.IPAddresses {
				ips[j] = ip.String()
			}
			b.WriteString(fmt.Sprintf("SANs (IP): %s\n", strings.Join(ips, ", ")))
		}
		b.WriteString("\n")
	}

	// Security assessment
	b.WriteString("--- Security Assessment ---\n")
	cert := state.PeerCertificates[0]
	issues := 0

	if state.Version < tls.VersionTLS12 {
		b.WriteString(fmt.Sprintf("• CRITICAL: TLS %s is insecure (requires 1.2+)\n", tlsVersion))
		issues++
	}
	if isWeakCipher(state.CipherSuite) {
		b.WriteString("• HIGH: Weak cipher suite detected\n")
		issues++
	}
	if time.Now().After(cert.NotAfter) {
		b.WriteString("• CRITICAL: Certificate has expired\n")
		issues++
	} else if time.Until(cert.NotAfter).Hours()/24 < 30 {
		b.WriteString(fmt.Sprintf("• MEDIUM: Certificate expires in %d days\n", int(time.Until(cert.NotAfter).Hours()/24)))
		issues++
	}
	if cert.Issuer.String() == cert.Subject.String() {
		b.WriteString("• HIGH: Self-signed certificate detected\n")
		issues++
	}
	for _, san := range cert.DNSNames {
		if strings.HasPrefix(san, "*") {
			b.WriteString("• INFO: Wildcard certificate in use\n")
			break
		}
	}

	if issues == 0 {
		b.WriteString("• No critical security issues found\n")
	}

	return strings.TrimSpace(b.String()), nil
}

var weakCiphers = map[uint16]bool{
	tls.TLS_RSA_WITH_RC4_128_SHA:                true,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           true,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            true,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            true,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        true,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          true,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     true,
}

func isWeakCipher(cs uint16) bool { return weakCiphers[cs] }

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

func publicKeyBits(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *x509.CertificateRequest:
		return 0
	default:
		_ = pub
	}
	// Heuristic based on key types
	if cert.PublicKeyAlgorithm == x509.RSA {
		if k, ok := cert.PublicKey.(interface{ Size() int }); ok {
			return k.Size() * 8
		}
	}
	if cert.PublicKeyAlgorithm == x509.ECDSA {
		return 256 // approximate
	}
	return 0
}
