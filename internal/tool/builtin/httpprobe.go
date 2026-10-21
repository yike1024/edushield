package builtin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"reasonix/internal/evidence"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(httpProbe{}) }

type httpProbe struct{}

func (httpProbe) Name() string { return "http_probe" }

func (httpProbe) Description() string {
	return "Probe HTTP/HTTPS endpoints for security-relevant information: response headers (Server, X-Powered-By, CSP, HSTS, etc.), HTTP methods allowed, status code, redirect chain, cookies with security flags, and basic technology fingerprinting."
}

func (httpProbe) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"url":{"type":"string","description":"Target URL (e.g., https://example.com or http://192.168.1.1:8080). Must be http:// or https://"},
	"timeout_ms":{"type":"integer","description":"Request timeout in milliseconds (default 8000)"},
	"follow_redirects":{"type":"boolean","description":"Follow HTTP redirects (default true, max 5)"},
	"method":{"type":"string","description":"HTTP method to use (default GET; also probes OPTIONS for allowed methods)"}
},
"required":["url"]
}`)
}

func (httpProbe) ReadOnly() bool { return true }

func (httpProbe) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		URL             string `json:"url"`
		TimeoutMs       int    `json:"timeout_ms"`
		FollowRedirects bool   `json:"follow_redirects"`
		Method          string `json:"method"`
	}{TimeoutMs: 8000, FollowRedirects: true, Method: "GET"}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.URL == "" {
		return "", fmt.Errorf("url is required")
	}
	if p.TimeoutMs < 1000 {
		p.TimeoutMs = 1000
	}
	if p.TimeoutMs > 30000 {
		p.TimeoutMs = 30000
	}

	timeout := time.Duration(p.TimeoutMs) * time.Millisecond
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	if !p.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(p.Method), p.URL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EduShield-Security/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(body)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("HTTP Probe: %s\n\n", p.URL))
	b.WriteString(fmt.Sprintf("Status: %d %s\n", resp.StatusCode, resp.Status))
	b.WriteString(fmt.Sprintf("Protocol: %s\n", resp.Proto))
	if resp.TLS != nil {
		b.WriteString(fmt.Sprintf("TLS Version: %s\n", tlsVersionString(resp.TLS.Version)))
	}

	// Response headers
	b.WriteString("\n--- Response Headers ---\n")
	securityHeaders := map[string]string{
		"Content-Security-Policy":           "",
		"X-Content-Type-Options":            "",
		"X-Frame-Options":                   "",
		"X-XSS-Protection":                  "",
		"Strict-Transport-Security":         "",
		"Referrer-Policy":                   "",
		"Permissions-Policy":                "",
		"X-Powered-By":                      "",
		"Server":                            "",
		"Set-Cookie":                        "",
		"Access-Control-Allow-Origin":       "",
		"Access-Control-Allow-Methods":      "",
		"Cache-Control":                     "",
		"Content-Type":                      "",
		"X-Forwarded-For":                   "",
	}

	for _, h := range []string{
		"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
		"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
		"X-XSS-Protection", "Strict-Transport-Security", "Referrer-Policy",
		"Permissions-Policy", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
		"Set-Cookie", "Cache-Control", "Content-Type", "Location",
	} {
		if val := resp.Header.Get(h); val != "" {
			b.WriteString(fmt.Sprintf("%s: %s\n", h, val))
			securityHeaders[h] = val
		}
	}

	// Security assessment
	b.WriteString("\n--- Security Header Assessment ---\n")
	missingHeaders := []string{}
	checks := map[string]string{
		"Content-Security-Policy":   "Missing CSP — no script/style source enforcement",
		"X-Content-Type-Options":    "Missing X-Content-Type-Options — MIME sniffing risk",
		"X-Frame-Options":           "Missing X-Frame-Options — clickjacking risk",
		"Strict-Transport-Security": "Missing HSTS — no HTTPS enforcement",
		"Referrer-Policy":           "Missing Referrer-Policy — referrer leakage",
	}
	for h, desc := range checks {
		if securityHeaders[h] == "" {
			missingHeaders = append(missingHeaders, fmt.Sprintf("• %s: %s", h, desc))
		}
	}
	if len(missingHeaders) > 0 {
		b.WriteString("Missing/Recommended:\n")
		for _, s := range missingHeaders {
			b.WriteString(s + "\n")
		}
	} else {
		b.WriteString("All recommended security headers present\n")
	}

	// Technology fingerprinting hints
	b.WriteString("\n--- Technology Hints ---\n")
	if sv := securityHeaders["Server"]; sv != "" {
		b.WriteString(fmt.Sprintf("Server: %s\n", sv))
	}
	if xpb := securityHeaders["X-Powered-By"]; xpb != "" {
		b.WriteString(fmt.Sprintf("Powered By: %s\n", xpb))
	}
	if strings.Contains(bodyStr, "wp-content") || strings.Contains(bodyStr, "wp-json") {
		b.WriteString("CMS: WordPress (detected from body patterns)\n")
	}
	if strings.Contains(bodyStr, "Drupal") {
		b.WriteString("CMS: Drupal (detected from body patterns)\n")
	}
	if strings.Contains(bodyStr, "jquery") || strings.Contains(bodyStr, "jQuery") {
		b.WriteString("JS: jQuery detected\n")
	}

	// Cookies
	cookies := resp.Cookies()
	if len(cookies) > 0 {
		b.WriteString("\n--- Cookies ---\n")
		for _, c := range cookies {
			flags := []string{}
			if c.Secure {
				flags = append(flags, "Secure")
			}
			if c.HttpOnly {
				flags = append(flags, "HttpOnly")
			}
			if c.SameSite > 0 {
				flags = append(flags, fmt.Sprintf("SameSite=%d", c.SameSite))
			}
			f := ""
			if len(flags) > 0 {
				f = " [" + strings.Join(flags, ", ") + "]"
			}
			weak := ""
			if !c.Secure && resp.TLS != nil {
				weak = " ⚠ no Secure flag over HTTPS"
			}
			if !c.HttpOnly {
				if weak != "" {
					weak += ", no HttpOnly"
				} else {
					weak = " ⚠ no HttpOnly flag"
				}
			}
			b.WriteString(fmt.Sprintf("%s=%s (Domain=%s, Path=%s)%s%s\n",
				c.Name, maskValue(c.Value, 20), c.Domain, c.Path, f, weak))
		}
	}

	// Allowed methods
	b.WriteString("\n--- HTTP Methods ---\n")
	methodsReq, _ := http.NewRequestWithContext(ctx, "OPTIONS", p.URL, nil)
	methodsReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EduShield-Security/1.0)")
	methodsResp, err := client.Do(methodsReq)
	if err == nil {
		defer methodsResp.Body.Close()
		if allow := methodsResp.Header.Get("Allow"); allow != "" {
			b.WriteString(fmt.Sprintf("Allowed (Allow header): %s\n", allow))
		} else {
			b.WriteString("No Allow header in OPTIONS response\n")
		}
		// Test common methods
		testMethods := []string{"PUT", "DELETE", "TRACE", "PATCH"}
		for _, meth := range testMethods {
			treq, _ := http.NewRequestWithContext(ctx, meth, p.URL, nil)
			treq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EduShield-Security/1.0)")
			tresp, err := client.Do(treq)
			if err == nil {
				tresp.Body.Close()
				if tresp.StatusCode != 405 {
					b.WriteString(fmt.Sprintf("  %s: %d (not blocked)\n", meth, tresp.StatusCode))
				}
			}
		}
	} else {
		b.WriteString(fmt.Sprintf("OPTIONS probe failed: %v\n", err))
	}

	// Write structured findings to FindingStore
	var findings []*evidence.Finding
	host := p.URL

	// Missing security headers
	for h, desc := range checks {
		if securityHeaders[h] == "" {
			sev := evidence.SeverityMedium
			if h == "Content-Security-Policy" || h == "Strict-Transport-Security" {
				sev = evidence.SeverityHigh
			}
			findings = append(findings, &evidence.Finding{
				ID:          fmt.Sprintf("http_probe:missing_header:%s:%s", host, h),
				Target:      host,
				Tool:        "http_probe",
				Severity:    sev,
				Title:       fmt.Sprintf("Missing security header: %s", h),
				Description: desc,
				Remediation: fmt.Sprintf("Add the %s header to your web server configuration.", h),
			})
		}
	}

	// Technology fingerprinting
	if sv := securityHeaders["Server"]; sv != "" {
		findings = append(findings, &evidence.Finding{
			ID:          fmt.Sprintf("http_probe:server:%s", host),
			Target:      host,
			Tool:        "http_probe",
			Severity:    evidence.SeverityInfo,
			Title:       fmt.Sprintf("Web server: %s", sv),
			Description: fmt.Sprintf("Server header reveals: %s. Version information may help attackers identify vulnerabilities.", sv),
		})
	}

	// Cookie security analysis (over HTTPS)
	if resp.TLS != nil {
		for _, c := range resp.Cookies() {
			if !c.Secure {
				findings = append(findings, &evidence.Finding{
					ID:          fmt.Sprintf("http_probe:cookie:%s:%s", host, c.Name),
					Target:      host,
					Tool:        "http_probe",
					Severity:    evidence.SeverityMedium,
					Title:       fmt.Sprintf("Cookie without Secure flag: %s", c.Name),
					Description: fmt.Sprintf("Cookie '%s' is set without the Secure flag over HTTPS. It will be sent over unencrypted connections.", c.Name),
					Remediation: "Add the Secure and HttpOnly flags to the cookie.",
				})
			}
		}
	}

	// TLS info
	if resp.TLS != nil {
		tlsVer := tlsVersionString(resp.TLS.Version)
		if resp.TLS.Version < tls.VersionTLS12 {
			findings = append(findings, &evidence.Finding{
				ID:          fmt.Sprintf("http_probe:tls_version:%s", host),
				Target:      host,
				Tool:        "http_probe",
				Severity:    evidence.SeverityHigh,
				Title:       fmt.Sprintf("Outdated TLS version: %s", tlsVer),
				Description: fmt.Sprintf("Server uses %s which is considered outdated. TLS 1.2+ recommended.", tlsVer),
				Remediation: "Upgrade TLS configuration to support TLS 1.2 and TLS 1.3 only.",
			})
		}
	}

	evidence.Global.AddFindings(findings)

	return strings.TrimSpace(b.String()), nil
}

func maskValue(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
