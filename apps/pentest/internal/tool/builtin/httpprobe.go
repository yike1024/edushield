package builtin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(httpProbe{}) }

// httpProbe inspects an authorized web target: status, redirect chain,
// technology hints, missing security headers, page title, and TLS certificate
// metadata. It is reconnaissance, not exploitation.
type httpProbe struct{}

func (httpProbe) Name() string { return "http_probe" }

func (httpProbe) Description() string {
	return "Inspect an authorized web target: follow redirects and report final status, redirect chain, server technology headers (Server/X-Powered-By/etc.), MISSING security headers (CSP/HSTS/X-Frame-Options/...), HTML title, and TLS certificate metadata. Offensive action - only target hosts the user authorized."
}

func (httpProbe) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"Absolute http:// or https:// URL of the authorized target"},"method":{"type":"string","description":"HTTP method (default GET)"},"headers":{"type":"string","description":"Extra request headers as \"Key: Value\" lines separated by newlines"},"follow_redirects":{"type":"boolean","description":"Follow up to 5 redirects (default true)"},"insecure":{"type":"boolean","description":"Accept self-signed certificates (default false)"},"timeout_ms":{"type":"integer","description":"Request timeout in ms (default 8000)"}},"required":["url"]}`)
}

func (httpProbe) ReadOnly() bool { return false }

// SnipHint front-loads the verdict lines like web_fetch.
func (httpProbe) SnipHint() tool.SnipHint {
	return tool.SnipHint{Head: 80, Tail: 8, HeadChars: 10000, TailChars: 1000}
}

// securityHeaders are response headers whose ABSENCE is a finding.
var securityHeaders = []string{
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// techHeaders are response headers that leak stack information.
var techHeaders = []string{
	"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
	"Via", "X-Generator", "X-Runtime", "Set-Cookie", "WWW-Authenticate",
}

var htmlTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (httpProbe) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		URL             string `json:"url"`
		Method          string `json:"method"`
		Headers         string `json:"headers"`
		FollowRedirects *bool  `json:"follow_redirects"`
		Insecure        bool   `json:"insecure"`
		TimeoutMs       int    `json:"timeout_ms"`
	}{Method: "GET", TimeoutMs: 8000}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	u, err := url.Parse(strings.TrimSpace(p.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("url must be an absolute http:// or https:// URL")
	}
	p.Method = strings.ToUpper(strings.TrimSpace(p.Method))
	if p.Method == "" {
		p.Method = "GET"
	}
	follow := true
	if p.FollowRedirects != nil {
		follow = *p.FollowRedirects
	}
	if p.TimeoutMs < 200 || p.TimeoutMs > 60000 {
		p.TimeoutMs = 8000
	}
	timeout := time.Duration(p.TimeoutMs) * time.Millisecond

	var chain []string
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: p.Insecure},
		},
	}
	if follow {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			chain = append(chain, req.URL.String())
			return nil
		}
	} else {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequestWithContext(ctx, p.Method, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reasonix-Pentest/1.0)")
	for _, line := range strings.Split(p.Headers, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request %s: %w", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s -> %d %s\n", p.Method, u, resp.StatusCode, resp.Status)
	if len(chain) > 0 {
		fmt.Fprintf(&b, "final URL: %s\n", resp.Request.URL)
	}
	for _, step := range chain {
		fmt.Fprintf(&b, "redirect: %s\n", step)
	}

	fmt.Fprintln(&b, "-- technology hints --")
	seenTech := false
	for _, h := range techHeaders {
		if v := resp.Header.Get(h); v != "" {
			if h == "Set-Cookie" {
				v = cookieAudit(v)
			}
			fmt.Fprintf(&b, "%s: %s\n", h, v)
			seenTech = true
		}
	}
	if !seenTech {
		b.WriteString("(none disclosed)\n")
	}

	fmt.Fprintln(&b, "-- missing security headers --")
	missing := 0
	for _, h := range securityHeaders {
		if resp.Header.Get(h) == "" {
			fmt.Fprintf(&b, "MISSING %s\n", h)
			missing++
		}
	}
	if missing == 0 {
		b.WriteString("(all present)\n")
	}

	if m := htmlTitleRe.FindSubmatch(body); len(m) > 1 {
		title := strings.Join(strings.Fields(string(m[1])), " ")
		if len(title) > 120 {
			title = title[:120]
		}
		if title != "" {
			fmt.Fprintf(&b, "title: %s\n", title)
		}
	}

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		fmt.Fprintf(&b, "tls: %s, subject=%s, issuer=%s, expires=%s\n",
			tlsVersionName(resp.TLS.Version), cert.Subject.String(),
			cert.Issuer.String(), cert.NotAfter.UTC().Format("2006-01-02"))
		if !cert.NotAfter.After(time.Now()) {
			b.WriteString("warning: certificate is EXPIRED\n")
		}
	}
	return b.String(), nil
}

// cookieAudit flags cookie attributes that harden session cookies.
func cookieAudit(v string) string {
	var notes []string
	lower := strings.ToLower(v)
	if !strings.Contains(lower, "secure") {
		notes = append(notes, "no Secure flag")
	}
	if !strings.Contains(lower, "httponly") {
		notes = append(notes, "no HttpOnly flag")
	}
	if !strings.Contains(lower, "samesite") {
		notes = append(notes, "no SameSite")
	}
	name := v
	if k, _, ok := strings.Cut(v, "="); ok {
		name = strings.TrimSpace(k)
	}
	if len(notes) == 0 {
		return name + " (hardened)"
	}
	return name + " (" + strings.Join(notes, ", ") + ")"
}
