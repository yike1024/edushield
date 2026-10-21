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

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(vulnScan{}) }

type vulnScan struct{}

func (vulnScan) Name() string { return "vuln_scan" }

func (vulnScan) Description() string {
	return "Perform basic web vulnerability scanning on a target URL. Checks for common issues: open directories, exposed files (.git, .env, backup files), default credentials pages, debug endpoints, server info disclosure, and basic XSS/SQLi reflection points. Non-intrusive by default — sends minimal safe payloads."
}

func (vulnScan) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"url":{"type":"string","description":"Target base URL (e.g., https://example.com)"},
	"checks":{"type":"string","description":"Comma-separated checks to run: 'files', 'headers', 'endpoints', 'info', 'all'. Default: 'all'"},
	"timeout_ms":{"type":"integer","description":"Per-request timeout in milliseconds (default 5000)"}
},
"required":["url"]
}`)
}

func (vulnScan) ReadOnly() bool { return true }

var sensitivePaths = []string{
	"/.git/HEAD",
	"/.env",
	"/.env.backup",
	"/.env.example",
	"/.svn/entries",
	"/.DS_Store",
	"/.htaccess",
	"/backup.zip",
	"/backup.sql",
	"/dump.sql",
	"/phpinfo.php",
	"/info.php",
	"/server-status",
	"/server-info",
	"/wp-config.php.bak",
	"/wp-config.php~",
	"/config.php.bak",
	"/admin/config.php",
	"/web.config",
	"/crossdomain.xml",
	"/clientaccesspolicy.xml",
}

var debugEndpoints = []string{
	"/actuator",
	"/actuator/health",
	"/actuator/env",
	"/actuator/mappings",
	"/debug",
	"/debug/vars",
	"/metrics",
	"/health",
	"/swagger-ui.html",
	"/swagger/index.html",
	"/api-docs",
	"/v2/api-docs",
	"/v3/api-docs",
	"/graphql",
	"/graphiql",
	"/api/graphql",
	"/console",
	"/_debug/",
	"/phpmyadmin/",
	"/phpMyAdmin/",
	"/adminer.php",
	"/.vscode/sftp.json",
	"/sftp-config.json",
}

var adminPaths = []string{
	"/admin",
	"/admin/",
	"/administrator",
	"/wp-admin",
	"/wp-login.php",
	"/user/login",
	"/login",
	"/cpanel",
	"/webmail",
	"/manager/html",
	"/jenkins/login",
	"/solr/",
	"/drupal/",
}

func (vulnScan) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		URL       string `json:"url"`
		Checks    string `json:"checks"`
		TimeoutMs int    `json:"timeout_ms"`
	}{Checks: "all", TimeoutMs: 5000}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.URL == "" {
		return "", fmt.Errorf("url is required")
	}
	if p.TimeoutMs < 2000 {
		p.TimeoutMs = 2000
	}
	if p.TimeoutMs > 15000 {
		p.TimeoutMs = 15000
	}

	baseURL := strings.TrimRight(p.URL, "/")
	timeout := time.Duration(p.TimeoutMs) * time.Millisecond
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: timeout}).DialContext,
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	checks := map[string]bool{}
	for _, c := range strings.Split(p.Checks, ",") {
		checks[strings.TrimSpace(c)] = true
	}
	runAll := checks["all"]

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Vulnerability Scan: %s\n\n", baseURL))
	findings := 0

	// 1. Check sensitive files
	if runAll || checks["files"] {
		b.WriteString("--- Sensitive File Check ---\n")
		for _, path := range sensitivePaths {
			if r, ok := quickGet(ctx, client, baseURL+path); ok && r.StatusCode == 200 {
				b.WriteString(fmt.Sprintf("🔴 EXPOSED: %s (HTTP 200, size: %d)\n", path, r.Size))
				findings++
			} else if ok && r.StatusCode == 403 {
				b.WriteString(fmt.Sprintf("🟡 PRESENT (403): %s\n", path))
				findings++
			}
		}
		if findings == 0 {
			b.WriteString("No sensitive files found exposed.\n")
		}
		b.WriteString("\n")
	}

	// 2. Debug endpoints
	if runAll || checks["endpoints"] {
		b.WriteString("--- Debug/Management Endpoints ---\n")
		epFindings := 0
		for _, path := range debugEndpoints {
			if r, ok := quickGet(ctx, client, baseURL+path); ok && r.StatusCode < 500 {
				b.WriteString(fmt.Sprintf("🟡 FOUND: %s (HTTP %d)\n", path, r.StatusCode))
				epFindings++
			}
		}
		if epFindings == 0 {
			b.WriteString("No debug/management endpoints found.\n")
		}
		findings += epFindings
		b.WriteString("\n")
	}

	// 3. Admin panels
	if runAll || checks["endpoints"] {
		b.WriteString("--- Admin/Login Pages ---\n")
		adminFindings := 0
		for _, path := range adminPaths {
			if r, ok := quickGet(ctx, client, baseURL+path); ok && r.StatusCode < 500 {
				b.WriteString(fmt.Sprintf("🟡 FOUND: %s (HTTP %d)\n", path, r.StatusCode))
				adminFindings++
			}
		}
		if adminFindings == 0 {
			b.WriteString("No admin/login pages discovered.\n")
		}
		findings += adminFindings
		b.WriteString("\n")
	}

	// 4. Header analysis
	if runAll || checks["headers"] {
		b.WriteString("--- Security Header Analysis ---\n")
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EduShield-Security-Scanner/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			b.WriteString(fmt.Sprintf("Failed to fetch headers: %v\n", err))
		} else {
			resp.Body.Close()
			missing := []string{}
			if resp.Header.Get("Content-Security-Policy") == "" {
				missing = append(missing, "Content-Security-Policy")
			}
			if resp.Header.Get("X-Frame-Options") == "" {
				missing = append(missing, "X-Frame-Options")
			}
			if resp.Header.Get("Strict-Transport-Security") == "" {
				missing = append(missing, "Strict-Transport-Security")
			}
			if resp.Header.Get("X-Content-Type-Options") == "" {
				missing = append(missing, "X-Content-Type-Options")
			}
			server := resp.Header.Get("Server")
			if server != "" {
				b.WriteString(fmt.Sprintf("🟡 Server header discloses: %s\n", server))
				findings++
			}
			xpb := resp.Header.Get("X-Powered-By")
			if xpb != "" {
				b.WriteString(fmt.Sprintf("🟡 X-Powered-By discloses: %s\n", xpb))
				findings++
			}
			if len(missing) > 0 {
				b.WriteString(fmt.Sprintf("🟡 Missing security headers: %s\n", strings.Join(missing, ", ")))
				findings++
			} else {
				b.WriteString("All recommended security headers present.\n")
			}
		}
		b.WriteString("\n")
	}

	// 5. Basic reflection test (safe)
	if runAll || checks["info"] {
		b.WriteString("--- Basic Reflection/Info ---\n")
		// Test a safe path with query string to check for basic reflection
		testURL := baseURL + "/?test=reasonix_reflection_test"
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EduShield-Security-Scanner/1.0)")
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
			resp.Body.Close()
			bodyStr := string(body)
			if strings.Contains(bodyStr, "reasonix_reflection_test") {
				b.WriteString("🟡 INPUT REFLECTION: Parameter value reflected in response (potential XSS vector)\n")
				findings++
			}
			if strings.Contains(bodyStr, "SQL syntax") || strings.Contains(bodyStr, "mysql_fetch") ||
				strings.Contains(bodyStr, "ORA-") || strings.Contains(bodyStr, "PostgreSQL") {
				b.WriteString("🔴 DATABASE ERROR DISCLOSURE: SQL error messages exposed in response\n")
				findings++
			}
			if strings.Contains(bodyStr, "Stacktrace:") || strings.Contains(bodyStr, "at ") && strings.Contains(bodyStr, ".java:") {
				b.WriteString("🔴 STACK TRACE DISCLOSURE: Stack traces exposed in response\n")
				findings++
			}
			if !strings.Contains(bodyStr, "reasonix_reflection_test") &&
				!strings.Contains(bodyStr, "SQL") && !strings.Contains(bodyStr, "Stack") {
				b.WriteString("No reflection or error disclosure issues detected.\n")
			}
		}
	}

	b.WriteString(fmt.Sprintf("\nScan complete. %d findings total.\n", findings))
	return b.String(), nil
}

type quickResp struct {
	StatusCode int
	Size       int64
}

func quickGet(ctx context.Context, client *http.Client, url string) (quickResp, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return quickResp{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EduShield-Security-Scanner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return quickResp{}, false
	}
	defer resp.Body.Close()
	return quickResp{StatusCode: resp.StatusCode, Size: resp.ContentLength}, true
}
