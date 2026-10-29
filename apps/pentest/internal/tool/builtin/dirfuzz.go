package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(dirFuzz{}) }

// dirFuzz enumerates hidden paths on an authorized web target with a compact
// built-in wordlist (or a caller-supplied one). It calibrates against a
// random nonexistent path first so catch-all 200/404 handlers don't flood the
// results.
type dirFuzz struct{}

func (dirFuzz) Name() string { return "dir_fuzz" }

func (dirFuzz) Description() string {
	return "Enumerate hidden paths on an authorized web target: probe a built-in wordlist of common sensitive paths (admin panels, backups, .git, config files...) or a custom list, optionally with extensions (.php,.bak). Calibrates the site's default not-found response first to suppress false positives. Offensive action - only target hosts the user authorized."
}

func (dirFuzz) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"Base URL of the authorized target (paths are appended to it)"},"wordlist":{"type":"string","description":"Custom wordlist, one entry per line or comma-separated; falls back to the built-in sensitive-path list"},"extensions":{"type":"string","description":"Extension suffixes to try per entry, e.g. \"\",.php,.bak (comma-separated; default no suffix only)"},"concurrency":{"type":"integer","description":"Parallel requests, 1-32 (default 16)"},"timeout_ms":{"type":"integer","description":"Per-request timeout in ms (default 5000)"}},"required":["url"]}`)
}

func (dirFuzz) ReadOnly() bool { return false }

// SnipHint: the summary + first hits matter most.
func (dirFuzz) SnipHint() tool.SnipHint {
	return tool.SnipHint{Head: 80, Tail: 8, HeadChars: 10000, TailChars: 1000}
}

// dirWordlist is a compact sensitive-path dictionary. Deliberately short so a
// single invocation stays within polite rate limits; deeper enumeration should
// go through bash + a dedicated external tool with explicit confirmation.
var dirWordlist = []string{
	"admin", "administrator", "login", "signin", "signup", "logout", "register",
	"dashboard", "console", "panel", "manage", "manager", "control", "cpanel",
	"api", "api/v1", "api/v2", "graphql", "swagger", "swagger.json", "swagger-ui.html",
	"openapi.json", "docs", "apidocs", "actuator", "actuator/env", "actuator/health",
	"actuator/heapdump", "metrics", "health", "status", "info", "debug", "trace",
	".env", ".env.local", ".env.production", ".env.backup", "config.php", "config.json",
	"config.yml", "configuration.php", "wp-config.php", "settings.py", "local_settings.py",
	"database.yml", "web.config", ".git/HEAD", ".git/config", ".gitignore", ".svn/entries",
	".hg/hgrc", ".DS_Store", ".htaccess", ".htpasswd", "id_rsa", "id_rsa.pub",
	"backup", "backups", "bak", "old", "archive", "dump.sql", "db.sql", "database.sql",
	"backup.zip", "backup.tar.gz", "site.zip", "www.zip", "web.zip", "wwwroot.rar",
	"robots.txt", "sitemap.xml", "crossdomain.xml", "humans.txt", "security.txt",
	"phpmyadmin", "pma", "myadmin", "mysql", "adminer.php", "pgadmin",
	"wp-admin", "wp-login.php", "wp-content", "xmlrpc.php", "wp-json",
	"server-status", "server-info", "jmx-console", "web-console", "invoker/JMXInvokerServlet",
	"solr", "elasticsearch", "_cat/indices", "kibana", "jenkins", "hudson",
	"manager/html", "host-manager/html", "axis2", "struts",
	"test", "tests", "dev", "staging", "temp", "tmp", "upload", "uploads",
	"files", "static", "assets", "internal", "private", "secret", "hidden",
	"user", "users", "account", "accounts", "profile", "settings", "password",
	"reset", "forgot", "debug/pprof", "trace.axd", "elmah.axd",
	".well-known/security.txt", "_profiler", "_debug", "nagios", "zabbix", "grafana",
	"prometheus", "portainer", "traefik", "consul", "vault", "phpinfo.php", "info.php",
	"cgi-bin", "fcgi-bin", "shell", "cmd", "command", "exec", "ws", "websocket",
	"oauth", "auth", "sso", "cas", "saml", "token", "callback",
}

type dirHit struct {
	path     string
	status   int
	length   int
	location string
}

func (dirFuzz) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		URL         string `json:"url"`
		Wordlist    string `json:"wordlist"`
		Extensions  string `json:"extensions"`
		Concurrency int    `json:"concurrency"`
		TimeoutMs   int    `json:"timeout_ms"`
	}{Concurrency: 16, TimeoutMs: 5000}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	base, err := url.Parse(strings.TrimSpace(p.URL))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return "", fmt.Errorf("url must be an absolute http:// or https:// URL")
	}
	if p.Concurrency < 1 || p.Concurrency > 32 {
		p.Concurrency = 16
	}
	if p.TimeoutMs < 200 || p.TimeoutMs > 30000 {
		p.TimeoutMs = 5000
	}
	timeout := time.Duration(p.TimeoutMs) * time.Millisecond

	words := dirWordlist
	if strings.TrimSpace(p.Wordlist) != "" {
		words = splitWordlist(p.Wordlist)
		if len(words) == 0 {
			return "", fmt.Errorf("custom wordlist is empty")
		}
		if len(words) > 2000 {
			return "", fmt.Errorf("custom wordlist too large (%d entries, max 2000)", len(words))
		}
	}
	exts := []string{""}
	if strings.TrimSpace(p.Extensions) != "" {
		exts = nil
		for _, e := range strings.Split(p.Extensions, ",") {
			exts = append(exts, strings.TrimSpace(e))
		}
	}

	client := &http.Client{
		Timeout: timeout,
		// Redirects are findings themselves; following them would hide the
		// 301/302 behind whatever the destination returns.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fetch := func(path string) (dirHit, bool) {
		target := base.JoinPath(path).String()
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return dirHit{}, false
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reasonix-Pentest/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			return dirHit{}, false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<18))
		return dirHit{path: path, status: resp.StatusCode, length: len(body), location: resp.Header.Get("Location")}, true
	}

	// Calibration: what does a definitely-missing path look like?
	cal, ok := fetch(fmt.Sprintf("rx-no-such-%d", rand.Intn(1_000_000)))
	if !ok {
		return "", fmt.Errorf("target unreachable: calibration request to %s failed", base)
	}

	type work struct{ path string }
	jobs := make(chan work)
	var (
		mu   sync.Mutex
		hits []dirHit
		wg   sync.WaitGroup
	)
	for i := 0; i < p.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				hit, ok := fetch(j.path)
				if !ok {
					continue
				}
				// Suppress the calibrated not-found shape; keep anything else.
				if hit.status == cal.status && lengthClose(hit.length, cal.length) {
					continue
				}
				mu.Lock()
				hits = append(hits, hit)
				mu.Unlock()
			}
		}()
	}
	total := 0
	for _, w := range words {
		for _, ext := range exts {
			if ctx.Err() != nil {
				break
			}
			total++
			jobs <- work{path: w + ext}
		}
	}
	close(jobs)
	wg.Wait()

	var b strings.Builder
	fmt.Fprintf(&b, "dir fuzz of %s: %d paths probed, calibration not-found = status %d/len %d\n",
		base, total, cal.status, cal.length)
	if len(hits) == 0 {
		b.WriteString("(nothing beyond the not-found baseline)\n")
		return b.String(), nil
	}
	fmt.Fprintf(&b, "%d interesting responses:\n", len(hits))
	for _, h := range hits {
		line := fmt.Sprintf("/%s\t%d\tlen=%d", h.path, h.status, h.length)
		if h.location != "" {
			line += "\t-> " + h.location
		}
		b.WriteString(line + "\n")
	}
	return b.String(), nil
}

func splitWordlist(raw string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == ',' || r == '\r'
	}) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
