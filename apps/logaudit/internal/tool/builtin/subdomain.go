package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(subdomainEnum{}) }

type subdomainEnum struct{}

func (subdomainEnum) Name() string { return "subdomain_enum" }

func (subdomainEnum) Description() string {
	return "Enumerate subdomains of a domain using a built-in common subdomain wordlist. Returns discovered subdomains with their resolved IP addresses. Useful for attack surface discovery and reconnaissance."
}

func (subdomainEnum) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"domain":{"type":"string","description":"Target domain (e.g., example.com)"},
	"wordlist":{"type":"string","description":"Wordlist to use: 'quick' (top 30), 'common' (top 150), 'extended' (top 500). Default: 'quick'"},
	"timeout_ms":{"type":"integer","description":"DNS resolution timeout in milliseconds (default 3000)"},
	"concurrency":{"type":"integer","description":"Max concurrent DNS queries (default 20, max 50)"}
},
"required":["domain"]
}`)
}

func (subdomainEnum) ReadOnly() bool { return true }

var quickSubdomains = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
	"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
	"ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
	"mail2", "new", "mysql",
}

var commonSubdomains = append(append([]string(nil), quickSubdomains...), []string{
	"api", "app", "apps", "beta", "cdn", "cloud", "dashboard", "demo", "docs",
	"download", "email", "gateway", "help", "internal", "intranet", "jenkins",
	"jira", "lab", "login", "manage", "media", "mobile", "monitor", "mx",
	"office", "owa", "portal", "prod", "remote", "secure", "server", "shop",
	"stage", "staging", "status", "store", "support", "svn", "syslog", "test2",
	"vpn2", "web", "wiki", "www3", "mails", "git", "sandbox", "search", "static",
	"stats", "training", "upload", "video", "voip", "chat", "crm", "db",
	"dns", "dns1", "dns2", "files", "firewall", "host", "images", "info",
	"kibana", "lists", "mssql", "music", "ns0", "ns4", "origin", "phpmyadmin",
	"proxy", "rdp", "sip", "static1", "static2", "stream", "survey", "temp",
	"terminal", "trac", "uat", "vcenter",
}...)

var extendedSubdomains = append(append([]string(nil), commonSubdomains...), []string{
	"ad", "ads", "analytics", "assets", "auth", "backup", "bbs", "billing", "boards",
	"cache", "calendar", "camera", "careers", "catalog", "cert", "cgi", "client",
	"clients", "cms", "code", "community", "config", "connect", "corp", "cs",
	"css", "data", "dav", "dc", "deploy", "design", "devel", "dir", "direct",
	"drupal", "edge", "engine", "enterprise", "err", "error", "eshop", "events",
	"exchange", "extranet", "feeds", "fonts", "ftp2", "gallery", "games", "grafana",
	"graphql", "group", "guest", "health", "home", "id", "int", "integration",
	"inventory", "ipv6", "js", "kb", "ldap", "library", "live", "log", "logs",
	"lync", "magento", "map", "maps", "master", "member", "members", "message",
	"metrics", "mirror", "mobil", "my", "mysql2", "nagios", "net", "network",
	"newsletter", "node", "ns5", "offsite", "openshift", "oracle", "order",
	"orders", "owa2", "partner", "partners", "pay", "payment", "phones", "photos",
	"php", "pki", "podcast", "policies", "poll", "post", "press", "preview",
	"print", "private", "products", "promo", "public", "puppet", "r", "radio",
	"radius", "ras", "repo", "reports", "research", "rest", "root", "router",
	"rss", "s", "sales", "saml", "schema", "sdk", "secret", "service", "sessions",
	"share", "signin", "signup", "slave", "soap", "social", "spam", "sql",
	"ssh", "stg", "storage", "sync", "sys", "tech", "tfs", "tickets", "time",
	"tmp", "tool", "tools", "track", "translations", "tunnel", "updates",
	"user", "videos", "virtual", "visitor", "webinar", "webserver", "ws",
}...)

func (subdomainEnum) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Domain      string `json:"domain"`
		Wordlist    string `json:"wordlist"`
		TimeoutMs   int    `json:"timeout_ms"`
		Concurrency int    `json:"concurrency"`
	}{Wordlist: "quick", TimeoutMs: 3000, Concurrency: 20}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Domain == "" {
		return "", fmt.Errorf("domain is required")
	}
	if p.Concurrency < 1 {
		p.Concurrency = 1
	}
	if p.Concurrency > 50 {
		p.Concurrency = 50
	}
	if p.TimeoutMs < 500 {
		p.TimeoutMs = 500
	}
	if p.TimeoutMs > 10000 {
		p.TimeoutMs = 10000
	}

	var wordlist []string
	switch p.Wordlist {
	case "quick":
		wordlist = quickSubdomains
	case "common":
		wordlist = commonSubdomains
	case "extended":
		wordlist = extendedSubdomains
	default:
		wordlist = quickSubdomains
	}

	domain := strings.TrimSuffix(strings.TrimSpace(p.Domain), ".")
	timeout := time.Duration(p.TimeoutMs) * time.Millisecond

	type result struct {
		Subdomain string   `json:"subdomain"`
		IPs       []string `json:"ips,omitempty"`
	}

	var mu sync.Mutex
	var found []result
	var wg sync.WaitGroup
	sem := make(chan struct{}, p.Concurrency)

	for _, sub := range wordlist {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			host := sub + "." + domain
			resolver := &net.Resolver{}
			ctx2, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			ips, err := resolver.LookupIPAddr(ctx2, host)
			if err != nil || len(ips) == 0 {
				return
			}

			var ipStrs []string
			for _, ip := range ips {
				ipStrs = append(ipStrs, ip.String())
			}

			mu.Lock()
			found = append(found, result{Subdomain: host, IPs: ipStrs})
			mu.Unlock()
		}(sub)
	}
	wg.Wait()

	sort.Slice(found, func(i, j int) bool { return found[i].Subdomain < found[j].Subdomain })

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Subdomain enumeration for: %s (wordlist: %s, attempted: %d)\n\n",
		domain, p.Wordlist, len(wordlist)))

	if len(found) == 0 {
		b.WriteString("No subdomains discovered. Try a larger wordlist ('common' or 'extended')\n")
		b.WriteString("or use bash with tools like subfinder, amass, or assetfinder.\n")
	} else {
		b.WriteString(fmt.Sprintf("Discovered %d subdomains:\n\n", len(found)))
		for _, r := range found {
			b.WriteString(fmt.Sprintf("%-50s %s\n", r.Subdomain, strings.Join(r.IPs, ", ")))
		}
	}

	return b.String(), nil
}
