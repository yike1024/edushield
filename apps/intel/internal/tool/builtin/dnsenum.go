package builtin

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(dnsEnum{}) }

// dnsEnum collects DNS attack-surface data for an authorized domain: standard
// record types, reverse lookups, subdomain brute force against a small
// built-in list, and a zone transfer (AXFR) attempt.
type dnsEnum struct{}

func (dnsEnum) Name() string { return "dns_enum" }

func (dnsEnum) Description() string {
	return "DNS enumeration for an authorized domain: query A/AAAA/MX/NS/TXT/CNAME records, reverse PTR lookups, brute-force subdomains from a built-in wordlist (or custom list), or attempt a zone transfer (AXFR). Offensive action - only target domains the user authorized."
}

func (dnsEnum) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"domain":{"type":"string","description":"Target domain (or IP for reverse mode) authorized for this engagement"},"mode":{"type":"string","description":"records (default) | subdomains | axfr | reverse"},"nameserver":{"type":"string","description":"Resolver to use, e.g. \"8.8.8.8:53\" (default: system resolver)"},"wordlist":{"type":"string","description":"Custom subdomain prefixes, one per line or comma-separated; falls back to the built-in list (subdomains mode)"}},"required":["domain"]}`)
}

func (dnsEnum) ReadOnly() bool { return false }

// SnipHint keeps the record summary head; the tail lists leftovers.
func (dnsEnum) SnipHint() tool.SnipHint {
	return tool.SnipHint{Head: 80, Tail: 8, HeadChars: 10000, TailChars: 1000}
}

// subdomainWordlist covers the common low-hanging subdomains.
var subdomainWordlist = []string{
	"www", "mail", "smtp", "imap", "pop", "pop3", "ftp", "sftp", "ssh", "vpn",
	"admin", "administrator", "panel", "dashboard", "portal", "intranet",
	"extranet", "internal", "corp", "office", "remote", "desktop", "rdp",
	"api", "api2", "app", "apps", "web", "webmail", "m", "mobile", "dev",
	"test", "testing", "staging", "stage", "uat", "qa", "demo", "beta",
	"preview", "sandbox", "ci", "cd", "jenkins", "git", "gitlab", "github",
	"svn", "hg", "repo", "registry", "docker", "k8s", "kube", "prod",
	"db", "database", "mysql", "pgsql", "postgres", "redis", "mongo", "es",
	"search", "elastic", "log", "logs", "metrics", "monitor", "grafana",
	"kibana", "prometheus", "zabbix", "nagios", "status", "health",
	"auth", "sso", "login", "oauth", "id", "identity", "cas", "ldap",
	"ns1", "ns2", "ns3", "dns", "proxy", "cdn", "static", "assets", "img",
	"images", "media", "video", "download", "downloads", "files", "share",
	"shop", "store", "pay", "payment", "billing", "crm", "erp", "hr",
	"blog", "news", "forum", "wiki", "docs", "help", "support", "tickets",
	"legacy", "old", "new", "v1", "v2", "backup", "bak",
}

func (dnsEnum) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Domain     string `json:"domain"`
		Mode       string `json:"mode"`
		Nameserver string `json:"nameserver"`
		Wordlist   string `json:"wordlist"`
	}{Mode: "records"}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	domain := strings.TrimSuffix(strings.TrimSpace(p.Domain), ".")
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}

	resolver := net.DefaultResolver
	if strings.TrimSpace(p.Nameserver) != "" {
		ns := strings.TrimSpace(p.Nameserver)
		if !strings.Contains(ns, ":") {
			ns += ":53"
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", ns)
			},
		}
	}

	switch strings.ToLower(strings.TrimSpace(p.Mode)) {
	case "", "records":
		return enumRecords(ctx, resolver, domain)
	case "reverse":
		names, err := resolver.LookupAddr(ctx, domain)
		if err != nil {
			return "", fmt.Errorf("reverse lookup %s: %w", domain, err)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "PTR for %s:\n", domain)
		for _, n := range names {
			b.WriteString(n + "\n")
		}
		return b.String(), nil
	case "subdomains":
		return enumSubdomains(ctx, resolver, domain, p.Wordlist)
	case "axfr":
		return tryAXFR(ctx, resolver, domain)
	default:
		return "", fmt.Errorf("unknown mode %q (want records, subdomains, axfr, reverse)", p.Mode)
	}
}

func enumRecords(ctx context.Context, r *net.Resolver, domain string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "DNS records for %s\n", domain)

	if ips, err := r.LookupIPAddr(ctx, domain); err == nil {
		for _, ip := range ips {
			kind := "A"
			if ip.IP.To4() == nil {
				kind = "AAAA"
			}
			fmt.Fprintf(&b, "%s\t%s\n", kind, ip.IP)
		}
	} else {
		fmt.Fprintf(&b, "A/AAAA: lookup failed (%v)\n", err)
	}
	if cname, err := r.LookupCNAME(ctx, domain); err == nil && cname != domain+"." {
		fmt.Fprintf(&b, "CNAME\t%s\n", strings.TrimSuffix(cname, "."))
	}
	if mxs, err := r.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			fmt.Fprintf(&b, "MX\t%d %s\n", mx.Pref, strings.TrimSuffix(mx.Host, "."))
		}
	}
	if nss, err := r.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			fmt.Fprintf(&b, "NS\t%s\n", strings.TrimSuffix(ns.Host, "."))
		}
	}
	if txts, err := r.LookupTXT(ctx, domain); err == nil {
		for _, t := range txts {
			label := "TXT"
			lower := strings.ToLower(t)
			if strings.HasPrefix(lower, "v=spf1") {
				label = "TXT/SPF"
			} else if strings.HasPrefix(lower, "v=dmarc1") {
				label = "TXT/DMARC"
			} else if strings.HasPrefix(lower, "v=dkim1") {
				label = "TXT/DKIM"
			}
			fmt.Fprintf(&b, "%s\t%s\n", label, t)
		}
	}
	// DMARC commonly lives at its own label.
	if dmarcs, err := r.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, t := range dmarcs {
			fmt.Fprintf(&b, "TXT/DMARC(_dmarc)\t%s\n", t)
		}
	}
	return b.String(), nil
}

func enumSubdomains(ctx context.Context, r *net.Resolver, domain, custom string) (string, error) {
	words := subdomainWordlist
	if strings.TrimSpace(custom) != "" {
		words = splitWordlist(custom)
		if len(words) == 0 {
			return "", fmt.Errorf("custom wordlist is empty")
		}
		if len(words) > 2000 {
			return "", fmt.Errorf("custom wordlist too large (%d entries, max 2000)", len(words))
		}
	}

	var (
		mu   sync.Mutex
		hits []string
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 32)
	)
	for _, w := range words {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()
			name := sub + "." + domain
			if ips, err := r.LookupIPAddr(ctx, name); err == nil && len(ips) > 0 {
				mu.Lock()
				hits = append(hits, fmt.Sprintf("%s\t%s", name, ips[0].IP))
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	sort.Strings(hits)

	var b strings.Builder
	fmt.Fprintf(&b, "subdomain brute force of %s: %d prefixes tried, %d resolved\n", domain, len(words), len(hits))
	for _, h := range hits {
		b.WriteString(h + "\n")
	}
	return b.String(), nil
}

// tryAXFR attempts a DNS zone transfer against each authoritative nameserver
// using a hand-built AXFR query (stdlib has no DNS wire client). A successful
// transfer leaks the whole zone - reporting ANCOUNT>0 is enough evidence.
func tryAXFR(ctx context.Context, r *net.Resolver, domain string) (string, error) {
	nss, err := r.LookupNS(ctx, domain)
	if err != nil || len(nss) == 0 {
		return "", fmt.Errorf("no authoritative nameservers found for %s: %v", domain, err)
	}
	query := buildAXFRQuery(domain)
	var b strings.Builder
	fmt.Fprintf(&b, "AXFR attempt for %s\n", domain)
	anySuccess := false
	for _, ns := range nss {
		host := strings.TrimSuffix(ns.Host, ".")
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "53"), 5*time.Second)
		if err != nil {
			fmt.Fprintf(&b, "%s: connect failed (%v)\n", host, err)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			fmt.Fprintf(&b, "%s: write failed (%v)\n", host, err)
			continue
		}
		count, err := readAXFRAnswerCount(conn)
		conn.Close()
		if err != nil {
			fmt.Fprintf(&b, "%s: no usable response (%v)\n", host, err)
			continue
		}
		if count > 0 {
			anySuccess = true
			fmt.Fprintf(&b, "FINDING %s: zone transfer ALLOWED (%d records offered)\n", host, count)
		} else {
			fmt.Fprintf(&b, "%s: refused or empty (0 records)\n", host)
		}
	}
	if !anySuccess {
		b.WriteString("verdict: no permissive zone transfer found\n")
	}
	return b.String(), nil
}

// buildAXFRQuery assembles a minimal DNS AXFR request: header + one question.
func buildAXFRQuery(domain string) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], 0x5EED) // transaction id
	binary.BigEndian.PutUint16(q[2:4], 0)      // standard query
	binary.BigEndian.PutUint16(q[4:6], 1)      // QDCOUNT
	var body []byte
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		body = append(body, byte(len(label)))
		body = append(body, []byte(label)...)
	}
	body = append(body, 0)          // root label
	body = append(body, 0x00, 0xFC) // QTYPE 252 = AXFR
	body = append(body, 0x00, 0x01) // QCLASS IN
	msg := append(q, body...)
	// TCP framing: 2-byte length prefix.
	frame := make([]byte, 2, len(msg)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(msg)))
	return append(frame, msg...)
}

// readAXFRAnswerCount reads the first framed response and returns ANCOUNT.
func readAXFRAnswerCount(conn net.Conn) (int, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf))
	if n < 12 {
		return 0, fmt.Errorf("short DNS frame (%d bytes)", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(msg[6:8])), nil // ANCOUNT
}
