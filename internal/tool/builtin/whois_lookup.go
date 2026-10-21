package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(whoisLookup{}) }

type whoisLookup struct{}

func (whoisLookup) Name() string { return "whois_lookup" }

func (whoisLookup) Description() string {
	return "Query WHOIS information for a domain or IP address. Returns registrar, creation/expiration dates, name servers, and registrant organization. Connects to appropriate WHOIS servers based on TLD."
}

func (whoisLookup) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"target":{"type":"string","description":"Domain name or IP address to look up (e.g., example.com or 1.2.3.4)"},
	"server":{"type":"string","description":"Optional: specify a WHOIS server (e.g., whois.verisign-grs.com). Default: auto-detect from TLD"}
},
"required":["target"]
}`)
}

func (whoisLookup) ReadOnly() bool { return true }

var tldServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"edu":  "whois.educause.net",
	"gov":  "whois.dotgov.gov",
	"cn":   "whois.cnnic.cn",
	"de":   "whois.denic.de",
	"uk":   "whois.nic.uk",
	"io":   "whois.nic.io",
	"info": "whois.afilias.net",
	"biz":  "whois.nic.biz",
	"xyz":  "whois.nic.xyz",
}

func (whoisLookup) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Target string `json:"target"`
		Server string `json:"server"`
	}{}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Target == "" {
		return "", fmt.Errorf("target is required")
	}
	p.Target = strings.TrimSpace(p.Target)

	server := p.Server
	if server == "" {
		server = "whois.iana.org"
		// Determine appropriate WHOIS server from TLD
		parts := strings.Split(p.Target, ".")
		if len(parts) >= 2 {
			tld := strings.ToLower(parts[len(parts)-1])
			if s, ok := tldServers[tld]; ok {
				server = s
			}
		}
		// For IP addresses, use ARIN
		if ip := net.ParseIP(p.Target); ip != nil {
			server = "whois.arin.net"
		}
	}

	addr := net.JoinHostPort(server, "43")
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server %s: %w", server, err)
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "%s\r\n", p.Target); err != nil {
		return "", fmt.Errorf("failed to send query: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	data, err := io.ReadAll(io.LimitReader(conn, 1<<19)) // 512KB max
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	result := string(data)
	if result == "" {
		return "", fmt.Errorf("empty response from WHOIS server %s", server)
	}

	// Parse key fields for structured summary
	var b strings.Builder
	b.WriteString(fmt.Sprintf("WHOIS query for: %s (server: %s)\n\n", p.Target, server))

	lines := strings.Split(result, "\n")
	extracted := map[string]string{}
	keyFields := []string{
		"Registrar", "Creation Date", "Registry Expiry Date", "Updated Date",
		"Name Server", "Registrant Organization", "Registrant Country",
		"Admin Organization", "Tech Organization",
		"Domain Status", "DNSSEC", "Registry Domain ID",
		"Registrar WHOIS Server", "Registrar URL",
	}

	for _, line := range lines {
		for _, key := range keyFields {
			l := strings.ToLower(line)
			if strings.Contains(l, strings.ToLower(key)) {
				idx := strings.Index(l, ":")
				if idx > 0 {
					extracted[key] = strings.TrimSpace(line[idx+1:])
				}
			}
		}
	}

	b.WriteString("--- Summary ---\n")
	printed := map[string]bool{}
	for _, key := range keyFields {
		if val, ok := extracted[key]; ok && !printed[key] {
			b.WriteString(fmt.Sprintf("%s: %s\n", key, val))
			printed[key] = true
		}
	}
	b.WriteString("\n--- Raw Response (truncated) ---\n")
	if len(result) > 2000 {
		b.WriteString(result[:2000] + "\n... [truncated]")
	} else {
		b.WriteString(result)
	}

	return b.String(), nil
}
