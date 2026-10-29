package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(dnsEnum{}) }

type dnsEnum struct{}

func (dnsEnum) Name() string { return "dns_enum" }

func (dnsEnum) Description() string {
	return "Perform DNS enumeration on a domain: query A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV records. Returns structured DNS record data useful for reconnaissance and attack surface mapping."
}

func (dnsEnum) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"domain":{"type":"string","description":"Domain name to enumerate (e.g., example.com)"},
	"record_types":{"type":"string","description":"Comma-separated DNS record types to query: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV. Default: 'A,AAAA,MX,NS,TXT,SOA'"},
	"resolver":{"type":"string","description":"Optional: specific DNS resolver IP to use (e.g., 8.8.8.8). Default: system resolver"}
},
"required":["domain"]
}`)
}

func (dnsEnum) ReadOnly() bool { return true }

func (dnsEnum) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Domain      string `json:"domain"`
		RecordTypes string `json:"record_types"`
		Resolver    string `json:"resolver"`
	}{RecordTypes: "A,AAAA,MX,NS,TXT,SOA"}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Domain == "" {
		return "", fmt.Errorf("domain is required")
	}

	p.Domain = strings.TrimSuffix(strings.TrimSpace(p.Domain), ".")

	var resolver *net.Resolver
	if p.Resolver != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", net.JoinHostPort(p.Resolver, "53"))
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	types := strings.Split(p.RecordTypes, ",")
	var b strings.Builder
	b.WriteString(fmt.Sprintf("DNS enumeration for: %s\n\n", p.Domain))

	for _, t := range types {
		t = strings.TrimSpace(strings.ToUpper(t))
		switch t {
		case "A":
			records, err := resolver.LookupIPAddr(ctx, p.Domain)
			if err != nil {
				b.WriteString(fmt.Sprintf("A: error - %v\n", err))
			} else {
				b.WriteString("A (IPv4):\n")
				for _, r := range records {
					if r.IP.To4() != nil {
						b.WriteString(fmt.Sprintf("  %s\n", r.IP.String()))
					}
				}
			}
		case "AAAA":
			records, err := resolver.LookupIPAddr(ctx, p.Domain)
			if err != nil {
				b.WriteString(fmt.Sprintf("AAAA: error - %v\n", err))
			} else {
				b.WriteString("AAAA (IPv6):\n")
				for _, r := range records {
					if r.IP.To4() == nil {
						b.WriteString(fmt.Sprintf("  %s\n", r.IP.String()))
					}
				}
			}
		case "MX":
			records, err := resolver.LookupMX(ctx, p.Domain)
			if err != nil {
				b.WriteString(fmt.Sprintf("MX: error - %v\n", err))
			} else {
				b.WriteString("MX (Mail Exchange):\n")
				for _, r := range records {
					b.WriteString(fmt.Sprintf("  %s (pref=%d)\n", r.Host, r.Pref))
				}
			}
		case "NS":
			records, err := resolver.LookupNS(ctx, p.Domain)
			if err != nil {
				b.WriteString(fmt.Sprintf("NS: error - %v\n", err))
			} else {
				b.WriteString("NS (Name Server):\n")
				for _, r := range records {
					b.WriteString(fmt.Sprintf("  %s\n", r.Host))
				}
			}
		case "TXT":
			records, err := resolver.LookupTXT(ctx, p.Domain)
			if err != nil {
				b.WriteString(fmt.Sprintf("TXT: error - %v\n", err))
			} else {
				b.WriteString("TXT:\n")
				for _, r := range records {
					b.WriteString(fmt.Sprintf("  %s\n", r))
				}
			}
		case "CNAME":
			cname, err := resolver.LookupCNAME(ctx, p.Domain)
			if err != nil {
				b.WriteString(fmt.Sprintf("CNAME: error - %v\n", err))
			} else {
				b.WriteString(fmt.Sprintf("CNAME: %s\n", cname))
			}
		case "SOA":
			// Go's net resolver doesn't expose SOA directly; attempt via NS
			_, err := resolver.LookupNS(ctx, p.Domain)
			if err != nil {
				b.WriteString(fmt.Sprintf("SOA: error - %v (use bash: dig %s SOA)\n", err, p.Domain))
			} else {
				b.WriteString(fmt.Sprintf("SOA: use bash (dig %s SOA) for full SOA record\n", p.Domain))
			}
		case "PTR":
			// PTR lookup (reverse DNS) for domain's IPs
			ips, err := resolver.LookupIPAddr(ctx, p.Domain)
			if err != nil {
				b.WriteString(fmt.Sprintf("PTR: error resolving A records first - %v\n", err))
			} else {
				b.WriteString("PTR (Reverse):\n")
				for _, ip := range ips {
					names, err := resolver.LookupAddr(ctx, ip.String())
					if err == nil {
						for _, name := range names {
							b.WriteString(fmt.Sprintf("  %s -> %s\n", ip.String(), name))
						}
					} else {
						b.WriteString(fmt.Sprintf("  %s -> (no PTR)\n", ip.String()))
					}
				}
			}
		case "SRV":
			b.WriteString(fmt.Sprintf("SRV: use bash (dig %s SRV) — specify service and protocol via bash\n", p.Domain))
		default:
			b.WriteString(fmt.Sprintf("%s: unsupported record type (use bash: dig %s %s)\n", t, p.Domain, t))
		}
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String()), nil
}
