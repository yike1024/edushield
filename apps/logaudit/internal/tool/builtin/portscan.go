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

	"reasonix/internal/evidence"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(portScan{}) }

type portScan struct{}

func (portScan) Name() string { return "port_scan" }

func (portScan) Description() string {
	return "Scan TCP ports on a target host to discover open services. Supports common port ranges (top-20, top-100, top-1000, well-known, all) and custom port lists. Returns open ports with service banner grabbing when available. Rate-limited to avoid overwhelming targets."
}

func (portScan) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"target":{"type":"string","description":"Target hostname or IP address to scan"},
	"ports":{"type":"string","description":"Port specification: 'top-20', 'top-100', 'top-1000', 'well-known' (1-1024), 'all' (1-65535), or comma-separated list like '22,80,443,8080-8090'"},
	"timeout_ms":{"type":"integer","description":"Per-port connect timeout in milliseconds (default 2000, min 200, max 10000)"},
	"banner_grab":{"type":"boolean","description":"Attempt to grab service banners from open ports (default true)"}
},
"required":["target"]
}`)
}

func (portScan) ReadOnly() bool { return true }

var top20Ports = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}

var top100Ports = []int{7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9090, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156}

func resolvePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = "top-100"
	}
	switch spec {
	case "top-20":
		return top20Ports, nil
	case "top-100":
		return top100Ports, nil
	case "top-1000", "common":
		all := make([]int, 0, 1024)
		for i := 1; i <= 1024; i++ {
			all = append(all, i)
		}
		return all, nil
	case "well-known":
		all := make([]int, 0, 1024)
		for i := 1; i <= 1024; i++ {
			all = append(all, i)
		}
		return all, nil
	case "all":
		all := make([]int, 0, 65535)
		for i := 1; i <= 65535; i++ {
			all = append(all, i)
		}
		return all, nil
	default:
		var ports []int
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "-") {
				ends := strings.SplitN(part, "-", 2)
				start, end := 0, 0
				if _, err := fmt.Sscanf(ends[0], "%d", &start); err != nil {
					return nil, fmt.Errorf("invalid port range: %s", part)
				}
				if _, err := fmt.Sscanf(ends[1], "%d", &end); err != nil {
					return nil, fmt.Errorf("invalid port range: %s", part)
				}
				for i := start; i <= end && i <= 65535; i++ {
					if i >= 1 {
						ports = append(ports, i)
					}
				}
			} else {
				p := 0
				if _, err := fmt.Sscanf(part, "%d", &p); err != nil {
					return nil, fmt.Errorf("invalid port: %s", part)
				}
				if p >= 1 && p <= 65535 {
					ports = append(ports, p)
				}
			}
		}
		if len(ports) == 0 {
			return nil, fmt.Errorf("no valid ports in spec: %s", spec)
		}
		return ports, nil
	}
}

var portServiceMap = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
	143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
	3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
	6379: "redis", 8080: "http-proxy", 8443: "https-alt", 9090: "websphere",
	27017: "mongodb", 11211: "memcached",
}

func (portScan) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Target    string `json:"target"`
		Ports     string `json:"ports"`
		TimeoutMs int    `json:"timeout_ms"`
		BannerGrab bool  `json:"banner_grab"`
	}{Ports: "top-100", TimeoutMs: 2000, BannerGrab: true}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Target == "" {
		return "", fmt.Errorf("target is required")
	}
	if p.TimeoutMs < 200 {
		p.TimeoutMs = 200
	}
	if p.TimeoutMs > 10000 {
		p.TimeoutMs = 10000
	}

	ports, err := resolvePorts(p.Ports)
	if err != nil {
		return "", err
	}
	if len(ports) > 1000 {
		ports = ports[:1000]
	}

	timeout := time.Duration(p.TimeoutMs) * time.Millisecond

	// Block internal/private network scanning unless explicitly targeting
	if ip := net.ParseIP(p.Target); ip != nil {
		if isPrivateIP(ip) {
			return "", fmt.Errorf("scanning private/internal IP %s is blocked for safety; use the bash tool with explicit authorization if needed", p.Target)
		}
	} else {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, p.Target)
		if err != nil {
			return "", fmt.Errorf("failed to resolve %s: %w", p.Target, err)
		}
		for _, ip := range ips {
			if isPrivateIP(ip.IP) {
				return "", fmt.Errorf("target %s resolves to private IP %s; blocked for safety", p.Target, ip.IP.String())
			}
		}
	}

	type result struct {
		Port    int    `json:"port"`
		Open    bool   `json:"open"`
		Service string `json:"service,omitempty"`
		Banner  string `json:"banner,omitempty"`
	}

	var mu sync.Mutex
	var results []result
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // max concurrency

	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(p.Target, fmt.Sprintf("%d", port))
			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			r := result{Port: port}
			if err == nil {
				r.Open = true
				if svc, ok := portServiceMap[port]; ok {
					r.Service = svc
				}
				if p.BannerGrab {
					conn.SetReadDeadline(time.Now().Add(timeout))
					buf := make([]byte, 256)
					n, _ := conn.Read(buf)
					if n > 0 {
						r.Banner = strings.TrimSpace(string(buf[:n]))
					}
				}
				conn.Close()
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

	var b strings.Builder
	openCount := 0
	for _, r := range results {
		if r.Open {
			openCount++
			fmt.Fprintf(&b, "%-6d OPEN", r.Port)
			if r.Service != "" {
				fmt.Fprintf(&b, "  %s", r.Service)
			}
			if r.Banner != "" {
				fmt.Fprintf(&b, "  [%s]", r.Banner)
			}
			b.WriteString("\n")
		}
	}

	summary := fmt.Sprintf("Port scan of %s: %d ports scanned, %d open\n\n", p.Target, len(results), openCount)

	// Write structured findings to the global FindingStore
	var findings []*evidence.Finding
	for _, r := range results {
		if !r.Open {
			continue
		}
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}
		findings = append(findings, &evidence.Finding{
			ID:       fmt.Sprintf("port_scan:%s:%d", p.Target, r.Port),
			Target:   p.Target,
			Tool:     "port_scan",
			Port:     r.Port,
			Service:  svc,
			Severity: evidence.SeverityInfo,
			Title:    fmt.Sprintf("Open port %d (%s)", r.Port, svc),
			Description: fmt.Sprintf("Port %d on %s is open. Service: %s.", r.Port, p.Target, svc),
			Evidence: r.Banner,
			Metadata: map[string]any{"scan_range": p.Ports},
		})
	}
	evidence.Global.AddFindings(findings)

	return summary + b.String(), nil
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	privateBlocks := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "fc00::/7", "fe80::/10",
	}
	for _, cidr := range privateBlocks {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
