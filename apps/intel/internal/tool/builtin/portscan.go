package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(portScan{}) }

// portScan performs a TCP connect scan against an authorized target. It is a
// pentest reconnaissance primitive: non-banner connects only complete the
// three-way handshake, so it stays within the noise envelope of ordinary
// health checks while still being an offensive action under the engagement
// policy.
type portScan struct{}

func (portScan) Name() string { return "port_scan" }

func (portScan) Description() string {
	return "TCP connect scan of an authorized host: probe a port list, range (\"80,443,8000-8100\"), or preset (top100/web/db/common) and report open ports with an optional short banner grab. Offensive action - only target hosts the user authorized."
}

func (portScan) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"host":{"type":"string","description":"Target host (IP or hostname) authorized for this engagement"},"ports":{"type":"string","description":"Port list/range, e.g. \"22,80,443,8000-8100\". Overrides preset when set."},"preset":{"type":"string","description":"Named port set when ports is empty: top100, web, db, common (default top100)"},"concurrency":{"type":"integer","description":"Parallel connects, 1-128 (default 64)"},"timeout_ms":{"type":"integer","description":"Per-port connect timeout in ms (default 1000)"},"banner":{"type":"boolean","description":"When true, read a short greeting banner from each open port (default false)"}},"required":["host"]}`)
}

func (portScan) ReadOnly() bool { return false }

// SnipHint keeps the summary header plus the first open ports; the tail
// confirms the scanned range.
func (portScan) SnipHint() tool.SnipHint {
	return tool.SnipHint{Head: 60, Tail: 6, HeadChars: 8000, TailChars: 800}
}

// portPresets are curated reconnaissance port sets.
var portPresets = map[string][]int{
	"web": {80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8888, 3000, 5000, 9090, 9000, 9200, 4443, 18080},
	"db":  {1433, 1521, 3306, 5432, 6379, 27017, 9200, 9300, 11211, 5984, 7001, 50000, 5439, 26257, 9042, 4369},
	"common": {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995,
		1080, 1433, 1521, 1723, 2049, 2181, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5984, 6379,
		8000, 8080, 8443, 8888, 9090, 9200, 11211, 27017},
	"top100": {7, 20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143,
		161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 631, 636, 873, 902, 993, 995,
		1025, 1080, 1194, 1433, 1434, 1521, 1701, 1723, 1812, 2049, 2082, 2083, 2181, 2222, 2375,
		2376, 2379, 3000, 3128, 3268, 3306, 3389, 4443, 5000, 5001, 5432, 5631, 5632, 5900, 5901,
		5984, 5985, 5986, 6379, 6443, 6660, 6667, 7001, 7077, 8000, 8008, 8009, 8080, 8081, 8083,
		8086, 8088, 8123, 8161, 8443, 8500, 8888, 9000, 9001, 9042, 9090, 9091, 9200, 9300, 9418,
		9999, 10000, 11211, 27017, 27018, 50000, 50070, 61616},
}

// parsePortSpec expands a "80,443,8000-8100" style spec into a deduped,
// bounded port list.
func parsePortSpec(spec string) ([]int, error) {
	var ports []int
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(lo))
			end, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || start > end {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			if end-start > 65535 {
				return nil, fmt.Errorf("port range %q too large", part)
			}
			for p := start; p <= end; p++ {
				if p < 1 || p > 65535 {
					return nil, fmt.Errorf("port %d out of range", p)
				}
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if len(ports) > 10000 {
		return nil, fmt.Errorf("too many ports (%d); narrow the range", len(ports))
	}
	sort.Ints(ports)
	return ports, nil
}

type portResult struct {
	port   int
	banner string
}

func (portScan) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Host        string `json:"host"`
		Ports       string `json:"ports"`
		Preset      string `json:"preset"`
		Concurrency int    `json:"concurrency"`
		TimeoutMs   int    `json:"timeout_ms"`
		Banner      bool   `json:"banner"`
	}{Preset: "top100", Concurrency: 64, TimeoutMs: 1000}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if strings.TrimSpace(p.Host) == "" {
		return "", fmt.Errorf("host is required")
	}
	var ports []int
	if strings.TrimSpace(p.Ports) != "" {
		var err error
		ports, err = parsePortSpec(p.Ports)
		if err != nil {
			return "", err
		}
	} else {
		preset, ok := portPresets[strings.ToLower(strings.TrimSpace(p.Preset))]
		if !ok {
			return "", fmt.Errorf("unknown preset %q (want top100, web, db, common)", p.Preset)
		}
		ports = preset
	}
	if p.Concurrency < 1 || p.Concurrency > 128 {
		p.Concurrency = 64
	}
	if p.TimeoutMs < 50 || p.TimeoutMs > 30000 {
		p.TimeoutMs = 1000
	}
	timeout := time.Duration(p.TimeoutMs) * time.Millisecond

	var (
		mu   sync.Mutex
		open []portResult
		wg   sync.WaitGroup
		sem  = make(chan struct{}, p.Concurrency)
	)
	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(p.Host, strconv.Itoa(port)), timeout)
			if err != nil {
				return
			}
			res := portResult{port: port}
			if p.Banner {
				res.banner = grabBanner(conn, 800*time.Millisecond)
			}
			conn.Close()
			mu.Lock()
			open = append(open, res)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i].port < open[j].port })

	var b strings.Builder
	fmt.Fprintf(&b, "TCP connect scan of %s: %d ports probed, %d open\n", p.Host, len(ports), len(open))
	for _, r := range open {
		if r.banner != "" {
			fmt.Fprintf(&b, "%d open\tbanner=%s\n", r.port, r.banner)
		} else {
			fmt.Fprintf(&b, "%d open\n", r.port)
		}
	}
	if len(open) == 0 {
		b.WriteString("(no open ports found - verify the host is up and reachable)\n")
	}
	return b.String(), nil
}

// grabBanner reads a short service greeting (if the service sends one
// unprompted) and sanitizes it to printable text.
func grabBanner(conn net.Conn, wait time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return sanitizeBanner(buf[:n])
}

func sanitizeBanner(raw []byte) string {
	var b strings.Builder
	for _, c := range raw {
		if c == '\n' || c == '\r' {
			break
		}
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
		}
	}
	s := strings.TrimSpace(b.String())
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
