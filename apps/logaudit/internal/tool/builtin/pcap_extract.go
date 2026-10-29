package builtin

// pcap_extract parses classic pcap captures with the standard library only
// (no libpcap / CGO, keeping the CGO_ENABLED=0 build convention), extracts
// HTTP transactions from TCP payloads, and feeds them into the session log
// store as normalized LogRecords. POST body snippets are kept so webshell
// command indicators can be surfaced as evidence. Limitations: payloads are
// reassembled in capture order (no full TCP sequence reconstruction) and
// responses are paired to requests by order within a flow; pcapng is not
// supported.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"reasonix/internal/evidence"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(pcapExtract{}) }

type pcapExtract struct{}

func (pcapExtract) Name() string { return "pcap_extract" }

func (pcapExtract) Description() string {
	return "Extract HTTP transactions from a classic pcap capture file (pure Go, no libpcap) and ingest them into the session log store. Recovers method, path, status, user agent and a POST body snippet per request; flags webshell command indicators found in request bodies. pcapng is not supported."
}

func (pcapExtract) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"path":{"type":"string","description":"Path to the pcap capture file"},
	"limit":{"type":"integer","description":"Maximum number of HTTP transactions to extract (default 100000)"},
	"body_capture":{"type":"integer","description":"Maximum bytes of each request body kept as evidence snippet (default 512, max 4096)"},
	"persist":{"type":"boolean","description":"Append extracted records to the on-disk JSONL store under REASONIX_HOME/logaudit (default false)"},
	"persist_retention_days":{"type":"integer","description":"When persist=true, purge stored records older than this many days (default 90; set 0 to disable purging)"}
},
"required":["path"]
}`)
}

func (pcapExtract) ReadOnly() bool { return true }

const pcapMaxStreamBytes = 4 << 20 // 4 MiB per directional stream

// pcapStream accumulates one directional TCP payload in capture order.
type pcapStream struct {
	data     []byte
	segStart []int
	segTS    []time.Time
	trunc    bool
}

func (s *pcapStream) append(b []byte, ts time.Time) {
	if s.trunc || len(s.data)+len(b) > pcapMaxStreamBytes {
		s.trunc = true
		return
	}
	s.segStart = append(s.segStart, len(s.data))
	s.segTS = append(s.segTS, ts)
	s.data = append(s.data, b...)
}

// tsAt returns the timestamp of the segment covering byte offset off.
func (s *pcapStream) tsAt(off int) time.Time {
	for i := len(s.segStart) - 1; i >= 0; i-- {
		if s.segStart[i] <= off {
			return s.segTS[i]
		}
	}
	if len(s.segTS) > 0 {
		return s.segTS[0]
	}
	return time.Time{}
}

type pcapTx struct {
	ts              time.Time
	clientIP        string
	method, target  string
	host, userAgent string
	body            []byte
	status          int
}

// pcapShellIndicators are command-execution markers commonly present in
// webshell request bodies (PHP/JSP families, incl. AntSword traffic).
var pcapShellIndicators = []string{
	"eval(", "assert(", "base64_decode", "gzinflate", "str_rot13",
	"system(", "shell_exec", "passthru(", "popen(", "proc_open",
	"exec(", "whoami", "cmd.exe", "/bin/sh", "/bin/bash",
	"@ini_set", "Runtime.getRuntime", "ProcessBuilder", "antsword",
}

func (pcapExtract) Execute(_ context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Path                 string `json:"path"`
		Limit                int    `json:"limit"`
		BodyCapture          int    `json:"body_capture"`
		Persist              bool   `json:"persist"`
		PersistRetentionDays int    `json:"persist_retention_days"`
	}{Limit: 100000, BodyCapture: 512, PersistRetentionDays: 90}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Path == "" {
		return "", fmt.Errorf("path is required")
	}
	if p.Limit < 1 {
		p.Limit = 1
	}
	if p.Limit > 100000 {
		p.Limit = 100000
	}
	if p.BodyCapture < 0 {
		p.BodyCapture = 0
	}
	if p.BodyCapture > 4096 {
		p.BodyCapture = 4096
	}

	abs, err := filepath.Abs(p.Path)
	if err != nil {
		abs = p.Path
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("cannot access pcap file: %w", err)
	}
	if fi.IsDir() {
		return "", fmt.Errorf("path is a directory, not a pcap file: %s", abs)
	}

	txs, packets, tcpPackets, err := parsePcapFile(abs, p.Limit)
	if err != nil {
		return "", err
	}

	records := pcapTxToRecords(txs, abs, p.BodyCapture)
	globalLogStore.replace(abs, records)

	persistPath, persisted, purged := "", 0, 0
	var persistErr error
	if p.Persist {
		retention := p.PersistRetentionDays
		if retention < 0 {
			retention = 0
		}
		persistPath, persisted, purged, persistErr = persistLogRecords(records, retention)
	}

	indicators, hitIPs := pcapIndicatorScan(txs)
	uniqueIPs, methods, statuses, firstTS, lastTS := summarizeRecords(records)

	var b strings.Builder
	fmt.Fprintf(&b, "Pcap extract: %s\n", abs)
	fmt.Fprintf(&b, "Packets: %d | TCP payload packets: %d | HTTP transactions: %d\n", packets, tcpPackets, len(txs))
	if !firstTS.IsZero() {
		fmt.Fprintf(&b, "Time range: %s -> %s\n", firstTS.Format("2006-01-02 15:04:05"), lastTS.Format("2006-01-02 15:04:05"))
	}
	fmt.Fprintf(&b, "Unique source IPs: %d | Session records: %d\n", uniqueIPs, globalLogStore.count())
	if p.Persist {
		if persistErr != nil {
			fmt.Fprintf(&b, "Persist: failed (%v)\n", persistErr)
		} else {
			fmt.Fprintf(&b, "Persist: %d records appended, %d expired purged -> %s\n", persisted, purged, persistPath)
		}
	}
	if len(methods) > 0 {
		fmt.Fprintf(&b, "Methods: %s\n", formatCountsString(methods))
	}
	if len(statuses) > 0 {
		fmt.Fprintf(&b, "Status: %s\n", formatIntCountsString(statuses))
	}
	if indicators > 0 {
		ips := make([]string, 0, len(hitIPs))
		for ip := range hitIPs {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		fmt.Fprintf(&b, "Webshell body indicators: %d hits from %s\n", indicators, strings.Join(ips, ", "))
	}
	if len(txs) == 0 {
		b.WriteString("No HTTP transactions found. Only classic pcap with IPv4/TCP plaintext HTTP is supported; pcapng and TLS traffic are not.\n")
	}

	evidence.Global.Add(&evidence.Finding{
		ID:          "pcap_extract:" + abs,
		Target:      abs,
		Tool:        "pcap_extract",
		Severity:    evidence.SeverityInfo,
		Title:       fmt.Sprintf("Extracted %d HTTP transactions from %s", len(txs), abs),
		Description: fmt.Sprintf("Parsed %d packets (%d TCP payload); recovered %d HTTP transactions.", packets, tcpPackets, len(txs)),
		Evidence:    evidenceSnippets(records, 5),
		Metadata: map[string]any{
			"packets":     packets,
			"tcp_packets": tcpPackets,
			"records":     len(records),
			"unique_ips":  uniqueIPs,
			"persisted":   persisted,
			"purged":      purged,
		},
	})
	if indicators > 0 {
		var ev []string
		for _, tx := range txs {
			snip := sanitizeBodySnippet(tx.body, p.BodyCapture)
			if snip == "" {
				continue
			}
			ev = append(ev, fmt.Sprintf("%s %s from %s | body: %s", tx.method, tx.target, tx.clientIP, snip))
			if len(ev) >= 5 {
				break
			}
		}
		ips := make([]string, 0, len(hitIPs))
		for ip := range hitIPs {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		evidence.Global.Add(&evidence.Finding{
			ID:          "pcap_extract:webshell-body:" + abs,
			Target:      abs,
			Tool:        "pcap_extract",
			Severity:    evidence.SeverityHigh,
			Title:       fmt.Sprintf("Webshell command indicators in %d HTTP request bodies", indicators),
			Description: fmt.Sprintf("Request bodies captured from %s contain command-execution markers typical of webshell traffic (e.g. AntSword). Final threat qualification belongs to the brain.", strings.Join(ips, ", ")),
			Evidence:    strings.Join(ev, "\n"),
			Metadata: map[string]any{
				"indicator_hits": indicators,
				"source_ips":     ips,
			},
		})
	}
	return strings.TrimSpace(b.String()), nil
}

// parsePcapFile reads a classic pcap and returns extracted HTTP transactions.
func parsePcapFile(path string, limit int) ([]pcapTx, int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("cannot open pcap file: %w", err)
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 256*1024)

	var hdr [24]byte
	if _, err := readFull(r, hdr[:]); err != nil {
		return nil, 0, 0, fmt.Errorf("truncated pcap global header: %w", err)
	}
	var bo binary.ByteOrder
	switch binary.BigEndian.Uint32(hdr[:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		bo = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		bo = binary.LittleEndian
	case 0x0a0d0d0a:
		return nil, 0, 0, fmt.Errorf("pcapng format is not supported; convert with `editcap -F pcap` first")
	default:
		return nil, 0, 0, fmt.Errorf("unknown pcap magic %x", hdr[:4])
	}
	linkType := bo.Uint32(hdr[20:24])
	streams := map[string]*pcapStream{}
	var recHdr [16]byte
	packets, tcpPackets := 0, 0
	for {
		if _, err := readFull(r, recHdr[:]); err != nil {
			break // EOF or truncated tail: keep what we have
		}
		tsSec := bo.Uint32(recHdr[0:4])
		tsFrac := bo.Uint32(recHdr[4:8])
		inclLen := bo.Uint32(recHdr[8:12])
		if inclLen > 262144 {
			return nil, 0, 0, fmt.Errorf("implausible packet length %d at packet %d", inclLen, packets)
		}
		pkt := make([]byte, inclLen)
		if _, err := readFull(r, pkt); err != nil {
			break
		}
		packets++
		ts := time.Unix(int64(tsSec), int64(tsFrac)*1000)

		flow, ok := pcapParsePacket(pkt, linkType)
		if !ok {
			continue
		}
		tcpPackets++
		if len(streams) > 20000 {
			continue // bound memory on huge captures
		}
		key := flowKey(flow, true)
		if _, ok := streams[key]; !ok {
			streams[key] = &pcapStream{}
		}
		streams[key].append(flow.payload, ts)
	}
	return pcapExtractHTTP(streams, limit), packets, tcpPackets, nil
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

type pcapFlow struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	payload          []byte
}

func flowKey(f pcapFlow, dir bool) string {
	if dir {
		return fmt.Sprintf("%s:%d>%s:%d", f.srcIP, f.srcPort, f.dstIP, f.dstPort)
	}
	return fmt.Sprintf("%s:%d>%s:%d", f.dstIP, f.dstPort, f.srcIP, f.srcPort)
}

// pcapParsePacket extracts the IPv4/TCP payload of one captured packet.
func pcapParsePacket(pkt []byte, linkType uint32) (pcapFlow, bool) {
	var ip []byte
	switch linkType {
	case 1: // Ethernet
		if len(pkt) < 14 {
			return pcapFlow{}, false
		}
		etherType := binary.BigEndian.Uint16(pkt[12:14])
		off := 14
		if etherType == 0x8100 && len(pkt) >= 18 { // single VLAN tag
			etherType = binary.BigEndian.Uint16(pkt[16:18])
			off = 18
		}
		if etherType != 0x0800 {
			return pcapFlow{}, false
		}
		ip = pkt[off:]
	case 0, 101: // NULL/loopback (4-byte family header) or raw IPv4
		if linkType == 0 {
			if len(pkt) < 4 {
				return pcapFlow{}, false
			}
			family := binary.LittleEndian.Uint32(pkt[:4])
			if family == 28 { // AF_INET6
				return pcapFlow{}, false
			}
			if family != 2 { // AF_INET
				// some captures store the family big-endian
				if binary.BigEndian.Uint32(pkt[:4]) != 2 {
					return pcapFlow{}, false
				}
			}
			pkt = pkt[4:]
		}
		ip = pkt
	default:
		return pcapFlow{}, false
	}
	if len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != 6 { // IPv4 + TCP only
		return pcapFlow{}, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl+20 {
		return pcapFlow{}, false
	}
	tcp := ip[ihl:]
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return pcapFlow{}, false
	}
	body := tcp[dataOff:]
	if len(body) == 0 {
		return pcapFlow{}, false
	}
	return pcapFlow{
		srcIP:   fmt.Sprintf("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15]),
		dstIP:   fmt.Sprintf("%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19]),
		srcPort: binary.BigEndian.Uint16(tcp[0:2]),
		dstPort: binary.BigEndian.Uint16(tcp[2:4]),
		payload: body,
	}, true
}

// pcapExtractHTTP pairs directional streams into request/response flows and
// parses HTTP transactions from them (capture-order reassembly).
func pcapExtractHTTP(streams map[string]*pcapStream, limit int) []pcapTx {
	keys := make([]string, 0, len(streams))
	for k := range streams {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	var txs []pcapTx
	for _, k := range keys {
		if seen[k] {
			continue
		}
		rev := reverseFlowKey(k)
		seen[k] = true
		seen[rev] = true
		a, b := streams[k], streams[rev]
		if b == nil {
			b = &pcapStream{}
		}
		reqs, reqStream := pcapParseRequests(a), a
		clientKey := k
		if len(reqs) == 0 {
			reqs = pcapParseRequests(b)
			reqStream, a, b = b, b, a
			clientKey = rev
		}
		if len(reqs) == 0 {
			continue
		}
		clientIP := clientKey[:strings.Index(clientKey, ":")]
		statuses := pcapParseStatuses(b)
		for i, rq := range reqs {
			if len(txs) >= limit {
				return txs
			}
			tx := pcapTx{
				ts:        reqStream.tsAt(rq.off),
				clientIP:  clientIP,
				method:    rq.method,
				target:    rq.target,
				host:      rq.host,
				userAgent: rq.userAgent,
				body:      rq.body,
			}
			if i < len(statuses) {
				tx.status = statuses[i]
			}
			txs = append(txs, tx)
		}
	}
	return txs
}

func reverseFlowKey(k string) string {
	gt := strings.Index(k, ">")
	col := strings.Index(k, ":")
	if gt < 0 || col < 0 {
		return k
	}
	return k[gt+1:] + ">" + k[:gt]
}

type pcapReq struct {
	off       int
	method    string
	target    string
	host      string
	userAgent string
	body      []byte
}

var pcapHdrEnd = []byte("\r\n\r\n")

// pcapParseRequests walks a reassembled client stream and splits it into
// pipelined/keep-alive HTTP requests.
func pcapParseRequests(s *pcapStream) []pcapReq {
	var reqs []pcapReq
	data := s.data
	off := 0
	for off < len(data) && len(reqs) < 100000 {
		idx := bytes.Index(data[off:], pcapHdrEnd)
		if idx < 0 {
			break
		}
		hdrEnd := off + idx
		head := data[off:hdrEnd]
		lineEnd := bytes.IndexByte(head, '\n')
		if lineEnd <= 0 {
			break
		}
		parts := strings.Fields(strings.TrimRight(string(head[:lineEnd]), "\r"))
		if len(parts) != 3 || !pcapMethodSet[parts[0]] || !strings.HasPrefix(parts[2], "HTTP/1.") {
			break
		}
		rq := pcapReq{off: off, method: parts[0], target: parts[1]}
		for _, line := range strings.Split(string(head[lineEnd+1:]), "\n") {
			line = strings.TrimRight(line, "\r")
			ci := strings.IndexByte(line, ':')
			if ci <= 0 {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(line[:ci]))
			val := strings.TrimSpace(line[ci+1:])
			switch name {
			case "host":
				rq.host = val
			case "user-agent":
				rq.userAgent = val
			}
		}
		bodyLen := pcapContentLength(head)
		bodyStart := hdrEnd + 4
		if bodyLen > 0 && bodyStart < len(data) {
			end := bodyStart + bodyLen
			if end > len(data) {
				end = len(data)
			}
			rq.body = data[bodyStart:end]
		}
		reqs = append(reqs, rq)
		off = bodyStart + bodyLen
		if off <= hdrEnd {
			off = hdrEnd + 4
		}
	}
	return reqs
}

func pcapContentLength(head []byte) int {
	for _, line := range strings.Split(string(head), "\n") {
		line = strings.TrimRight(line, "\r")
		ci := strings.IndexByte(line, ':')
		if ci <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:ci]), "content-length") {
			n, err := strconv.Atoi(strings.TrimSpace(line[ci+1:]))
			if err == nil && n >= 0 && n <= pcapMaxStreamBytes {
				return n
			}
		}
	}
	return 0
}

// pcapParseStatuses collects response status codes in order from a server
// stream (first status line of each HTTP response).
func pcapParseStatuses(s *pcapStream) []int {
	var out []int
	rest := s.data
	marker := []byte("HTTP/1.")
	for len(out) < 100000 {
		idx := bytes.Index(rest, marker)
		if idx < 0 {
			break
		}
		line := rest[idx:]
		if nl := bytes.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		fields := strings.Fields(strings.TrimRight(string(line), "\r"))
		if len(fields) >= 2 {
			if code, err := strconv.Atoi(fields[1]); err == nil && code >= 100 && code < 600 {
				out = append(out, code)
			}
		}
		rest = rest[idx+len(marker):]
	}
	return out
}

var pcapMethodSet = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true,
	"OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
}

func pcapTxToRecords(txs []pcapTx, source string, bodyCapture int) []LogRecord {
	records := make([]LogRecord, 0, len(txs))
	for _, tx := range txs {
		r := LogRecord{
			Source:    source,
			Format:    "pcap",
			Timestamp: tx.ts,
			Host:      tx.host,
			SourceIP:  tx.clientIP,
			Method:    tx.method,
			Request:   fmt.Sprintf("%s %s HTTP/1.1", tx.method, tx.target),
			Path:      tx.target,
			Status:    tx.status,
			UserAgent: tx.userAgent,
			Raw:       fmt.Sprintf("%s %s", tx.method, tx.target),
		}
		if len(tx.body) > 0 {
			r.Message = "POST body: " + sanitizeBodySnippet(tx.body, bodyCapture)
			r.Bytes = int64(len(tx.body))
		}
		records = append(records, r)
	}
	return records
}

// sanitizeBodySnippet keeps printable characters, collapses whitespace and
// caps the snippet length so raw bytes never leak into reports uncontrolled.
func sanitizeBodySnippet(body []byte, max int) string {
	if max <= 0 || len(body) == 0 {
		return ""
	}
	b := body
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	prevSpace := false
	for _, c := range b {
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			if !prevSpace && sb.Len() > 0 {
				sb.WriteByte(' ')
				prevSpace = true
			}
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
			prevSpace = false
		default:
			sb.WriteByte('.')
			prevSpace = false
		}
	}
	return strings.TrimSpace(sb.String())
}

// pcapIndicatorScan URL-decodes and scans request bodies for webshell markers.
func pcapIndicatorScan(txs []pcapTx) (int, map[string]bool) {
	hits := 0
	ips := map[string]bool{}
	for i := range txs {
		tx := &txs[i]
		if len(tx.body) == 0 {
			continue
		}
		bodies := []string{string(tx.body)}
		if dec, err := url.QueryUnescape(string(tx.body)); err == nil && dec != string(tx.body) {
			bodies = append(bodies, dec)
		}
		for _, body := range bodies {
			lower := strings.ToLower(body)
			for _, ind := range pcapShellIndicators {
				if strings.Contains(lower, ind) {
					hits++
					ips[tx.clientIP] = true
					break
				}
			}
		}
	}
	return hits, ips
}
