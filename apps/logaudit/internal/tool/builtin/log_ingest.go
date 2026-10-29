package builtin

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"reasonix/internal/evidence"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(logIngest{}) }

type logIngest struct{}

func (logIngest) Name() string { return "log_ingest" }

func (logIngest) Description() string {
	return "Ingest a log file into the session's normalized log store for later anomaly detection and correlation. Supports nginx/apache combined or common log, syslog, JSON-lines, CSV, and generic text. Extracts source IP, timestamp, method, request path, status, user agent, and message fields."
}

func (logIngest) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"path":{"type":"string","description":"Path to the log file to ingest"},
	"format":{"type":"string","description":"Log format: auto (default), nginx, apache, syslog, json, csv, generic"},
	"limit":{"type":"integer","description":"Maximum number of lines to ingest (default 100000, max 500000)"},
	"tail":{"type":"boolean","description":"Read the last N lines instead of the first N (default false)"},
	"delimiter":{"type":"string","description":"CSV delimiter when format=csv (default comma)"},
	"persist":{"type":"boolean","description":"Append parsed records to the on-disk JSONL store under REASONIX_HOME/logaudit for later log_query searches (default false)"},
	"persist_retention_days":{"type":"integer","description":"When persist=true, purge stored records older than this many days (default 90; set 0 to disable purging)"}
},
"required":["path"]
}`)
}

func (logIngest) ReadOnly() bool { return true }

func (logIngest) Execute(_ context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Path                 string `json:"path"`
		Format               string `json:"format"`
		Limit                int    `json:"limit"`
		Tail                 bool   `json:"tail"`
		Delimiter            string `json:"delimiter"`
		Persist              bool   `json:"persist"`
		PersistRetentionDays int    `json:"persist_retention_days"`
	}{Format: "auto", Limit: 100000, Delimiter: ",", PersistRetentionDays: 90}
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
	if p.Limit > 500000 {
		p.Limit = 500000
	}

	abs, err := filepath.Abs(p.Path)
	if err != nil {
		abs = p.Path
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("cannot access log file: %w", err)
	}
	if fi.IsDir() {
		return "", fmt.Errorf("path is a directory, not a log file: %s", abs)
	}

	f, err := os.Open(abs)
	if err != nil {
		return "", fmt.Errorf("cannot open log file: %w", err)
	}
	defer f.Close()

	lines, err := readLogLines(f, p.Tail, p.Limit)
	if err != nil {
		return "", fmt.Errorf("cannot read log file: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(p.Format))
	if format == "" {
		format = "auto"
	}
	records, skipped := parseLogLines(abs, format, p.Delimiter, lines)
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

	uniqueIPs, methods, statuses, firstTS, lastTS := summarizeRecords(records)
	var b strings.Builder
	fmt.Fprintf(&b, "Log ingest: %s\n", abs)
	fmt.Fprintf(&b, "Format: %s | Parsed: %d | Skipped: %d | Limit: %d | Tail: %v\n",
		format, len(records), skipped, p.Limit, p.Tail)
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
	if len(records) == 0 {
		b.WriteString("No records parsed. Check the format or path; use format=json/csv/generic when auto-detection fails.\n")
	}

	evidence.Global.Add(&evidence.Finding{
		ID:          "log_ingest:" + abs,
		Target:      abs,
		Tool:        "log_ingest",
		Severity:    evidence.SeverityInfo,
		Title:       fmt.Sprintf("Ingested %d log records from %s", len(records), abs),
		Description: fmt.Sprintf("Parsed %d records using %s format; skipped %d lines.", len(records), format, skipped),
		Evidence:    evidenceSnippets(records, 5),
		Metadata: map[string]any{
			"format":     format,
			"records":    len(records),
			"skipped":    skipped,
			"unique_ips": uniqueIPs,
			"tail":       p.Tail,
			"persisted":  persisted,
			"purged":     purged,
		},
	})
	return strings.TrimSpace(b.String()), nil
}

func readLogLines(f *os.File, tail bool, limit int) ([]string, error) {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if tail {
			lines = append(lines, line)
			if len(lines) > limit {
				copy(lines, lines[len(lines)-limit:])
				lines = lines[:limit]
			}
		} else {
			lines = append(lines, line)
			if len(lines) >= limit {
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

var (
	combinedLogRe = regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) ([^"]*)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"`)
	commonLogRe   = regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) ([^"]*)" (\d{3}) (\d+|-)`)
	syslogRe      = regexp.MustCompile(`^(?:<(\d+)>)?([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+(?:\.\d+)?)\s+(\S+)\s+([^:]+):\s*(.*)$`)
	ipPrefixRe    = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3})\s+(.*)$`)
	// sshd and friends put the remote IP mid-message: "Failed password for
	// root from 1.2.3.4 port 22 ssh2" or "... rhost=1.2.3.4 user=root".
	sshdFromIPRe = regexp.MustCompile(`(?:\bfrom|\brhost=)\s*(\d{1,3}(?:\.\d{1,3}){3})\b`)
)

var timeLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05",
	"02/Jan/2006:15:04:05 -0700",
	"02/Jan/2006:15:04:05",
	"Jan _2 15:04:05",
	"Jan 2 15:04:05",
	"2006-01-02",
}

func parseLogLines(source, format, delimiter string, lines []string) ([]LogRecord, int) {
	if format == "auto" || format == "" {
		format = detectLogFormat(lines)
	}
	var records []LogRecord
	skipped := 0

	if format == "csv" {
		var header []string
		for _, line := range lines {
			line = strings.TrimSuffix(line, "\r")
			if strings.TrimSpace(line) == "" {
				continue
			}
			if header == nil {
				fields, err := splitCSVFields(line, delimiter)
				if err == nil && csvLooksLikeHeader(fields) {
					header = fields
					continue
				}
			}
			r, ok := parseCSVLine(source, delimiter, line, header)
			if !ok {
				skipped++
				continue
			}
			records = append(records, r)
		}
		return records, skipped
	}

	for _, line := range lines {
		r, ok := parseLogLine(source, format, delimiter, line)
		if !ok {
			skipped++
			continue
		}
		records = append(records, r)
	}
	return records, skipped
}

func detectLogFormat(lines []string) string {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "{") {
			return "json"
		}
		if combinedLogRe.MatchString(trimmed) {
			return "nginx"
		}
		if commonLogRe.MatchString(trimmed) {
			return "apache"
		}
		if syslogRe.MatchString(trimmed) {
			return "syslog"
		}
		if strings.Contains(trimmed, ",") {
			return "csv"
		}
	}
	return "generic"
}

func parseLogLine(source, format, delimiter, line string) (LogRecord, bool) {
	line = strings.TrimSuffix(line, "\r")
	if strings.TrimSpace(line) == "" {
		return LogRecord{}, false
	}
	switch format {
	case "json":
		return parseJSONLogLine(source, line)
	case "nginx", "apache":
		return parseWebLogLine(source, format, line)
	case "syslog":
		return parseSyslogLine(source, line)
	case "generic":
		return parseGenericLine(source, line)
	default:
		return LogRecord{}, false
	}
}

func parseWebLogLine(source, format, line string) (LogRecord, bool) {
	if m := combinedLogRe.FindStringSubmatch(line); m != nil {
		r := LogRecord{
			Source:    source,
			Format:    format,
			SourceIP:  m[1],
			User:      m[3],
			Method:    m[5],
			Request:   m[6],
			Status:    parseInt(m[7]),
			Bytes:     parseInt64(m[8]),
			Referer:   trimQuotes(m[9]),
			UserAgent: trimQuotes(m[10]),
			Raw:       line,
		}
		r.Timestamp = parseAnyTime(m[4])
		r.Path = requestPath(m[6])
		return r, true
	}
	if m := commonLogRe.FindStringSubmatch(line); m != nil {
		r := LogRecord{
			Source:   source,
			Format:   format,
			SourceIP: m[1],
			User:     m[3],
			Method:   m[5],
			Request:  m[6],
			Status:   parseInt(m[7]),
			Bytes:    parseInt64(m[8]),
			Raw:      line,
		}
		r.Timestamp = parseAnyTime(m[4])
		r.Path = requestPath(m[6])
		return r, true
	}
	return parseGenericLine(source, line)
}

func parseSyslogLine(source, line string) (LogRecord, bool) {
	m := syslogRe.FindStringSubmatch(line)
	if m == nil {
		return parseGenericLine(source, line)
	}
	r := LogRecord{
		Source:  source,
		Format:  "syslog",
		Host:    m[3],
		Process: m[4],
		Message: m[5],
		Raw:     line,
	}
	r.Timestamp = parseSyslogTime(m[2])
	msg := m[5]
	if pm := ipPrefixRe.FindStringSubmatch(msg); pm != nil {
		r.SourceIP = pm[1]
	} else if pm := sshdFromIPRe.FindStringSubmatch(msg); pm != nil {
		r.SourceIP = pm[1]
	}
	return r, true
}

func parseSyslogTime(s string) time.Time {
	if t, err := time.Parse("Jan _2 15:04:05", s); err == nil {
		now := time.Now()
		return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), now.Location())
	}
	return parseAnyTime(s)
}

func parseJSONLogLine(source, line string) (LogRecord, bool) {
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return LogRecord{}, false
	}
	r := LogRecord{
		Source:    source,
		Format:    "json",
		Timestamp: firstJSONTime(m, "timestamp", "time", "@timestamp", "datetime", "date", "event_time"),
		Host:      firstJSONString(m, "host", "hostname", "server"),
		SourceIP:  firstJSONString(m, "ip", "client_ip", "source_ip", "remote_addr", "src_ip", "clientaddr"),
		User:      firstJSONString(m, "user", "username", "auth_user", "user_id"),
		Method:    firstJSONString(m, "method", "request_method", "verb"),
		Request:   firstJSONString(m, "request", "uri", "url", "request_uri", "path"),
		Status:    firstJSONInt(m, "status", "response", "http_status", "response_status", "code"),
		Bytes:     firstJSONInt64(m, "bytes", "size", "body_bytes_sent", "response_size"),
		Referer:   firstJSONString(m, "referer", "referrer"),
		UserAgent: firstJSONString(m, "user_agent", "ua", "agent"),
		Message:   firstJSONString(m, "message", "msg", "log", "event"),
		Process:   firstJSONString(m, "process", "program", "ident"),
		Raw:       line,
	}
	if r.Request != "" {
		r.Path = requestPath(r.Request)
	}
	return r, true
}

// parseGenericLine is the last-resort parser. To keep garbage/truncated
// lines from polluting the normalized store (and silently skipping the
// Skipped counter), a line is only accepted when it carries an IPv4
// prefix or a parseable timestamp.
func parseGenericLine(source, line string) (LogRecord, bool) {
	r := LogRecord{Source: source, Format: "generic", Raw: line}
	accepted := false
	if m := ipPrefixRe.FindStringSubmatch(line); m != nil {
		r.SourceIP = m[1]
		r.Message = m[2]
		accepted = true
	} else {
		r.Message = line
	}
	fields := strings.Fields(line)
	if len(fields) > 0 {
		r.Timestamp = parseAnyTime(fields[0])
		if r.Timestamp.IsZero() {
			r.Timestamp = parseAnyTime(line)
		}
		if !r.Timestamp.IsZero() {
			accepted = true
		}
	}
	if !accepted {
		return LogRecord{}, false
	}
	return r, true
}

func splitCSVFields(line, delimiter string) ([]string, error) {
	r := csv.NewReader(strings.NewReader(line))
	r.Comma = firstRune(delimiter, ',')
	r.FieldsPerRecord = -1
	return r.Read()
}

func csvLooksLikeHeader(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	lower := strings.ToLower(strings.Join(fields, " "))
	for _, key := range []string{"timestamp", "time", "date", "ip", "client", "src", "status", "method", "request", "path", "user", "message"} {
		if strings.Contains(lower, key) {
			return true
		}
	}
	return false
}

func parseCSVLine(source, delimiter, line string, header []string) (LogRecord, bool) {
	fields, err := splitCSVFields(line, delimiter)
	if err != nil || len(fields) == 0 {
		return LogRecord{}, false
	}
	r := LogRecord{Source: source, Format: "csv", Raw: line}
	if len(header) > 0 {
		for i, name := range header {
			if i >= len(fields) {
				break
			}
			applyCSVField(&r, name, fields[i])
		}
		return r, true
	}
	switch {
	case len(fields) >= 7:
		r.Timestamp = parseAnyTime(fields[0])
		r.SourceIP = fields[1]
		r.User = fields[2]
		r.Method = fields[3]
		r.Request = fields[4]
		r.Path = requestPath(fields[4])
		r.Status = parseInt(fields[5])
		r.Bytes = parseInt64(fields[6])
		r.Message = strings.Join(fields[7:], ",")
	case len(fields) >= 5:
		r.Timestamp = parseAnyTime(fields[0])
		r.SourceIP = fields[1]
		r.Method = fields[2]
		r.Request = fields[3]
		r.Path = requestPath(fields[3])
		r.Status = parseInt(fields[4])
		r.Message = strings.Join(fields[5:], ",")
	case len(fields) >= 3:
		r.Timestamp = parseAnyTime(fields[0])
		r.SourceIP = fields[1]
		r.Message = strings.Join(fields[2:], ",")
	default:
		r.Message = line
	}
	return r, true
}

func applyCSVField(r *LogRecord, name, value string) {
	name = strings.ToLower(strings.TrimSpace(name))
	value = strings.TrimSpace(value)
	switch {
	case name == "timestamp" || name == "time" || name == "date" || strings.Contains(name, "datetime"):
		r.Timestamp = parseAnyTime(value)
	case name == "ip" || name == "client_ip" || name == "source_ip" || name == "remote_addr" || name == "src_ip":
		r.SourceIP = value
	case name == "user" || name == "username" || name == "auth_user" || name == "user_id":
		r.User = value
	case name == "method" || name == "request_method":
		r.Method = value
	case name == "request" || name == "uri" || name == "url" || name == "request_uri" || name == "path":
		r.Request = value
		r.Path = requestPath(value)
	case name == "status" || name == "response" || name == "http_status" || name == "response_status" || name == "code":
		r.Status = parseInt(value)
	case name == "bytes" || name == "size" || name == "body_bytes_sent" || name == "response_size":
		r.Bytes = parseInt64(value)
	case name == "referer" || name == "referrer":
		r.Referer = value
	case name == "user_agent" || name == "ua" || name == "agent":
		r.UserAgent = value
	case name == "host" || name == "hostname" || name == "server":
		r.Host = value
	case name == "process" || name == "program" || name == "ident":
		r.Process = value
	case name == "message" || name == "msg" || name == "log" || name == "event":
		r.Message = value
	default:
		if r.Message == "" {
			r.Message = value
		}
	}
}

func firstJSONString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		for mk, mv := range m {
			if !strings.EqualFold(mk, key) {
				continue
			}
			switch v := mv.(type) {
			case string:
				return v
			case float64:
				return strconv.FormatFloat(v, 'f', -1, 64)
			case json.Number:
				return v.String()
			}
		}
	}
	return ""
}

func firstJSONInt(m map[string]any, keys ...string) int {
	for _, key := range keys {
		for mk, mv := range m {
			if !strings.EqualFold(mk, key) {
				continue
			}
			switch v := mv.(type) {
			case float64:
				return int(v)
			case json.Number:
				n, _ := v.Int64()
				return int(n)
			case string:
				return parseInt(v)
			}
		}
	}
	return 0
}

func firstJSONInt64(m map[string]any, keys ...string) int64 {
	return int64(firstJSONInt(m, keys...))
}

func firstJSONTime(m map[string]any, keys ...string) time.Time {
	return parseAnyTime(firstJSONString(m, keys...))
}

func parseAnyTime(s string) time.Time {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func requestPath(request string) string {
	fields := strings.Fields(request)
	if len(fields) > 0 {
		return fields[0]
	}
	return request
}

func parseInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func parseInt64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func trimQuotes(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"`)
}

func firstRune(s string, def rune) rune {
	if s == "" {
		return def
	}
	for _, r := range s {
		return r
	}
	return def
}

func summarizeRecords(records []LogRecord) (int, map[string]int, map[int]int, time.Time, time.Time) {
	ips := map[string]bool{}
	methods := map[string]int{}
	statuses := map[int]int{}
	var first, last time.Time
	for _, r := range records {
		if r.SourceIP != "" {
			ips[r.SourceIP] = true
		}
		if r.Method != "" {
			methods[strings.ToUpper(r.Method)]++
		}
		if r.Status > 0 {
			statuses[r.Status]++
		}
		if !r.Timestamp.IsZero() {
			if first.IsZero() || r.Timestamp.Before(first) {
				first = r.Timestamp
			}
			if last.IsZero() || r.Timestamp.After(last) {
				last = r.Timestamp
			}
		}
	}
	return len(ips), methods, statuses, first, last
}

func formatCountsString(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func formatIntCountsString(m map[int]int) string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortInts(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func sortStrings(s []string) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

func sortInts(s []int) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}
