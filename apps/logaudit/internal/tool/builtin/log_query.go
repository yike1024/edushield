package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(logQuery{}) }

type logQuery struct{}

func (logQuery) Name() string { return "log_query" }

func (logQuery) Description() string {
	return "Search persisted log audit records in the on-disk date-sharded JSONL store written by log_ingest/pcap_extract persist. Filters by source IP, ingested source path, time range, HTTP status, or free-text keyword (case-insensitive); time-range queries only read overlapping shards. With verify=true it recomputes every shard's hash chain to detect tampering. Read-only: never modifies the store."
}

func (logQuery) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"ip":{"type":"string","description":"Match records with this exact source IP"},
	"source":{"type":"string","description":"Match records ingested from this source path (exact)"},
	"since":{"type":"string","description":"Include records at or after this time (any common log timestamp format)"},
	"until":{"type":"string","description":"Include records at or before this time (any common log timestamp format)"},
	"status":{"type":"integer","description":"Match records with this exact HTTP status code"},
	"keyword":{"type":"string","description":"Case-insensitive substring matched against the record text"},
	"limit":{"type":"integer","description":"Maximum records to display (default 50, max 500)"},
	"verify":{"type":"boolean","description":"Instead of searching, recompute the store hash chain and report integrity (tamper detection)"}
}
}`)
}

func (logQuery) ReadOnly() bool { return true }

func (logQuery) Execute(_ context.Context, args json.RawMessage) (string, error) {
	p := struct {
		IP      string `json:"ip"`
		Source  string `json:"source"`
		Since   string `json:"since"`
		Until   string `json:"until"`
		Status  int    `json:"status"`
		Keyword string `json:"keyword"`
		Limit   int    `json:"limit"`
		Verify  bool   `json:"verify"`
	}{Limit: 50}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Limit < 1 {
		p.Limit = 1
	}
	if p.Limit > 500 {
		p.Limit = 500
	}

	since := parseAnyTime(p.Since)
	until := parseAnyTime(p.Until)
	if p.Since != "" && since.IsZero() {
		return "", fmt.Errorf("cannot parse since time: %s", p.Since)
	}
	if p.Until != "" && until.IsZero() {
		return "", fmt.Errorf("cannot parse until time: %s", p.Until)
	}

	if p.Verify {
		res, err := verifyLogStoreChain()
		if err != nil {
			return "", fmt.Errorf("cannot verify log store: %w", err)
		}
		if res.Total == 0 {
			return "Chain verify: log store is empty, nothing to verify.", nil
		}
		if res.OK {
			return fmt.Sprintf("Chain verify: OK. %d entries verified across all shards, hash chain intact.", res.Total), nil
		}
		return fmt.Sprintf("Chain verify: BROKEN at line %d of %d in %s (legacy un-chained lines: %d). Treat the store as tampered and re-ingest from trusted sources.",
			res.FirstBrokenLine, res.Total, res.FirstBrokenFile, res.Legacy), nil
	}

	records, err := loadPersistedLogRecords(since, until)
	if err != nil {
		return "", fmt.Errorf("cannot read log store: %w", err)
	}
	if len(records) == 0 {
		return "Log store is empty. Ingest logs with log_ingest persist=true first.", nil
	}

	keyword := strings.ToLower(strings.TrimSpace(p.Keyword))
	var matched []LogRecord
	for _, r := range records {
		if p.IP != "" && r.SourceIP != p.IP {
			continue
		}
		if p.Source != "" && r.Source != p.Source {
			continue
		}
		if p.Status > 0 && r.Status != p.Status {
			continue
		}
		if !since.IsZero() && (r.Timestamp.IsZero() || r.Timestamp.Before(since)) {
			continue
		}
		if !until.IsZero() && (r.Timestamp.IsZero() || r.Timestamp.After(until)) {
			continue
		}
		if keyword != "" && !strings.Contains(strings.ToLower(recordText(r)), keyword) {
			continue
		}
		matched = append(matched, r)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Log query: %d matched / %d stored records\n", len(matched), len(records))
	var filters []string
	if p.IP != "" {
		filters = append(filters, "ip="+p.IP)
	}
	if p.Source != "" {
		filters = append(filters, "source="+p.Source)
	}
	if p.Status > 0 {
		filters = append(filters, fmt.Sprintf("status=%d", p.Status))
	}
	if !since.IsZero() {
		filters = append(filters, "since="+since.Format("2006-01-02 15:04:05"))
	}
	if !until.IsZero() {
		filters = append(filters, "until="+until.Format("2006-01-02 15:04:05"))
	}
	if keyword != "" {
		filters = append(filters, "keyword="+p.Keyword)
	}
	if len(filters) > 0 {
		fmt.Fprintf(&b, "Filters: %s\n", strings.Join(filters, ", "))
	}
	if len(matched) == 0 {
		b.WriteString("No records matched the filters.")
		return strings.TrimSpace(b.String()), nil
	}

	sortRecordsOnTimeDesc(matched)
	shown := matched
	if len(shown) > p.Limit {
		shown = shown[:p.Limit]
	}
	b.WriteString("\n")
	for _, r := range shown {
		ts := "-"
		if !r.Timestamp.IsZero() {
			ts = r.Timestamp.Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(&b, "%s | %s | %s\n", ts, orDash(r.SourceIP), recordSnippet(r, 160))
	}
	if len(matched) > p.Limit {
		fmt.Fprintf(&b, "\n(showing %d of %d matches; raise limit to see more)\n", len(shown), len(matched))
	}
	return strings.TrimSpace(b.String()), nil
}

func recordText(r LogRecord) string {
	return strings.Join([]string{r.Raw, r.Message, r.Request, r.Path, r.UserAgent, r.User, r.SourceIP}, " ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sortRecordsOnTimeDesc(records []LogRecord) {
	sortRecordsByTime(records)
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
}
