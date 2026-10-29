package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"reasonix/internal/evidence"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(correlationTool{}) }

type correlationTool struct{}

func (correlationTool) Name() string { return "correlation" }

func (correlationTool) Description() string {
	return "Correlate ingested log records into attack timelines and multi-source chains: credential-stuffing success, scan-to-exploit progression, and activity that spans multiple log sources. Writes structured findings to the session FindingStore."
}

func (correlationTool) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"source":{"type":"string","description":"Optional source path filter; empty correlates all ingested logs"},
	"window_minutes":{"type":"integer","description":"Time window for chaining events in minutes (default 60)"},
	"min_events":{"type":"integer","description":"Minimum events per IP before correlation is considered (default 2)"}
}
}`)
}

func (correlationTool) ReadOnly() bool { return true }

func (correlationTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Source        string `json:"source"`
		WindowMinutes int    `json:"window_minutes"`
		MinEvents     int    `json:"min_events"`
	}{WindowMinutes: 60, MinEvents: 2}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.WindowMinutes <= 0 {
		p.WindowMinutes = 60
	}
	if p.MinEvents <= 0 {
		p.MinEvents = 2
	}

	records := globalLogStore.recordsFor(p.Source)
	if len(records) == 0 {
		sources := globalLogStore.sources()
		if len(sources) == 0 {
			return "No ingested logs. Run log_ingest first.", nil
		}
		return fmt.Sprintf("No records for source %q. Ingested sources: %s", p.Source, strings.Join(sources, ", ")), nil
	}

	groups := groupRecordsByIP(records)
	ips := make([]string, 0, len(groups))
	for ip := range groups {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	var b strings.Builder
	fmt.Fprintf(&b, "Correlation analysis: %d source IPs, %d records\n", len(ips), len(records))
	if p.Source != "" {
		fmt.Fprintf(&b, "Source filter: %s\n", p.Source)
	}
	b.WriteString("\n")

	totalFindings := 0
	for _, ip := range ips {
		group := append([]LogRecord(nil), groups[ip]...)
		sortRecordsByTime(group)
		stats := computeIPCorrelationStats(group, p.WindowMinutes)

		fmt.Fprintf(&b, "Timeline for %s (%d events)\n", ip, len(group))
		for _, r := range group[:minInt(len(group), 20)] {
			ts := "-"
			if !r.Timestamp.IsZero() {
				ts = r.Timestamp.Format("2006-01-02 15:04:05")
			}
			detail := strings.TrimSpace(strings.Join([]string{r.Method, fmt.Sprintf("%d", r.Status), r.Path, r.Message}, " "))
			fmt.Fprintf(&b, "  [%s] %s | %s | %s\n", ts, r.Source, r.SourceIP, detail)
		}
		if len(group) > 20 {
			fmt.Fprintf(&b, "  ... %d more events\n", len(group)-20)
		}
		b.WriteString("\n")

		for _, f := range ipCorrelationFindings(ip, group, stats, p.WindowMinutes, p.MinEvents) {
			totalFindings++
			fmt.Fprintf(&b, "[%s] %s\n", f.Severity, f.Title)
			fmt.Fprintf(&b, "  Count: %d | Sources: %s\n", f.Count, strings.Join(f.Sources, ", "))
			if ev := evidenceSnippets(f.Samples, 3); ev != "" {
				fmt.Fprintf(&b, "  Evidence:\n    %s\n", strings.ReplaceAll(ev, "\n", "\n    "))
			}
			if len(f.MITRE) > 0 {
				fmt.Fprintf(&b, "  MITRE: %s | CWE: %s\n", strings.Join(f.MITRE, ", "), f.CWE)
			}
			fmt.Fprintf(&b, "  Remediation: %s\n\n", f.Remediation)

			evidence.Global.Add(&evidence.Finding{
				ID:          fmt.Sprintf("correlation:%s:%s", ip, f.Rule),
				Target:      ip,
				Tool:        "correlation",
				Severity:    f.Severity,
				Title:       f.Title,
				Description: fmt.Sprintf("%s Count: %d. Sources: %s.", f.Description, f.Count, strings.Join(f.Sources, ", ")),
				Evidence:    evidenceSnippets(f.Samples, 5),
				Remediation: f.Remediation,
				CWE:         f.CWE,
				Metadata: map[string]any{
					"rule":    f.Rule,
					"count":   f.Count,
					"mitre":   f.MITRE,
					"sources": f.Sources,
				},
			})
		}
	}

	if totalFindings == 0 {
		b.WriteString("No correlated chains met the configured thresholds.\n")
	}
	return strings.TrimSpace(b.String()), nil
}

type ipCorrelationStats struct {
	failureCount     int
	successAfterFail bool
	scanThenAttack   bool
	sourceCount      int
}

func computeIPCorrelationStats(records []LogRecord, windowMinutes int) ipCorrelationStats {
	stats := ipCorrelationStats{sourceCount: len(recordSources(records))}
	var lastFailure, firstSuccess, firstScan, firstAttack time.Time
	sawFailure := false
	sawScan := false
	for _, r := range records {
		if isFailureRecord(r) {
			sawFailure = true
			stats.failureCount++
			lastFailure = r.Timestamp
		}
		if sawFailure && isSuccessRecord(r) && firstSuccess.IsZero() {
			firstSuccess = r.Timestamp
		}
		if isScanRecord(r) {
			sawScan = true
			if firstScan.IsZero() {
				firstScan = r.Timestamp
			}
		}
		if sawScan && (isWebAttackRecord(r) || isWebshellRecord(r)) && firstAttack.IsZero() {
			firstAttack = r.Timestamp
		}
	}
	stats.successAfterFail = stats.failureCount > 0 &&
		!firstSuccess.IsZero() &&
		withinWindow(lastFailure, firstSuccess, windowMinutes)
	stats.scanThenAttack = !firstScan.IsZero() &&
		!firstAttack.IsZero() &&
		firstAttack.After(firstScan) &&
		withinWindow(firstScan, firstAttack, windowMinutes)
	return stats
}

func ipCorrelationFindings(ip string, records []LogRecord, stats ipCorrelationStats, windowMinutes, minEvents int) []correlationFinding {
	var findings []correlationFinding
	if stats.successAfterFail && stats.failureCount >= minEvents {
		samples := filterRecords(records, func(r LogRecord) bool {
			return isFailureRecord(r) || isSuccessRecord(r)
		})
		findings = append(findings, correlationFinding{
			Rule:        "credential_stuffing_success",
			Severity:    evidence.SeverityHigh,
			Count:       stats.failureCount,
			Samples:     samples,
			Sources:     recordSources(records),
			Title:       fmt.Sprintf("Credential-stuffing success chain from %s", ip),
			Description: "Failed authentication events were followed by a successful request within the configured window.",
			Remediation: "Treat the account as compromised: force password reset, revoke sessions, review post-login activity, and enable MFA/risk-based authentication.",
			MITRE:       []string{"T1110"},
			CWE:         "CWE-287",
		})
	}
	if stats.scanThenAttack {
		samples := filterRecords(records, func(r LogRecord) bool {
			return isScanRecord(r) || isWebAttackRecord(r) || isWebshellRecord(r)
		})
		findings = append(findings, correlationFinding{
			Rule:        "scan_to_attack",
			Severity:    evidence.SeverityCritical,
			Count:       len(samples),
			Samples:     samples,
			Sources:     recordSources(records),
			Title:       fmt.Sprintf("Scan-to-exploit chain from %s", ip),
			Description: "Reconnaissance/scanning from the source was followed by web attack or webshell indicators.",
			Remediation: "Review the matched exploit attempts, check for successful exploitation or uploaded files, contain the affected service, and preserve logs for incident response.",
			MITRE:       []string{"T1595", "T1190"},
			CWE:         "CWE-20",
		})
	}
	if stats.sourceCount >= 2 && len(records) >= minEvents {
		samples := records
		if len(samples) > 10 {
			samples = samples[:10]
		}
		findings = append(findings, correlationFinding{
			Rule:        "multi_source_activity",
			Severity:    evidence.SeverityMedium,
			Count:       len(records),
			Samples:     samples,
			Sources:     recordSources(records),
			Title:       fmt.Sprintf("Multi-source activity from %s", ip),
			Description: "The source IP appears across multiple ingested log sources, suggesting lateral movement or broader activity.",
			Remediation: "Build the full timeline across all hosts, check for corresponding findings on other systems, and correlate with authentication and endpoint logs.",
			MITRE:       []string{"T1021"},
			CWE:         "CWE-778",
		})
	}
	return findings
}

type correlationFinding struct {
	Rule        string
	Severity    evidence.Severity
	Count       int
	Samples     []LogRecord
	Sources     []string
	Title       string
	Description string
	Remediation string
	MITRE       []string
	CWE         string
}

func withinWindow(a, b time.Time, minutes int) bool {
	if a.IsZero() || b.IsZero() {
		return true
	}
	diff := b.Sub(a)
	if diff < 0 {
		diff = -diff
	}
	return diff <= time.Duration(minutes)*time.Minute
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
