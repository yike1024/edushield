package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"reasonix/internal/evidence"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(anomalyDetect{}) }

type anomalyDetect struct{}

func (anomalyDetect) Name() string { return "anomaly_detect" }

func (anomalyDetect) Description() string {
	return "Detect anomalies in ingested log records: brute-force/credential stuffing, scanning/recon, SQL injection, webshell access, high request volume, and out-of-hours activity. Writes structured findings to the session FindingStore."
}

func (anomalyDetect) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"source":{"type":"string","description":"Optional source path filter; empty analyzes all ingested logs"},
	"checks":{"type":"string","description":"Comma-separated checks: brute_force, scan, traffic, webshell, sqli, out_of_hours, all (default all)"},
	"brute_force_threshold":{"type":"integer","description":"Failed auth events per IP before flagging (default 5)"},
	"scan_threshold":{"type":"integer","description":"404/scan-tool events per IP before flagging (default 20)"},
	"traffic_threshold":{"type":"integer","description":"Total requests per IP before flagging (default 1000)"},
	"out_of_hours_threshold":{"type":"integer","description":"Out-of-hours events per IP before flagging (default 10)"},
	"attack_threshold":{"type":"integer","description":"SQLi/webshell event count per IP before flagging (default 1)"}
}
}`)
}

func (anomalyDetect) ReadOnly() bool { return true }

type anomalyThresholds struct {
	bruteForce int
	scan       int
	traffic    int
	outOfHours int
	attack     int
}

type anomalyHit struct {
	Rule        string
	Severity    evidence.Severity
	Count       int
	Samples     []LogRecord
	Title       string
	Description string
	Remediation string
	MITRE       []string
	CWE         string
}

func (anomalyDetect) Execute(_ context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Source              string `json:"source"`
		Checks              string `json:"checks"`
		BruteForceThreshold int    `json:"brute_force_threshold"`
		ScanThreshold       int    `json:"scan_threshold"`
		TrafficThreshold    int    `json:"traffic_threshold"`
		OutOfHoursThreshold int    `json:"out_of_hours_threshold"`
		AttackThreshold     int    `json:"attack_threshold"`
	}{Checks: "all", BruteForceThreshold: 5, ScanThreshold: 20, TrafficThreshold: 1000, OutOfHoursThreshold: 10, AttackThreshold: 1}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.BruteForceThreshold <= 0 {
		p.BruteForceThreshold = 5
	}
	if p.ScanThreshold <= 0 {
		p.ScanThreshold = 20
	}
	if p.TrafficThreshold <= 0 {
		p.TrafficThreshold = 1000
	}
	if p.OutOfHoursThreshold <= 0 {
		p.OutOfHoursThreshold = 10
	}
	if p.AttackThreshold <= 0 {
		p.AttackThreshold = 1
	}

	records := globalLogStore.recordsFor(p.Source)
	if len(records) == 0 {
		sources := globalLogStore.sources()
		if len(sources) == 0 {
			return "No ingested logs. Run log_ingest first.", nil
		}
		return fmt.Sprintf("No records for source %q. Ingested sources: %s", p.Source, strings.Join(sources, ", ")), nil
	}

	checks := parseAnomalyChecks(p.Checks)
	thresholds := anomalyThresholds{
		bruteForce: p.BruteForceThreshold,
		scan:       p.ScanThreshold,
		traffic:    p.TrafficThreshold,
		outOfHours: p.OutOfHoursThreshold,
		attack:     p.AttackThreshold,
	}

	groups := groupRecordsByIP(records)
	ips := make([]string, 0, len(groups))
	for ip := range groups {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	var b strings.Builder
	fmt.Fprintf(&b, "Anomaly detection: %d source IPs analyzed, %d records\n", len(ips), len(records))
	if p.Source != "" {
		fmt.Fprintf(&b, "Source filter: %s\n", p.Source)
	}
	b.WriteString("\n")

	totalHits := 0
	for _, ip := range ips {
		hits := detectAnomaliesForIP(ip, groups[ip], checks, thresholds)
		if len(hits) == 0 {
			continue
		}
		totalHits += len(hits)
		for _, h := range hits {
			fmt.Fprintf(&b, "[%s] %s\n", h.Severity, h.Title)
			fmt.Fprintf(&b, "  Count: %d | Sources: %s\n", h.Count, strings.Join(recordSources(h.Samples), ", "))
			if ev := evidenceSnippets(h.Samples, 3); ev != "" {
				fmt.Fprintf(&b, "  Evidence:\n    %s\n", strings.ReplaceAll(ev, "\n", "\n    "))
			}
			if len(h.MITRE) > 0 {
				fmt.Fprintf(&b, "  MITRE: %s | CWE: %s\n", strings.Join(h.MITRE, ", "), h.CWE)
			}
			fmt.Fprintf(&b, "  Remediation: %s\n\n", h.Remediation)

			evidence.Global.Add(&evidence.Finding{
				ID:          fmt.Sprintf("anomaly_detect:%s:%s", ip, h.Rule),
				Target:      ip,
				Tool:        "anomaly_detect",
				Severity:    h.Severity,
				Title:       h.Title,
				Description: fmt.Sprintf("%s Count: %d. Sources: %s.", h.Description, h.Count, strings.Join(recordSources(h.Samples), ", ")),
				Evidence:    evidenceSnippets(h.Samples, 5),
				Remediation: h.Remediation,
				CWE:         h.CWE,
				Metadata: map[string]any{
					"rule":    h.Rule,
					"count":   h.Count,
					"mitre":   h.MITRE,
					"sources": recordSources(h.Samples),
				},
			})
		}
	}

	if totalHits == 0 {
		b.WriteString("No anomalies met the configured thresholds.\n")
	}
	return strings.TrimSpace(b.String()), nil
}

func parseAnomalyChecks(spec string) map[string]bool {
	all := map[string]bool{
		"brute_force": true,
		"scan":        true,
		"traffic":     true,
		"webshell":    true,
		"sqli":        true,
		"out_of_hours": true,
	}
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" || spec == "all" {
		return all
	}
	out := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out[part] = true
		}
	}
	return out
}

func detectAnomaliesForIP(ip string, group []LogRecord, checks map[string]bool, t anomalyThresholds) []anomalyHit {
	var hits []anomalyHit

	failures := filterRecords(group, isFailureRecord)
	if checks["brute_force"] && len(failures) >= t.bruteForce {
		sev := evidence.SeverityMedium
		if len(failures) >= 10 {
			sev = evidence.SeverityHigh
		}
		hits = append(hits, anomalyHit{
			Rule:        "brute_force",
			Severity:    sev,
			Count:       len(failures),
			Samples:     failures,
			Title:       fmt.Sprintf("Brute-force / credential stuffing from %s", ip),
			Description: "Repeated failed authentication events from one source IP.",
			Remediation: "Enable account lockout/rate limiting, add fail2ban or WAF rules, review the affected accounts for compromise, and verify whether any later login succeeded.",
			MITRE:       []string{"T1110"},
			CWE:         "CWE-307",
		})
	}

	scans := filterRecords(group, isScanRecord)
	if checks["scan"] && len(scans) >= t.scan {
		hits = append(hits, anomalyHit{
			Rule:        "scan",
			Severity:    evidence.SeverityMedium,
			Count:       len(scans),
			Samples:     scans,
			Title:       fmt.Sprintf("Reconnaissance / scanning activity from %s", ip),
			Description: "High volume of 404 responses or known scanner user agents from one source IP.",
			Remediation: "Block or rate-limit the source, verify whether the scanning led to exploitation, and check adjacent hosts for the same source.",
			MITRE:       []string{"T1046", "T1595"},
			CWE:         "CWE-200",
		})
	}

	sqlis := filterRecords(group, isSQLiRecord)
	if checks["sqli"] && len(sqlis) >= t.attack {
		hits = append(hits, anomalyHit{
			Rule:        "sqli",
			Severity:    evidence.SeverityCritical,
			Count:       len(sqlis),
			Samples:     sqlis,
			Title:       fmt.Sprintf("Potential SQL injection from %s", ip),
			Description: "Requests containing SQLi indicators such as UNION SELECT, sleep(), information_schema, or comment injection.",
			Remediation: "Review the matching requests for exploitation, parameterize all database queries, and add WAF rules for SQLi payloads.",
			MITRE:       []string{"T1190"},
			CWE:         "CWE-89",
		})
	}

	shells := filterRecords(group, isWebshellRecord)
	if checks["webshell"] && len(shells) >= t.attack {
		hits = append(hits, anomalyHit{
			Rule:        "webshell",
			Severity:    evidence.SeverityCritical,
			Count:       len(shells),
			Samples:     shells,
			Title:       fmt.Sprintf("Potential webshell access from %s", ip),
			Description: "Requests targeting script files or command execution indicators consistent with webshell usage.",
			Remediation: "Immediately review the script/upload directories, scan for webshell files, isolate the host if confirmed, and rotate credentials.",
			MITRE:       []string{"T1505.003", "T1190"},
			CWE:         "CWE-434",
		})
	}

	outOfHours := filterRecords(group, isOutOfHoursRecord)
	if checks["out_of_hours"] && len(outOfHours) >= t.outOfHours {
		hits = append(hits, anomalyHit{
			Rule:        "out_of_hours",
			Severity:    evidence.SeverityLow,
			Count:       len(outOfHours),
			Samples:     outOfHours,
			Title:       fmt.Sprintf("Out-of-hours activity from %s", ip),
			Description: "Events from one source IP concentrated in 00:00-05:59, outside typical business hours.",
			Remediation: "Confirm whether the activity is legitimate automation; otherwise investigate the source and correlate with other findings.",
			MITRE:       []string{"T1078"},
			CWE:         "CWE-778",
		})
	}

	if checks["traffic"] && len(group) >= t.traffic {
		hits = append(hits, anomalyHit{
			Rule:        "traffic",
			Severity:    evidence.SeverityMedium,
			Count:       len(group),
			Samples:     group,
			Title:       fmt.Sprintf("High request volume from %s", ip),
			Description: "Request count from one source IP exceeded the configured traffic threshold.",
			Remediation: "Verify whether the traffic is a load test or crawler; apply rate limiting and inspect for data exfiltration or scraping behavior.",
			MITRE:       []string{"T1071"},
			CWE:         "CWE-770",
		})
	}

	return hits
}
