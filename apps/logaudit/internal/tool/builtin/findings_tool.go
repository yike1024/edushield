package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"reasonix/internal/evidence"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(findingsTool{}) }

type findingsTool struct{}

func (findingsTool) Name() string { return "findings" }

func (findingsTool) Description() string {
	return "Query and analyze structured security findings collected during this session. Supports filtering by target, tool, severity, and port. Also provides cross-tool correlation (e.g., open ports + CVEs). Use this to get a structured overview of all security observations."
}

func (findingsTool) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"target":{"type":"string","description":"Filter by target host/URL (optional)"},
	"tool":{"type":"string","description":"Filter by source tool: port_scan, cve_search, http_probe, etc. (optional)"},
	"severity":{"type":"string","description":"Filter by minimum severity: critical, high, medium, low, info (optional)"},
	"port":{"type":"integer","description":"Filter by port number (optional)"},
	"mode":{"type":"string","description":"Output mode: 'summary' (default, grouped counts), 'all' (all findings), 'correlations' (cross-tool correlations only)"}
},
"dependencies":{}
}`)
}

func (findingsTool) ReadOnly() bool { return true }

func (findingsTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Target   string `json:"target"`
		Tool     string `json:"tool"`
		Severity string `json:"severity"`
		Port     int    `json:"port"`
		Mode     string `json:"mode"`
	}{Mode: "summary"}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}

	store := evidence.Global
	if store.Count() == 0 {
		return "No findings in the current session. Run security tools first (port_scan, cve_search, http_probe) to generate findings.", nil
	}

	switch p.Mode {
	case "correlations":
		return formatCorrelations(store), nil
	case "all":
		return formatAll(store, p.Target, p.Tool, evidence.ParseSeverity(p.Severity), p.Port), nil
	default:
		return formatSummary(store), nil
	}
}

func formatSummary(store *evidence.FindingStore) string {
	return store.Summary()
}

func formatAll(store *evidence.FindingStore, target, tool string, sev evidence.Severity, port int) string {
	findings := store.Query(target, tool, sev, port)
	if len(findings) == 0 {
		return "No findings match the filters."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "📋 Findings Report (%d matching)\n\n", len(findings))
	for _, f := range findings {
		icon := severityIcon(f.Severity)
		portStr := ""
		if f.Port > 0 {
			portStr = fmt.Sprintf(" [port %d/%s]", f.Port, f.Service)
		}
		fmt.Fprintf(&b, "%s [%s] %s%s\n", icon, f.Tool, f.Title, portStr)
		fmt.Fprintf(&b, "   Target: %s\n", f.Target)
		if f.CVE != "" {
			fmt.Fprintf(&b, "   CVE: %s (CVSS %.1f)\n", f.CVE, f.CVSS)
		}
		if f.Description != "" {
			desc := f.Description
			if len(desc) > 200 {
				desc = desc[:200] + "..."
			}
			fmt.Fprintf(&b, "   %s\n", desc)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "   → %s\n", f.Remediation)
		}
		fmt.Fprintf(&b, "\n")
	}
	return strings.TrimSpace(b.String())
}

func formatCorrelations(store *evidence.FindingStore) string {
	corrs := store.CorrelateServicesWithCVEs()
	if len(corrs) == 0 {
		// Check if we have both port findings and CVE findings
		ports := store.Query("", "port_scan", "", 0)
		cves := store.Query("", "cve_search", "", 0)
		if len(ports) > 0 && len(cves) > 0 {
			return "No service-CVE correlations found. The discovered CVEs may not directly match the services on open ports."
		}
		return "Cannot correlate: need both port_scan and cve_search findings. Run port_scan first, then cve_search on identified services."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "🔗 Cross-Tool Correlations (%d found)\n\n", len(corrs))
	for _, c := range corrs {
		icon := severityIcon(c.Severity)
		fmt.Fprintf(&b, "%s %s\n", icon, c.Title)
		fmt.Fprintf(&b, "   Target: %s\n", c.Target)
		fmt.Fprintf(&b, "   Sources: %s\n", strings.Join(c.Sources, ", "))
		fmt.Fprintf(&b, "   %s\n", c.Description)
		if c.Remediation != "" {
			fmt.Fprintf(&b, "   → %s\n", c.Remediation)
		}
		fmt.Fprintf(&b, "\n")
	}
	return strings.TrimSpace(b.String())
}

func severityIcon(s evidence.Severity) string {
	switch s {
	case evidence.SeverityCritical:
		return "🔴"
	case evidence.SeverityHigh:
		return "🟠"
	case evidence.SeverityMedium:
		return "🟡"
	case evidence.SeverityLow:
		return "🔵"
	case evidence.SeverityInfo:
		return "⚪"
	default:
		return "❓"
	}
}
