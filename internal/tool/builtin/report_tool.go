package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"reasonix/internal/evidence"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(reportTool{}) }

type reportTool struct{}

func (reportTool) Name() string { return "report" }

func (reportTool) Description() string {
	return "Generate a structured security assessment report from all findings collected during this session. Supports multiple output formats. Call after running security tools (port_scan, cve_search, http_probe) to produce a professional report."
}

func (reportTool) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"format":{"type":"string","description":"Output format: 'markdown' (default, full report with tables), 'summary' (concise text summary)", "enum": ["markdown", "summary"]},
	"title":{"type":"string","description":"Report title (default: 'Security Assessment Report')"},
	"include_remediations":{"type":"boolean","description":"Include remediation steps for each finding (default true)"}
},
"dependencies":{}
}`)
}

func (reportTool) ReadOnly() bool { return true }

func (reportTool) Execute(_ context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Format              string `json:"format"`
		Title               string `json:"title"`
		IncludeRemediations bool   `json:"include_remediations"`
	}{Format: "markdown", Title: "Security Assessment Report", IncludeRemediations: true}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}

	store := evidence.Global
	if store.Count() == 0 {
		return "No findings to report. Run security tools first (port_scan, cve_search, http_probe) to collect findings.", nil
	}

	switch p.Format {
	case "summary":
		return reportSummary(store, p.Title)
	default:
		return reportMarkdown(store, p.Title, p.IncludeRemediations)
	}
}

func reportSummary(store *evidence.FindingStore, title string) (string, error) {
	all := store.All()
	byTarget := store.ByTarget()
	corrs := store.CorrelateServicesWithCVEs()

	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s\n\n", title))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("**Targets:** %d | **Findings:** %d | **Correlations:** %d\n\n",
		len(byTarget), len(all), len(corrs)))

	// Severity breakdown
	sevCounts := map[evidence.Severity]int{}
	for _, f := range all {
		sevCounts[f.Severity]++
	}
	b.WriteString("## Severity Breakdown\n\n")
	for _, s := range []evidence.Severity{
		evidence.SeverityCritical, evidence.SeverityHigh,
		evidence.SeverityMedium, evidence.SeverityLow, evidence.SeverityInfo,
	} {
		if sevCounts[s] > 0 {
			b.WriteString(fmt.Sprintf("- **%s**: %d\n", strings.Title(string(s)), sevCounts[s]))
		}
	}

	// Per-target
	b.WriteString("\n## Per-Target Summary\n\n")
	for target, findings := range byTarget {
		b.WriteString(fmt.Sprintf("### %s\n", target))
		b.WriteString(fmt.Sprintf("Findings: %d\n\n", len(findings)))
		for _, f := range findings {
			portStr := ""
			if f.Port > 0 {
				portStr = fmt.Sprintf(" [:%d]", f.Port)
			}
			b.WriteString(fmt.Sprintf("- %s **%s**%s\n", f.Tool, f.Title, portStr))
		}
		b.WriteString("\n")
	}

	return strings.TrimSpace(b.String()), nil
}

func reportMarkdown(store *evidence.FindingStore, title string, includeRemediations bool) (string, error) {
	all := store.All()
	byTarget := store.ByTarget()
	corrs := store.CorrelateServicesWithCVEs()

	// Sort targets for consistent output
	targets := make([]string, 0, len(byTarget))
	for t := range byTarget {
		targets = append(targets, t)
	}

	var b strings.Builder

	// Header
	b.WriteString(fmt.Sprintf("# %s\n\n", title))
	b.WriteString(fmt.Sprintf("**Assessment Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	b.WriteString(fmt.Sprintf("**Total Findings:** %d | **Targets Assessed:** %d | **Cross-Tool Correlations:** %d\n\n",
		len(all), len(byTarget), len(corrs)))

	// Executive Summary
	b.WriteString("## Executive Summary\n\n")
	sevCounts := map[evidence.Severity]int{}
	for _, f := range all {
		sevCounts[f.Severity]++
	}
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	for _, s := range []evidence.Severity{
		evidence.SeverityCritical, evidence.SeverityHigh,
		evidence.SeverityMedium, evidence.SeverityLow, evidence.SeverityInfo,
	} {
		if sevCounts[s] > 0 {
			b.WriteString(fmt.Sprintf("| **%s** | %d |\n", strings.Title(string(s)), sevCounts[s]))
		}
	}
	b.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", len(all)))

	// Risk rating
	risk := "Low"
	if sevCounts[evidence.SeverityCritical] > 0 {
		risk = "Critical"
	} else if sevCounts[evidence.SeverityHigh] > 3 {
		risk = "High"
	} else if sevCounts[evidence.SeverityHigh] > 0 {
		risk = "Medium"
	}
	b.WriteString(fmt.Sprintf("**Overall Risk Rating:** %s\n\n", risk))

	// Cross-Tool Correlations
	if len(corrs) > 0 {
		b.WriteString("## 🔗 Cross-Tool Correlations\n\n")
		b.WriteString("These correlations link open services to known vulnerabilities:\n\n")
		for _, c := range corrs {
			b.WriteString(fmt.Sprintf("- **%s**: %s\n", c.Title, c.Description))
			b.WriteString(fmt.Sprintf("  - Severity: %s | Sources: %s\n", c.Severity, strings.Join(c.Sources, ", ")))
			if includeRemediations && c.Remediation != "" {
				b.WriteString(fmt.Sprintf("  - Remediation: %s\n", c.Remediation))
			}
		}
		b.WriteString("\n")
	}

	// Detailed Findings by Target
	b.WriteString("## Detailed Findings\n\n")
	for _, target := range targets {
		findings := byTarget[target]
		b.WriteString(fmt.Sprintf("### Target: %s\n\n", target))
		b.WriteString(fmt.Sprintf("**%d finding(s)**\n\n", len(findings)))

		for _, f := range findings {
			portStr := ""
			if f.Port > 0 {
				portStr = fmt.Sprintf(" on port %d", f.Port)
			}
			b.WriteString(fmt.Sprintf("#### %s%s\n\n", f.Title, portStr))
			b.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
			b.WriteString(fmt.Sprintf("- **Source:** %s\n", f.Tool))
			if f.CVE != "" {
				b.WriteString(fmt.Sprintf("- **CVE:** %s (CVSS %.1f)\n", f.CVE, f.CVSS))
			}
			if f.CWE != "" {
				b.WriteString(fmt.Sprintf("- **CWE:** %s\n", f.CWE))
			}
			if f.Description != "" {
				b.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
			}
			if includeRemediations && f.Remediation != "" {
				b.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.Remediation))
			}
			if f.Evidence != "" {
				ev := f.Evidence
				if len(ev) > 150 {
					ev = ev[:150] + "..."
				}
				b.WriteString(fmt.Sprintf("- **Evidence:** `%s`\n", ev))
			}
			b.WriteString("\n")
		}
	}

	// Tools Used
	b.WriteString("## Tools Used\n\n")
	toolSet := map[string]bool{}
	for _, f := range all {
		toolSet[f.Tool] = true
	}
	for t := range toolSet {
		b.WriteString(fmt.Sprintf("- `%s`\n", t))
	}
	b.WriteString("\n")

	// Footer
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("*Report generated by EduShield Security Agent on %s*\n", time.Now().Format("2006-01-02 15:04:05")))

	return strings.TrimSpace(b.String()), nil
}
