package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"reasonix/internal/evidence"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(cveSearch{}) }

type cveSearch struct{}

func (cveSearch) Name() string { return "cve_search" }

func (cveSearch) Description() string {
	return "Search for CVE (Common Vulnerabilities and Exposures) entries by CVE ID, keyword, product, or vendor. Returns CVSS score, severity, description, references, and affected product versions. Uses the NVD NIST API."
}

func (cveSearch) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"query":{"type":"string","description":"Search query: CVE ID (e.g., CVE-2024-1234), keyword (e.g., 'log4j'), product name, or vendor"},
	"limit":{"type":"integer","description":"Maximum results to return (default 5, max 20)"},
	"include_references":{"type":"boolean","description":"Include reference URLs (default false)"}
},
"required":["query"]
}`)
}

func (cveSearch) ReadOnly() bool { return true }

func (cveSearch) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Query              string `json:"query"`
		Limit              int    `json:"limit"`
		IncludeReferences  bool   `json:"include_references"`
	}{Limit: 5}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Query == "" {
		return "", fmt.Errorf("query is required")
	}
	if p.Limit < 1 {
		p.Limit = 1
	}
	if p.Limit > 20 {
		p.Limit = 20
	}

	var apiURL string
	q := strings.TrimSpace(p.Query)

	// If it looks like a CVE ID, use direct lookup
	if strings.HasPrefix(strings.ToUpper(q), "CVE-") {
		apiURL = fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", url.QueryEscape(q))
	} else {
		apiURL = fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=%d",
			url.QueryEscape(q), p.Limit)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "EduShield-Security-Agent/1.0")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("NVD API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return fmt.Sprintf("CVE not found: %s", q), nil
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var result nvdResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse NVD response: %w", err)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("CVE search: %s\n", q))
	b.WriteString(fmt.Sprintf("Total results: %d\n\n", result.TotalResults))

	if len(result.Vulnerabilities) == 0 {
		b.WriteString("No CVEs found matching the query.\n")
		return b.String(), nil
	}

	count := 0
	for _, vuln := range result.Vulnerabilities {
		if count >= p.Limit {
			break
		}
		cve := vuln.CVE
		b.WriteString(fmt.Sprintf("--- %s ---\n", cve.ID))
		b.WriteString(fmt.Sprintf("Published: %s | Modified: %s\n", cve.Published, cve.LastModified))
		b.WriteString(fmt.Sprintf("Source: %s\n", cve.SourceIdentifier))

		// CVSS scores
		if len(cve.Metrics.CVSSv31) > 0 {
			m := cve.Metrics.CVSSv31[0]
			b.WriteString(fmt.Sprintf("CVSS v3.1: %.1f (%s) — Vector: %s\n",
				m.CVSSData.BaseScore, m.CVSSData.BaseSeverity, m.CVSSData.VectorString))
		} else if len(cve.Metrics.CVSSv30) > 0 {
			m := cve.Metrics.CVSSv30[0]
			b.WriteString(fmt.Sprintf("CVSS v3.0: %.1f (%s) — Vector: %s\n",
				m.CVSSData.BaseScore, m.CVSSData.BaseSeverity, m.CVSSData.VectorString))
		} else if len(cve.Metrics.CVSSv2) > 0 {
			m := cve.Metrics.CVSSv2[0]
			b.WriteString(fmt.Sprintf("CVSS v2: %.1f\n", m.CVSSData.BaseScore))
		}

		// Description
		for _, desc := range cve.Descriptions {
			if desc.Lang == "en" {
				b.WriteString(fmt.Sprintf("\nDescription: %s\n", desc.Value))
				break
			}
		}

		// Weaknesses (CWE)
		if len(cve.Weaknesses) > 0 {
			b.WriteString("Weaknesses:\n")
			for _, w := range cve.Weaknesses {
				for _, d := range w.Description {
					if d.Lang == "en" {
						b.WriteString(fmt.Sprintf("  • %s\n", d.Value))
					}
				}
			}
		}

		// Affected configurations/products
		for _, config := range cve.Configurations {
			for _, node := range config.Nodes {
				for _, cpe := range node.CPEMatch {
					b.WriteString(fmt.Sprintf("  Affected: %s (up to %s)\n",
						cpe.Criteria, cpe.VersionEndIncluding))
				}
			}
		}

		// References
		if p.IncludeReferences && len(cve.References) > 0 {
			b.WriteString("References:\n")
			for i, ref := range cve.References {
				if i >= 5 {
					b.WriteString(fmt.Sprintf("  ... and %d more\n", len(cve.References)-5))
					break
				}
				b.WriteString(fmt.Sprintf("  • %s: %s\n", ref.Source, ref.URL))
			}
		}
		b.WriteString("\n")
		count++
	}

	// Write structured findings to the FindingStore
	findings := writeCVEFindings(result.Vulnerabilities, q)
	evidence.Global.AddFindings(findings)

	// Also write any CVE-to-port correlations
	correlations := evidence.Global.CorrelateServicesWithCVEs()
	for _, c := range correlations {
		b.WriteString(fmt.Sprintf("\n⚠️  Service-{Vulnerability}: %s\n", c.Description))
		b.WriteString(fmt.Sprintf("   Severity: %s | Remediation: %s\n", c.Severity, c.Remediation))
	}

	return strings.TrimSpace(b.String()), nil
}

// getCVSSSeverity maps a CVSS score to a Severity level.
func getCVSSSeverity(score float64) evidence.Severity {
	switch {
	case score >= 9.0:
		return evidence.SeverityCritical
	case score >= 7.0:
		return evidence.SeverityHigh
	case score >= 4.0:
		return evidence.SeverityMedium
	case score > 0:
		return evidence.SeverityLow
	default:
		return evidence.SeverityInfo
	}
}

// writeCVEFindings creates structured findings from NVD CVE results and
// cross-references them with existing port_scan findings in the store.
func writeCVEFindings(vulns []nvdVulnItem, query string) []*evidence.Finding {
	var findings []*evidence.Finding
	for _, vuln := range vulns {
		cve := vuln.CVE
		var desc string
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		var cwes []string
		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if d.Lang == "en" {
					cwes = append(cwes, d.Value)
				}
			}
		}
		cwe := strings.Join(cwes, ", ")
		if len(cwe) > 200 {
			cwe = cwe[:200] + "..."
		}

		var score float64
		var severity evidence.Severity
		if len(cve.Metrics.CVSSv31) > 0 {
			score = cve.Metrics.CVSSv31[0].CVSSData.BaseScore
			severity = getCVSSSeverity(score)
		} else if len(cve.Metrics.CVSSv30) > 0 {
			score = cve.Metrics.CVSSv30[0].CVSSData.BaseScore
			severity = getCVSSSeverity(score)
		} else if len(cve.Metrics.CVSSv2) > 0 {
			severity = getCVSSSeverity(cve.Metrics.CVSSv2[0].CVSSData.BaseScore)
		}

		if len(desc) > 500 {
			desc = desc[:500] + "..."
		}

		f := &evidence.Finding{
			ID:          fmt.Sprintf("cve_search:%s", cve.ID),
			Target:      query,
			Tool:        "cve_search",
			Severity:    severity,
			Title:       fmt.Sprintf("%s — CVSS %.1f", cve.ID, score),
			Description: desc,
			CVE:         cve.ID,
			CWE:         cwe,
			CVSS:        score,
			Remediation: fmt.Sprintf("Review and apply the vendor patch for %s. Check references for mitigation guidance.", cve.ID),
		}

		// Cross-reference with port_scan findings: if a known port service
		// matches the CVE description, tag the finding with port/service.
		ports := evidence.Global.Query("", "port_scan", "", 0)
		for _, p := range ports {
			if p.Service != "" && strings.Contains(
				strings.ToLower(f.Description),
				strings.ToLower(p.Service),
			) {
				f.Port = p.Port
				f.Service = p.Service
				break
			}
		}

		findings = append(findings, f)
	}
	return findings
}

// NVD API response structures
type nvdResponse struct {
	TotalResults    int              `json:"totalResults"`
	Vulnerabilities []nvdVulnItem    `json:"vulnerabilities"`
}

type nvdVulnItem struct {
	CVE nvdCVEItem `json:"cve"`
}

type nvdCVEItem struct {
	ID               string           `json:"id"`
	SourceIdentifier string           `json:"sourceIdentifier"`
	Published        string           `json:"published"`
	LastModified     string           `json:"lastModified"`
	Descriptions     []nvdDescription `json:"descriptions"`
	Metrics          nvdMetrics       `json:"metrics"`
	Weaknesses       []nvdWeakness    `json:"weaknesses"`
	Configurations   []nvdConfig      `json:"configurations"`
	References       []nvdReference   `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSv31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSv30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSv2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Criteria            string `json:"criteria"`
	VersionEndIncluding string `json:"versionEndIncluding"`
}

type nvdReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}
