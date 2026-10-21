package evidence

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity classifies a security finding's impact level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Finding is a single structured security observation produced by a tool.
type Finding struct {
	// ID is a unique identifier for deduplication, e.g. "port_scan:8.215.92.252:80".
	ID string `json:"id"`
	// Target is the host / URL / asset the finding applies to.
	Target string `json:"target"`
	// Tool that produced this finding (port_scan, cve_search, http_probe, etc.).
	Tool string `json:"tool"`
	// Port, when non-zero, is the network port the finding is associated with.
	Port int `json:"port,omitempty"`
	// Service name when applicable (http, ssh, mysql, etc.).
	Service string `json:"service,omitempty"`
	// Severity of the finding.
	Severity Severity `json:"severity"`
	// Title is a one-line summary.
	Title string `json:"title"`
	// Description is a longer explanation.
	Description string `json:"description"`
	// Evidence is the raw tool output snippet supporting this finding.
	Evidence string `json:"evidence,omitempty"`
	// CVE identifier when the finding maps to a known vulnerability.
	CVE string `json:"cve,omitempty"`
	// CWE identifier when applicable, e.g. "CWE-79".
	CWE string `json:"cwe,omitempty"`
	// Remediation describes how to fix the issue.
	Remediation string `json:"remediation,omitempty"`
	// CVSS score, if available (0.0 means unset).
	CVSS float64 `json:"cvss,omitempty"`
	// Timestamp when the finding was created.
	Timestamp time.Time `json:"timestamp"`
	// Metadata captures tool-specific attributes.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// FindingStore is a thread-safe, in-memory store for security findings.
// It is the central hub that every security tool writes to and the report
// generator reads from.
type FindingStore struct {
	mu       sync.RWMutex
	findings map[string]*Finding // keyed by finding ID
}

// NewFindingStore creates an empty store.
func NewFindingStore() *FindingStore {
	return &FindingStore{findings: make(map[string]*Finding)}
}

// Global is the default application-wide FindingStore. Security tools
// write here by default; tests may create isolated stores.
var Global = NewFindingStore()

// Add inserts or updates a finding. If a finding with the same ID already
// exists and has higher severity, the existing one is kept. Returns true
// if the finding was added or upgraded.
func (s *FindingStore) Add(f *Finding) bool {
	if f == nil {
		return false
	}
	if f.ID == "" {
		f.ID = fmt.Sprintf("%s:%s:%d", f.Tool, f.Target, f.Port)
	}
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.findings[f.ID]
	if ok && severityWeight(existing.Severity) >= severityWeight(f.Severity) {
		return false // existing is same or worse, keep as-is
	}
	s.findings[f.ID] = f
	return true
}

// AddFindings bulk-adds findings.
func (s *FindingStore) AddFindings(findings []*Finding) int {
	added := 0
	for _, f := range findings {
		if s.Add(f) {
			added++
		}
	}
	return added
}

// Get retrieves a finding by ID.
func (s *FindingStore) Get(id string) *Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findings[id]
}

// All returns a copy of all findings, sorted by severity (critical first) then timestamp.
func (s *FindingStore) All() []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Finding, 0, len(s.findings))
	for _, f := range s.findings {
		result = append(result, f)
	}
	sort.Slice(result, func(i, j int) bool {
		wi, wj := severityWeight(result[i].Severity), severityWeight(result[j].Severity)
		if wi != wj {
			return wi > wj
		}
		return result[i].Timestamp.After(result[j].Timestamp)
	})
	return result
}

// Query returns findings matching all non-empty filter fields.
func (s *FindingStore) Query(target, tool string, severity Severity, port int) []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Finding
	for _, f := range s.findings {
		if target != "" && !strings.Contains(f.Target, target) {
			continue
		}
		if tool != "" && f.Tool != tool {
			continue
		}
		if severity != "" && f.Severity != severity {
			continue
		}
		if port > 0 && f.Port != port {
			continue
		}
		result = append(result, f)
	}
	sort.Slice(result, func(i, j int) bool {
		wi, wj := severityWeight(result[i].Severity), severityWeight(result[j].Severity)
		if wi != wj {
			return wi > wj
		}
		return result[i].Timestamp.After(result[j].Timestamp)
	})
	return result
}

// ByTarget groups all findings by target.
func (s *FindingStore) ByTarget() map[string][]*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	groups := make(map[string][]*Finding)
	for _, f := range s.findings {
		groups[f.Target] = append(groups[f.Target], f)
	}
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool {
			return severityWeight(g[i].Severity) > severityWeight(g[j].Severity)
		})
	}
	return groups
}

// Clear removes all findings (useful between scans).
func (s *FindingStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = make(map[string]*Finding)
}

// Count returns the total number of findings.
func (s *FindingStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.findings)
}

// Summary returns a concise text summary of all findings grouped by severity.
func (s *FindingStore) Summary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := map[Severity]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range s.findings {
		counts[f.Severity]++
	}
	var b strings.Builder
	b.WriteString("📊 Finding Summary\n")
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if counts[sev] > 0 {
			icon := severityIcon(sev)
			fmt.Fprintf(&b, "%s  %s: %d\n", icon, string(sev), counts[sev])
		}
	}
	fmt.Fprintf(&b, "Total: %d findings\n", len(s.findings))
	return b.String()
}

// --- Scanner: cross-tool correlation ---

// CorrelatedFinding represents a correlation between findings from different tools.
type CorrelatedFinding struct {
	Title       string
	Target      string
	Severity    Severity
	Sources     []string // tool names that contributed
	Findings    []*Finding
	Description string
	Remediation string
}

// CorrelateServicesWithCVEs finds open ports whose services match CVE findings.
// For example: port 80 (http) + cve_search for "http" = potential web vuln.
func (s *FindingStore) CorrelateServicesWithCVEs() []CorrelatedFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var correlations []CorrelatedFinding

	// Group findings by target
	byTarget := make(map[string][]*Finding)
	for _, f := range s.findings {
		byTarget[f.Target] = append(byTarget[f.Target], f)
	}

	for target, findings := range byTarget {
		// Collect open services and their CVEs
		type serviceInfo struct {
			port    int
			service string
			cves    []*Finding
		}
		services := make(map[int]*serviceInfo)

		for _, f := range findings {
			if f.Tool == "port_scan" && f.Port > 0 {
				if _, ok := services[f.Port]; !ok {
					services[f.Port] = &serviceInfo{port: f.Port, service: f.Service}
				}
			}
		}
		for _, f := range findings {
			if f.Tool == "cve_search" {
				for _, svc := range services {
					if svc.service != "" && strings.Contains(
						strings.ToLower(f.Description),
						strings.ToLower(svc.service),
					) {
						svc.cves = append(svc.cves, f)
					}
				}
			}
		}

		// Build correlations
		for port, svc := range services {
			if len(svc.cves) > 0 {
				cveIDs := make([]string, len(svc.cves))
				cveFindings := make([]*Finding, len(svc.cves))
				maxSev := SeverityInfo
				for i, cve := range svc.cves {
					cveIDs[i] = cve.CVE
					cveFindings[i] = cve
					if severityWeight(cve.Severity) > severityWeight(maxSev) {
						maxSev = cve.Severity
					}
				}
				cf := CorrelatedFinding{
					Title:       fmt.Sprintf("Service %s (port %d) has %d known CVEs", svc.service, port, len(cveIDs)),
					Target:      target,
					Severity:    maxSev,
					Sources:     []string{"port_scan", "cve_search"},
					Findings:    cveFindings,
					Description: fmt.Sprintf("Port %d (%s) on %s has %d known vulnerabilities: %s", port, svc.service, target, len(cveIDs), strings.Join(cveIDs, ", ")),
					Remediation: fmt.Sprintf("Review and patch the %s service on port %d", svc.service, port),
				}
				correlations = append(correlations, cf)
			}
		}
	}

	sort.Slice(correlations, func(i, j int) bool {
		return severityWeight(correlations[i].Severity) > severityWeight(correlations[j].Severity)
	})
	return correlations
}

// --- helpers ---

func severityWeight(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func severityIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🔵"
	case SeverityInfo:
		return "⚪"
	default:
		return "❓"
	}
}

// SeverityColor returns an ANSI color code for the severity.
func SeverityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return "31" // red
	case SeverityHigh:
		return "31"
	case SeverityMedium:
		return "33" // yellow
	case SeverityLow:
		return "34" // blue
	case SeverityInfo:
		return "37" // white
	default:
		return "0"
	}
}
