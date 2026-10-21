// Package skill defines invokable playbooks. This file adds executable workflow
// phase definitions that drive built-in security tools in a structured sequence.
package skill

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PhaseStep is a single tool invocation within a workflow phase.
type PhaseStep struct {
	// Tool is the name of the built-in tool to call (e.g. "port_scan", "dns_enum").
	Tool string `json:"tool"`
	// Description explains what this step does for the LLM.
	Description string `json:"description"`
	// ArgsTemplate is a JSON object with value strings. The string "{target}" is
	// replaced with the phase's target argument at runtime. Booleans pass through.
	ArgsTemplate map[string]any `json:"args_template"`
}

// PhaseDef defines one phase of a security workflow.
type PhaseDef struct {
	// Name identifies the phase (e.g. "reconnaissance", "port_scanning").
	Name string `json:"name"`
	// Description explains the phase's goal.
	Description string `json:"description"`
	// Steps are the tool invocations to execute in order.
	Steps []PhaseStep `json:"steps"`
	// ExpectedOutputs describes what FindingStore entries this phase produces.
	ExpectedOutputs []string `json:"expected_outputs"`
}

// WorkflowDef defines the full sequence of phases for a security skill.
type WorkflowDef struct {
	// Name matches the skill name (e.g. "pentest", "vuln-assessment").
	Name string `json:"name"`
	// Description of the workflow.
	Description string `json:"description"`
	// Phases in execution order.
	Phases []PhaseDef `json:"phases"`
}

// Workflows maps skill name to its executable workflow definition.
var Workflows = map[string]WorkflowDef{
	"pentest": {
		Name:        "pentest",
		Description: "Full penetration testing workflow: recon → scanning → enumeration → vulnerability identification → correlation → reporting",
		Phases: []PhaseDef{
			{
				Name:        "reconnaissance",
				Description: "Discover targets: DNS records, subdomains, WHOIS data",
				Steps: []PhaseStep{
					{Tool: "dns_enum", Description: "Query DNS records (A, MX, NS, TXT, SOA)", ArgsTemplate: map[string]any{"domain": "{target}", "record_types": "A,AAAA,MX,NS,TXT,SOA,CNAME"}},
					{Tool: "subdomain_enum", Description: "Brute-force subdomain discovery", ArgsTemplate: map[string]any{"domain": "{target}", "wordlist": "common"}},
					{Tool: "whois_lookup", Description: "WHOIS information gathering", ArgsTemplate: map[string]any{"target": "{target}"}},
				},
				ExpectedOutputs: []string{"dns_enum findings", "subdomain_enum findings", "whois_lookup findings"},
			},
			{
				Name:        "port_scanning",
				Description: "Port scan discovered targets for open services",
				Steps: []PhaseStep{
					{Tool: "port_scan", Description: "Scan top 1000 ports on target", ArgsTemplate: map[string]any{"target": "{target}", "ports": "top-1000", "banner_grab": true}},
				},
				ExpectedOutputs: []string{"port_scan findings (open ports)"},
			},
			{
				Name:        "service_enumeration",
				Description: "Enumerate services on open ports for detailed information",
				Steps: []PhaseStep{
					{Tool: "http_probe", Description: "HTTP security probe on web services", ArgsTemplate: map[string]any{"url": "http://{target}", "timeout_ms": 8000}},
					{Tool: "ssl_check", Description: "TLS certificate analysis", ArgsTemplate: map[string]any{"host": "{target}"}},
				},
				ExpectedOutputs: []string{"http_probe findings (headers, cookies, TLS)", "ssl_check findings"},
			},
			{
				Name:        "vulnerability_identification",
				Description: "Identify known vulnerabilities in discovered services",
				Steps: []PhaseStep{
					{Tool: "cve_search", Description: "Search CVEs for identified services", ArgsTemplate: map[string]any{"query": "{target}", "limit": 10}},
					{Tool: "vuln_scan", Description: "Web vulnerability scan", ArgsTemplate: map[string]any{"url": "http://{target}", "checks": "all"}},
				},
				ExpectedOutputs: []string{"cve_search findings (CVEs)", "vuln_scan findings"},
			},
			{
				Name:        "correlation",
				Description: "Cross-tool correlation: link open ports to known CVEs",
				Steps: []PhaseStep{
					{Tool: "findings", Description: "Cross-tool correlation analysis", ArgsTemplate: map[string]any{"mode": "correlations"}},
				},
				ExpectedOutputs: []string{"correlated findings (port + CVE matches)"},
			},
			{
				Name:        "reporting",
				Description: "Generate formatted security assessment report",
				Steps: []PhaseStep{
					{Tool: "report", Description: "Generate Markdown report", ArgsTemplate: map[string]any{"format": "markdown", "title": "Penetration Test Report"}},
				},
				ExpectedOutputs: []string{"Markdown security report"},
			},
		},
	},
	"vuln-assessment": {
		Name:        "vuln-assessment",
		Description: "Vulnerability assessment workflow: service discovery → CVE lookup → correlation → reporting",
		Phases: []PhaseDef{
			{
				Name:        "service_discovery",
				Description: "Discover running services and web technologies",
				Steps: []PhaseStep{
					{Tool: "port_scan", Description: "Quick port scan for common services", ArgsTemplate: map[string]any{"target": "{target}", "ports": "top-100", "banner_grab": true}},
					{Tool: "http_probe", Description: "HTTP technology fingerprinting", ArgsTemplate: map[string]any{"url": "http://{target}", "timeout_ms": 8000}},
				},
				ExpectedOutputs: []string{"port_scan findings", "http_probe findings"},
			},
			{
				Name:        "cve_lookup",
				Description: "Look up known vulnerabilities for discovered services",
				Steps: []PhaseStep{
					{Tool: "cve_search", Description: "Keyword CVE search", ArgsTemplate: map[string]any{"query": "{target}", "limit": 10}},
				},
				ExpectedOutputs: []string{"cve_search findings"},
			},
			{
				Name:        "correlation",
				Description: "Correlate services with CVEs",
				Steps: []PhaseStep{
					{Tool: "findings", Description: "Cross-tool correlations", ArgsTemplate: map[string]any{"mode": "correlations"}},
				},
				ExpectedOutputs: []string{"correlated findings"},
			},
			{
				Name:        "reporting",
				Description: "Generate assessment report",
				Steps: []PhaseStep{
					{Tool: "report", Description: "Generate report", ArgsTemplate: map[string]any{"format": "markdown", "title": "Vulnerability Assessment Report"}},
				},
				ExpectedOutputs: []string{"assessment report"},
			},
		},
	},
	"forensics": {
		Name:        "forensics",
		Description: "Digital forensics workflow: file analysis → IOC extraction → timeline → reporting",
		Phases: []PhaseDef{
			{
				Name:        "file_analysis",
				Description: "Analyze suspicious files for hashes, strings, and IOCs",
				Steps: []PhaseStep{
					{Tool: "forensic_extract", Description: "Extract forensic artifacts from files", ArgsTemplate: map[string]any{"path": "{target}"}},
				},
				ExpectedOutputs: []string{"forensic_extract findings"},
			},
			{
				Name:        "reporting",
				Description: "Document forensic findings",
				Steps: []PhaseStep{
					{Tool: "report", Description: "Generate forensics report", ArgsTemplate: map[string]any{"format": "markdown", "title": "Digital Forensics Report"}},
				},
				ExpectedOutputs: []string{"forensics report"},
			},
		},
	},
}

// PhaseNames returns the ordered phase names for a workflow.
func PhaseNames(workflow string) []string {
	wf, ok := Workflows[workflow]
	if !ok {
		return nil
	}
	names := make([]string, len(wf.Phases))
	for i, p := range wf.Phases {
		names[i] = p.Name
	}
	return names
}

// ResolveArgs substitutes "{target}" placeholders in args templates.
func ResolveArgs(tmpl map[string]any, target string) json.RawMessage {
	resolved := make(map[string]any)
	for k, v := range tmpl {
		switch val := v.(type) {
		case string:
			resolved[k] = strings.ReplaceAll(val, "{target}", target)
		case bool:
			resolved[k] = val
		case float64:
			resolved[k] = val
		default:
			resolved[k] = v
		}
	}
	b, _ := json.Marshal(resolved)
	return b
}

// LookupPhase returns the phase definition for a workflow+phase name.
func LookupPhase(workflow, phase string) *PhaseDef {
	wf, ok := Workflows[workflow]
	if !ok {
		return nil
	}
	for _, p := range wf.Phases {
		if p.Name == phase {
			return &p
		}
	}
	return nil
}

// FormatWorkflowIndex returns a concise text index of all workflows and their phases.
func FormatWorkflowIndex() string {
	var b strings.Builder
	b.WriteString("Available security workflows (use run_phase with workflow+phase):\n\n")
	for _, wf := range Workflows {
		b.WriteString(fmt.Sprintf("■ %s: %s\n", wf.Name, wf.Description))
		for _, p := range wf.Phases {
			b.WriteString(fmt.Sprintf("  ├─ %s — %s\n", p.Name, p.Description))
			for _, s := range p.Steps {
				b.WriteString(fmt.Sprintf("  │   ↳ %s\n", s.Tool))
			}
		}
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}
