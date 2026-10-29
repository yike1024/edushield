package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// globalCache is wired in main() so every adapter can read/write through
// the same SQLite cache without re-plumbing.
var globalCache *store

// toolRegistry exposes external threat-intel sources as MCP tools. Every
// tool declares readOnlyHint=true so the Reasonix host can batch /
// auto-approve; the plugin itself writes nothing to durable knowledge —
// callers normalize records and persist via mcp__seckb__kb_ingest.
func (s *server) toolRegistry() []toolDef {
	nvd := newNVDClient(s.http)
	kev := newKEVClient(s.http)
	edb := newExploitDBClient(s.http)
	ghsa := newGHSAClient(s.http)

	return []toolDef{
		{
			name:        "intel_cve_lookup",
			description: "Look up a single CVE by ID from NVD. Returns CVSS v3.1 score/vector, severity, description, and reference URLs. Always pair with intel_kev_check(cve_id) to know if it's exploited in the wild.",
			readOnly:    true,
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"cve_id": map[string]any{"type": "string", "description": "CVE ID like CVE-2024-12345"},
				},
				"required": []string{"cve_id"},
			},
			run: func(args map[string]any) (string, error) {
				cve := argString(args, "cve_id")
				if cve == "" {
					return "", fmt.Errorf("cve_id is required")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				rec, err := nvd.lookupCVE(ctx, cve)
				if err != nil {
					return "", fmt.Errorf("NVD lookup failed: %w", err)
				}
				return jsonResult(rec)
			},
		},
		{
			name:        "intel_cve_recent",
			description: "List CVEs last modified within the last N days, optionally filtered by CVSS severity / keyword in description. Pair each result with intel_kev_check to flag exploited-in-the-wild. Caches per (days, min_cvss, keyword, limit) for 30 minutes to respect NVD rate limits.",
			readOnly:    true,
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"days":    map[string]any{"type": "integer", "description": "Window in days, default 7"},
					"min_cvss": map[string]any{"type": "number", "description": "Minimum CVSS v3 base score, default 0 (no filter)"},
					"keyword": map[string]any{"type": "string", "description": "Keyword filter on description (e.g. product name, vendor)"},
					"limit":   map[string]any{"type": "integer", "description": "Max results, default 20, max 100"},
				},
			},
			run: func(args map[string]any) (string, error) {
				days := argInt(args, "days", 7)
				limit := argInt(args, "limit", 20)
				minCVSS := 0.0
				if v, ok := args["min_cvss"].(float64); ok {
					minCVSS = v
				}
				keyword := argString(args, "keyword")
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				recs, err := nvd.recentCVEs(ctx, days, minCVSS, keyword, limit)
				if err != nil {
					return "", fmt.Errorf("NVD recent failed: %w", err)
				}
				return jsonResult(map[string]any{
					"window_days":  days,
					"min_cvss":     minCVSS,
					"keyword":      keyword,
					"count":        len(recs),
					"fetched_at":   nowUTC(),
					"source":       "NVD CVE 2.0",
					"results":      recs,
				})
			},
		},
		{
			name:        "intel_kev_check",
			description: "Check whether a CVE is on the CISA Known Exploited Vulnerabilities (KEV) catalog. If yes, returns due date, required action, and short description. KEV = actively exploited in the wild; remediation due dates are usually 2-3 weeks.",
			readOnly:    true,
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"cve_id": map[string]any{"type": "string", "description": "CVE ID like CVE-2024-12345"},
				},
				"required": []string{"cve_id"},
			},
			run: func(args map[string]any) (string, error) {
				cve := argString(args, "cve_id")
				if cve == "" {
					return "", fmt.Errorf("cve_id is required")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				entry, err := kev.lookup(ctx, strings.ToUpper(cve))
				if err != nil {
					return "", fmt.Errorf("KEV check failed: %w", err)
				}
				return jsonResult(map[string]any{
					"cve_id":      strings.ToUpper(cve),
					"on_kev":      entry != nil,
					"entry":       entry,
					"checked_at":  nowUTC(),
					"source":      "CISA Known Exploited Vulnerabilities Catalog",
				})
			},
		},
		{
			name:        "intel_kev_recent",
			description: "List CVEs added to CISA KEV in the last N days. Use for 'what's newly exploited in the wild' feeds.",
			readOnly:    true,
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"days": map[string]any{"type": "integer", "description": "Window in days, default 30"},
				},
			},
			run: func(args map[string]any) (string, error) {
				days := argInt(args, "days", 30)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				entries, err := kev.recent(ctx, days)
				if err != nil {
					return "", fmt.Errorf("KEV recent failed: %w", err)
				}
				return jsonResult(map[string]any{
					"window_days": days,
					"count":       len(entries),
					"fetched_at":  nowUTC(),
					"source":      "CISA Known Exploited Vulnerabilities Catalog",
					"entries":     entries,
				})
			},
		},
		{
			name:        "intel_exploitdb_search",
			description: "Search ExploitDB for public exploit code by keyword or CVE ID. Returns EDB-ID, title, CVE mapping, platform, type. Pair with intel_kev_check to assess risk of actively-exploited-with-public-poc CVEs.",
			readOnly:    true,
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"keyword": map[string]any{"type": "string", "description": "Keyword to match in exploit title"},
					"cve_id":  map[string]any{"type": "string", "description": "Filter to a specific CVE"},
					"limit":   map[string]any{"type": "integer", "description": "Max results, default 10, max 50"},
				},
			},
			run: func(args map[string]any) (string, error) {
				keyword := argString(args, "keyword")
				cve := argString(args, "cve_id")
				limit := argInt(args, "limit", 10)
				if keyword == "" && cve == "" {
					return "", fmt.Errorf("at least one of keyword or cve_id is required")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				hits, err := edb.search(ctx, keyword, cve, limit)
				if err != nil {
					return "", fmt.Errorf("ExploitDB search failed: %w", err)
				}
				return jsonResult(map[string]any{
					"keyword":    keyword,
					"cve":        strings.ToUpper(cve),
					"count":      len(hits),
					"fetched_at": nowUTC(),
					"source":     "ExploitDB (GitLab mirror)",
					"results":    hits,
				})
			},
		},
		{
			name:        "intel_github_advisory",
			description: "Query the GitHub Advisory Database (GHSA). Either by CVE ID (single) or by ecosystem+package (list). Useful for open-source dependency vulnerability tracking.",
			readOnly:    true,
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"cve_id":    map[string]any{"type": "string", "description": "Look up GHSA by CVE ID"},
					"ecosystem": map[string]any{"type": "string", "description": "Package ecosystem: npm|pip|maven|nuget|composer|rubygems|go|rust|erlang|pub|swift|actions"},
					"package":   map[string]any{"type": "string", "description": "Package name (requires ecosystem)"},
				},
			},
			run: func(args map[string]any) (string, error) {
				cve := argString(args, "cve_id")
				eco := argString(args, "ecosystem")
				pkg := argString(args, "package")
				if cve == "" && (eco == "" || pkg == "") {
					return "", fmt.Errorf("provide either cve_id, or both ecosystem+package")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if cve != "" {
					rec, err := ghsa.fetchByCVE(ctx, cve)
					if err != nil {
						return "", fmt.Errorf("GHSA fetch failed: %w", err)
					}
					return jsonResult(map[string]any{
						"cve_id":     strings.ToUpper(cve),
						"found":      rec != nil,
						"advisory":   rec,
						"fetched_at": nowUTC(),
						"source":     "GitHub Advisory Database",
					})
				}
				recs, err := ghsa.fetchByPackage(ctx, eco, pkg)
				if err != nil {
					return "", fmt.Errorf("GHSA fetch failed: %w", err)
				}
				return jsonResult(map[string]any{
					"ecosystem":  eco,
					"package":    pkg,
					"count":      len(recs),
					"fetched_at": nowUTC(),
					"source":     "GitHub Advisory Database",
					"advisories": recs,
				})
			},
		},
		{
			name:        "intel_stats",
			description: "Show cache state per external source: how many queries cached, when each source was last successfully fetched. Use when intel_* tools are failing to know whether to fall back to local KB or wait.",
			readOnly:    true,
			schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			run: func(args map[string]any) (string, error) {
				st := s.st.stats()
				st["plugin_version"] = version
				st["sources_supported"] = []string{"nvd", "cisa_kev", "exploitdb", "github_advisory"}
				return jsonResult(st)
			},
		},
	}
}
