package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ghsaClient queries GitHub's Advisory Database via REST.
// Docs: https://docs.github.com/en/rest/security-advisories/global-advisories
//
// Auth is optional: public advisories work without a token (rate-limited),
// but REASONIX_THREATINTEL_GITHUB_TOKEN lifts the cap to 5000 req/h.
type ghsaClient struct {
	http *http.Client
	tok  string
}

func newGHSAClient(http *http.Client) *ghsaClient {
	return &ghsaClient{http: http, tok: strings.TrimSpace(getenv("REASONIX_THREATINTEL_GITHUB_TOKEN"))}
}

type ghsaEntry struct {
	GHSAID      string   `json:"ghsa_id"`
	CVEID       string   `json:"cve_id,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	CVSS        *cvss3   `json:"cvss_v3,omitempty"`
	Summary     string   `json:"summary"`
	Description string   `json:"description,omitempty"`
	PublishedAt string   `json:"published_at,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
	URL         string   `json:"url"`
	Vulns       []string `json:"vulnerable_packages,omitempty"`
	Source      string   `json:"source"`
	FetchedAt   string   `json:"fetched_at"`
}

// ghsaAdvisory is the raw JSON shape for one advisory as returned by
// GET https://api.github.com/advisories?cve_id=...
type ghsaAdvisory struct {
	GhsaID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	CVSS        struct {
		Score        float64 `json:"score"`
		VectorString string  `json:"vector_string"`
	} `json:"cvss"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	PublishedAt string `json:"published_at"`
	UpdatedAt   string `json:"updated_at"`
	HTMLURL     string `json:"html_url"`
	Vulnerabilities []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
	} `json:"vulnerabilities"`
}

type ghsaListResp []ghsaAdvisory

func normalizeSingle(a *ghsaAdvisory) *ghsaEntry {
	if a == nil {
		return nil
	}
	out := &ghsaEntry{
		GHSAID:      a.GhsaID,
		CVEID:       a.CVEID,
		Severity:    a.Severity,
		Summary:     a.Summary,
		Description: a.Description,
		PublishedAt: a.PublishedAt,
		UpdatedAt:   a.UpdatedAt,
		URL:         a.HTMLURL,
		Source:      "GitHub Advisory Database",
		FetchedAt:   nowUTC(),
	}
	if a.CVSS.Score > 0 {
		out.CVSS = &cvss3{Score: a.CVSS.Score, Vector: a.CVSS.VectorString, Severity: a.Severity}
	}
	for _, v := range a.Vulnerabilities {
		if v.Package.Name == "" {
			continue
		}
		out.Vulns = append(out.Vulns, fmt.Sprintf("%s/%s %s", v.Package.Ecosystem, v.Package.Name, v.VulnerableVersionRange))
	}
	return out
}

func normalizeList(list ghsaListResp) []ghsaEntry {
	out := make([]ghsaEntry, 0, len(list))
	for i := range list {
		out = append(out, *normalizeSingle(&list[i]))
	}
	return out
}

func (g *ghsaClient) do(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "reasonix-plugin-threatintel/"+version)
	if g.tok != "" {
		req.Header.Set("Authorization", "Bearer "+g.tok)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub Advisory fetch: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GitHub Advisory HTTP %d: %s", resp.StatusCode, snippet(string(body), 200))
	}
	return body, nil
}

func (g *ghsaClient) fetchByCVE(ctx context.Context, cve string) (*ghsaEntry, error) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	u := "https://api.github.com/advisories?cve_id=" + url.QueryEscape(cve)
	if cached, _, hit, err := globalCache.get("ghsa", cve, "12h"); err == nil && hit {
		var list ghsaListResp
		if json.Unmarshal([]byte(cached), &list) == nil && len(list) > 0 {
			return normalizeSingle(&list[0]), nil
		}
	}
	body, err := g.do(ctx, u)
	if err != nil {
		return nil, err
	}
	_ = globalCache.put("ghsa", cve, 200, string(body))
	var list ghsaListResp
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode GHSA list: %w", err)
	}
	if len(list) == 0 {
		return nil, nil
	}
	return normalizeSingle(&list[0]), nil
}

func (g *ghsaClient) fetchByPackage(ctx context.Context, ecosystem, pkg string) ([]ghsaEntry, error) {
	ecosystem = strings.TrimSpace(ecosystem)
	pkg = strings.TrimSpace(pkg)
	if ecosystem == "" || pkg == "" {
		return nil, fmt.Errorf("ecosystem and package are required")
	}
	u := "https://api.github.com/advisories?ecosystem=" + url.QueryEscape(ecosystem) + "&affects=" + url.QueryEscape(pkg)
	cacheKey := ecosystem + "|" + pkg
	if cached, _, hit, err := globalCache.get("ghsa_pkg", cacheKey, "12h"); err == nil && hit {
		var list ghsaListResp
		if json.Unmarshal([]byte(cached), &list) == nil {
			return normalizeList(list), nil
		}
	}
	body, err := g.do(ctx, u)
	if err != nil {
		return nil, err
	}
	_ = globalCache.put("ghsa_pkg", cacheKey, 200, string(body))
	var list ghsaListResp
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode GHSA list: %w", err)
	}
	return normalizeList(list), nil
}
