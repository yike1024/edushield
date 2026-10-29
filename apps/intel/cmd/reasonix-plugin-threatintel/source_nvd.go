package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// nvdClient talks to NVD CVE 2.0 API.
// Docs: https://nvd.nist.gov/developers/vulnerabilities
//
// Rate limit (per NVD): without API key ~5 req / 30s; with key ~50 req / 30s.
// We honor the user's key via REASONIX_THREATINTEL_NVD_API_KEY.
type nvdClient struct {
	http *http.Client
	key  string
}

func newNVDClient(http *http.Client) *nvdClient {
	return &nvdClient{http: http, key: strings.TrimSpace(envOr("REASONIX_THREATINTEL_NVD_API_KEY", ""))}
}


// cveRecord is the normalized form returned to the agent.
type cveRecord struct {
	ID           string   `json:"id"`
	Published    string   `json:"published,omitempty"`
	LastModified string   `json:"last_modified,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	CVSSv3       *cvss3   `json:"cvss_v3,omitempty"`
	Description  string   `json:"description,omitempty"`
	Refs         []string `json:"refs,omitempty"`
	Source       string   `json:"source"`
	FetchedAt    string   `json:"fetched_at"`
}

type cvss3 struct {
	Score    float64 `json:"score"`
	Vector   string  `json:"vector"`
	Severity string  `json:"severity"`
}

// nvdSingleResp is the response of GET /rest/json/cves/2.0?cveId=CVE-...
type nvdSingleResp struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
	TotalResults int `json:"totalResults"`
}

// lookupCVE fetches a single CVE by ID.
func (n *nvdClient) lookupCVE(ctx context.Context, cveID string) (*cveRecord, error) {
	cveID = strings.TrimSpace(strings.ToUpper(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		return nil, fmt.Errorf("invalid CVE id: %s", cveID)
	}
	u := "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + url.QueryEscape(cveID)
	var raw []byte
	if cached, _, hit, err := globalCache.get("nvd_lookup", cveID, "6h"); err == nil && hit {
		raw = []byte(cached)
	} else {
		body, err := n.do(ctx, u)
		if err != nil {
			return nil, err
		}
		_ = globalCache.put("nvd_lookup", cveID, 200, string(body))
		raw = body
	}
	var resp nvdSingleResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}
	if len(resp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}
	v := resp.Vulnerabilities[0].CVE
	rec := &cveRecord{
		ID:           v.ID,
		Published:    v.Published,
		LastModified: v.LastModified,
		Description:  firstEN(v.Descriptions),
		Source:       "NVD CVE 2.0",
		FetchedAt:    nowUTC(),
	}
	for _, r := range v.References {
		rec.Refs = append(rec.Refs, r.URL)
	}
	// Prefer CVSS v3.1, fall back to v3.0.
	if len(v.Metrics.CVSSMetricV31) > 0 {
		m := v.Metrics.CVSSMetricV31[0]
		rec.CVSSv3 = &cvss3{Score: m.CVSSData.BaseScore, Vector: m.CVSSData.VectorString, Severity: m.CVSSData.BaseSeverity}
	} else if len(v.Metrics.CVSSMetricV30) > 0 {
		m := v.Metrics.CVSSMetricV30[0]
		rec.CVSSv3 = &cvss3{Score: m.CVSSData.BaseScore, Vector: m.CVSSData.VectorString, Severity: m.CVSSData.BaseSeverity}
	}
	if rec.CVSSv3 != nil {
		rec.Severity = rec.CVSSv3.Severity
	}
	return rec, nil
}

// recentCVEs returns CVEs modified within the last `days` days, optionally
// filtered by keyword in description and minimum CVSS score.
func (n *nvdClient) recentCVEs(ctx context.Context, days int, minCVSS float64, keyword string, limit int) ([]cveRecord, error) {
	if days <= 0 {
		days = 7
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -days)
	q := url.Values{}
	q.Set("lastModStartDate", start.Format(time.RFC3339))
	q.Set("lastModEndDate", end.Format(time.RFC3339))
	q.Set("resultsPerPage", fmt.Sprintf("%d", limit))
	if keyword = strings.TrimSpace(keyword); keyword != "" {
		q.Set("keywordSearch", keyword)
	}
	if minCVSS > 0 {
		q.Set("cvssV3Severity", "") // server-side: we still filter client-side
	}
	u := "https://services.nvd.nist.gov/rest/json/cves/2.0?" + q.Encode()

	cacheKey := fmt.Sprintf("%d|%.1f|%s|%d", days, minCVSS, keyword, limit)
	var raw []byte
	if cached, _, hit, err := globalCache.get("nvd_recent", cacheKey, "30m"); err == nil && hit {
		raw = []byte(cached)
	} else {
		body, err := n.do(ctx, u)
		if err != nil {
			return nil, err
		}
		_ = globalCache.put("nvd_recent", cacheKey, 200, string(body))
		raw = body
	}
	var resp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							VectorString string  `json:"vectorString"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"cvssMetricV31"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode NVD recent: %w", err)
	}
	out := make([]cveRecord, 0, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		c := v.CVE
		rec := cveRecord{
			ID:           c.ID,
			Published:    c.Published,
			LastModified: c.LastModified,
			Description:  firstEN(c.Descriptions),
			Source:       "NVD CVE 2.0",
			FetchedAt:    nowUTC(),
		}
		for _, m := range c.Metrics.CVSSMetricV31 {
			rec.CVSSv3 = &cvss3{Score: m.CVSSData.BaseScore, Vector: m.CVSSData.VectorString, Severity: m.CVSSData.BaseSeverity}
			break
		}
		if rec.CVSSv3 != nil {
			rec.Severity = rec.CVSSv3.Severity
			if rec.CVSSv3.Score < minCVSS {
				continue
			}
		} else if minCVSS > 0 {
			continue
		}
		for _, r := range c.References {
			rec.Refs = append(rec.Refs, r.URL)
		}
		out = append(out, rec)
	}
	return out, nil
}

func (n *nvdClient) do(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "reasonix-plugin-threatintel/"+version)
	if n.key != "" {
		req.Header.Set("apiKey", n.key)
	}
	resp, err := n.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5MB cap
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("NVD HTTP %d: %s", resp.StatusCode, snippet(string(body), 200))
	}
	return body, nil
}

func firstEN(descs []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, d := range descs {
		if strings.EqualFold(d.Lang, "en") {
			return d.Value
		}
	}
	for _, d := range descs {
		if d.Value != "" {
			return d.Value
		}
	}
	return ""
}

func snippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
