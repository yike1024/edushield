package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// kevClient talks to CISA's Known Exploited Vulnerabilities catalog.
// Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
//
// The catalog is a single JSON file updated daily. We fetch it fresh, cache
// for 24h, and serve per-CVE lookups from memory. No API key required.
type kevClient struct {
	http *http.Client
}

func newKEVClient(http *http.Client) *kevClient {
	return &kevClient{http: http}
}

type kevEntry struct {
	CVEID            string `json:"cveID"`
	VendorProject    string `json:"vendorProject"`
	Product          string `json:"product"`
	Vulnerability    string `json:"vulnerabilityName"`
	DateAdded        string `json:"dateAdded"`
	DueDate          string `json:"dueDate"`
	ShortDescription string `json:"shortDescription"`
	RequiredAction   string `json:"requiredAction"`
	Notes            string `json:"notes"`
}

type kevCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

func (k *kevClient) fetch(ctx context.Context) (*kevCatalog, error) {
	const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	if cached, _, hit, err := globalCache.get("kev", "all", "24h"); err == nil && hit {
		var cat kevCatalog
		if json.Unmarshal([]byte(cached), &cat) == nil {
			return &cat, nil
		}
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "reasonix-plugin-threatintel/"+version)
	resp, err := k.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CISA KEV fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("CISA KEV HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	var cat kevCatalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, fmt.Errorf("decode KEV: %w", err)
	}
	_ = globalCache.put("kev", "all", resp.StatusCode, string(body))
	return &cat, nil
}

// lookup returns the KEV entry for cveID, or nil if not on the list.
func (k *kevClient) lookup(ctx context.Context, cveID string) (*kevEntry, error) {
	cat, err := k.fetch(ctx)
	if err != nil {
		return nil, err
	}
	for i := range cat.Vulnerabilities {
		if cat.Vulnerabilities[i].CVEID == cveID {
			return &cat.Vulnerabilities[i], nil
		}
	}
	return nil, nil
}

// recent returns KEV entries added in the last `days` days.
func (k *kevClient) recent(ctx context.Context, days int) ([]kevEntry, error) {
	if days <= 0 {
		days = 30
	}
	cat, err := k.fetch(ctx)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	out := []kevEntry{}
	for _, e := range cat.Vulnerabilities {
		t, err := time.Parse("2006-01-02", e.DateAdded)
		if err != nil {
			continue
		}
		if !t.Before(cutoff) {
			out = append(out, e)
		}
	}
	return out, nil
}
