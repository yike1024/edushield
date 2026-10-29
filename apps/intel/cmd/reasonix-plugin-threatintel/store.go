package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// store holds a tiny SQLite cache for external API responses. We do NOT
// persist CVE records here — durable knowledge lives in seckb. The cache
// only exists to (a) survive "data sources unreachable" with a usable
// last-good-response, and (b) implement per-source rate-limit tracking.
//
// Schema is intentionally minimal: one row per cache entry, keyed by
// (source, query_hash). Entries expire after 24h by default.
type store struct {
	db *sql.DB
}

const cacheSchema = `
CREATE TABLE IF NOT EXISTS cache(
  source      TEXT NOT NULL,
  query_key   TEXT NOT NULL,
  fetched_at  TEXT NOT NULL,
  status      INTEGER NOT NULL,
  payload     TEXT NOT NULL,
  PRIMARY KEY (source, query_key)
);
CREATE INDEX IF NOT EXISTS cache_age ON cache(fetched_at);
`

func openStore(path string) (*store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create cache directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	if _, err := db.Exec(cacheSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &store{db: db}, nil
}

func (s *store) close() error { return s.db.Close() }

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// get returns the cached entry if present and fresh (<= maxAge).
// Returns (payload, fetched_at, hit). On miss returns ("", "", false).
func (s *store) get(source, key, maxAge string) (string, string, bool, error) {
	row := s.db.QueryRow(
		"SELECT payload, fetched_at FROM cache WHERE source = ? AND query_key = ?", source, key)
	var payload, fetchedAt string
	if err := row.Scan(&payload, &fetchedAt); err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	ts, err := time.Parse(time.RFC3339, fetchedAt)
	if err != nil {
		return "", "", false, nil // corrupted: treat as miss
	}
	d, err := time.ParseDuration(maxAge)
	if err != nil {
		return "", "", false, err
	}
	if time.Since(ts) > d {
		return "", fetchedAt, false, nil // stale: caller decides whether to serve
	}
	return payload, fetchedAt, true, nil
}

// put upserts a cache entry.
func (s *store) put(source, key string, status int, payload string) error {
	_, err := s.db.Exec(`
		INSERT INTO cache(source, query_key, fetched_at, status, payload)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(source, query_key) DO UPDATE SET
		  fetched_at = excluded.fetched_at,
		  status = excluded.status,
		  payload = excluded.payload
	`, source, key, nowUTC(), status, payload)
	return err
}

// count is exposed in startup log.
func (s *store) count() int {
	row := s.db.QueryRow("SELECT COUNT(*) FROM cache")
	var n int
	_ = row.Scan(&n)
	return n
}

// stats is exposed via intel_stats tool — useful when all sources are
// unreachable and the caller wants to know the last successful sync time
// per source.
func (s *store) stats() map[string]any {
	out := map[string]any{}
	rows, err := s.db.Query("SELECT source, COUNT(*), MAX(fetched_at) FROM cache GROUP BY source")
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	defer rows.Close()
	bySource := []map[string]any{}
	for rows.Next() {
		var src string
		var n int
		var last string
		if err := rows.Scan(&src, &n, &last); err == nil {
			bySource = append(bySource, map[string]any{
				"source":      src,
				"cached_hits": n,
				"last_sync":   last,
			})
		}
	}
	out["sources"] = bySource
	out["total_entries"] = len(bySource)
	return out
}
