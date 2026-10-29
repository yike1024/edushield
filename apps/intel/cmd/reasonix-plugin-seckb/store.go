package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"reasonix/internal/retrieval"
)

// store owns the SQLite knowledge base and scores queries against it. The
// corpus is small (curated KB, not a web crawl), so every search recomputes
// per-collection document frequency over in-memory token counts — the same
// BM25 helpers the host agent uses, keeping ranking behavior consistent.
type store struct {
	db *sql.DB
}

const kbSchema = `
CREATE TABLE IF NOT EXISTS docs(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  collection TEXT NOT NULL,
  title      TEXT NOT NULL,
  body       TEXT NOT NULL,
  source     TEXT NOT NULL DEFAULT '',
  url        TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE(collection, title)
);
CREATE TABLE IF NOT EXISTS embeddings(
  doc_id INTEGER PRIMARY KEY REFERENCES docs(id) ON DELETE CASCADE,
  model  TEXT NOT NULL,
  vector BLOB NOT NULL
);
`

func openStore(path string) (*store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create knowledge base directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single-writer SQLite: serialize, never contend
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON"} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	if _, err := db.Exec(kbSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &store{db: db}, nil
}

func (s *store) close() error { return s.db.Close() }

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// kbDoc is one knowledge document.
type kbDoc struct {
	ID         int64  `json:"id"`
	Collection string `json:"collection"`
	Title      string `json:"title"`
	Body       string `json:"-"`
	Source     string `json:"source,omitempty"`
	URL        string `json:"url,omitempty"`
}

func (s *store) count() int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM docs`).Scan(&n)
	return n
}

// ensureSeeds loads the embedded starter KB once, when the table is empty.
func (s *store) ensureSeeds() (int, error) {
	if s.count() > 0 {
		return 0, nil
	}
	n := 0
	for _, d := range seedDocs {
		if _, created, err := s.ingest(d.Collection, d.Title, d.Body, d.Source, d.URL); err != nil {
			return n, err
		} else if created {
			n++
		}
	}
	return n, nil
}

// ingest inserts or updates one document (keyed by collection+title).
func (s *store) ingest(collection, title, body, source, url string) (int64, bool, error) {
	collection = strings.ToLower(strings.TrimSpace(collection))
	if collection == "" || strings.TrimSpace(title) == "" || strings.TrimSpace(body) == "" {
		return 0, false, fmt.Errorf("collection, title and body are required")
	}
	var existing int64
	err := s.db.QueryRow(`SELECT id FROM docs WHERE collection = ? AND title = ?`, collection, title).Scan(&existing)
	if err == nil {
		if _, err := s.db.Exec(
			`UPDATE docs SET body = ?, source = ?, url = ? WHERE id = ?`, body, source, url, existing); err != nil {
			return 0, false, err
		}
		// Stale cached vector no longer matches the new body.
		if _, err := s.db.Exec(`DELETE FROM embeddings WHERE doc_id = ?`, existing); err != nil {
			return 0, false, err
		}
		return existing, false, nil
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}
	res, err := s.db.Exec(
		`INSERT INTO docs(collection, title, body, source, url, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		collection, title, body, source, url, nowUTC())
	if err != nil {
		return 0, false, err
	}
	id, err := res.LastInsertId()
	return id, true, err
}

// hit is one scored search result.
type hit struct {
	doc   kbDoc
	bm25  float64
	final float64
}

// searchBM25 ranks documents of one collection (or all) by BM25, best first.
func (s *store) searchBM25(query, collection string, topK int) ([]hit, error) {
	terms, err := retrieval.QueryTerms(query)
	if err != nil {
		return nil, err
	}
	q := `SELECT id, collection, title, body, source, url FROM docs`
	var args []any
	if collection != "" {
		q += ` WHERE collection = ?`
		args = append(args, collection)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var docs []kbDoc
	var counts []map[string]int
	var lengths []int
	for rows.Next() {
		var d kbDoc
		if err := rows.Scan(&d.ID, &d.Collection, &d.Title, &d.Body, &d.Source, &d.URL); err != nil {
			return nil, err
		}
		tokens := retrieval.Tokens(d.Title + " " + d.Title + " " + d.Body) // title weighted twice
		docs = append(docs, d)
		counts = append(counts, retrieval.Counts(tokens))
		lengths = append(lengths, len(tokens))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, nil
	}
	df := retrieval.DocumentFrequency(counts)
	totalLen := 0
	for _, l := range lengths {
		totalLen += l
	}
	avgLen := float64(totalLen) / float64(len(docs))
	hits := make([]hit, 0, len(docs))
	for i, d := range docs {
		score := retrieval.BM25Score(counts[i], lengths[i], terms, df, len(docs), avgLen)
		if score <= 0 {
			continue
		}
		hits = append(hits, hit{doc: d, bm25: score, final: score})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].bm25 > hits[j].bm25 })
	if topK > 0 && len(hits) > topK {
		hits = hits[:topK]
	}
	return hits, nil
}

// snippet returns a query-centered excerpt of a document body.
func snippet(d kbDoc, query string, terms []string) string {
	text := d.Body
	if text == "" {
		text = d.Title
	}
	return retrieval.MakeSnippet(text, query, terms, 240)
}

// stats summarizes the knowledge base per collection.
func (s *store) stats() (map[string]any, error) {
	rows, err := s.db.Query(`SELECT collection, COUNT(*) FROM docs GROUP BY collection ORDER BY collection`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	collections := map[string]int{}
	total := 0
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return nil, err
		}
		collections[name] = n
		total += n
	}
	return map[string]any{
		"documents":   total,
		"collections": collections,
		"embedder":    false, // filled by the caller, which knows the env config
	}, rows.Err()
}

// loadDir bulk-imports a directory tree of *.md files. The subdirectory name
// becomes the collection ("general" for files at the root). An optional YAML
// frontmatter may set collection/title; the remainder is the document body.
func (s *store) loadDir(dir string) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		collection := "general"
		if rel, err := filepath.Rel(dir, path); err == nil {
			if sub := filepath.Dir(rel); sub != "." {
				collection = strings.ToLower(strings.ReplaceAll(sub, string(filepath.Separator), "-"))
			}
		}
		title := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		body := string(raw)
		if fm, rest, ok := splitFrontmatter(body); ok {
			if v := fm["collection"]; v != "" {
				collection = strings.ToLower(v)
			}
			if v := fm["title"]; v != "" {
				title = v
			}
			body = rest
		}
		if _, _, err := s.ingest(collection, title, body, "file:"+path, ""); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		n++
		return nil
	})
	return n, err
}

// splitFrontmatter extracts simple "key: value" YAML frontmatter if present.
func splitFrontmatter(text string) (map[string]string, string, bool) {
	if !strings.HasPrefix(text, "---\n") {
		return nil, text, false
	}
	end := strings.Index(text[4:], "\n---")
	if end < 0 {
		return nil, text, false
	}
	meta := map[string]string{}
	for _, line := range strings.Split(text[4:4+end], "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			meta[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	rest := strings.TrimLeft(text[4+end+4:], "\n")
	return meta, rest, true
}
