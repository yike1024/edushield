package main

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// store owns the SQLite case ledger. The chat transcript is a run log; this
// database is the authoritative task state every round writes into and every
// resumed session loads from.
type store struct {
	db *sql.DB
}

const caseSchema = `
CREATE TABLE IF NOT EXISTS cases(
  id                TEXT PRIMARY KEY,
  title             TEXT NOT NULL DEFAULT '',
  description       TEXT NOT NULL DEFAULT '',
  status            TEXT NOT NULL DEFAULT 'open',
  verdict           TEXT NOT NULL DEFAULT '',
  verdict_rationale TEXT NOT NULL DEFAULT '',
  confidence        TEXT NOT NULL DEFAULT '',
  resolution        TEXT NOT NULL DEFAULT '',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id    TEXT NOT NULL REFERENCES cases(id),
  kind       TEXT NOT NULL DEFAULT 'observation',
  summary    TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  source     TEXT NOT NULL DEFAULT 'agent',
  refs       TEXT NOT NULL DEFAULT '',
  dedup_key  TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(case_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id, id);
`

func openStore(path string) (*store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create case database directory: %w", err)
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
	if _, err := db.Exec(caseSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &store{db: db}, nil
}

func (s *store) close() error { return s.db.Close() }

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// caseRecord mirrors the cases table for JSON output.
type caseRecord struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
	Verdict     string `json:"verdict,omitempty"`
	Rationale   string `json:"verdict_rationale,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	Resolution  string `json:"resolution,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type evidenceRecord struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	Summary   string `json:"summary"`
	Detail    string `json:"detail,omitempty"`
	Source    string `json:"source,omitempty"`
	Refs      string `json:"refs,omitempty"`
	CreatedAt string `json:"created_at"`
}

var errCaseNotFound = fmt.Errorf("case not found")

func (s *store) getCase(id string) (caseRecord, error) {
	var c caseRecord
	err := s.db.QueryRow(
		`SELECT id, title, description, status, verdict, verdict_rationale, confidence, resolution, created_at, updated_at FROM cases WHERE id = ?`, id,
	).Scan(&c.ID, &c.Title, &c.Description, &c.Status, &c.Verdict, &c.Rationale, &c.Confidence, &c.Resolution, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return c, errCaseNotFound
	}
	return c, err
}

// upsertCase creates the case when absent; existing cases keep their state and
// only gain missing title/description, so re-opening after a resume never
// clobbers recorded progress.
func (s *store) upsertCase(id, title, description string) (caseRecord, bool, error) {
	if existing, err := s.getCase(id); err == nil {
		if title != "" && existing.Title == "" || description != "" && existing.Description == "" {
			if title != "" && existing.Title == "" {
				existing.Title = title
			}
			if description != "" && existing.Description == "" {
				existing.Description = description
			}
			if _, err := s.db.Exec(`UPDATE cases SET title = ?, description = ?, updated_at = ? WHERE id = ?`,
				existing.Title, existing.Description, nowUTC(), id); err != nil {
				return existing, false, err
			}
		}
		return existing, false, nil
	} else if err != errCaseNotFound {
		return caseRecord{}, false, err
	}
	now := nowUTC()
	if _, err := s.db.Exec(
		`INSERT INTO cases(id, title, description, status, created_at, updated_at) VALUES(?, ?, ?, 'open', ?, ?)`,
		id, title, description, now, now); err != nil {
		return caseRecord{}, false, err
	}
	rec, err := s.getCase(id)
	return rec, true, err
}

// dedupKey normalizes an evidence item's identity so repeated rounds recording
// the same finding merge instead of bloating the ledger.
func dedupKey(summary, detail string) string {
	norm := strings.ToLower(strings.Join(strings.Fields(summary), " ")) + "\x00" + strings.Join(strings.Fields(detail), " ")
	h := sha1.Sum([]byte(norm))
	return hex.EncodeToString(h[:])
}

// addEvidence inserts one finding; a duplicate (same case + normalized
// summary/detail) reports the existing row instead of inserting.
func (s *store) addEvidence(caseID, kind, summary, detail, source, refs string) (evidenceRecord, bool, error) {
	if _, err := s.getCase(caseID); err != nil {
		return evidenceRecord{}, false, err
	}
	if kind == "" {
		kind = "observation"
	}
	if source == "" {
		source = "agent"
	}
	key := dedupKey(summary, detail)
	var dup evidenceRecord
	err := s.db.QueryRow(
		`SELECT id, kind, summary, detail, source, refs, created_at FROM evidence WHERE case_id = ? AND dedup_key = ?`, caseID, key,
	).Scan(&dup.ID, &dup.Kind, &dup.Summary, &dup.Detail, &dup.Source, &dup.Refs, &dup.CreatedAt)
	if err == nil {
		return dup, false, nil
	}
	if err != sql.ErrNoRows {
		return evidenceRecord{}, false, err
	}
	now := nowUTC()
	res, err := s.db.Exec(
		`INSERT INTO evidence(case_id, kind, summary, detail, source, refs, dedup_key, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		caseID, kind, summary, detail, source, refs, key, now)
	if err != nil {
		return evidenceRecord{}, false, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return evidenceRecord{}, false, err
	}
	if _, err := s.db.Exec(`UPDATE cases SET updated_at = ? WHERE id = ?`, now, caseID); err != nil {
		return evidenceRecord{}, false, err
	}
	return evidenceRecord{ID: id, Kind: kind, Summary: summary, Detail: detail, Source: source, Refs: refs, CreatedAt: now}, true, nil
}

func (s *store) listEvidence(caseID, kind string, sinceID, limit int) ([]evidenceRecord, error) {
	if _, err := s.getCase(caseID); err != nil {
		return nil, err
	}
	query := `SELECT id, kind, summary, detail, source, refs, created_at FROM evidence WHERE case_id = ? AND id > ?`
	args := []any{caseID, sinceID}
	if kind != "" {
		query += ` AND kind = ?`
		args = append(args, kind)
	}
	query += ` ORDER BY id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []evidenceRecord
	for rows.Next() {
		var e evidenceRecord
		if err := rows.Scan(&e.ID, &e.Kind, &e.Summary, &e.Detail, &e.Source, &e.Refs, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *store) evidenceCount(caseID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM evidence WHERE case_id = ?`, caseID).Scan(&n)
	return n, err
}

// recentEvidence returns the newest n findings, oldest first, for snapshot loads.
func (s *store) recentEvidence(caseID string, n int) ([]evidenceRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, kind, summary, detail, source, refs, created_at FROM evidence WHERE case_id = ? ORDER BY id DESC LIMIT ?`, caseID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []evidenceRecord
	for rows.Next() {
		var e evidenceRecord
		if err := rows.Scan(&e.ID, &e.Kind, &e.Summary, &e.Detail, &e.Source, &e.Refs, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Reverse to chronological order.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (s *store) setVerdict(caseID, verdict, rationale, confidence string) (caseRecord, error) {
	if _, err := s.getCase(caseID); err != nil {
		return caseRecord{}, err
	}
	if _, err := s.db.Exec(
		`UPDATE cases SET verdict = ?, verdict_rationale = ?, confidence = ?, updated_at = ? WHERE id = ?`,
		verdict, rationale, confidence, nowUTC(), caseID); err != nil {
		return caseRecord{}, err
	}
	return s.getCase(caseID)
}

func (s *store) closeCase(caseID, resolution string) (caseRecord, error) {
	if _, err := s.getCase(caseID); err != nil {
		return caseRecord{}, err
	}
	if _, err := s.db.Exec(
		`UPDATE cases SET status = 'closed', resolution = ?, updated_at = ? WHERE id = ?`,
		resolution, nowUTC(), caseID); err != nil {
		return caseRecord{}, err
	}
	return s.getCase(caseID)
}
