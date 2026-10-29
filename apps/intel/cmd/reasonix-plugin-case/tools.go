package main

import (
	"fmt"
)

// toolRegistry exposes the case ledger as MCP tools. Read paths (case_load,
// evidence_list) declare readOnlyHint so reasonix can batch and auto-allow
// them; writes go through the normal permission flow.
func (s *server) toolRegistry() []toolDef {
	return []toolDef{
		{
			name:        "case_open",
			description: "Open (or resume) an investigation case. Call this first with a stable case_id (e.g. the alert ID); returns the current case state. Re-opening never clobbers recorded progress.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"case_id":     map[string]any{"type": "string", "description": "Stable case identifier, e.g. alert/incident ID"},
					"title":       map[string]any{"type": "string", "description": "Short case title (set only on first open)"},
					"description": map[string]any{"type": "string", "description": "Original alert/task description"},
				},
				"required": []string{"case_id"},
			},
			run: func(args map[string]any) (string, error) {
				id := argString(args, "case_id")
				if id == "" {
					return "", fmt.Errorf("case_id is required")
				}
				rec, created, err := s.st.upsertCase(id, argString(args, "title"), argString(args, "description"))
				if err != nil {
					return "", err
				}
				return jsonResult(map[string]any{"created": created, "case": rec})
			},
		},
		{
			name:        "case_load",
			description: "Load the authoritative case snapshot: case metadata, verdict, evidence count and the newest evidence summaries. Call this when resuming or before drawing a verdict — the chat history is only a run log.",
			readOnly:    true,
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"case_id": map[string]any{"type": "string", "description": "Case identifier"},
					"recent":  map[string]any{"type": "integer", "description": "How many newest evidence items to include (default 8)"},
				},
				"required": []string{"case_id"},
			},
			run: func(args map[string]any) (string, error) {
				id := argString(args, "case_id")
				rec, err := s.st.getCase(id)
				if err == errCaseNotFound {
					return "", fmt.Errorf("case %q does not exist; call case_open first", id)
				}
				if err != nil {
					return "", err
				}
				count, err := s.st.evidenceCount(id)
				if err != nil {
					return "", err
				}
				recent, err := s.st.recentEvidence(id, argInt(args, "recent", 8))
				if err != nil {
					return "", err
				}
				return jsonResult(map[string]any{
					"case":            rec,
					"evidence_count":  count,
					"recent_evidence": recent,
				})
			},
		},
		{
			name:        "evidence_add",
			description: "Persist one evidence item into the case ledger after a tool round produces a finding. Duplicates (same summary/detail) are merged. Do this every round instead of relying on chat context.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"case_id": map[string]any{"type": "string", "description": "Case identifier"},
					"summary": map[string]any{"type": "string", "description": "One-line finding statement"},
					"detail":  map[string]any{"type": "string", "description": "Supporting raw output excerpt (kept durable, not sent to the model unless loaded)"},
					"kind":    map[string]any{"type": "string", "description": "Evidence kind, e.g. observation|indicator|kb_match|verdict_input (default observation)"},
					"source":  map[string]any{"type": "string", "description": "Where it came from: tool name, kb collection, url (default agent)"},
					"refs":    map[string]any{"type": "string", "description": "Comma-separated references (file paths, CVE IDs, technique IDs)"},
				},
				"required": []string{"case_id", "summary"},
			},
			run: func(args map[string]any) (string, error) {
				id := argString(args, "case_id")
				summary := argString(args, "summary")
				if id == "" || summary == "" {
					return "", fmt.Errorf("case_id and summary are required")
				}
				rec, created, err := s.st.addEvidence(id, argString(args, "kind"), summary,
					argString(args, "detail"), argString(args, "source"), argString(args, "refs"))
				if err == errCaseNotFound {
					return "", fmt.Errorf("case %q does not exist; call case_open first", id)
				}
				if err != nil {
					return "", err
				}
				return jsonResult(map[string]any{"id": rec.ID, "created": created})
			},
		},
		{
			name:        "evidence_list",
			description: "List evidence items of a case in chronological order, optionally filtered by kind and paged with since_id.",
			readOnly:    true,
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"case_id":  map[string]any{"type": "string", "description": "Case identifier"},
					"kind":     map[string]any{"type": "string", "description": "Only this evidence kind"},
					"since_id": map[string]any{"type": "integer", "description": "Only items with id greater than this (paging)"},
					"limit":    map[string]any{"type": "integer", "description": "Max items (default 20)"},
				},
				"required": []string{"case_id"},
			},
			run: func(args map[string]any) (string, error) {
				id := argString(args, "case_id")
				items, err := s.st.listEvidence(id, argString(args, "kind"), argInt(args, "since_id", 0), argInt(args, "limit", 20))
				if err == errCaseNotFound {
					return "", fmt.Errorf("case %q does not exist", id)
				}
				if err != nil {
					return "", err
				}
				return jsonResult(map[string]any{"case_id": id, "evidence": items})
			},
		},
		{
			name:        "case_verdict",
			description: "Record the case verdict with rationale and confidence. Base it on the full evidence ledger (case_load), not on what is still visible in context.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"case_id":    map[string]any{"type": "string", "description": "Case identifier"},
					"verdict":    map[string]any{"type": "string", "description": "Conclusion, e.g. true_positive|false_positive|benign|needs_escalation"},
					"rationale":  map[string]any{"type": "string", "description": "Evidence-backed reasoning"},
					"confidence": map[string]any{"type": "string", "description": "low|medium|high"},
				},
				"required": []string{"case_id", "verdict"},
			},
			run: func(args map[string]any) (string, error) {
				id := argString(args, "case_id")
				verdict := argString(args, "verdict")
				if id == "" || verdict == "" {
					return "", fmt.Errorf("case_id and verdict are required")
				}
				rec, err := s.st.setVerdict(id, verdict, argString(args, "rationale"), argString(args, "confidence"))
				if err == errCaseNotFound {
					return "", fmt.Errorf("case %q does not exist", id)
				}
				if err != nil {
					return "", err
				}
				return jsonResult(rec)
			},
		},
		{
			name:        "case_close",
			description: "Close the case with a resolution note. The full ledger stays queryable afterwards.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"case_id":    map[string]any{"type": "string", "description": "Case identifier"},
					"resolution": map[string]any{"type": "string", "description": "What was done / recommended follow-ups"},
				},
				"required": []string{"case_id"},
			},
			run: func(args map[string]any) (string, error) {
				id := argString(args, "case_id")
				if id == "" {
					return "", fmt.Errorf("case_id is required")
				}
				rec, err := s.st.closeCase(id, argString(args, "resolution"))
				if err == errCaseNotFound {
					return "", fmt.Errorf("case %q does not exist", id)
				}
				if err != nil {
					return "", err
				}
				return jsonResult(rec)
			},
		},
	}
}
