package main

import (
	"fmt"
	"strings"

	"reasonix/internal/retrieval"
)

// toolRegistry exposes the knowledge base as MCP tools. kb_search and
// kb_stats declare readOnlyHint so reasonix can batch and auto-allow them;
// kb_ingest goes through the normal permission flow.
func (s *server) toolRegistry() []toolDef {
	return []toolDef{
		{
			name:        "kb_search",
			description: "Search the security knowledge base (ATT&CK techniques, CVEs, IOC handling, response playbooks). Call it every investigation round with the current alert + findings as the query; persist useful matches into the case ledger via evidence_add(source=kb).",
			readOnly:    true,
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":      map[string]any{"type": "string", "description": "Search text, e.g. alert description, technique name, CVE ID, indicator"},
					"collection": map[string]any{"type": "string", "description": "Restrict to one collection: attack|vuln|ioc|playbook (default: all)"},
					"top_k":      map[string]any{"type": "integer", "description": "Max results (default 5)"},
					"mode":       map[string]any{"type": "string", "description": "auto (default, hybrid when an embedding endpoint is configured) | bm25 | hybrid"},
				},
				"required": []string{"query"},
			},
			run: func(args map[string]any) (string, error) {
				query := argString(args, "query")
				if query == "" {
					return "", fmt.Errorf("query is required")
				}
				collection := strings.ToLower(argString(args, "collection"))
				topK := argInt(args, "top_k", 5)
				mode := strings.ToLower(argString(args, "mode"))
				if mode == "" {
					mode = "auto"
				}

				var (
					hits     []hit
					usedMode string
					err      error
				)
				switch mode {
				case "bm25":
					hits, err = s.st.searchBM25(query, collection, topK)
					usedMode = "bm25"
				case "hybrid":
					if s.embed == nil {
						return "", fmt.Errorf("hybrid mode needs REASONIX_SECKB_EMBED_URL; use mode=bm25")
					}
					hits, usedMode, err = s.searchHybrid(query, collection, topK)
				case "auto":
					if s.embed != nil {
						hits, usedMode, err = s.searchHybrid(query, collection, topK)
					} else {
						hits, err = s.st.searchBM25(query, collection, topK)
						usedMode = "bm25"
					}
				default:
					return "", fmt.Errorf("unknown mode %q (want auto|bm25|hybrid)", mode)
				}
				if err != nil {
					return "", err
				}

				terms, _ := retrieval.QueryTerms(query)
				results := make([]map[string]any, 0, len(hits))
				for _, h := range hits {
					results = append(results, map[string]any{
						"collection": h.doc.Collection,
						"title":      h.doc.Title,
						"score":      round3(h.final),
						"snippet":    snippet(h.doc, query, terms),
						"source":     h.doc.Source,
						"url":        h.doc.URL,
					})
				}
				return jsonResult(map[string]any{
					"query":      query,
					"mode":       usedMode,
					"collection": collection,
					"results":    results,
				})
			},
		},
		{
			name:        "kb_ingest",
			description: "Add or update one knowledge document (keyed by collection+title; same key updates the body). Use it to grow the KB with verified findings, e.g. internal incident lessons.",
			schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"collection": map[string]any{"type": "string", "description": "Collection name, e.g. attack|vuln|ioc|playbook or a custom one"},
					"title":      map[string]any{"type": "string", "description": "Document title (unique within the collection)"},
					"body":       map[string]any{"type": "string", "description": "Document body"},
					"source":     map[string]any{"type": "string", "description": "Origin, e.g. report name, url"},
					"url":        map[string]any{"type": "string", "description": "Reference link"},
				},
				"required": []string{"collection", "title", "body"},
			},
			run: func(args map[string]any) (string, error) {
				id, created, err := s.st.ingest(
					argString(args, "collection"), argString(args, "title"), argString(args, "body"),
					argString(args, "source"), argString(args, "url"))
				if err != nil {
					return "", err
				}
				return jsonResult(map[string]any{"id": id, "created": created})
			},
		},
		{
			name:        "kb_stats",
			description: "Show knowledge base size per collection and whether semantic rerank is enabled.",
			readOnly:    true,
			schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			run: func(args map[string]any) (string, error) {
				st, err := s.st.stats()
				if err != nil {
					return "", err
				}
				st["embedder"] = s.embed != nil
				if s.embed != nil {
					st["embed_model"] = s.embed.model
				}
				return jsonResult(st)
			},
		},
	}
}

func round3(f float64) float64 {
	return float64(int(f*1000+0.5)) / 1000
}
