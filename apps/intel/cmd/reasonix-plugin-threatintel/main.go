// Command reasonix-plugin-threatintel is a Reasonix MCP plugin that surfaces
// external threat-intelligence sources (NVD / CISA KEV / ExploitDB / GitHub
// Advisory) as MCP tools for the agent. The plugin is intentionally read-only:
// callers normalize records and ingest them into the local KB (seckb) via
// kb_ingest, keeping the threatintel plugin stateless w.r.t. durable knowledge.
//
// Why a separate plugin instead of folding into seckb:
//   - Each external source has its own rate limit, schema, and failure mode.
//     Isolating them keeps retrieval hot-path logic (seckb BM25) untouched.
//   - The "external API" half can be evolved (add CISA KEV today, VulnCheck
//     tomorrow) without touching the corpus store.
//   - Reuse of the same single-writer SQLite cache layer (modernc.org/sqlite,
//     WAL) keeps failure-mode behavior consistent across plugins.
//
// Wire it up in reasonix.toml:
//
//	[[plugins]]
//	name    = "threatintel"
//	command = "reasonix-plugin-threatintel"
//	env = { REASONIX_THREATINTEL_NVD_API_KEY = "${NVD_API_KEY:-}" }
//
// Tools surface as mcp__threatintel__intel_*. The plugin is read-only by
// construction (every tool declares readOnlyHint = true).
//
// Protocol: newline-delimited JSON-RPC 2.0 on stdin/stdout (same contract as
// reasonix-plugin-seckb and reasonix-plugin-case); logs go to stderr.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var version = "dev"

func main() {
	log.SetPrefix("reasonix-plugin-threatintel: ")
	log.SetFlags(0)
	cachePath := flag.String("cache-db", "", "SQLite cache path (default: $REASONIX_THREATINTEL_DB or <config dir>/reasonix/plugins/threatintel/cache.db)")
	loadDump := flag.String("dump", "", "if set, dump sample seed table to stdout (for diagnostics) and exit")
	flag.Parse()

	srv, err := newServer(resolveCachePath(*cachePath))
	if err != nil {
		log.Fatalf("open cache at %s: %v", resolveCachePath(*cachePath), err)
	}
	defer srv.close()

	if d := strings.TrimSpace(*loadDump); d != "" {
		fmt.Println("cache path:", resolveCachePath(*cachePath))
		fmt.Println("stats:", srv.st.stats())
		return
	}

	log.Printf("threat intel cache: %s (hit=%d)", resolveCachePath(*cachePath), srv.st.count())
	if err := serve(srv, os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func resolveCachePath(flagVal string) string {
	if p := strings.TrimSpace(flagVal); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("REASONIX_THREATINTEL_DB")); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "reasonix", "plugins", "threatintel", "cache.db")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".reasonix", "plugins", "threatintel", "cache.db")
	}
	return "reasonix-threatintel.db"
}

// JSON-RPC 2.0 over newline-delimited stdin/stdout. Identical framing to
// reasonix-plugin-seckb / -case; that contract is what the host MCP client
// expects across all reasonix-sidecar plugins.

type request struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	protocolVersion    = "2024-11-05"
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

type server struct {
	st    *store
	http  *http.Client
	tools []toolDef
}

func newServer(cachePath string) (*server, error) {
	st, err := openStore(cachePath)
	if err != nil {
		return nil, err
	}
	globalCache = st
	s := &server{
		st:   st,
		http: &http.Client{Timeout: 30 * time.Second},
	}
	s.tools = s.toolRegistry()
	return s, nil
}

func (s *server) close() { _ = s.st.close() }

func serve(s *server, in *os.File, out *os.File) error {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer w.Flush()
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if rerr := s.handleLine(line, w); rerr != nil {
				return rerr
			}
			if ferr := w.Flush(); ferr != nil {
				return ferr
			}
		}
		if err != nil {
			return nil // stdin closed: clean shutdown
		}
	}
}

func (s *server) handleLine(line []byte, w *bufio.Writer) error {
	line = []byte(strings.TrimSpace(string(line)))
	if len(line) == 0 {
		return nil
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		log.Printf("skipping unparseable line: %v", err)
		return nil
	}
	if req.ID == nil {
		return nil // notification: no reply
	}
	resp := response{JSONRPC: "2.0", ID: *req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "reasonix-plugin-threatintel", "version": version},
		}
	case "tools/list":
		resp.Result = map[string]any{"tools": toolList(s.tools)}
	case "tools/call":
		resp.Result, resp.Error = callTool(s.tools, req.Params)
	default:
		resp.Error = &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// tool plumbing (intentionally identical to seckb / case for consistency).

type toolDef struct {
	name        string
	description string
	schema      map[string]any
	readOnly    bool
	run         func(args map[string]any) (string, error)
}

func toolList(tools []toolDef) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{
			"name":        t.name,
			"description": t.description,
			"inputSchema": t.schema,
			"annotations": map[string]any{"readOnlyHint": t.readOnly, "title": t.name},
		})
	}
	return out
}

func callTool(tools []toolDef, params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	for _, t := range tools {
		if t.name != p.Name {
			continue
		}
		text, err := t.run(p.Arguments)
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		return textResult(text, false), nil
	}
	return nil, &rpcError{Code: codeInvalidParams, Message: "unknown tool: " + p.Name}
}

func textResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func jsonResult(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// arg helpers — duplicated (rather than imported) to keep this plugin's
// compilation independent of internal/* changes.

func argString(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

func argInt(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}
