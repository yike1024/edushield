// Command reasonix-plugin-seckb is a Reasonix MCP plugin that gives the agent
// a durable security knowledge base (ATT&CK techniques, CVEs, IOCs, response
// playbooks) with BM25 retrieval and optional embedding rerank.
//
// Why: verdicts must be grounded in curated knowledge, not model memory alone.
// The KB ships with embedded seed documents, accepts kb_ingest for growth, and
// can bulk-import a directory of Markdown files with -load.
//
// Wire it up in reasonix.toml:
//
//	[[plugins]]
//	name    = "seckb"
//	command = "reasonix-plugin-seckb"
//
// Tools surface as mcp__seckb__kb_search / kb_ingest / kb_stats. The database
// lives at -db flag > $REASONIX_SECKB_DB > <user config dir>/reasonix/plugins/seckb/seckb.db.
//
// Hybrid retrieval: BM25 always runs offline. When REASONIX_SECKB_EMBED_URL
// (OpenAI-compatible /embeddings endpoint), REASONIX_SECKB_EMBED_MODEL and
// optionally REASONIX_SECKB_EMBED_API_KEY are set, candidates are reranked by
// 0.5*normalized BM25 + 0.5*cosine similarity; per-doc vectors are cached in
// SQLite. Swap in Milvus/Chroma later by replacing the rerank step — the tool
// contract stays identical.
//
// Protocol: newline-delimited JSON-RPC 2.0 on stdin/stdout (same contract as
// reasonix-plugin-example); logs go to stderr.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var version = "dev"

func main() {
	log.SetPrefix("reasonix-plugin-seckb: ")
	log.SetFlags(0)
	dbPath := flag.String("db", "", "SQLite database path (default: $REASONIX_SECKB_DB or <config dir>/reasonix/plugins/seckb/seckb.db)")
	loadDir := flag.String("load", "", "import a directory tree of *.md documents into the database and exit (subdirectory name = collection)")
	flag.Parse()

	path := resolveDBPath(*dbPath)
	srv, err := newServer(path, embedderFromEnv())
	if err != nil {
		log.Fatalf("open knowledge base at %s: %v", path, err)
	}
	defer srv.close()

	if dir := strings.TrimSpace(*loadDir); dir != "" {
		n, err := srv.st.loadDir(dir)
		if err != nil {
			log.Fatalf("load %s: %v", dir, err)
		}
		fmt.Printf("imported %d documents into %s\n", n, path)
		return
	}

	log.Printf("knowledge base: %s (%d documents, embedder=%v)", path, srv.st.count(), srv.embed != nil)
	if err := serve(srv, os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// resolveDBPath picks the database location: explicit flag, then env, then a
// stable per-user default. The directory is created lazily by the store.
func resolveDBPath(flagVal string) string {
	if p := strings.TrimSpace(flagVal); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("REASONIX_SECKB_DB")); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "reasonix", "plugins", "seckb", "seckb.db")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".reasonix", "plugins", "seckb", "seckb.db")
	}
	return "reasonix-seckb.db"
}

// JSON-RPC framing (identical contract to reasonix-plugin-example).

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
	embed *embedder
	tools []toolDef
}

func newServer(dbPath string, emb *embedder) (*server, error) {
	st, err := openStore(dbPath)
	if err != nil {
		return nil, err
	}
	if n, err := st.ensureSeeds(); err != nil {
		_ = st.close()
		return nil, fmt.Errorf("seed knowledge base: %w", err)
	} else if n > 0 {
		log.Printf("seeded %d knowledge documents", n)
	}
	s := &server{st: st, embed: emb}
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
			"serverInfo":      map[string]any{"name": "reasonix-plugin-seckb", "version": version},
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

// tool plumbing

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

// argument helpers

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
