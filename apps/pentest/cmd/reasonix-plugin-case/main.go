// Command reasonix-plugin-case is a Reasonix MCP plugin that keeps the
// authoritative task state for long-running investigations (security triage,
// incident analysis, multi-round research) in SQLite instead of the chat
// transcript.
//
// Why: chat history is a run log, not an evidence base. Every tool round's
// findings belong in a durable, queryable ledger so a session can be resumed
// across process restarts, HTTP reconnects, or model context resets by loading
// the case snapshot — never by replaying conversation.
//
// Wire it up in reasonix.toml:
//
//	[[plugins]]
//	name    = "case"
//	command = "reasonix-plugin-case"
//
// Tools surface as mcp__case__case_open / case_load / evidence_add /
// evidence_list / case_verdict / case_close. The database lives at
// -db flag > $REASONIX_CASE_DB > <user config dir>/reasonix/plugins/case/case.db.
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
	log.SetPrefix("reasonix-plugin-case: ")
	log.SetFlags(0)
	dbPath := flag.String("db", "", "SQLite database path (default: $REASONIX_CASE_DB or <config dir>/reasonix/plugins/case/case.db)")
	flag.Parse()

	path := resolveDBPath(*dbPath)
	srv, err := newServer(path)
	if err != nil {
		log.Fatalf("open case store at %s: %v", path, err)
	}
	defer srv.close()
	log.Printf("case state database: %s", path)
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
	if p := strings.TrimSpace(os.Getenv("REASONIX_CASE_DB")); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "reasonix", "plugins", "case", "case.db")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".reasonix", "plugins", "case", "case.db")
	}
	return "reasonix-case.db"
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
	tools []toolDef
}

func newServer(dbPath string) (*server, error) {
	st, err := openStore(dbPath)
	if err != nil {
		return nil, err
	}
	s := &server{st: st}
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
			"serverInfo":      map[string]any{"name": "reasonix-plugin-case", "version": version},
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
