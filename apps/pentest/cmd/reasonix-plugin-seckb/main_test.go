package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rpc sends one JSON-RPC request through the protocol handler and returns the
// parsed response, mirroring how reasonix drives the plugin over stdio.
func rpc(t *testing.T, s *server, id int, method string, params any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	line := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, id, method, raw)
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	if err := s.handleLine([]byte(line), w); err != nil {
		t.Fatalf("handleLine: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", buf.String(), err)
	}
	return resp
}

func newTestServer(t *testing.T) *server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seckb.db")
	s, err := newServer(path, nil)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(s.close)
	return s
}

func callToolText(t *testing.T, s *server, name string, args map[string]any) (string, bool) {
	t.Helper()
	resp := rpc(t, s, 1, "tools/call", map[string]any{"name": name, "arguments": args})
	if e, ok := resp["error"]; ok && e != nil {
		t.Fatalf("tool %s returned rpc error: %v", name, e)
	}
	result, _ := resp["result"].(map[string]any)
	if result == nil {
		t.Fatalf("tool %s: missing result in %v", name, resp)
	}
	isErr, _ := result["isError"].(bool)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("tool %s: empty content", name)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	return text, isErr
}

func TestInitializeAndToolsList(t *testing.T) {
	s := newTestServer(t)

	resp := rpc(t, s, 1, "initialize", map[string]any{})
	result, _ := resp["result"].(map[string]any)
	if result["protocolVersion"] != protocolVersion {
		t.Fatalf("protocolVersion = %v, want %s", result["protocolVersion"], protocolVersion)
	}

	resp = rpc(t, s, 2, "tools/list", nil)
	result, _ = resp["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	want := map[string]bool{"kb_search": true, "kb_ingest": false, "kb_stats": true}
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		name, _ := tool["name"].(string)
		readOnly, ok := want[name]
		if !ok {
			continue
		}
		ann, _ := tool["annotations"].(map[string]any)
		if got, _ := ann["readOnlyHint"].(bool); got != readOnly {
			t.Errorf("tool %s readOnlyHint = %v, want %v", name, got, readOnly)
		}
		delete(want, name)
	}
	if len(want) > 0 {
		t.Fatalf("missing tools: %v", want)
	}
}

func TestSeedsLoadOnce(t *testing.T) {
	s := newTestServer(t)
	text, isErr := callToolText(t, s, "kb_stats", nil)
	if isErr {
		t.Fatalf("kb_stats: %s", text)
	}
	for _, collection := range []string{"attack", "vuln", "ioc", "playbook"} {
		if !strings.Contains(text, `"`+collection+`"`) {
			t.Errorf("stats missing collection %s: %s", collection, text)
		}
	}

	// Reopening the same database must not duplicate seeds.
	path := filepath.Join(t.TempDir(), "again.db")
	s1, err := newServer(path, nil)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	before := s1.st.count()
	s1.close()
	s2, err := newServer(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.close()
	if after := s2.st.count(); after != before {
		t.Fatalf("seeds re-inserted on reopen: %d -> %d", before, after)
	}
}

func TestSearchSeededKnowledge(t *testing.T) {
	s := newTestServer(t)

	text, isErr := callToolText(t, s, "kb_search", map[string]any{"query": "Log4Shell JNDI"})
	if isErr {
		t.Fatalf("search: %s", text)
	}
	if !strings.Contains(text, "CVE-2021-44228") {
		t.Errorf("Log4Shell query should hit the Log4j CVE doc: %s", text)
	}

	// Chinese bigram query must reach the phishing playbook.
	text, isErr = callToolText(t, s, "kb_search", map[string]any{"query": "钓鱼邮件处置"})
	if isErr || !strings.Contains(text, "钓鱼邮件处置预案") {
		t.Errorf("CJK query should hit the phishing playbook: err=%v %s", isErr, text)
	}

	// Collection filter narrows results.
	text, isErr = callToolText(t, s, "kb_search", map[string]any{"query": "钓鱼", "collection": "attack"})
	if isErr {
		t.Fatalf("filtered search: %s", text)
	}
	if strings.Contains(text, `"collection":"playbook"`) {
		t.Errorf("collection=attack leaked playbook results: %s", text)
	}

	// Nonsense query returns an empty result set, not an error.
	text, isErr = callToolText(t, s, "kb_search", map[string]any{"query": "zzzqqqxxx"})
	if isErr || !strings.Contains(text, `"results":[]`) {
		t.Errorf("no-match query: err=%v %s", isErr, text)
	}

	// Empty query is a tool error.
	if _, isErr = callToolText(t, s, "kb_search", map[string]any{}); !isErr {
		t.Error("empty query must fail")
	}
}

func TestIngestDedupAndRetrieval(t *testing.T) {
	s := newTestServer(t)

	text, isErr := callToolText(t, s, "kb_ingest", map[string]any{
		"collection": "internal", "title": "2024 挖矿事件复盘",
		"body": "攻击者通过 Redis 未授权访问写入计划任务下载挖矿程序。", "source": "内部报告",
	})
	if isErr || !strings.Contains(text, `"created":true`) {
		t.Fatalf("ingest: err=%v %s", isErr, text)
	}

	// Same key updates instead of duplicating.
	text, isErr = callToolText(t, s, "kb_ingest", map[string]any{
		"collection": "internal", "title": "2024 挖矿事件复盘", "body": "更新后的正文。",
	})
	if isErr || !strings.Contains(text, `"created":false`) {
		t.Fatalf("re-ingest should update: err=%v %s", isErr, text)
	}

	text, isErr = callToolText(t, s, "kb_search", map[string]any{"query": "Redis 挖矿", "collection": "internal"})
	if isErr || !strings.Contains(text, "更新后的正文") {
		t.Fatalf("ingested doc not searchable with updated body: err=%v %s", isErr, text)
	}

	// Missing required fields fail.
	if _, isErr = callToolText(t, s, "kb_ingest", map[string]any{"collection": "x", "title": "y"}); !isErr {
		t.Error("ingest without body must fail")
	}
}

// deterministicEmbedder returns [1,0] for texts containing "alpha" and [0,1]
// otherwise, so hybrid ranking is fully predictable in tests.
func deterministicEmbedder(t *testing.T) (*httptest.Server, *embedder) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req embedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := embedResponse{}
		for _, text := range req.Input {
			vec := []float64{0, 1}
			if strings.Contains(strings.ToLower(text), "alpha") {
				vec = []float64{1, 0}
			}
			resp.Data = append(resp.Data, struct {
				Embedding []float64 `json:"embedding"`
			}{Embedding: vec})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &embedder{url: srv.URL, model: "test-embed", client: srv.Client()}
}

func TestHybridRerank(t *testing.T) {
	_, emb := deterministicEmbedder(t)
	path := filepath.Join(t.TempDir(), "hybrid.db")
	s, err := newServer(path, emb)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(s.close)

	// Doc B outranks doc A on BM25 for "alpha beta" (far more beta hits) but
	// only doc A contains the semantic marker "alpha" — hybrid must flip the
	// order so A comes first.
	_, createdA, err := s.st.ingest("test", "alpha marker doc", "alpha marker", "", "")
	_, createdB, err2 := s.st.ingest("test", "shared terms doc", "beta beta beta beta beta beta shared", "", "")
	if err != nil || err2 != nil || !createdA || !createdB {
		t.Fatalf("seed test docs: %v %v", err, err2)
	}

	text, isErr := callToolText(t, s, "kb_search", map[string]any{
		"query": "alpha beta", "collection": "test", "mode": "hybrid",
	})
	if isErr {
		t.Fatalf("hybrid search: %s", text)
	}
	if !strings.Contains(text, `"mode":"hybrid"`) {
		t.Fatalf("expected hybrid mode: %s", text)
	}
	idxA := strings.Index(text, "alpha marker doc")
	idxB := strings.Index(text, "shared terms doc")
	if idxA < 0 || idxB < 0 || idxA > idxB {
		t.Fatalf("hybrid rerank did not put the semantic match first: %s", text)
	}

	// bm25 mode stays lexical.
	text, isErr = callToolText(t, s, "kb_search", map[string]any{
		"query": "alpha beta", "collection": "test", "mode": "bm25",
	})
	if isErr || !strings.Contains(text, `"mode":"bm25"`) {
		t.Fatalf("bm25 search: err=%v %s", isErr, text)
	}

	// Embedding vectors are cached: searching again must not call the endpoint.
	hits, _, err := s.searchHybrid("alpha beta", "test", 5)
	if err != nil || len(hits) == 0 {
		t.Fatalf("cached hybrid search: %v", err)
	}
	if _, ok := s.st.getVector(hits[0].doc.ID, emb.model); !ok {
		t.Fatal("embedding vector was not cached")
	}
}

func TestHybridFallsBackOnEndpointFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	emb := &embedder{url: srv.URL, model: "broken", client: srv.Client()}

	path := filepath.Join(t.TempDir(), "fallback.db")
	s, err := newServer(path, emb)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(s.close)

	text, isErr := callToolText(t, s, "kb_search", map[string]any{"query": "钓鱼", "mode": "auto"})
	if isErr {
		t.Fatalf("search must degrade to bm25, not fail: %s", text)
	}
	if !strings.Contains(text, `"mode":"bm25"`) {
		t.Fatalf("expected bm25 fallback mode: %s", text)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "custom")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	root := "# 根目录文档\ncustom-root-body"
	subDoc := "---\ntitle: 前置标题\ncollection: override\n---\noverride-body"
	if err := os.WriteFile(filepath.Join(dir, "root.md"), []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "doc.md"), []byte(subDoc), 0o600); err != nil {
		t.Fatal(err)
	}

	s := newTestServer(t)
	n, err := s.st.loadDir(dir)
	if err != nil || n != 2 {
		t.Fatalf("loadDir: n=%d err=%v", n, err)
	}
	text, isErr := callToolText(t, s, "kb_search", map[string]any{"query": "custom-root-body", "collection": "general"})
	if isErr || !strings.Contains(text, "根目录文档") {
		t.Fatalf("root file not imported into general: err=%v %s", isErr, text)
	}
	text, isErr = callToolText(t, s, "kb_search", map[string]any{"query": "override-body", "collection": "override"})
	if isErr || !strings.Contains(text, "前置标题") {
		t.Fatalf("frontmatter not honored: err=%v %s", isErr, text)
	}
}
