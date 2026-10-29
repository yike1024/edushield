package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
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
	path := filepath.Join(t.TempDir(), "case.db")
	s, err := newServer(path)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(s.close)
	return s
}

// callToolText invokes a tool and returns the text payload plus the isError flag.
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
	want := map[string]bool{
		"case_open": false, "case_load": true, "evidence_add": false,
		"evidence_list": true, "case_verdict": false, "case_close": false,
	}
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		name, _ := tool["name"].(string)
		if _, ok := want[name]; !ok {
			continue
		}
		ann, _ := tool["annotations"].(map[string]any)
		readOnly, _ := ann["readOnlyHint"].(bool)
		if readOnly != want[name] {
			t.Errorf("tool %s readOnlyHint = %v, want %v", name, readOnly, want[name])
		}
		delete(want, name)
	}
	if len(want) > 0 {
		t.Fatalf("missing tools: %v", want)
	}
}

func TestFullCaseLifecycle(t *testing.T) {
	s := newTestServer(t)

	text, isErr := callToolText(t, s, "case_open", map[string]any{
		"case_id": "ALERT-1", "title": "Suspicious login", "description": "Brute force from 203.0.113.7",
	})
	if isErr {
		t.Fatalf("case_open failed: %s", text)
	}
	if !strings.Contains(text, `"created":true`) {
		t.Fatalf("expected created=true, got %s", text)
	}

	for i, summary := range []string{"3 failed logins in 60s", "source IP on blocklist", "account locked"} {
		text, isErr = callToolText(t, s, "evidence_add", map[string]any{
			"case_id": "ALERT-1", "summary": summary, "kind": "indicator", "source": "siem",
			"detail": fmt.Sprintf("detail-%d", i),
		})
		if isErr || !strings.Contains(text, `"created":true`) {
			t.Fatalf("evidence_add %q: err=%v text=%s", summary, isErr, text)
		}
	}

	text, isErr = callToolText(t, s, "case_load", map[string]any{"case_id": "ALERT-1"})
	if isErr {
		t.Fatalf("case_load failed: %s", text)
	}
	for _, frag := range []string{`"evidence_count":3`, `"status":"open"`, "Brute force from 203.0.113.7"} {
		if !strings.Contains(text, frag) {
			t.Errorf("case_load missing %s in %s", frag, text)
		}
	}

	text, isErr = callToolText(t, s, "evidence_list", map[string]any{"case_id": "ALERT-1", "kind": "indicator"})
	if isErr || !strings.Contains(text, "account locked") {
		t.Fatalf("evidence_list: err=%v text=%s", isErr, text)
	}

	text, isErr = callToolText(t, s, "case_verdict", map[string]any{
		"case_id": "ALERT-1", "verdict": "true_positive", "rationale": "correlated indicators", "confidence": "high",
	})
	if isErr || !strings.Contains(text, `"verdict":"true_positive"`) {
		t.Fatalf("case_verdict: err=%v text=%s", isErr, text)
	}

	text, isErr = callToolText(t, s, "case_close", map[string]any{"case_id": "ALERT-1", "resolution": "blocked IP, reset creds"})
	if isErr || !strings.Contains(text, `"status":"closed"`) {
		t.Fatalf("case_close: err=%v text=%s", isErr, text)
	}
}

func TestEvidenceDedup(t *testing.T) {
	s := newTestServer(t)
	callToolText(t, s, "case_open", map[string]any{"case_id": "C1"})

	args := map[string]any{"case_id": "C1", "summary": "  Evil   process spawned ", "detail": "cmd.exe /c whoami"}
	text, isErr := callToolText(t, s, "evidence_add", args)
	if isErr || !strings.Contains(text, `"created":true`) {
		t.Fatalf("first add: err=%v text=%s", isErr, text)
	}
	// Whitespace/case normalized duplicate must merge.
	args2 := map[string]any{"case_id": "C1", "summary": "evil process SPAWNED", "detail": "cmd.exe  /c   whoami"}
	text, isErr = callToolText(t, s, "evidence_add", args2)
	if isErr || !strings.Contains(text, `"created":false`) {
		t.Fatalf("duplicate should merge: err=%v text=%s", isErr, text)
	}

	text, _ = callToolText(t, s, "case_load", map[string]any{"case_id": "C1"})
	if !strings.Contains(text, `"evidence_count":1`) {
		t.Fatalf("expected merged ledger of 1, got %s", text)
	}
}

func TestReopenDoesNotClobber(t *testing.T) {
	s := newTestServer(t)
	callToolText(t, s, "case_open", map[string]any{"case_id": "C2", "title": "Original"})
	callToolText(t, s, "evidence_add", map[string]any{"case_id": "C2", "summary": "finding"})
	callToolText(t, s, "case_verdict", map[string]any{"case_id": "C2", "verdict": "benign"})

	text, isErr := callToolText(t, s, "case_open", map[string]any{"case_id": "C2", "title": "Overwrite attempt"})
	if isErr || !strings.Contains(text, `"created":false`) {
		t.Fatalf("reopen: err=%v text=%s", isErr, text)
	}
	if strings.Contains(text, "Overwrite attempt") {
		t.Fatalf("reopen clobbered title: %s", text)
	}
	if !strings.Contains(text, `"verdict":"benign"`) {
		t.Fatalf("reopen lost verdict: %s", text)
	}
}

func TestMissingCaseErrors(t *testing.T) {
	s := newTestServer(t)
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"case_load", map[string]any{"case_id": "nope"}},
		{"evidence_add", map[string]any{"case_id": "nope", "summary": "x"}},
		{"evidence_list", map[string]any{"case_id": "nope"}},
		{"case_verdict", map[string]any{"case_id": "nope", "verdict": "benign"}},
		{"case_close", map[string]any{"case_id": "nope"}},
	} {
		text, isErr := callToolText(t, s, tc.tool, tc.args)
		if !isErr || !strings.Contains(text, "does not exist") {
			t.Errorf("%s on unknown case: err=%v text=%s", tc.tool, isErr, text)
		}
	}

	// Missing required args surface as tool errors, not RPC errors.
	text, isErr := callToolText(t, s, "evidence_add", map[string]any{"case_id": "C"})
	if !isErr || !strings.Contains(text, "required") {
		t.Errorf("missing summary: err=%v text=%s", isErr, text)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "case.db")
	s, err := newServer(path)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	callToolText(t, s, "case_open", map[string]any{"case_id": "P1", "title": "persistent"})
	callToolText(t, s, "evidence_add", map[string]any{"case_id": "P1", "summary": "durable finding"})
	s.close()

	s2, err := newServer(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.close()
	text, isErr := callToolText(t, s2, "case_load", map[string]any{"case_id": "P1"})
	if isErr || !strings.Contains(text, "durable finding") || !strings.Contains(text, `"title":"persistent"`) {
		t.Fatalf("state lost across reopen: err=%v text=%s", isErr, text)
	}
}

func TestNotificationGetsNoReply(t *testing.T) {
	s := newTestServer(t)
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	if err := s.handleLine([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), w); err != nil {
		t.Fatalf("handleLine: %v", err)
	}
	_ = w.Flush()
	if buf.Len() != 0 {
		t.Fatalf("notification must not produce a reply, got %q", buf.String())
	}
}
