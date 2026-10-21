package tool_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"reasonix/internal/provider"
	"reasonix/internal/tool"
	_ "reasonix/internal/tool/builtin"
)

func TestBuiltinToolContractDocumentation(t *testing.T) {
	entries := tool.BuiltinContractEntries()
	if len(entries) == 0 {
		t.Fatal("no built-in tool contract entries")
	}
	doc, err := os.ReadFile("../../docs/TOOL_CONTRACT.md")
	if err != nil {
		t.Fatalf("read docs/TOOL_CONTRACT.md: %v", err)
	}
	text := string(doc)
	for _, e := range entries {
		if !strings.Contains(text, "| `"+e.Name+"` |") {
			t.Errorf("documentation missing table row for %s", e.Name)
		}
		if !strings.Contains(text, "| `"+e.Name+"` | "+boolString(e.ReadOnly)+" |") {
			t.Errorf("documentation missing read-only flag for %s", e.Name)
		}
		if strings.TrimSpace(e.Description) == "" {
			t.Errorf("%s has empty description", e.Name)
		}
		if !json.Valid(e.Schema) {
			t.Errorf("%s schema is invalid JSON: %s", e.Name, e.Schema)
		}
		if got := string(provider.CanonicalizeSchema(e.Schema)); got != string(e.Schema) {
			t.Errorf("%s schema is not canonical", e.Name)
		}
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// contractRowRe matches one body row of the committed TOOL_CONTRACT.md table:
// | `name` | read-only | description |
var contractRowRe = regexp.MustCompile(`^\| ` + "`([^`]+)`" + ` \| (true|false) \| (.*) \|$`)

type documentedRow struct {
	readOnly    bool
	description string
}

// parseContractTable extracts the name -> (read-only, description) map from a
// contract markdown body. It ignores headers, separators, and prose sections.
func parseContractTable(t *testing.T, text string) map[string]documentedRow {
	t.Helper()
	rows := make(map[string]documentedRow)
	for _, line := range strings.Split(text, "\n") {
		m := contractRowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		if _, dup := rows[name]; dup {
			t.Fatalf("duplicate table row for %q", name)
		}
		rows[name] = documentedRow{readOnly: m[2] == "true", description: m[3]}
	}
	return rows
}

// TestBuiltinToolContractTableMatchesCode regenerates the committed table from
// the live built-in set and compares it field-for-field (name, read-only flag,
// and exact normalized description) against docs/TOOL_CONTRACT.md. A new,
// renamed, or re-described built-in — or any stale documented row — fails the
// test, so the contract documentation cannot drift from the tool surface.
func TestBuiltinToolContractTableMatchesCode(t *testing.T) {
	entries := tool.BuiltinContractEntries()
	if len(entries) == 0 {
		t.Fatal("no built-in tool contract entries")
	}
	want := parseContractTable(t, tool.RenderContractMarkdown(entries))

	doc, err := os.ReadFile("../../docs/TOOL_CONTRACT.md")
	if err != nil {
		t.Fatalf("read docs/TOOL_CONTRACT.md: %v", err)
	}
	got := parseContractTable(t, string(doc))

	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("docs/TOOL_CONTRACT.md missing table row for %q", name)
			continue
		}
		if g.readOnly != w.readOnly {
			t.Errorf("%q read-only flag is %t in docs, want %t", name, g.readOnly, w.readOnly)
		}
		if g.description != w.description {
			t.Errorf("%q description in docs does not match code:\n  docs: %s\n  want: %s", name, g.description, w.description)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("docs/TOOL_CONTRACT.md documents %q, which is not a registered built-in; remove the stale row", name)
		}
	}
}

// acceptsDefaultSnip lists built-in tools that deliberately take the
// ReadOnly-tiered default snip geometry instead of implementing
// tool.SnipHinter. A tool belongs here only if its output has no special shape
// a generic head/tail split would garble — typically tools whose results are
// short (todo_write, complete_step) or already structured small (edit results).
// Membership is an explicit decision, not a fallback: a new or renamed built-in
// that lands in neither this set nor SnipHinter fails TestEveryBuiltinDeclaresSnipStance,
// which is the guard against a context-maintenance strategy silently desyncing
// from the tool surface.
var acceptsDefaultSnip = map[string]bool{
	"bash_output":      true, // streamed job output; tailing handled by the job, not the snip pass
	"code_index":       true,
	"complete_step":    true,
	"cve_search":       true, // security tool: structured CVE list; generic split is fine
	"delete_range":     true,
	"delete_symbol":    true,
	"dns_enum":         true, // security tool: structured DNS record list
	"edit_file":        true,
	"findings":         true, // security tool: structured findings list
	"forensic_extract": true, // security tool: extracted-artifact lines
	"hash_identify":    true, // security tool: short hash-type verdict
	"http_probe":       true, // security tool: structured header/method list
	"kill_shell":       true,
	"move_file":        true,
	"multi_edit":       true,
	"notebook_edit":    true,
	"port_scan":        true, // security tool: port/service line list
	"report":           true, // security tool: aggregated report text
	"run_phase":        true, // security tool: phase execution summary
	"ssl_check":        true, // security tool: certificate detail block
	"subdomain_enum":   true, // security tool: subdomain line list
	"todo_write":       true,
	"vuln_scan":        true, // security tool: vulnerability finding list
	"wait":             true,
	"whois_lookup":     true, // security tool: WHOIS record block
	"write_file":       true,
}

func TestEveryBuiltinDeclaresSnipStance(t *testing.T) {
	for _, b := range tool.Builtins() {
		name := b.Name()
		_, hints := b.(tool.SnipHinter)
		switch {
		case hints && acceptsDefaultSnip[name]:
			t.Errorf("%s both implements SnipHinter and is listed in acceptsDefaultSnip; remove it from the list", name)
		case !hints && !acceptsDefaultSnip[name]:
			t.Errorf("built-in %q declares no snip stance: implement tool.SnipHinter for a tailored geometry, or add it to acceptsDefaultSnip if the ReadOnly-tiered default is right (this guards against a renamed/new tool silently taking a generic default)", name)
		}
	}
}
