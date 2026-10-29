package builtincontent_test

import (
	"strings"
	"testing"

	"reasonix/internal/skill/builtincontent"
)

func TestLoadReasonixGuide(t *testing.T) {
	sk, err := builtincontent.LoadReasonixGuide()
	if err != nil {
		t.Fatal(err)
	}
	if sk.Name != "reasonix-guide" {
		t.Fatalf("name = %q", sk.Name)
	}
	if sk.Description == "" {
		t.Fatal("missing description")
	}
	if sk.RunAs != "inline" {
		t.Fatalf("runAs = %q, want inline", sk.RunAs)
	}
	if !strings.Contains(sk.Body, "reasonix doctor capabilities") {
		t.Fatal("body should recommend doctor capabilities")
	}
	if strings.Contains(strings.ToLower(sk.Frontmatter["auto-use"]), "require") {
		t.Fatal("guide must not set auto-use require")
	}
}

func TestAllLoadsPentestPlaybooks(t *testing.T) {
	items, err := builtincontent.All()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]builtincontent.SkillMarkdown{}
	for _, sk := range items {
		byName[sk.Name] = sk
	}
	for _, name := range []string{"reasonix-guide", "pentest-recon", "web-exploit", "pentest-report"} {
		sk, ok := byName[name]
		if !ok {
			t.Fatalf("embedded skill %s missing from All()", name)
		}
		if sk.Description == "" {
			t.Fatalf("%s missing description", name)
		}
		if sk.RunAs != "inline" {
			t.Fatalf("%s runAs = %q, want inline", name, sk.RunAs)
		}
	}
	// The offensive playbooks must carry the authorization gate.
	for _, name := range []string{"pentest-recon", "web-exploit"} {
		if !strings.Contains(strings.ToLower(byName[name].Body), "authorized") {
			t.Fatalf("%s body must gate on authorized targets", name)
		}
	}
}

func TestParseSkillMarkdownStable(t *testing.T) {
	raw := "---\nname: demo\ndescription: d\nrunAs: inline\n---\n\n# hi\n"
	a, err := builtincontent.ParseSkillMarkdown("demo/SKILL.md", raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := builtincontent.ParseSkillMarkdown("demo/SKILL.md", raw)
	if err != nil {
		t.Fatal(err)
	}
	if a.Body != b.Body || a.Description != b.Description {
		t.Fatal("parse not deterministic")
	}
}
