package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"reasonix/internal/skill"
	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(phaseRunner{}) }

type phaseRunner struct{}

func (phaseRunner) Name() string { return "run_phase" }

func (phaseRunner) Description() string {
	return "Execute a named phase of a security workflow. Workflows (pentest, vuln-assessment, forensics) define structured tool sequences. Call this instead of manually orchestrating multiple tool calls — it handles the sequencing and aggregates findings automatically. Use 'list' mode to see available workflows and phases."
}

func (phaseRunner) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"workflow":{"type":"string","description":"Workflow name: pentest, vuln-assessment, forensics. Use mode=list to list all."},
	"phase":{"type":"string","description":"Phase name within the workflow (e.g. reconnaissance, port_scanning). Use mode=list to list all."},
	"target":{"type":"string","description":"Target domain, URL, IP, or file path for the phase"},
	"mode":{"type":"string","description":"Execution mode: 'run' (default, execute the phase), 'list' (show all workflows and phases), 'status' (show what phases have been completed)"}
},
"oneOf":[
	{"required":["mode"]},
	{"required":["workflow","phase","target"]}
]
}`)
}

func (phaseRunner) ReadOnly() bool { return false } // writes to FindingStore

// completedPhases tracks which workflow phases have been executed in this session.
var completedPhases struct {
	mu   sync.Mutex
	data map[string][]string // workflow → []phase names done
}

func init() {
	completedPhases.data = make(map[string][]string)
}

func markPhaseDone(workflow, phase string) {
	completedPhases.mu.Lock()
	defer completedPhases.mu.Unlock()
	completedPhases.data[workflow] = append(completedPhases.data[workflow], phase)
}

func isPhaseDone(workflow, phase string) bool {
	completedPhases.mu.Lock()
	defer completedPhases.mu.Unlock()
	for _, p := range completedPhases.data[workflow] {
		if p == phase {
			return true
		}
	}
	return false
}

func phaseProgress(workflow string) string {
	completedPhases.mu.Lock()
	defer completedPhases.mu.Unlock()
	done := completedPhases.data[workflow]
	all := skill.PhaseNames(workflow)
	if len(all) == 0 {
		return fmt.Sprintf("Workflow %q not found.", workflow)
	}

	doneSet := make(map[string]bool)
	for _, p := range done {
		doneSet[p] = true
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n📋 Workflow: %s\n", workflow))
	for _, p := range all {
		if doneSet[p] {
			b.WriteString(fmt.Sprintf("  ✅ %s\n", p))
		} else {
			b.WriteString(fmt.Sprintf("  ⬜ %s\n", p))
		}
	}
	return b.String()
}

func (phaseRunner) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Workflow string `json:"workflow"`
		Phase    string `json:"phase"`
		Target   string `json:"target"`
		Mode     string `json:"mode"`
	}{Mode: "run"}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}

	switch p.Mode {
	case "list":
		return skill.FormatWorkflowIndex(), nil
	case "status":
		return phaseProgress(p.Workflow), nil
	}

	if p.Workflow == "" || p.Phase == "" {
		return "", fmt.Errorf("workflow, phase, and target are required (or use mode=list to see options)")
	}
	if p.Target == "" {
		return "", fmt.Errorf("target is required for phase execution")
	}

	// Look up the phase
	phaseDef := skill.LookupPhase(p.Workflow, p.Phase)
	if phaseDef == nil {
		return "", fmt.Errorf("phase %q not found in workflow %q. Use mode=list to see available phases.", p.Phase, p.Workflow)
	}

	// Execute steps in sequence
	var results []string
	var stepErrors []string

	for i, step := range phaseDef.Steps {
		// Resolve args
		stepArgs := skill.ResolveArgs(step.ArgsTemplate, p.Target)

		// Look up the tool
		t, ok := tool.LookupBuiltin(step.Tool)
		if !ok {
			stepErrors = append(stepErrors, fmt.Sprintf("step %d (%s): tool %q not found", i+1, step.Description, step.Tool))
			continue
		}

		// Execute
		result, err := t.Execute(ctx, stepArgs)
		if err != nil {
			stepErrors = append(stepErrors, fmt.Sprintf("step %d (%s): %v", i+1, step.Description, err))
			results = append(results, fmt.Sprintf("❌ %s — error: %v", step.Description, err))
			continue
		}

		results = append(results, fmt.Sprintf("✅ %s", step.Description))
		// Truncate result for display (full result goes to FindingStore via the tool itself)
		short := result
		if len(short) > 300 {
			short = short[:300] + "..."
		}
		results = append(results, fmt.Sprintf("   → %s", short))
	}

	// Mark phase as completed
	markPhaseDone(p.Workflow, p.Phase)

	// Build output
	var b strings.Builder
	b.WriteString(fmt.Sprintf("🏁 Phase: %s (%s)\n", phaseDef.Name, phaseDef.Description))
	b.WriteString(fmt.Sprintf("   Target: %s\n", p.Target))
	b.WriteString(fmt.Sprintf("   Steps: %d/%d completed successfully\n\n",
		len(results)-len(stepErrors), len(phaseDef.Steps)))

	for _, r := range results {
		b.WriteString(r + "\n")
	}

	if len(stepErrors) > 0 {
		b.WriteString("\n⚠️  Errors encountered:\n")
		for _, e := range stepErrors {
			b.WriteString(fmt.Sprintf("  • %s\n", e))
		}
	}

	// Show workflow progress
	b.WriteString(phaseProgress(p.Workflow))
	b.WriteString("\n")

	// Suggested next phases
	allPhases := skill.PhaseNames(p.Workflow)
	foundCurrent := false
	for _, ph := range allPhases {
		if ph == p.Phase {
			foundCurrent = true
			continue
		}
		if foundCurrent && !isPhaseDone(p.Workflow, ph) {
			b.WriteString(fmt.Sprintf("💡 Next phase: run_phase(workflow=%q, phase=%q, target=%q)\n", p.Workflow, ph, p.Target))
			break
		}
	}

	return strings.TrimSpace(b.String()), nil
}
