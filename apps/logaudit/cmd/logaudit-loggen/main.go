// logaudit-loggen —— 日志审计模块配套日志生成器（方案3）。
// 在无真实日志的环境中批量产出与 log_ingest 兼容的
// nginx combined / syslog 日志，支持正常基线、攻击场景注入与脏行变异，
// 用于功能验证、压力测试与规则缺陷探测。
//
// 用法示例：
//
//	logaudit-loggen -out-dir ./genlogs -normal 1000 -seed 42
//	logaudit-loggen -out-dir ./genlogs -scenarios bruteforce_ssh,scan -dirty-every 20
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reasonix/internal/tool/builtin"
)

func main() {
	outDir := flag.String("out-dir", ".", "output directory")
	normal := flag.Int("normal", 200, "normal baseline nginx lines (0 disables)")
	scenarios := flag.String("scenarios", "all", "comma-separated injected scenarios: all or names ("+scenarioNames()+")")
	perScenario := flag.Int("per-scenario", 12, "line count per injected scenario")
	dirtyEvery := flag.Int("dirty-every", 0, "insert one dirty line every N normal lines (0 disables)")
	seed := flag.Int64("seed", 1, "random seed for deterministic output")
	start := flag.String("start", "2026-08-15 09:00:00", "baseline start time (2006-01-02 15:04:05)")
	list := flag.Bool("list", false, "list available scenarios and exit")
	flag.Parse()

	all := builtin.LoggenScenarios()
	if *list {
		for _, sc := range all {
			tag := "baseline"
			if sc.Injected {
				tag = "attack -> " + sc.ExpectedFinding
			}
			fmt.Printf("%-18s %s\n", sc.Name, tag)
		}
		fmt.Printf("dirty kinds: %d\n", len(builtin.LoggenDirtyLines()))
		return
	}

	base, err := time.Parse("2006-01-02 15:04:05", *start)
	if err != nil {
		fatalf("invalid -start: %v", err)
	}
	rnd := rand.New(rand.NewSource(*seed))
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		fatalf("mkdir: %v", err)
	}

	want := map[string]bool{}
	if strings.TrimSpace(*scenarios) == "" || *scenarios == "all" {
		for _, sc := range all {
			if sc.Injected {
				want[sc.Name] = true
			}
		}
	} else {
		for _, part := range strings.Split(*scenarios, ",") {
			want[strings.TrimSpace(part)] = true
		}
	}

	var accessLines, syslogLines []string
	if *normal > 0 {
		accessLines = append(accessLines, all[0].Gen(rnd, base, *normal)...)
	}
	injected := 0
	for _, sc := range all {
		if !sc.Injected || !want[sc.Name] {
			continue
		}
		lines := sc.Gen(rnd, base, *perScenario)
		if sc.Name == "bruteforce_ssh" {
			syslogLines = append(syslogLines, lines...)
		} else {
			accessLines = append(accessLines, lines...)
		}
		injected++
	}
	if *dirtyEvery > 0 {
		accessLines = builtin.LoggenRender(accessLines, builtin.LoggenDirtyLines(), *dirtyEvery)
	}

	accessPath := filepath.Join(*outDir, "access.log")
	if err := writeFile(accessPath, accessLines); err != nil {
		fatalf("write access.log: %v", err)
	}
	fmt.Printf("access.log: %d lines -> %s\n", len(accessLines), accessPath)
	if len(syslogLines) > 0 {
		authPath := filepath.Join(*outDir, "auth.log")
		if err := writeFile(authPath, syslogLines); err != nil {
			fatalf("write auth.log: %v", err)
		}
		fmt.Printf("auth.log: %d lines -> %s\n", len(syslogLines), authPath)
	}
	fmt.Printf("done: normal=%d injected_scenarios=%d seed=%d\n", *normal, injected, *seed)
}

func scenarioNames() string {
	var names []string
	for _, sc := range builtin.LoggenScenarios() {
		if sc.Injected {
			names = append(names, sc.Name)
		}
	}
	return strings.Join(names, ",")
}

func writeFile(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "logaudit-loggen: "+format+"\n", args...)
	os.Exit(1)
}
