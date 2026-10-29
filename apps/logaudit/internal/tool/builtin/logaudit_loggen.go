package builtin

// logaudit_loggen.go —— 日志生成库（方案3：无真实日志时的数据供给与缺陷探测）
// 生成与 log_ingest 解析格式严格兼容的 nginx combined / syslog / json 日志，
// 支持正常基线流量与 6 类攻击场景注入，以及脏行/乱序/截断等变异行，
// 供 cmd/logaudit-loggen CLI 与 logaudit_loggen_e2e_test 共同使用。

import (
	"fmt"
	"math/rand"
	"time"
)

// LoggenScenario 描述一段可注入的日志场景。
type LoggenScenario struct {
	Name string
	// Injected 是否属于"应被告警"的注入场景（用于已知答案测试）。
	Injected bool
	// ExpectedFinding 为注入场景时期望出现的 Finding ID 子串。
	ExpectedFinding string
	// Gen 返回该场景生成的原始日志行。
	Gen func(rnd *rand.Rand, start time.Time, n int) []string
}

var loggenNormalPaths = []string{
	"/index.html", "/css/main.css", "/js/app.js", "/api/course/list",
	"/api/score/query?term=2026", "/static/logo.png", "/health",
}

var loggenNormalUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
}

func loggenNginxLine(ip string, ts time.Time, method, req string, status, bytes int, ua string) string {
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"`,
		ip, ts.Format("02/Jan/2006:15:04:05 -0700"), method, req, status, bytes, ua)
}

func loggenSyslogFailed(ts time.Time, ip, user string, pid int) string {
	return fmt.Sprintf("%s jwxt-web sshd[%d]: Failed password for %s from %s port %d ssh2",
		ts.Format("Jan _2 15:04:05"), pid, user, ip, 40000+pid)
}

// LoggenScenarios 返回全部内置场景。正常场景 Injected=false。
func LoggenScenarios() []LoggenScenario {
	return []LoggenScenario{
		{
			Name: "normal", Injected: false,
			Gen: func(rnd *rand.Rand, start time.Time, n int) []string {
				out := make([]string, 0, n)
				for i := 0; i < n; i++ {
					// IP 池 2500 个：保证百万级生成时单 IP 均值（约 400 次）
					// 低于默认 traffic 阈值 1000，不污染误报断言。
					ip := fmt.Sprintf("10.20.%d.%d", rnd.Intn(10), 2+rnd.Intn(250))
					ts := start.Add(time.Duration(rnd.Intn(8*3600)) * time.Second)
					// 9~17 点白天时段，避免落入 00-05 凌晨检测窗口
					ts = time.Date(ts.Year(), ts.Month(), ts.Day(), 9+rnd.Intn(9), rnd.Intn(60), rnd.Intn(60), 0, ts.Location())
					out = append(out, loggenNginxLine(ip, ts, "GET",
						loggenNormalPaths[rnd.Intn(len(loggenNormalPaths))],
						200, 512+rnd.Intn(4096),
						loggenNormalUAs[rnd.Intn(len(loggenNormalUAs))]))
				}
				return out
			},
		},
		{
			Name: "bruteforce_nginx", Injected: true,
			ExpectedFinding: ":brute_force",
			Gen: func(rnd *rand.Rand, start time.Time, n int) []string {
				out := make([]string, 0, n)
				for i := 0; i < n; i++ {
					ts := start.Add(time.Duration(i*2) * time.Second)
					out = append(out, loggenNginxLine("203.0.113.77", ts, "POST", "/admin/login", 401, 128, loggenNormalUAs[0]))
				}
				return out
			},
		},
		{
			Name: "bruteforce_ssh", Injected: true,
			ExpectedFinding: ":brute_force",
			Gen: func(rnd *rand.Rand, start time.Time, n int) []string {
				users := []string{"root", "admin", "oracle", "test", "postgres"}
				out := make([]string, 0, n)
				for i := 0; i < n; i++ {
					ts := start.Add(time.Duration(i*2) * time.Second)
					out = append(out, loggenSyslogFailed(ts, "45.155.205.100", users[i%len(users)], 2000+i))
				}
				return out
			},
		},
		{
			Name: "scan", Injected: true,
			ExpectedFinding: ":scan",
			Gen: func(rnd *rand.Rand, start time.Time, n int) []string {
				paths := []string{"/.env", "/wp-admin/", "/phpmyadmin/", "/backup.zip", "/.git/config", "/admin.bak", "/config.php", "/test.php"}
				out := make([]string, 0, n)
				for i := 0; i < n; i++ {
					ts := start.Add(time.Duration(i*2) * time.Second)
					out = append(out, loggenNginxLine("192.0.2.45", ts, "GET", paths[i%len(paths)], 404, 153, "dirsearch/0.4.2"))
				}
				return out
			},
		},
		{
			Name: "sqli", Injected: true,
			ExpectedFinding: ":sqli",
			Gen: func(rnd *rand.Rand, start time.Time, n int) []string {
				payloads := []string{
					"/search?q=%27%20or%20%271%27=%271",
					"/product?id=1%20union%20select%20user(),2",
					"/news?id=1;select%20sleep(5)",
				}
				out := make([]string, 0, n)
				for i := 0; i < n; i++ {
					ts := start.Add(time.Duration(i*3) * time.Second)
					out = append(out, loggenNginxLine("198.51.100.23", ts, "GET", payloads[i%len(payloads)], 200, 2048, loggenNormalUAs[1]))
				}
				return out
			},
		},
		{
			Name: "webshell", Injected: true,
			ExpectedFinding: ":webshell",
			Gen: func(rnd *rand.Rand, start time.Time, n int) []string {
				out := make([]string, 0, n)
				for i := 0; i < n; i++ {
					ts := start.Add(time.Duration(i*45) * time.Second)
					out = append(out, loggenNginxLine("203.0.113.200", ts, "POST", "/shell/cmd.jsp", 200, 1024, loggenNormalUAs[0]))
				}
				return out
			},
		},
		{
			Name: "out_of_hours", Injected: true,
			ExpectedFinding: ":out_of_hours",
			Gen: func(rnd *rand.Rand, start time.Time, n int) []string {
				out := make([]string, 0, n)
				base := time.Date(start.Year(), start.Month(), start.Day(), 2, 0, 0, 0, start.Location())
				for i := 0; i < n; i++ {
					ts := base.Add(time.Duration(i*60) * time.Second)
					out = append(out, loggenNginxLine("172.16.9.9", ts, "GET", "/api/export/students", 200, 65536, loggenNormalUAs[0]))
				}
				return out
			},
		},
		{
			// 异常流量：单 IP 高频请求，需超过默认 traffic 阈值 1000，
			// 因此实际行数强制不低于 1200（忽略传入的 n）。
			Name: "high_traffic", Injected: true,
			ExpectedFinding: ":traffic",
			Gen: func(rnd *rand.Rand, start time.Time, n int) []string {
				if n < 1200 {
					n = 1200
				}
				out := make([]string, 0, n)
				for i := 0; i < n; i++ {
					ts := start.Add(time.Duration(i) * time.Second)
					ts = time.Date(ts.Year(), ts.Month(), ts.Day(), 9+ts.Hour()%8, ts.Minute(), ts.Second(), 0, ts.Location())
					out = append(out, loggenNginxLine("198.51.100.99", ts, "GET",
						fmt.Sprintf("/api/page?i=%d", i), 200, 1024, loggenNormalUAs[0]))
				}
				return out
			},
		},
	}
}

// LoggenDirtyLine 枚举脏行变异类型（用于探测解析器健壮性缺陷）。
type LoggenDirtyLine struct {
	Kind string
	Line string
}

// LoggenDirtyLines 返回一组已知会被跳过（或暴露解析缺陷）的脏行。
func LoggenDirtyLines() []LoggenDirtyLine {
	return []LoggenDirtyLine{
		{Kind: "empty", Line: ""},
		{Kind: "garbage", Line: "\x00\x01\x02 binary junk"},
		{Kind: "truncated", Line: `203.0.113.9 - - [15/Aug/2026:10:00:00 +0800] "GET /pa`},
		{Kind: "bad_timestamp", Line: `203.0.113.9 - - [not-a-date] "GET /a HTTP/1.1" 200 10 "-" "-"`},
		{Kind: "missing_status", Line: `203.0.113.9 - - [15/Aug/2026:10:00:01 +0800] "GET /b HTTP/1.1" abc 10 "-" "-"`},
		{Kind: "unterminated_quote", Line: `203.0.113.9 - - [15/Aug/2026:10:00:02 +0800] "GET /c HTTP/1.1" 200 10 "-" "unterminated`},
	}
}

// LoggenFPProbes 返回"不应告警但规则正则可能误判"的诱饵行（缺陷探测用）。
// 每行注明预期：任何由此产生的 Finding 都是误报缺陷。
type LoggenFPProbe struct {
	Name string
	Line string
	Note string
}

func LoggenFPProbes() []LoggenFPProbe {
	return []LoggenFPProbe{
		{
			Name: "doc_path_bin_sh",
			Line: loggenNginxLine("10.20.0.70", time.Date(2026, 8, 15, 10, 0, 0, 0, time.FixedZone("CST", 8*3600)), "GET", "/docs/linux-bin-sh-tutorial.pdf", 200, 4096, loggenNormalUAs[0]),
			Note: "文档路径含字串 /bin/sh，webshellRe 应不命中",
		},
		{
			Name: "single_404_scanner_ua",
			Line: loggenNginxLine("10.20.0.71", time.Date(2026, 8, 15, 10, 1, 0, 0, time.FixedZone("CST", 8*3600)), "GET", "/favicon.ico", 200, 0, "sqlmap/1.7"),
			Note: "单条 200 请求，UA 含 sqlmap，scan 计数不得达到阈值",
		},
		{
			Name: "login_failed_static_page",
			Line: loggenNginxLine("10.20.0.72", time.Date(2026, 8, 15, 10, 2, 0, 0, time.FixedZone("CST", 8*3600)), "GET", "/static/login-failed.html", 200, 1024, loggenNormalUAs[0]),
			Note: "静态提示页路径含 login failed，不得计入认证失败",
		},
		{
			Name: "encoded_apostrophe_search",
			Line: loggenNginxLine("10.20.0.73", time.Date(2026, 8, 15, 10, 3, 0, 0, time.FixedZone("CST", 8*3600)), "GET", "/search?q=it%27s%20fine", 200, 1024, loggenNormalUAs[1]),
			Note: "普通检索词含 %27 编码，不得判为 SQLi",
		},
	}
}

// LoggenRender 将场景行与脏行按确定性顺序混合输出。
// dirtyEvery<=0 表示不插入脏行。
func LoggenRender(lines []string, dirty []LoggenDirtyLine, dirtyEvery int) []string {
	if dirtyEvery <= 0 || len(dirty) == 0 {
		return lines
	}
	out := make([]string, 0, len(lines)+len(lines)/dirtyEvery+1)
	di := 0
	for i, l := range lines {
		out = append(out, l)
		if (i+1)%dirtyEvery == 0 {
			out = append(out, dirty[di%len(dirty)].Line)
			di++
		}
	}
	return out
}
