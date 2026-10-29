package builtin

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"reasonix/internal/config"
)

// LogRecord is a normalized log line shared by the log audit tools.
type LogRecord struct {
	Source    string    `json:"source"`
	Format    string    `json:"format"`
	Timestamp time.Time `json:"timestamp"`
	Host      string    `json:"host,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
	User      string    `json:"user,omitempty"`
	Method    string    `json:"method,omitempty"`
	Request   string    `json:"request,omitempty"`
	Path      string    `json:"path,omitempty"`
	Status    int       `json:"status,omitempty"`
	Bytes     int64     `json:"bytes,omitempty"`
	Referer   string    `json:"referer,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Message   string    `json:"message,omitempty"`
	Process   string    `json:"process,omitempty"`
	Raw       string    `json:"raw,omitempty"`
}

// logStore keeps normalized records in session memory so log_ingest,
// anomaly_detect, and correlation can share one dataset without touching disk.
type logStore struct {
	mu      sync.RWMutex
	records []LogRecord
}

var globalLogStore = &logStore{}

func (s *logStore) replace(source string, records []LogRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.records[:0]
	for _, r := range s.records {
		if r.Source != source {
			kept = append(kept, r)
		}
	}
	s.records = append(kept, records...)
}

func (s *logStore) recordsFor(source string) []LogRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if source == "" {
		out := make([]LogRecord, len(s.records))
		copy(out, s.records)
		return out
	}
	var out []LogRecord
	for _, r := range s.records {
		if r.Source == source {
			out = append(out, r)
		}
	}
	return out
}

func (s *logStore) sources() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := map[string]bool{}
	for _, r := range s.records {
		if r.Source != "" {
			seen[r.Source] = true
		}
	}
	out := make([]string, 0, len(seen))
	for src := range seen {
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

func (s *logStore) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

func (s *logStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = nil
}

var logStoreIOLock sync.Mutex

// logauditChainGenesis seeds the first hash-chain link of every shard.
const logauditChainGenesis = "logaudit-genesis-v1"

// logStoreEntry is one persisted line: the normalized record plus the chain
// hash binding it to every preceding line in the same shard (tamper evidence).
type logStoreEntry struct {
	ChainHash string    `json:"chain_hash"`
	Record    LogRecord `json:"record"`
}

// logauditStoreDir is the on-disk log archive directory under Reasonix home:
// REASONIX_HOME/logaudit. Empty string means the home directory could not be
// resolved and persistence must be skipped. Records live in date shards
// records-YYYY-MM-DD.jsonl (one hash chain per shard); records without a
// timestamp go to records-undated.jsonl. A legacy single-file store
// records.jsonl from older versions is still read and migrated on next write.
func logauditStoreDir() string {
	home := config.ReasonixHomeDir()
	if strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, "logaudit")
}

// logauditStorePath kept for legacy single-file stores written before sharding.
func logauditStorePath() string {
	dir := logauditStoreDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "records.jsonl")
}

func shardNameForRecord(r LogRecord) string {
	if r.Timestamp.IsZero() {
		return "records-undated.jsonl"
	}
	return "records-" + r.Timestamp.Format("2006-01-02") + ".jsonl"
}

// listStoreShards returns sorted shard paths plus the legacy file when present.
func listStoreShards(dir string) []string {
	matches, _ := filepath.Glob(filepath.Join(dir, "records-*.jsonl"))
	sort.Strings(matches)
	legacy := filepath.Join(dir, "records.jsonl")
	if _, err := os.Stat(legacy); err == nil {
		matches = append(matches, legacy)
	}
	return matches
}

// shardInWindow decides whether a dated shard may contain records inside
// [since, until]. Undated/legacy shards always qualify. A +/- one-day
// tolerance absorbs timezone offsets between shard dates and query times.
func shardInWindow(name string, since, until time.Time) bool {
	base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(name), "records-"), ".jsonl")
	if base == "undated" || base == "" {
		return true
	}
	d, err := time.Parse("2006-01-02", base)
	if err != nil {
		return true
	}
	if !since.IsZero() && d.Before(since.AddDate(0, 0, -1)) {
		return false
	}
	if !until.IsZero() && d.After(until.AddDate(0, 0, 1)) {
		return false
	}
	return true
}

// chainHash links one record to the previous chain hash.
func chainHash(prev string, r LogRecord) string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256([]byte(prev + "\n" + string(b)))
	return hex.EncodeToString(sum[:])
}

// readLogStoreEntriesLocked parses the store file. Caller holds
// logStoreIOLock. Lines written before hash chaining parse with an empty
// ChainHash (legacy, reported separately by verification).
func readLogStoreEntriesLocked(path string) ([]logStoreEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []logStoreEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e logStoreEntry
		if err := json.Unmarshal([]byte(line), &e); err == nil && e.ChainHash != "" {
			out = append(out, e)
			continue
		}
		var r LogRecord
		if err := json.Unmarshal([]byte(line), &r); err == nil && r.Source+r.SourceIP+r.Path != "" {
			out = append(out, logStoreEntry{Record: r})
			continue
		}
		// Envelope line without a chain hash (hand-edited store): keep the record.
		if err := json.Unmarshal([]byte(line), &e); err == nil && e.Record.Source+e.Record.SourceIP+e.Record.Path != "" {
			out = append(out, logStoreEntry{Record: e.Record})
		}
	}
	return out, sc.Err()
}

// persistLogRecords appends records into date-sharded JSONL stores with hash
// chaining (one chain per shard) and drops shards older than retentionDays
// (0 disables the purge). Records are masked for sensitive patterns before
// they touch disk. Legacy single-file stores are read, migrated into shards
// and removed. Append semantics are preserved via atomic per-shard rewrites.
func persistLogRecords(records []LogRecord, retentionDays int) (string, int, int, error) {
	dir := logauditStoreDir()
	if dir == "" {
		return "", 0, 0, fmt.Errorf("reasonix home not resolved; cannot persist logs")
	}
	if len(records) == 0 && retentionDays <= 0 {
		return dir, 0, 0, nil
	}
	logStoreIOLock.Lock()
	defer logStoreIOLock.Unlock()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return dir, 0, 0, err
	}

	var cutoff time.Time
	if retentionDays > 0 {
		cutoff = time.Now().AddDate(0, 0, -retentionDays)
	}

	// Group incoming (masked) records by target shard.
	pending := map[string][]LogRecord{}
	for _, r := range records {
		name := shardNameForRecord(r)
		pending[name] = append(pending[name], maskLogRecord(r))
	}

	purged := 0
	touched := map[string]bool{}

	// Retention: drop whole expired date shards; the undated shard keeps its
	// zero-timestamp records and only purges dated records below the cutoff.
	if retentionDays > 0 {
		for _, path := range listStoreShards(dir) {
			name := filepath.Base(path)
			if name == "records.jsonl" || name == "records-undated.jsonl" {
				continue
			}
			base := strings.TrimSuffix(strings.TrimPrefix(name, "records-"), ".jsonl")
			d, err := time.Parse("2006-01-02", base)
			if err != nil || !d.Before(cutoff) {
				continue
			}
			entries, err := readLogStoreEntriesLocked(path)
			if err != nil {
				continue
			}
			purged += len(entries)
			os.Remove(path)
			touched[name] = true
		}
	}

	// Migrate the legacy single-file store into shards (entries are
	// re-chained per shard, masked on rewrite).
	legacy := logauditStorePath()
	if legacyEntries, err := readLogStoreEntriesLocked(legacy); err == nil && len(legacyEntries) > 0 {
		for _, e := range legacyEntries {
			name := shardNameForRecord(e.Record)
			pending[name] = append([]LogRecord{e.Record}, pending[name]...) // keep original order
		}
		if err := os.Remove(legacy); err == nil {
			touched["records.jsonl"] = true
		}
	}

	// Rewrite each touched shard atomically.
	for name, recs := range pending {
		path := filepath.Join(dir, name)
		var entries []logStoreEntry
		if _, err := os.Stat(path); err == nil && !touched[name] {
			entries, err = readLogStoreEntriesLocked(path)
			if err != nil {
				return dir, 0, 0, err
			}
		}
		if retentionDays > 0 && name == "records-undated.jsonl" {
			kept := entries[:0]
			for _, e := range entries {
				if !e.Record.Timestamp.IsZero() && e.Record.Timestamp.Before(cutoff) {
					purged++
					continue
				}
				kept = append(kept, e)
			}
			entries = kept
		}
		prev := logauditChainGenesis
		for _, e := range entries {
			if e.ChainHash != "" {
				prev = e.ChainHash
			}
		}
		for _, r := range recs {
			prev = chainHash(prev, r)
			entries = append(entries, logStoreEntry{ChainHash: prev, Record: r})
		}
		if err := writeShardEntriesLocked(path, entries); err != nil {
			return dir, 0, 0, err
		}
	}
	return dir, len(records), purged, nil
}

func writeShardEntriesLocked(path string, entries []logStoreEntry) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// loadPersistedLogRecords reads all shards (optionally pruned to shards
// overlapping [since, until]) back into records. A missing store yields an
// empty result, not an error.
func loadPersistedLogRecords(since, until time.Time) ([]LogRecord, error) {
	dir := logauditStoreDir()
	if dir == "" {
		return nil, fmt.Errorf("reasonix home not resolved; cannot read log store")
	}
	logStoreIOLock.Lock()
	defer logStoreIOLock.Unlock()
	var out []LogRecord
	for _, path := range listStoreShards(dir) {
		if !shardInWindow(path, since, until) {
			continue
		}
		entries, err := readLogStoreEntriesLocked(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			out = append(out, e.Record)
		}
	}
	return out, nil
}

// chainVerifyResult summarizes a hash-chain integrity check over all shards.
type chainVerifyResult struct {
	Total           int
	Legacy          int
	FirstBrokenLine int
	FirstBrokenFile string
	OK              bool
}

// verifyLogStoreChain recomputes every shard's hash chain and reports the
// first tampered or un-chained line, if any.
func verifyLogStoreChain() (chainVerifyResult, error) {
	dir := logauditStoreDir()
	res := chainVerifyResult{OK: true}
	if dir == "" {
		return res, fmt.Errorf("reasonix home not resolved; cannot verify log store")
	}
	logStoreIOLock.Lock()
	defer logStoreIOLock.Unlock()
	for _, path := range listStoreShards(dir) {
		entries, err := readLogStoreEntriesLocked(path)
		if err != nil {
			return res, err
		}
		prev := logauditChainGenesis
		for i, e := range entries {
			res.Total++
			line := i + 1
			switch {
			case e.ChainHash == "":
				res.Legacy++
				if res.OK {
					res.OK = false
					res.FirstBrokenLine = line
					res.FirstBrokenFile = filepath.Base(path)
				}
			case e.ChainHash != chainHash(prev, e.Record):
				if res.OK {
					res.OK = false
					res.FirstBrokenLine = line
					res.FirstBrokenFile = filepath.Base(path)
				}
			}
			if e.ChainHash != "" {
				prev = e.ChainHash
			}
		}
	}
	return res, nil
}

func sortRecordsByTime(records []LogRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Timestamp.IsZero() || records[j].Timestamp.IsZero() {
			return false
		}
		return records[i].Timestamp.Before(records[j].Timestamp)
	})
}

func groupRecordsByIP(records []LogRecord) map[string][]LogRecord {
	groups := map[string][]LogRecord{}
	for _, r := range records {
		if r.SourceIP == "" {
			continue
		}
		groups[r.SourceIP] = append(groups[r.SourceIP], r)
	}
	return groups
}

func recordSources(records []LogRecord) []string {
	seen := map[string]bool{}
	for _, r := range records {
		if r.Source != "" {
			seen[r.Source] = true
		}
	}
	out := make([]string, 0, len(seen))
	for src := range seen {
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

var (
	failedAuthRe = regexp.MustCompile(`(?i)(failed password|authentication failure|invalid user|login failed|incorrect password|account locked|authentication error)`)
	scanToolRe   = regexp.MustCompile(`(?i)(sqlmap|nikto|nuclei|acunetix|nessus|masscan|zmap|nmap|gobuster|dirsearch|wpscan)`)
	webAttackRe  = regexp.MustCompile(`(?i)(union\s+select|information_schema|sleep\s*\(|benchmark\s*\(|\.\./|/etc/passwd|cmd\.exe|powershell|base64|eval\s*\(|passthru|shell_exec|system\s*\(|<\s*script|onerror\s*=)`)
	webshellRe   = regexp.MustCompile(`(?i)(\.(php|jsp|jspx|asp|aspx|ashx|cgi)(\?|$)|/shell|webshell|cmd\.exe|whoami|/bin/sh)`)
	// %27 alone matches any URL-encoded apostrophe in legitimate search
	// strings, so only quote-based tautologies (' or '1'='1) are kept.
	sqliRe = regexp.MustCompile(`(?i)(union\s+select|information_schema|sleep\s*\(|benchmark\s*\(|updatexml|extractvalue|load_file\s*\(|concat\s*\(|\x27\s*or\s*\x27)`)
)

func isFailureRecord(r LogRecord) bool {
	return r.Status == 401 || r.Status == 403 || failedAuthRe.MatchString(r.Message) || failedAuthRe.MatchString(r.Raw)
}

func isScanRecord(r LogRecord) bool {
	if r.Status == 404 {
		return true
	}
	// Scanner user agents alone are not recon when the request succeeded:
	// a lone 2xx hit (e.g. /favicon.ico) must not accumulate scan counts.
	if r.Status >= 200 && r.Status < 300 {
		return false
	}
	return scanToolRe.MatchString(r.UserAgent) ||
		scanToolRe.MatchString(r.Message) ||
		scanToolRe.MatchString(r.Raw)
}

func isWebAttackRecord(r LogRecord) bool {
	text := strings.Join([]string{r.Path, r.Request, r.Message, r.Raw}, " ")
	return webAttackRe.MatchString(text)
}

func isSQLiRecord(r LogRecord) bool {
	text := strings.Join([]string{r.Path, r.Request, r.Message, r.Raw}, " ")
	if sqliRe.MatchString(text) {
		return true
	}
	// URL-encoded payloads (e.g. "UNION%20SELECT") are invisible to the raw
	// regex because %20 is not whitespace; retry against a percent-decoded
	// copy. Only %XX triplets are decoded so '+' stays literal.
	return sqliRe.MatchString(percentDecode(text))
}

// percentDecode replaces valid %XX triplets with their byte value and
// leaves everything else untouched (cheap, allocation-light for clean text).
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexNibble(s[i+1])
			lo, ok2 := hexNibble(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func isWebshellRecord(r LogRecord) bool {
	text := strings.Join([]string{r.Path, r.Request, r.Message, r.Raw}, " ")
	return webshellRe.MatchString(text)
}

func isSuccessRecord(r LogRecord) bool {
	return r.Status >= 200 && r.Status < 300
}

func isOutOfHoursRecord(r LogRecord) bool {
	return !r.Timestamp.IsZero() && r.Timestamp.Hour() >= 0 && r.Timestamp.Hour() <= 5
}

func filterRecords(records []LogRecord, keep func(LogRecord) bool) []LogRecord {
	var out []LogRecord
	for _, r := range records {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

// sensitiveValueRe masks credential-like key=value / key: value pairs
// (passwords, authorization headers, cookies, session tokens, API keys).
// The key is kept, the value replaced with ***. "Failed password for root"
// style prose does not match (no separator right after the key).
var sensitiveValueRe = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|session|bearer|credential)("?\s*[:=]\s*)[^\s"'&;]+`)

// sensitiveBearerRe masks "Bearer <token>" pairs where the token follows
// the scheme after a space (not covered by the key-separator rule).
var sensitiveBearerRe = regexp.MustCompile(`(?i)(bearer)(\s+)[A-Za-z0-9._~+/=-]+`)

// maskSensitiveString replaces credential values with *** so persisted
// stores and exported evidence never carry plaintext secrets.
func maskSensitiveString(s string) string {
	if s == "" {
		return s
	}
	s = sensitiveBearerRe.ReplaceAllString(s, "${1}${2}***")
	return sensitiveValueRe.ReplaceAllString(s, "${1}${2}***")
}

// maskLogRecord masks the free-text fields of a record copy. Structured
// fields (IP/status/method) stay intact for detection and filtering.
func maskLogRecord(r LogRecord) LogRecord {
	r.Raw = maskSensitiveString(r.Raw)
	r.Message = maskSensitiveString(r.Message)
	r.Request = maskSensitiveString(r.Request)
	r.Path = maskSensitiveString(r.Path)
	r.UserAgent = maskSensitiveString(r.UserAgent)
	r.Referer = maskSensitiveString(r.Referer)
	return r
}

func recordSnippet(r LogRecord, max int) string {
	text := r.Raw
	if text == "" {
		text = fmt.Sprintf("%s %s %s", r.SourceIP, r.Method, r.Request)
		if r.Message != "" {
			text += " " + r.Message
		}
	}
	text = strings.TrimSpace(text)
	if len(text) > max {
		text = text[:max] + "..."
	}
	return text
}

func evidenceSnippets(records []LogRecord, limit int) string {
	var b strings.Builder
	for i, r := range records {
		if i >= limit {
			break
		}
		b.WriteString(maskSensitiveString(recordSnippet(r, 180)))
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}
