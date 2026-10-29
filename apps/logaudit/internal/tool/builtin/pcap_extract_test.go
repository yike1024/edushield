package builtin

// pcap_extract 回归测试：用内存构造的经典 pcap（Ethernet/IPv4/TCP）做
// 确定性断言；另对真实流量包 AntSword2.pcap 做可选自检（缺失则跳过）。

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reasonix/internal/evidence"
)

type testPkt struct {
	tsSec        uint32
	srcIP, dstIP [4]byte
	srcPort      uint16
	dstPort      uint16
	payload      []byte
}

func buildEthIPv4TCP(p testPkt) []byte {
	var b bytes.Buffer
	// Ethernet: dst MAC, src MAC, EtherType IPv4
	b.Write(bytes.Repeat([]byte{0xaa}, 6))
	b.Write(bytes.Repeat([]byte{0xbb}, 6))
	b.Write([]byte{0x08, 0x00})
	ipLen := 20 + 20 + len(p.payload)
	// IPv4 header (checksum not verified by the parser, left zero)
	b.Write([]byte{0x45, 0x00, byte(ipLen >> 8), byte(ipLen), 0, 0, 0x40, 0, 64, 6})
	b.Write([]byte{0, 0})
	b.Write(p.srcIP[:])
	b.Write(p.dstIP[:])
	// TCP header: ports, seq, ack, data offset 5, flags ACK, window, checksum, urgent
	binary.Write(&b, binary.BigEndian, p.srcPort)
	binary.Write(&b, binary.BigEndian, p.dstPort)
	b.Write([]byte{0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x10, 0x20, 0x00, 0, 0, 0, 0})
	b.Write(p.payload)
	return b.Bytes()
}

func writeTestPcap(t *testing.T, pkts ...testPkt) string {
	t.Helper()
	var buf bytes.Buffer
	bo := binary.LittleEndian
	binary.Write(&buf, bo, uint32(0xa1b2c3d4))
	binary.Write(&buf, bo, uint16(2))
	binary.Write(&buf, bo, uint16(4))
	binary.Write(&buf, bo, int32(0))
	binary.Write(&buf, bo, uint32(0))
	binary.Write(&buf, bo, uint32(65535))
	binary.Write(&buf, bo, uint32(1)) // linktype Ethernet
	for _, p := range pkts {
		pkt := buildEthIPv4TCP(p)
		binary.Write(&buf, bo, p.tsSec)
		binary.Write(&buf, bo, uint32(0))
		binary.Write(&buf, bo, uint32(len(pkt)))
		binary.Write(&buf, bo, uint32(len(pkt)))
		buf.Write(pkt)
	}
	path := filepath.Join(t.TempDir(), "test.pcap")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write test pcap: %v", err)
	}
	return path
}

var (
	testClientIP = [4]byte{203, 0, 113, 9}
	testServerIP = [4]byte{10, 20, 0, 8}
)

func TestPcapExtractGetTransaction(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()
	t.Setenv("REASONIX_HOME", t.TempDir())

	req := "GET /probe?id=1 HTTP/1.1\r\nHost: target.local\r\nUser-Agent: test-agent/1.0\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	path := writeTestPcap(t,
		testPkt{tsSec: 1756350000, srcIP: testClientIP, dstIP: testServerIP, srcPort: 40000, dstPort: 80, payload: []byte(req)},
		testPkt{tsSec: 1756350001, srcIP: testServerIP, dstIP: testClientIP, srcPort: 80, dstPort: 40000, payload: []byte(resp)},
	)

	out := runTool(t, pcapExtract{}, map[string]any{"path": path, "persist": true})
	if !strings.Contains(out, "HTTP transactions: 1") {
		t.Fatalf("expected 1 transaction:\n%s", out)
	}

	recs := globalLogStore.recordsFor(path)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record in store, got %d", len(recs))
	}
	r := recs[0]
	if r.SourceIP != "203.0.113.9" || r.Method != "GET" || r.Path != "/probe?id=1" || r.Status != 200 || r.UserAgent != "test-agent/1.0" || r.Host != "target.local" {
		t.Errorf("unexpected record: %+v", r)
	}
	if !strings.Contains(out, "Persist: 1 records appended") {
		t.Errorf("persist line missing:\n%s", out)
	}
	out = runTool(t, logQuery{}, map[string]any{"verify": true})
	if !strings.Contains(out, "Chain verify: OK") {
		t.Errorf("chain verify failed:\n%s", out)
	}
}

func TestPcapExtractPostBodyWebshellIndicator(t *testing.T) {
	globalLogStore.clear()
	evidence.Global.Clear()
	t.Setenv("REASONIX_HOME", t.TempDir())

	// URL 编码的 @eval(...) 载荷：解码后命中指标，原始形态不命中
	body := "ant=%40eval%28%24_request%29&z0=whoami"
	req := "POST /shell/cmd.jsp HTTP/1.1\r\nHost: target.local\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
		itoaFixed(len(body)) + "\r\n\r\n" + body
	path := writeTestPcap(t,
		testPkt{tsSec: 1756350100, srcIP: testClientIP, dstIP: testServerIP, srcPort: 40002, dstPort: 8080, payload: []byte(req)},
	)

	out := runTool(t, pcapExtract{}, map[string]any{"path": path})
	if !strings.Contains(out, "HTTP transactions: 1") {
		t.Fatalf("expected 1 transaction:\n%s", out)
	}
	if !strings.Contains(out, "Webshell body indicators: 2 hits from 203.0.113.9") {
		t.Errorf("expected indicator hits (eval via decoded body + whoami raw):\n%s", out)
	}

	recs := globalLogStore.recordsFor(path)
	if len(recs) != 1 || !strings.HasPrefix(recs[0].Message, "POST body: ") {
		t.Fatalf("expected POST body captured in Message, got: %+v", recs)
	}
	// 高危 Finding 必须落证据库
	found := false
	for _, f := range evidence.Global.All() {
		if strings.HasPrefix(f.ID, "pcap_extract:webshell-body:") {
			found = true
			if f.Severity != evidence.SeverityHigh {
				t.Errorf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("webshell-body finding missing")
	}
}

func TestPcapExtractRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pcap")
	if err := os.WriteFile(path, []byte("not a pcap file at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (pcapExtract{}).Execute(t.Context(), []byte(`{"path":"`+path+`"}`)); err == nil {
		t.Fatalf("expected error for invalid magic")
	}
}

// TestPcapExtractAntSwordReal 用工作区真实流量包自检（缺失则跳过）。
func TestPcapExtractAntSwordReal(t *testing.T) {
	const real = `d:\004-pocket\trea-1\AntSword2.pcap`
	if _, err := os.Stat(real); err != nil {
		t.Skipf("real pcap missing: %v", err)
	}
	globalLogStore.clear()
	evidence.Global.Clear()
	t.Setenv("REASONIX_HOME", t.TempDir())

	out := runTool(t, pcapExtract{}, map[string]any{"path": real, "persist": true})
	t.Logf("[pcap_extract AntSword2.pcap]\n%s", out)
	if strings.Contains(out, "HTTP transactions: 0") {
		t.Fatalf("no HTTP transactions extracted from real capture:\n%s", out)
	}
	recs := globalLogStore.recordsFor(real)
	shell := 0
	for _, r := range recs {
		if r.Method == "POST" && strings.Contains(r.Path, "/shell/yesec.jsp") {
			shell++
		}
	}
	if shell == 0 {
		t.Errorf("expected webshell POST /shell/yesec.jsp records, got none of %d", len(recs))
	}
}

// itoaFixed avoids importing strconv just for test header formatting.
func itoaFixed(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
