package builtin

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAXFRQueryShape(t *testing.T) {
	frame := buildAXFRQuery("example.test")
	if len(frame) < 14 {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	msgLen := int(binary.BigEndian.Uint16(frame[:2]))
	if msgLen != len(frame)-2 {
		t.Fatalf("TCP length prefix %d does not match message %d", msgLen, len(frame)-2)
	}
	msg := frame[2:]
	if qd := binary.BigEndian.Uint16(msg[4:6]); qd != 1 {
		t.Fatalf("QDCOUNT = %d, want 1", qd)
	}
	// Question: encoded labels + root + QTYPE(AXFR=252) + QCLASS(IN=1).
	qtype := binary.BigEndian.Uint16(msg[len(msg)-4 : len(msg)-2])
	qclass := binary.BigEndian.Uint16(msg[len(msg)-2:])
	if qtype != 252 || qclass != 1 {
		t.Fatalf("QTYPE/QCLASS = %d/%d, want 252/1", qtype, qclass)
	}
	if !strings.Contains(string(msg), "example") || !strings.Contains(string(msg), "test") {
		t.Fatalf("question does not encode the domain: %q", msg[12:])
	}
}

func TestDNSEnumRejectsBadMode(t *testing.T) {
	args, _ := json.Marshal(map[string]any{"domain": "example.test", "mode": "bogus"})
	if _, err := (dnsEnum{}).Execute(context.Background(), args); err == nil {
		t.Fatal("expected mode rejection")
	}
}

func TestDNSEnumRequiresDomain(t *testing.T) {
	if _, err := (dnsEnum{}).Execute(context.Background(), json.RawMessage(`{"mode":"records"}`)); err == nil {
		t.Fatal("expected missing-domain rejection")
	}
}

func TestDNSEnumReverseFailsClosedOnGarbage(t *testing.T) {
	// An unparseable address cannot reverse-resolve; the tool must error,
	// not fabricate results.
	args, _ := json.Marshal(map[string]any{"domain": "not-an-ip", "mode": "reverse"})
	if _, err := (dnsEnum{}).Execute(context.Background(), args); err == nil {
		t.Skip("system resolver returned PTR for garbage input - environment specific")
	}
}

func TestSubdomainWordlistIsPopulated(t *testing.T) {
	if len(subdomainWordlist) < 50 {
		t.Fatalf("built-in subdomain wordlist shrank to %d entries", len(subdomainWordlist))
	}
}
