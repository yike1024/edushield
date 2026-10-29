package builtin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func runCrypto(t *testing.T, args map[string]any) (string, error) {
	t.Helper()
	raw, _ := json.Marshal(args)
	return cryptoUtil{}.Execute(context.Background(), raw)
}

func TestCryptoEncodeDecodeRoundtrip(t *testing.T) {
	for _, enc := range []string{"base64", "hex", "url"} {
		out, err := runCrypto(t, map[string]any{"op": "encode", "input": "admin:pass", "encoding": enc})
		if err != nil {
			t.Fatalf("encode %s: %v", enc, err)
		}
		back, err := runCrypto(t, map[string]any{"op": "decode", "input": strings.TrimSpace(out), "encoding": enc})
		if err != nil {
			t.Fatalf("decode %s: %v", enc, err)
		}
		if strings.TrimSpace(back) != "admin:pass" {
			t.Fatalf("%s roundtrip = %q", enc, back)
		}
	}
}

func TestCryptoHashes(t *testing.T) {
	out, err := runCrypto(t, map[string]any{"op": "hash", "input": "abc", "algorithm": "md5"})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if strings.TrimSpace(out) != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("md5(abc) = %q", out)
	}
	out, err = runCrypto(t, map[string]any{"op": "hash", "input": "abc", "algorithm": "sha256"})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if strings.TrimSpace(out) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256(abc) = %q", out)
	}
	if _, err := runCrypto(t, map[string]any{"op": "hash", "input": "x", "algorithm": "crc32"}); err == nil {
		t.Fatal("expected unknown algorithm rejection")
	}
}

// makeHS256 signs a JWT with the given secret for crack/parse tests.
func makeHS256(t *testing.T, payload, secret string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + body))
	return header + "." + body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestJWTParseDecodesClaims(t *testing.T) {
	token := makeHS256(t, `{"sub":"admin","exp":1700000000}`, "irrelevant")
	out, err := runCrypto(t, map[string]any{"op": "jwt_parse", "input": token})
	if err != nil {
		t.Fatalf("jwt_parse: %v", err)
	}
	for _, want := range []string{`"alg":"HS256"`, `"sub":"admin"`, "exp: 1700000000", "(EXPIRED)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("jwt_parse missing %q:\n%s", want, out)
		}
	}
}

func TestJWTCrackFindsWeakSecret(t *testing.T) {
	token := makeHS256(t, `{"sub":"admin"}`, "secret")
	out, err := runCrypto(t, map[string]any{"op": "jwt_crack", "input": token})
	if err != nil {
		t.Fatalf("jwt_crack: %v", err)
	}
	if !strings.Contains(out, `WEAK secret "secret"`) {
		t.Fatalf("jwt_crack did not find the weak secret:\n%s", out)
	}
}

func TestJWTCrackRejectsStrongSecret(t *testing.T) {
	token := makeHS256(t, `{"sub":"admin"}`, "this-is-not-in-any-wordlist-9F3k")
	out, err := runCrypto(t, map[string]any{"op": "jwt_crack", "input": token})
	if err != nil {
		t.Fatalf("jwt_crack: %v", err)
	}
	if !strings.Contains(out, "no weak secret matched") {
		t.Fatalf("unexpected crack result:\n%s", out)
	}
}

func TestJWTCrackRejectsNonHS256(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	token := header + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + "."
	if _, err := runCrypto(t, map[string]any{"op": "jwt_crack", "input": token}); err == nil {
		t.Fatal("expected alg rejection")
	}
}

func TestJWTCrackRejectsMalformedToken(t *testing.T) {
	if _, err := runCrypto(t, map[string]any{"op": "jwt_crack", "input": "not.a.jwt.extra"}); err == nil {
		t.Fatal("expected malformed token rejection")
	}
}

func TestTimestampConversion(t *testing.T) {
	out, err := runCrypto(t, map[string]any{"op": "timestamp", "input": "1700000000"})
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	if !strings.Contains(out, "2023-11-14T22:13:20Z") {
		t.Fatalf("timestamp conversion wrong:\n%s", out)
	}
	if _, err := runCrypto(t, map[string]any{"op": "timestamp", "input": "yesterday"}); err == nil {
		t.Fatal("expected non-numeric rejection")
	}
}

func TestCryptoRejectsUnknownOp(t *testing.T) {
	if _, err := runCrypto(t, map[string]any{"op": "rainbow", "input": "x"}); err == nil {
		t.Fatal("expected unknown op rejection")
	}
}
