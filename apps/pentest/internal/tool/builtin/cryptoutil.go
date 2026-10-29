package builtin

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(cryptoUtil{}) }

// cryptoUtil bundles the encoding/hash/token primitives a pentest session
// keeps reaching for: base64/hex/url codec, common digests, JWT inspection,
// HS256 weak-secret verification against a small dictionary, and Unix
// timestamp conversion. Everything runs locally.
type cryptoUtil struct{}

func (cryptoUtil) Name() string { return "crypto_util" }

func (cryptoUtil) Description() string {
	return "Local pentest crypto/encoding helpers: op=encode|decode (base64/hex/url), op=hash (md5/sha1/sha256/sha512), op=jwt_parse (header/payload/claims decode), op=jwt_crack (verify an HS256 token against a weak-secret dictionary), op=timestamp (Unix<->UTC). No network involved."
}

func (cryptoUtil) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"op":{"type":"string","description":"Operation: encode, decode, hash, jwt_parse, jwt_crack, timestamp"},"input":{"type":"string","description":"Input text (or JWT token, or Unix timestamp digits)"},"encoding":{"type":"string","description":"For encode/decode: base64, hex, url (default base64)"},"algorithm":{"type":"string","description":"For hash: md5, sha1, sha256, sha512 (default sha256)"}},"required":["op","input"]}`)
}

// ReadOnly: pure local computation, no host or network side effects.
func (cryptoUtil) ReadOnly() bool { return true }

// SnipHint: outputs are compact; keep everything.
func (cryptoUtil) SnipHint() tool.SnipHint {
	return tool.SnipHint{Head: 60, Tail: 10, HeadChars: 8000, TailChars: 1000}
}

// jwtWeakSecrets is the classic weak-secret dictionary for HS256 verification.
var jwtWeakSecrets = []string{
	"secret", "secret123", "password", "password123", "123456", "12345678",
	"123456789", "1234567890", "admin", "admin123", "root", "toor", "test",
	"test123", "qwerty", "abc123", "letmein", "welcome", "monkey", "dragon",
	"iloveyou", "sunshine", "princess", "master", "shadow", "superman",
	"batman", "trustno1", "whatever", "changeme", "default", "temp", "tmp",
	"jwt_secret", "jwt-secret", "jwtsecret", "mysecret", "my_secret",
	"my-secret", "hs256_secret", "token_secret", "app_secret", "appsecret",
	"key", "key123", "private", "public", "debug", "dev", "development",
	"production", "staging", "p@ssw0rd", "Passw0rd", "P@ssword1", "hunter2",
	"your-256-bit-secret", "your-secret-key", "my-secret-key", "supersecret",
	"super-secret", "secretkey", "secret-key", "signing-key", "signingkey",
	"auth_secret", "auth-secret", "session_secret", "cookie_secret",
	"keyboard cat", "shhhhh", "asdf", "asdfgh", "zxcvbnm", "qazwsx",
	"111111", "000000", "654321", "666666", "888888", "123123", "112233",
}

func (cryptoUtil) Execute(_ context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Op        string `json:"op"`
		Input     string `json:"input"`
		Encoding  string `json:"encoding"`
		Algorithm string `json:"algorithm"`
	}{Encoding: "base64", Algorithm: "sha256"}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if strings.TrimSpace(p.Input) == "" {
		return "", fmt.Errorf("input is required")
	}
	input := strings.TrimSpace(p.Input)

	switch strings.ToLower(strings.TrimSpace(p.Op)) {
	case "encode":
		return encodeValue(input, strings.ToLower(p.Encoding))
	case "decode":
		return decodeValue(input, strings.ToLower(p.Encoding))
	case "hash":
		return hashValue(input, strings.ToLower(p.Algorithm))
	case "jwt_parse":
		return jwtParse(input)
	case "jwt_crack":
		return jwtCrack(input)
	case "timestamp":
		return convertTimestamp(input)
	default:
		return "", fmt.Errorf("unknown op %q (want encode, decode, hash, jwt_parse, jwt_crack, timestamp)", p.Op)
	}
}

func encodeValue(input, encoding string) (string, error) {
	switch encoding {
	case "", "base64":
		return base64.StdEncoding.EncodeToString([]byte(input)), nil
	case "hex":
		return hex.EncodeToString([]byte(input)), nil
	case "url":
		return url.QueryEscape(input), nil
	default:
		return "", fmt.Errorf("unknown encoding %q (want base64, hex, url)", encoding)
	}
}

func decodeValue(input, encoding string) (string, error) {
	switch encoding {
	case "", "base64":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
		if err != nil {
			// JWT segments use base64url without padding.
			if raw, err2 := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(input), "=")); err2 == nil {
				return fmt.Sprintf("%s\n(base64url, no padding)", raw), nil
			}
			return "", fmt.Errorf("base64 decode: %w", err)
		}
		return string(raw), nil
	case "hex":
		raw, err := hex.DecodeString(strings.TrimSpace(input))
		if err != nil {
			return "", fmt.Errorf("hex decode: %w", err)
		}
		return string(raw), nil
	case "url":
		raw, err := url.QueryUnescape(strings.TrimSpace(input))
		if err != nil {
			return "", fmt.Errorf("url decode: %w", err)
		}
		return raw, nil
	default:
		return "", fmt.Errorf("unknown encoding %q (want base64, hex, url)", encoding)
	}
}

func hashValue(input, algorithm string) (string, error) {
	switch algorithm {
	case "", "sha256":
		sum := sha256.Sum256([]byte(input))
		return hex.EncodeToString(sum[:]), nil
	case "md5":
		sum := md5.Sum([]byte(input))
		return hex.EncodeToString(sum[:]), nil
	case "sha1":
		sum := sha1.Sum([]byte(input))
		return hex.EncodeToString(sum[:]), nil
	case "sha512":
		sum := sha512.Sum512([]byte(input))
		return hex.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unknown algorithm %q (want md5, sha1, sha256, sha512)", algorithm)
	}
}

// splitJWT validates shape and returns the three segments.
func splitJWT(token string) (headerB64, payloadB64, sigB64 string, err error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("not a JWT: expected 3 dot-separated segments, got %d", len(parts))
	}
	return parts[0], parts[1], parts[2], nil
}

func b64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func jwtParse(token string) (string, error) {
	headerB64, payloadB64, _, err := splitJWT(token)
	if err != nil {
		return "", err
	}
	header, err := b64URLDecode(headerB64)
	if err != nil {
		return "", fmt.Errorf("decode header: %w", err)
	}
	payload, err := b64URLDecode(payloadB64)
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "header: %s\n", header)
	fmt.Fprintf(&b, "payload: %s\n", payload)

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err == nil {
		for _, claim := range []string{"exp", "iat", "nbf"} {
			if v, ok := claims[claim].(float64); ok {
				ts := time.Unix(int64(v), 0).UTC()
				note := ""
				if claim == "exp" && !ts.After(time.Now()) {
					note = " (EXPIRED)"
				}
				fmt.Fprintf(&b, "%s: %d = %s%s\n", claim, int64(v), ts.Format(time.RFC3339), note)
			}
		}
		if alg := extractStringField(string(header), "alg"); alg != "" && !strings.HasPrefix(alg, "HS") {
			fmt.Fprintf(&b, "note: alg=%s - jwt_crack only verifies HS256; for 'none'/RS->HS confusion tests use manual verification\n", alg)
		}
	}
	return b.String(), nil
}

// jwtCrack verifies an HS256 token against the weak-secret dictionary. A hit
// proves the signing key is guessable - verification only; forging tokens for
// an unauthorized purpose is out of scope.
func jwtCrack(token string) (string, error) {
	headerB64, payloadB64, sigB64, err := splitJWT(token)
	if err != nil {
		return "", err
	}
	header, err := b64URLDecode(headerB64)
	if err != nil {
		return "", fmt.Errorf("decode header: %w", err)
	}
	if alg := extractStringField(string(header), "alg"); alg != "HS256" {
		return "", fmt.Errorf("jwt_crack only verifies HS256 tokens (token alg=%q)", alg)
	}
	sig, err := b64URLDecode(sigB64)
	if err != nil {
		return "", fmt.Errorf("decode signature: %w", err)
	}
	signingInput := headerB64 + "." + payloadB64

	for _, secret := range jwtWeakSecrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), sig) {
			return fmt.Sprintf("FINDING: HS256 token verified with WEAK secret %q - the signing key is guessable\n", secret), nil
		}
	}
	return fmt.Sprintf("no weak secret matched (%d tried); signature length %d bytes\n", len(jwtWeakSecrets), len(sig)), nil
}

// extractStringField pulls "alg" style fields from a compact JSON object
// without pulling the whole claim set into a typed shape.
func extractStringField(js, key string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// convertTimestamp converts Unix seconds to UTC and the current instant back,
// or treats a non-numeric input as a hint error.
func convertTimestamp(input string) (string, error) {
	sec, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return "", fmt.Errorf("timestamp must be Unix seconds (got %q)", input)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d = %s\n", sec, time.Unix(sec, 0).UTC().Format(time.RFC3339))
	now := time.Now()
	fmt.Fprintf(&b, "now = %d (%s)\n", now.Unix(), now.UTC().Format(time.RFC3339))
	if sec > now.Unix() {
		b.WriteString("note: timestamp is in the future\n")
	}
	return b.String(), nil
}
