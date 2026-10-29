package serve

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"reasonix/internal/config"
)

func TestGenerateToken(t *testing.T) {
	t1 := generateToken()
	t2 := generateToken()
	if t1 == t2 {
		t.Error("generateToken should produce unique values")
	}
	if len(t1) < 32 {
		t.Errorf("token too short: %d bytes", len(t1))
	}
	// Should be base64url-encoded (no +, no /).
	if strings.ContainsAny(t1, "+/") {
		t.Errorf("token contains non-base64url chars: %q", t1)
	}
}

func TestAuthGateModeNone(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{}) // default: authNone
	if ag.Mode() != "none" {
		t.Errorf("mode = %q, want none", ag.Mode())
	}
	if ag.Token() != "" {
		t.Errorf("token = %q, want empty", ag.Token())
	}

	// In none mode, requests pass through.
	ts := httptest.NewServer(ag.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNormalizeAuthModeRejectsUnknown(t *testing.T) {
	if _, err := NormalizeAuthMode("tokne"); err == nil {
		t.Fatal("unknown auth mode should be rejected")
	}
}

func TestNormalizeAuthModeRejectsPassword(t *testing.T) {
	// The headless API only supports none/token; the password login surface
	// belonged to the removed browser UI.
	if _, err := NormalizeAuthMode("password"); err == nil {
		t.Fatal("password auth mode should be rejected")
	}
}

func TestInvalidAuthModeFailsClosed(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "tokne"})
	if ag.Mode() != "invalid" {
		t.Errorf("mode = %q, want invalid", ag.Mode())
	}
	ts := httptest.NewServer(ag.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run for invalid auth mode")
	})))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// ── Token mode tests ──

func TestTokenModeNoAuthReturns401(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "secret"})
	ts := httptest.NewServer(ag.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestTokenModeValidCookie(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "secret"})
	ts := httptest.NewServer(ag.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/status", nil)
	req.AddCookie(&http.Cookie{Name: cookieToken, Value: "secret"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestTokenModeInvalidCookie(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "secret"})
	ts := httptest.NewServer(ag.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/status", nil)
	req.AddCookie(&http.Cookie{Name: cookieToken, Value: "wrong"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestTokenModeValidQueryParamRedirects(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "secret"})

	// Use a handler that records whether auth passed.
	var passed bool
	ts := httptest.NewServer(ag.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passed = true
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	// Don't follow redirects so we can inspect the 302.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(ts.URL + "/?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}

	// Check that the Set-Cookie header is present.
	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, cookieToken+"=secret") {
		t.Errorf("Set-Cookie missing token: %s", setCookie)
	}
	if !strings.Contains(setCookie, "HttpOnly") {
		t.Errorf("Set-Cookie missing HttpOnly: %s", setCookie)
	}
	if passed {
		t.Error("handler should not have run (redirected first)")
	}
}

func TestTokenModeLoopbackCookieAllowsLocalHTTP(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "secret"})
	ts := httptest.NewServer(ag.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(ts.URL + "/?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	c := findCookie(resp.Cookies(), cookieToken)
	if c == nil {
		t.Fatal("token cookie missing")
	}
	if c.Secure {
		t.Fatal("loopback HTTP token cookie should stay usable without Secure")
	}
}

func TestTokenModeNonLoopbackCookieAllowsPlainHTTP(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "secret"})
	ts := httptest.NewServer(ag.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/?token=secret", nil)
	req.Host = "192.0.2.10:8787"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	c := findCookie(resp.Cookies(), cookieToken)
	if c == nil {
		t.Fatal("token cookie missing")
	}
	if c.Secure {
		t.Fatal("plain HTTP token cookie should stay usable without Secure")
	}
}

func TestTokenModeInvalidQueryParam(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "secret"})
	ts := httptest.NewServer(ag.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/?token=wrong")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestTokenModeAutoGeneratesToken(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token"})
	if ag.Mode() != "token" {
		t.Errorf("mode = %q, want token", ag.Mode())
	}
	if ag.Token() == "" {
		t.Error("token should be auto-generated")
	}
	if len(ag.Token()) < 32 {
		t.Errorf("auto-generated token too short: %d", len(ag.Token()))
	}
}

// ── isTLS tests ──

func TestIsTLS(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "x"})
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	if ag.isTLS(req) {
		t.Error("plain request should not be TLS")
	}
}

func TestIsTLSIgnoresForwardedProtoWithoutProxy(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "x"})
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if ag.isTLS(req) {
		t.Error("should ignore X-Forwarded-Proto without behind_proxy")
	}
}

func TestIsTLSTrustsForwardedProtoWithProxy(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "x", BehindProxy: true})
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if !ag.isTLS(req) {
		t.Error("should trust X-Forwarded-Proto with behind_proxy")
	}
}

func TestAuthCookieSecurePolicy(t *testing.T) {
	ag := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "x"})
	for _, host := range []string{"localhost:8787", "127.0.0.1:8787", "[::1]:8787"} {
		req, _ := http.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		if ag.authCookieSecure(req) {
			t.Errorf("loopback host %s should allow local HTTP cookies", host)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, "http://192.0.2.10:8787/", nil)
	if ag.authCookieSecure(req) {
		t.Fatal("plain HTTP cookies should stay usable without Secure")
	}

	proxy := newAuthGate(config.ServeConfig{AuthMode: "token", Token: "x", BehindProxy: true})
	req, _ = http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if !proxy.authCookieSecure(req) {
		t.Fatal("trusted forwarded HTTPS should mark cookies Secure")
	}
}

func TestPlainHTTPAuthWarning(t *testing.T) {
	if got := PlainHTTPAuthWarning(config.ServeConfig{AuthMode: "none"}, "0.0.0.0:8787"); got != "" {
		t.Fatalf("none auth warning = %q, want empty", got)
	}
	if got := PlainHTTPAuthWarning(config.ServeConfig{AuthMode: "token", Token: "x"}, "127.0.0.1:8787"); got != "" {
		t.Fatalf("loopback warning = %q, want empty", got)
	}
	if got := PlainHTTPAuthWarning(config.ServeConfig{AuthMode: "token", Token: "x"}, "0.0.0.0:8787"); !strings.Contains(got, "non-loopback HTTP") {
		t.Fatalf("non-loopback warning = %q, want HTTP exposure warning", got)
	}
	if got := PlainHTTPAuthWarning(config.ServeConfig{AuthMode: "token", Token: "x"}, ":8787"); !strings.Contains(got, "non-loopback HTTP") {
		t.Fatalf("wildcard warning = %q, want HTTP exposure warning", got)
	}
}

func TestSafeRedirectTarget(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"/", "/"},
		{"/sessions?id=abc#frag", "/sessions?id=abc"},
		{"", "/"},
		{"https://evil.example/path", "/"},
		{"//evil.example/path", "/"},
		{`/\evil.example/path`, "/"},
		{"/%2f%2fevil.example/path", "/"},
		{"/%5cevil.example/path", "/"},
		{"relative/path", "/"},
	} {
		if got := safeRedirectTarget(tc.in); got != tc.want {
			t.Errorf("safeRedirectTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── helpers ──

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
