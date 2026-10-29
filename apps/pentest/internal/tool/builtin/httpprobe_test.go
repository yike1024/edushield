package builtin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPProbeReportsTechAndMissingHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Powered-By", "PHP/5.4")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>  Target  App </title></head><body>hi</body></html>"))
	}))
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{"url": srv.URL})
	out, err := httpProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, want := range []string{
		"Server: TestServer/1.0",
		"X-Powered-By: PHP/5.4",
		"MISSING Content-Security-Policy",
		"MISSING Strict-Transport-Security",
		"title: Target App",
		"PHPSESSID (no Secure flag, no HttpOnly flag, no SameSite)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestHTTPProbeFollowsRedirectChain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=()")
		_, _ = w.Write([]byte("done"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{"url": srv.URL})
	out, err := httpProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "redirect: "+srv.URL+"/final") {
		t.Fatalf("output missing redirect step:\n%s", out)
	}
	if !strings.Contains(out, "(all present)") {
		t.Fatalf("output should report all security headers present:\n%s", out)
	}
}

func TestHTTPProbeRejectsBadScheme(t *testing.T) {
	args, _ := json.Marshal(map[string]any{"url": "ftp://example.com"})
	if _, err := (httpProbe{}).Execute(context.Background(), args); err == nil {
		t.Fatal("expected scheme rejection")
	}
}

func TestCookieAudit(t *testing.T) {
	if got := cookieAudit("id=1; Secure; HttpOnly; SameSite=Strict"); !strings.Contains(got, "(hardened)") {
		t.Fatalf("hardened cookie misclassified: %q", got)
	}
	got := cookieAudit("id=1")
	for _, flag := range []string{"no Secure flag", "no HttpOnly flag", "no SameSite"} {
		if !strings.Contains(got, flag) {
			t.Fatalf("cookie audit missing %q: %q", flag, got)
		}
	}
}
