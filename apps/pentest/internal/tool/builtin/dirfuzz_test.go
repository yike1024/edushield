package builtin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDirFuzzFindsSensitivePaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			_, _ = w.Write([]byte("ADMIN PANEL"))
		case "/.env":
			_, _ = w.Write([]byte("SECRET=1"))
		case "/robots.txt":
			http.Redirect(w, r, "/robots", http.StatusMovedPermanently)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}
	}))
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{"url": srv.URL, "wordlist": "admin,.env,robots.txt,nothing-here"})
	out, err := dirFuzz{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, want := range []string{"/admin\t200", "/.env\t200", "/robots.txt\t301"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "nothing-here") {
		t.Fatalf("not-found path leaked into results:\n%s", out)
	}
}

func TestDirFuzzSuppressesCatchAll200(t *testing.T) {
	// Catch-all returns 200 with a fixed body: calibration must suppress it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			_, _ = w.Write([]byte("REAL ADMIN - different length body 123456789"))
			return
		}
		_, _ = w.Write([]byte("spa shell"))
	}))
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{"url": srv.URL, "wordlist": "admin,login,test,backup"})
	out, err := dirFuzz{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "/admin\t200") {
		t.Fatalf("output missing the genuinely different path:\n%s", out)
	}
	if strings.Contains(out, "/login\t200") {
		t.Fatalf("catch-all response not suppressed:\n%s", out)
	}
}

func TestDirFuzzRejectsBadURL(t *testing.T) {
	args, _ := json.Marshal(map[string]any{"url": "not-a-url"})
	if _, err := (dirFuzz{}).Execute(context.Background(), args); err == nil {
		t.Fatal("expected URL rejection")
	}
}

func TestDirFuzzCustomWordlistValidation(t *testing.T) {
	args, _ := json.Marshal(map[string]any{"url": "http://127.0.0.1:1", "wordlist": " , \n"})
	if _, err := (dirFuzz{}).Execute(context.Background(), args); err == nil {
		t.Fatal("expected empty wordlist rejection")
	}
}

func TestSplitWordlist(t *testing.T) {
	got := splitWordlist("a, b\n\nc,,d")
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("splitWordlist = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitWordlist = %v", got)
		}
	}
}

func TestDirWordlistIsPopulated(t *testing.T) {
	if len(dirWordlist) < 100 {
		t.Fatalf("built-in wordlist shrank to %d entries", len(dirWordlist))
	}
}
