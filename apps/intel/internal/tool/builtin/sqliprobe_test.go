package builtin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sqliTarget models a page whose id parameter is injectable in one of the
// three classic shapes, selected by the handler.
func sqliTarget(t *testing.T, kind string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if q := r.URL.Query().Get("q"); q != "" {
			v = q
		}
		switch kind {
		case "error":
			if v == "'" {
				_, _ = w.Write([]byte("You have an error in your SQL syntax near '\\'' at line 1"))
				return
			}
			_, _ = w.Write([]byte("product page"))
		case "boolean":
			switch v {
			case "rxbaseline", "' OR '1'='1":
				_, _ = w.Write([]byte("user profile: alice"))
			case "' OR '1'='2":
				_, _ = w.Write([]byte("no results"))
			default:
				_, _ = w.Write([]byte("user profile: alice"))
			}
		case "time":
			if strings.Contains(v, "SLEEP") {
				time.Sleep(2200 * time.Millisecond)
			}
			_, _ = w.Write([]byte("ok"))
		case "clean":
			_, _ = w.Write([]byte("static content"))
		}
	}))
}

func TestSQLiProbeDetectsErrorBased(t *testing.T) {
	srv := sqliTarget(t, "error")
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/item", "param": "id"})
	out, err := sqliProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "FINDING error-based") {
		t.Fatalf("output missing error finding:\n%s", out)
	}
	if !strings.Contains(out, "LIKELY INJECTABLE") {
		t.Fatalf("output missing verdict:\n%s", out)
	}
}

func TestSQLiProbeDetectsBooleanBased(t *testing.T) {
	srv := sqliTarget(t, "boolean")
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{"url": srv.URL + "/profile", "param": "id"})
	out, err := sqliProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "FINDING boolean-based") {
		t.Fatalf("output missing boolean finding:\n%s", out)
	}
}

func TestSQLiProbeDetectsTimeBased(t *testing.T) {
	srv := sqliTarget(t, "time")
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{
		"url": srv.URL + "/search", "param": "q", "time_delay_s": 2,
	})
	out, err := sqliProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "FINDING time-based") {
		t.Fatalf("output missing time finding:\n%s", out)
	}
}

func TestSQLiProbeCleanTargetReportsNoInjection(t *testing.T) {
	srv := sqliTarget(t, "clean")
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{"url": srv.URL, "param": "id"})
	out, err := sqliProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "no injection differential detected") {
		t.Fatalf("output missing clean verdict:\n%s", out)
	}
}

func TestSQLiProbePayloadModeSendsNothing(t *testing.T) {
	// An unreachable URL proves payload_mode makes zero requests.
	args, _ := json.Marshal(map[string]any{
		"url": "http://127.0.0.1:1/", "param": "id", "payload_mode": true,
	})
	out, err := sqliProbe{}.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, want := range []string{"-- error --", "-- boolean --", "-- waf-bypass --", "SLEEP"} {
		if !strings.Contains(out, want) {
			t.Fatalf("payload dictionary missing %q:\n%s", want, out)
		}
	}
}

func TestSQLiProbePOSTWithFormBody(t *testing.T) {
	var sawBody bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil && r.PostForm.Get("user") == "rxbaseline" && r.PostForm.Get("pass") == "x" {
			sawBody = true
		}
		_, _ = w.Write([]byte("static"))
	}))
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{
		"url": srv.URL, "param": "user", "method": "POST", "data": "user=a&pass=x",
	})
	if _, err := (sqliProbe{}).Execute(context.Background(), args); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !sawBody {
		t.Fatal("POST probe did not carry the form template with the replaced parameter")
	}
}

func TestSQLiProbeRequiresArgs(t *testing.T) {
	if _, err := (sqliProbe{}).Execute(context.Background(), json.RawMessage(`{"url":"http://x"}`)); err == nil {
		t.Fatal("expected error for missing param")
	}
}

func TestReplaceFormValue(t *testing.T) {
	got := replaceFormValue("user=old&pass=x", "user", "new value")
	if !strings.Contains(got, "user=new+value") || !strings.Contains(got, "pass=x") {
		t.Fatalf("replaceFormValue = %q", got)
	}
}

func TestLengthClose(t *testing.T) {
	if !lengthClose(100, 105) {
		t.Fatal("close lengths should match")
	}
	if lengthClose(100, 400) {
		t.Fatal("distant lengths should differ")
	}
}
