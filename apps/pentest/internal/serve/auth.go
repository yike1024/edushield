package serve

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"reasonix/internal/config"
)

// authMode represents the authentication mode for the serve API.
type authMode int

const (
	authInvalid authMode = iota // invalid config; deny all requests
	authNone                    // no authentication (default, backward-compatible)
	authToken                   // pre-shared token in URL or cookie
)

const (
	cookieToken     = "reasonix_token"    // holds the token for token mode
	tokenByteLen    = 32                  // 256-bit random token
	sessionDuration = 30 * 24 * time.Hour // how long an issued token cookie lasts
)

// NormalizeAuthMode normalizes and validates the serve auth mode.
func NormalizeAuthMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "none"
	}
	switch mode {
	case "none", "token":
		return mode, nil
	default:
		return "", fmt.Errorf("auth mode must be none or token, got %q", mode)
	}
}

// authGate is the authentication middleware and its runtime state.
type authGate struct {
	mode        authMode
	token       string // pre-shared token (token mode)
	behindProxy bool   // trust X-Forwarded-For / X-Forwarded-Proto headers
}

// newAuthGate creates the auth middleware from the serve config. For token mode
// without a configured token, it generates a random one.
func newAuthGate(cfg config.ServeConfig) *authGate {
	ag := &authGate{
		behindProxy: cfg.BehindProxy,
	}
	mode, err := NormalizeAuthMode(cfg.AuthMode)
	if err != nil {
		ag.mode = authInvalid
		return ag
	}
	switch mode {
	case "token":
		ag.mode = authToken
		ag.token = strings.TrimSpace(cfg.Token)
		if ag.token == "" {
			ag.token = generateToken()
		}
	default:
		ag.mode = authNone
	}
	return ag
}

// Token returns the shared token (empty if not in token mode).
func (ag *authGate) Token() string { return ag.token }

// Mode returns the auth mode name as a string.
func (ag *authGate) Mode() string {
	switch ag.mode {
	case authToken:
		return "token"
	case authInvalid:
		return "invalid"
	default:
		return "none"
	}
}

// middleware returns an http.Handler that wraps next with authentication checks.
// Unauthenticated requests receive a 401; there is no browser login surface.
func (ag *authGate) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ag.mode == authInvalid {
			ag.deny(w, r)
			return
		}
		if ag.mode == authNone {
			next.ServeHTTP(w, r)
			return
		}
		// token mode
		if r.URL.Path == "/auth/token" {
			ag.handleTokenBootstrap(w, r)
			return
		}
		// Let the inert shell trade its URL fragment for an HttpOnly cookie
		// before API or SSE calls; query-token links use the legacy path below.
		if r.URL.Query().Get("token") == "" && tokenBootstrapPublicPath(r) {
			next.ServeHTTP(w, r)
			return
		}
		ag.checkToken(w, r, next)
	})
}

func tokenBootstrapPublicPath(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.URL.Path == "/" {
		return true
	}
	// Only one non-empty session segment is an inert shell entry point; this
	// prevents API-like paths from becoming public in token mode.
	const prefix = "/sessions/"
	id := strings.TrimPrefix(r.URL.Path, prefix)
	return id != r.URL.Path && id != "" && !strings.Contains(id, "/")
}

// handleTokenBootstrap validates a token delivered from the URL fragment by
// the Web shell. The token travels in a bounded JSON body rather than the URL,
// keeping it out of request lines, access logs, browser history, and referrers.
func (ag *authGate) handleTokenBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	contentType := r.Header.Get("Content-Type")
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	if !strings.EqualFold(strings.TrimSpace(contentType), "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var body struct {
		Token string `json:"token"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Token), []byte(ag.token)) != 1 {
		ag.deny(w, r)
		return
	}
	ag.setAuthCookie(w, r, &http.Cookie{
		Name:     cookieToken,
		Value:    ag.token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// checkToken validates the token from a cookie or the legacy query parameter.
// New links use a URL fragment and handleTokenBootstrap; query links remain
// supported so previously shared URLs keep working.
func (ag *authGate) checkToken(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// 1. Check cookie first (fast path).
	if c, err := r.Cookie(cookieToken); err == nil && strings.TrimSpace(c.Value) != "" {
		if subtle.ConstantTimeCompare([]byte(c.Value), []byte(ag.token)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
	}

	// 2. Check query parameter.
	if q := r.URL.Query().Get("token"); q != "" {
		if subtle.ConstantTimeCompare([]byte(q), []byte(ag.token)) == 1 {
			// Set a persistent cookie so future requests (including SSE) are
			// authenticated without the token in the URL.
			ag.setAuthCookie(w, r, &http.Cookie{
				Name:     cookieToken,
				Value:    ag.token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(sessionDuration.Seconds()),
			})
			// Redirect to the same path without the token query parameter.
			cleanURL := *r.URL
			qry := cleanURL.Query()
			qry.Del("token")
			cleanURL.RawQuery = qry.Encode()
			if cleanURL.RawQuery == "" {
				cleanURL.RawQuery = ""
			}
			redirectToSafeTarget(w, r, cleanURL.RequestURI(), http.StatusFound)
			return
		}
	}

	// 3. Not authenticated.
	ag.deny(w, r)
}

// deny sends a 401 response. The message is intentionally generic to avoid
// leaking information about which auth mode is active.
func (ag *authGate) deny(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("Unauthorized\n"))
}

func (ag *authGate) setAuthCookie(w http.ResponseWriter, r *http.Request, c *http.Cookie) {
	c.Secure = ag.authCookieSecure(r)
	// codeql[go/cookie-secure-not-set] Secure cookies are only sent back over HTTPS; plain-HTTP serve must keep token auth usable.
	http.SetCookie(w, c)
}

func (ag *authGate) authCookieSecure(r *http.Request) bool {
	return ag.isTLS(r)
}

func safeRedirectTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\\", "/")
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" {
		return "/"
	}
	if raw != "/" && (len(raw) <= 1 || raw[0] != '/' || raw[1] == '/' || raw[1] == '\\') {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.IsAbs() || u.Hostname() != "" {
		return "/"
	}
	path := strings.ReplaceAll(u.Path, "\\", "/")
	if path == "" {
		return "/"
	}
	if path != "/" && (len(path) <= 1 || path[0] != '/' || path[1] == '/' || path[1] == '\\') {
		return "/"
	}
	return u.RequestURI()
}

func redirectToSafeTarget(w http.ResponseWriter, r *http.Request, raw string, status int) {
	target := safeRedirectTarget(raw)
	target = strings.ReplaceAll(target, "\\", "/")
	u, err := url.Parse(target)
	if err == nil && u != nil && !u.IsAbs() && u.Hostname() == "" {
		redirect := u.RequestURI()
		if redirect == "/" {
			http.Redirect(w, r, "/", status)
			return
		}
		if len(redirect) > 1 && redirect[0] == '/' && redirect[1] != '/' && redirect[1] != '\\' {
			http.Redirect(w, r, redirect, status)
			return
		}
	}
	http.Redirect(w, r, "/", status)
}

// generateToken returns a cryptographically random URL-safe token.
func generateToken() string {
	b := make([]byte, tokenByteLen)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failure is fatal for token generation.
		panic("serve/auth: crypto/rand.Read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// isTLS reports whether the request arrived over TLS. It trusts
// X-Forwarded-Proto only when behindProxy is true.
func (ag *authGate) isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if ag.behindProxy {
		return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
	return false
}

func isLoopbackHost(hostport string) bool {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return false
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PlainHTTPAuthWarning reports whether serve is exposing authenticated access
// over a non-loopback plain-HTTP listener. The listener may still be valid for a
// trusted LAN or reverse-proxy setup, but users should see the risk explicitly.
func PlainHTTPAuthWarning(cfg config.ServeConfig, addr string) string {
	mode, err := NormalizeAuthMode(cfg.AuthMode)
	if err != nil || mode == "none" || isLoopbackHost(addr) {
		return ""
	}
	return "warning: authenticated serve is listening on non-loopback HTTP; use HTTPS via a trusted reverse proxy or bind to 127.0.0.1 for local-only access"
}
