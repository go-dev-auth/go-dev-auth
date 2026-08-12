// Package bearer lets clients authenticate with the session token in an
// Authorization: Bearer header instead of a cookie — useful for mobile
// apps and non-browser clients. Port of better-auth's bearer plugin.
package bearer

import (
	"net/http"
	"strings"

	godevauth "github.com/go-dev-auth/go-dev-auth"
)

// Options configures the bearer plugin.
type Options struct {
	// RequireSignature only accepts signed tokens (value of the session
	// cookie) rather than raw session tokens.
	RequireSignature bool
}

// Plugin implements the bearer token plugin.
type Plugin struct {
	opts Options
	auth *godevauth.Auth
}

// New builds the plugin.
func New(opts ...Options) *Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	return &Plugin{opts: o}
}

// ID implements godevauth.Plugin.
func (p *Plugin) ID() string { return "bearer" }

// Init implements godevauth.Plugin.
func (p *Plugin) Init(a *godevauth.Auth) error {
	p.auth = a
	return nil
}

// Routes implements godevauth.Plugin.
func (p *Plugin) Routes() []godevauth.Route { return nil }

// Middleware converts an Authorization: Bearer token into the session
// cookie so downstream handlers authenticate normally. It also exposes
// the freshly created session token in the `set-auth-token` response
// header for sign-in style endpoints.
func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		// Only fall back to the header when there is no session cookie
		// to use. Checking the raw Cookie header would let an unrelated
		// cookie (analytics, CSRF) silently disable bearer auth.
		_, cookieErr := r.Cookie(p.auth.SessionCookieName())
		noSessionCookie := cookieErr != nil
		if authz != "" && noSessionCookie {
			token, ok := strings.CutPrefix(authz, "Bearer ")
			if ok && token != "" {
				cookieValue := p.toCookieValue(token)
				if cookieValue != "" {
					r.AddCookie(&http.Cookie{
						Name:  p.auth.SessionCookieName(),
						Value: cookieValue,
					})
				}
			}
		}
		next.ServeHTTP(&tokenHeaderWriter{ResponseWriter: w, auth: p.auth}, r)
	})
}

// toCookieValue normalizes a bearer token to a signed cookie value.
func (p *Plugin) toCookieValue(token string) string {
	// already signed? (contains a signature suffix that verifies)
	if raw, ok := p.auth.VerifySignedToken(token); ok {
		_ = raw
		return token
	}
	if p.opts.RequireSignature {
		return ""
	}
	return p.auth.SignToken(token)
}

// tokenHeaderWriter mirrors the session cookie into a `set-auth-token`
// header so non-browser clients can capture it.
type tokenHeaderWriter struct {
	http.ResponseWriter
	auth        *godevauth.Auth
	wroteHeader bool
}

func (w *tokenHeaderWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		for _, sc := range w.Header().Values("Set-Cookie") {
			if strings.HasPrefix(sc, w.auth.SessionCookieName()+"=") {
				value := strings.TrimPrefix(sc, w.auth.SessionCookieName()+"=")
				if i := strings.Index(value, ";"); i >= 0 {
					value = value[:i]
				}
				if value != "" {
					w.Header().Set("set-auth-token", value)
				}
			}
		}
	}
	w.ResponseWriter.WriteHeader(status)
}
