package godevauth

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Cross-origin policy lives in one file on purpose.
//
// CORS and CSRF look like separate features but they are two halves of a
// single decision: which origins may drive a cookie-authenticated
// request. Splitting them invites the two lists to drift apart, and a
// CORS allowance that the CSRF check does not honour (or the reverse) is
// exactly the gap an attacker looks for. Both read Config.TrustedOrigins
// through isTrustedOrigin below.

// isTrustedOrigin reports whether origin (scheme://host[:port]) is
// trusted. Supports leading "*." wildcards in configured origins.
func (a *Auth) isTrustedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	base, err := url.Parse(a.config.BaseURL)
	if err == nil && base.Host != "" {
		if sameOrigin(origin, base.Scheme+"://"+base.Host) {
			return true
		}
	}
	o, err := url.Parse(origin)
	if err != nil {
		return false
	}
	for _, trusted := range a.config.TrustedOrigins {
		trusted = strings.TrimSuffix(trusted, "/")
		if sameOrigin(origin, trusted) {
			return true
		}
		// wildcard subdomain match: https://*.example.com or *.example.com
		if strings.Contains(trusted, "*") {
			pattern := trusted
			scheme := ""
			if i := strings.Index(pattern, "://"); i >= 0 {
				scheme = pattern[:i]
				pattern = pattern[i+3:]
			}
			if scheme != "" && scheme != o.Scheme {
				continue
			}
			if strings.HasPrefix(pattern, "*.") {
				suffix := pattern[1:] // ".example.com"
				// The "*" must stand for at least one character. Without
				// the length check the host ".example.com" — a suffix
				// with nothing in front of it — matches its own
				// wildcard, which is not a subdomain of anything.
				// FuzzIsTrustedOrigin found this.
				if len(o.Host) > len(suffix) && strings.HasSuffix(o.Host, suffix) {
					return true
				}
			}
		}
	}
	return false
}

func sameOrigin(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "/"), strings.TrimSuffix(b, "/"))
}

// isSameSiteRequest reports whether Sec-Fetch-Site marks the request as
// same-origin/same-site or as a direct navigation. Browsers set this
// header themselves and it cannot be forged from script.
func isSameSiteRequest(r *http.Request) (known bool, sameSite bool) {
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "":
		return false, false
	case "same-origin", "same-site", "none":
		return true, true
	default:
		return true, false
	}
}

// checkOrigin blocks state-changing cookie-authenticated requests from
// untrusted origins.
func (a *Auth) checkOrigin(r *http.Request, path string) error {
	if a.config.Advanced.DisableCSRFCheck {
		return nil
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return nil
	}
	for _, p := range a.config.Advanced.DisableOriginCheckForPaths {
		if p == path {
			return nil
		}
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, err := url.Parse(ref); err == nil && u.Host != "" {
				origin = u.Scheme + "://" + u.Host
			}
		}
	}
	if origin != "" {
		if a.isTrustedOrigin(origin) {
			return nil
		}
		return ErrInvalidOrigin
	}

	// No Origin and no Referer. Modern browsers still label the request
	// via Sec-Fetch-Site, so use it when present: a cross-site form POST
	// is rejected even though it carries no Origin.
	if known, sameSite := isSameSiteRequest(r); known {
		if sameSite {
			return nil
		}
		return ErrInvalidOrigin
	}

	// Header-less client (curl, a mobile app, a server-to-server call).
	// A browser cannot be silently coerced into sending no Origin, no
	// Referer and no Sec-Fetch-Site, so if the request also carries no
	// session cookie there is nothing to forge with.
	if _, err := r.Cookie(a.SessionCookieName()); err != nil {
		return nil
	}
	// A cookie-authenticated request from a client that identifies
	// itself as a browser but sent no origin information is not
	// something to trust silently.
	if ua := r.Header.Get("User-Agent"); strings.HasPrefix(ua, "Mozilla/") {
		return ErrInvalidOrigin
	}
	return nil
}

// CORS wraps the auth handler with the headers a browser needs when the
// frontend is served from a different origin than the API.
//
// Credentialed cross-origin requests are what make this necessary: the
// session cookie is only sent when the response echoes the exact origin
// and sets Access-Control-Allow-Credentials. Wildcards are therefore not
// permitted by browsers here, so the allowed origins are taken from
// Config.TrustedOrigins (plus BaseURL) — the same list checkOrigin uses.
//
//	mux.Handle("/api/auth/", auth.CORS(auth.Handler()))
//
// Remember that cross-origin cookies also require
// Advanced.SameSite = "none" and an https BaseURL.
func (a *Auth) CORS(next http.Handler) http.Handler {
	const maxAge = 12 * time.Hour
	allowedHeaders := "Content-Type, Authorization, x-api-key"
	allowedMethods := "GET, POST, OPTIONS"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		// Vary is required so a shared cache cannot serve one origin's
		// response to another.
		w.Header().Add("Vary", "Origin")
		if !a.isTrustedOrigin(origin) {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Access-Control-Expose-Headers", "set-auth-token, set-auth-jwt")

		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", allowedMethods)
			if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
				h.Set("Access-Control-Allow-Headers", req)
			} else {
				h.Set("Access-Control-Allow-Headers", allowedHeaders)
			}
			h.Set("Access-Control-Max-Age", strconv.Itoa(int(maxAge/time.Second)))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
