package godevauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
)

const (
	cookieSessionToken = "session_token"
	cookieSessionData  = "session_data"
	cookieOAuthState   = "oauth_state"
)

// sessionTokenPurpose domain-separates the session cookie signature so
// a signature minted for another payload cannot be replayed as one.
const sessionTokenPurpose = "session-token"

func (a *Auth) cookieName(name string) string {
	prefix := a.config.Advanced.CookiePrefix
	if a.useSecureCookies() {
		return "__Secure-" + prefix + "." + name
	}
	return prefix + "." + name
}

func (a *Auth) useSecureCookies() bool {
	if a.config.Advanced.UseSecureCookies {
		return true
	}
	return strings.HasPrefix(a.config.BaseURL, "https://")
}

func (a *Auth) sameSite() http.SameSite {
	switch strings.ToLower(a.config.Advanced.SameSite) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func (a *Auth) newCookie(name, value string, maxAge int) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.useSecureCookies(),
		SameSite: a.sameSite(),
	}
	if maxAge > 0 {
		c.MaxAge = maxAge
		c.Expires = time.Now().Add(time.Duration(maxAge) * time.Second)
	} else if maxAge < 0 {
		c.MaxAge = -1
		c.Expires = time.Unix(0, 0)
	}
	if cs := a.config.Advanced.CrossSubDomainCookies; cs.Enabled && cs.Domain != "" {
		c.Domain = cs.Domain
	}
	return c
}

type signedValue struct {
	body string
	sig  string
}

// splitSigned splits "value.signature". Both halves are base64url
// (dot-free), so splitting at the last dot is unambiguous.
func splitSigned(signed string) (signedValue, bool) {
	idx := strings.LastIndex(signed, ".")
	if idx <= 0 || idx == len(signed)-1 {
		return signedValue{}, false
	}
	return signedValue{body: signed[:idx], sig: signed[idx+1:]}, true
}

// signCookieValue signs value as "value.signature".
func (a *Auth) signCookieValue(purpose, value string) string {
	return value + "." + crypto.SignHMACPurpose(a.config.Secret, purpose, value)
}

// verifyCookieValue splits and verifies a signed cookie value.
func (a *Auth) verifyCookieValue(purpose, signed string) (string, bool) {
	parts, ok := splitSigned(signed)
	if !ok {
		return "", false
	}
	if !crypto.VerifyHMACPurpose(a.config.Secret, purpose, parts.body, parts.sig) {
		return "", false
	}
	return parts.body, true
}

// setSessionCookie writes the signed session token cookie.
func (a *Auth) setSessionCookie(w http.ResponseWriter, token string, rememberMe bool) {
	maxAge := int(a.config.Session.ExpiresIn / time.Second)
	if !rememberMe {
		maxAge = 0 // session cookie
	}
	http.SetCookie(w, a.newCookie(a.cookieName(cookieSessionToken),
		a.signCookieValue(sessionTokenPurpose, token), maxAge))
}

// clearSessionCookie removes session cookies.
func (a *Auth) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, a.newCookie(a.cookieName(cookieSessionToken), "", -1))
	http.SetCookie(w, a.newCookie(a.cookieName(cookieSessionData), "", -1))
}

// SessionCookieName returns the full session token cookie name.
func (a *Auth) SessionCookieName() string {
	return a.cookieName(cookieSessionToken)
}

// SignToken signs a raw session token for cookie transport.
func (a *Auth) SignToken(token string) string {
	return a.signCookieValue(sessionTokenPurpose, token)
}

// VerifySignedToken verifies a signed session token and returns the raw
// token.
func (a *Auth) VerifySignedToken(signed string) (string, bool) {
	return a.verifyCookieValue(sessionTokenPurpose, signed)
}

// readSessionToken extracts and verifies the session token from the
// request cookie.
func (a *Auth) readSessionToken(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(a.cookieName(cookieSessionToken))
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return a.verifyCookieValue(sessionTokenPurpose, cookie.Value)
}

// setOAuthStateCookie binds an in-flight OAuth authorization request to
// this browser. Without it, an attacker who completes their own
// authorization at the provider can feed the resulting callback URL to
// a victim and silently sign them into the attacker's account.
// crossSitePost is true for providers that deliver the callback as a
// cross-site POST (response_mode=form_post; Sign in with Apple). A Lax
// cookie is not sent on a cross-site POST, so the state check would
// always fail; those flows need SameSite=None, which browsers only
// accept together with Secure — form_post providers require an https
// redirect URI anyway.
func (a *Auth) setOAuthStateCookie(w http.ResponseWriter, state string, crossSitePost bool) {
	c := a.newCookie(a.cookieName(cookieOAuthState), state, int(10*time.Minute/time.Second))
	switch {
	case crossSitePost && c.Secure:
		c.SameSite = http.SameSiteNoneMode
	case c.SameSite == http.SameSiteStrictMode:
		// The callback is a top-level cross-site redirect from the
		// provider, so the cookie must survive it.
		c.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, c)
}

func (a *Auth) readOAuthStateCookie(r *http.Request) string {
	cookie, err := r.Cookie(a.cookieName(cookieOAuthState))
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (a *Auth) clearOAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, a.newCookie(a.cookieName(cookieOAuthState), "", -1))
}
