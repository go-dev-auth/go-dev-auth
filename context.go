package godevauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Ctx carries a single auth API request through hooks and handlers.
type Ctx struct {
	W    http.ResponseWriter
	R    *http.Request
	Auth *Auth

	// Path is the matched route path (relative to BasePath).
	Path string
	// Params holds path parameters, e.g. Params["provider"].
	Params map[string]string

	// pattern is the route pattern that matched, e.g.
	// "/reset-password/:token". Unlike Path it contains no parameter
	// values, which is what makes it safe to use as a rate-limit key
	// and to record in audit events.
	pattern string
	// authMethod labels how the subject of this request authenticated
	// ("credential", "magic-link", a provider id). Sign-in flows set it
	// before calling SignInUser so the audit trail can tell them apart.
	authMethod string

	written    bool
	status     int
	session    *SessionData
	sessionSet bool
	body       []byte
	bodyRead   bool
}

// SessionData bundles a session with its user, as returned by
// /get-session.
type SessionData struct {
	Session *storage.Session `json:"session"`
	User    *storage.User    `json:"user"`

	// fromCache marks data served from the signed cookie cache rather
	// than the database. It prevents the cache from being refreshed
	// from itself, which would let a client defer revocation forever.
	fromCache bool
}

// FromCache reports whether this session was served from the signed
// cookie cache instead of the database.
func (sd *SessionData) FromCache() bool { return sd.fromCache }

// Context returns the request context.
func (c *Ctx) Context() context.Context { return c.R.Context() }

// NewCtx builds a Ctx for the given request/response pair. It is useful
// when calling handler-style helpers (session creation, plugin methods)
// from your own routes, and in tests.
func (a *Auth) NewCtx(w http.ResponseWriter, r *http.Request) *Ctx {
	return &Ctx{W: w, R: r, Auth: a, Path: r.URL.Path}
}

// Written reports whether a response has been written.
func (c *Ctx) Written() bool { return c.written }

// RoutePattern returns the pattern of the matched route, with parameter
// placeholders left in place ("/reset-password/:token"). Use it wherever
// a path is grouped or recorded — rate-limit keys, metrics, audit
// events — because the resolved path can contain a credential.
func (c *Ctx) RoutePattern() string {
	if c.pattern != "" {
		return c.pattern
	}
	return c.Path
}

// AuthMethod returns how the subject of this request authenticated, as
// set by the sign-in flow ("credential", "magic-link", a social
// provider id). It is empty outside a sign-in.
func (c *Ctx) AuthMethod() string { return c.authMethod }

// SetAuthMethod labels the authentication method for this request.
// Sign-in flows, including those in plugins, call it before creating a
// session so the audit trail records how the user got in.
func (c *Ctx) SetAuthMethod(method string) { c.authMethod = method }

// markWritten records that the handler wrote the response itself (for
// non-JSON bodies) and sends the status code.
func (c *Ctx) markWritten(status int) {
	c.written = true
	c.status = status
	c.W.WriteHeader(status)
}

// Status returns the response status code written so far (0 if none).
func (c *Ctx) Status() int { return c.status }

// JSON writes a JSON response.
//
// A nil value is written as the JSON literal null, not as an empty body.
// The two are not interchangeable to a client: a response that declares
// application/json and then carries zero bytes makes JSON.parse (and
// res.json() in every browser) throw, so "there is no session" arrived
// as a parse error rather than as a value. /get-session is the endpoint
// that does this on every signed-out request.
func (c *Ctx) JSON(status int, v any) error {
	c.written = true
	c.status = status
	c.W.Header().Set("Content-Type", "application/json; charset=utf-8")
	c.W.WriteHeader(status)
	return json.NewEncoder(c.W).Encode(v)
}

// OK writes {"status": true}.
func (c *Ctx) OK() error {
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

// Error writes an error response.
func (c *Ctx) Error(err error) error {
	apiErr := AsAPIError(err)
	if apiErr.Status >= 500 {
		// Log the route pattern, never the resolved path: a 5xx on
		// /reset-password/:token would otherwise write the one-time
		// token straight into the error log.
		c.Auth.logger.Error("go-dev-auth: internal error", "route", c.RoutePattern(), "err", err)
	}
	return c.JSON(apiErr.Status, apiErr)
}

// Redirect sends an HTTP redirect.
func (c *Ctx) Redirect(to string) error {
	c.written = true
	c.status = http.StatusFound
	http.Redirect(c.W, c.R, to, http.StatusFound)
	return nil
}

// BindJSON decodes the request body into v. The body may be read multiple
// times across hooks and handlers.
func (c *Ctx) BindJSON(v any) error {
	raw, err := c.RawBody()
	if err != nil {
		return ErrInvalidBody
	}
	if len(raw) == 0 {
		return ErrInvalidBody
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return ErrInvalidBody
	}
	return nil
}

// BindJSONOptional decodes the body when present; empty bodies are okay.
func (c *Ctx) BindJSONOptional(v any) error {
	raw, err := c.RawBody()
	if err != nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return ErrInvalidBody
	}
	return nil
}

// RawBody returns the request body, caching it for repeated reads.
func (c *Ctx) RawBody() ([]byte, error) {
	if c.bodyRead {
		return c.body, nil
	}
	c.bodyRead = true
	if c.R.Body == nil {
		return nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(c.R.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	c.body = raw
	return raw, nil
}

// Query returns a query string parameter.
func (c *Ctx) Query(name string) string {
	return c.R.URL.Query().Get(name)
}

// Param returns a path parameter.
func (c *Ctx) Param(name string) string {
	if c.Params == nil {
		return ""
	}
	return c.Params[name]
}

// BaseURL returns the configured external base URL joined with BasePath,
// e.g. "https://example.com/api/auth".
func (c *Ctx) BaseURL() string {
	return strings.TrimSuffix(c.Auth.config.BaseURL, "/") + c.Auth.config.BasePath
}

// forwardedHeaders are the headers a proxy uses to report the original
// client. They are only read from a trusted peer.
var forwardedHeaders = []string{"X-Forwarded-For", "X-Real-IP"}

// ClientIP resolves the client IP address.
//
// It is the rate limiter's bucket key and the address recorded on every
// session, so getting it wrong is not cosmetic: one shared value turns
// a per-client limit into a global one, and a client-controlled value
// turns it into no limit at all.
//
// The peer address is used unless forwarded headers are both enabled
// (Advanced.TrustProxyHeaders or IPAddressHeaders) and arriving from a
// peer in Advanced.TrustedProxies. The header chain is then walked from
// the right, skipping trusted hops, so entries a client prepended are
// never mistaken for the client.
func (c *Ctx) ClientIP() string {
	cfg := &c.Auth.config.Advanced
	peer := peerHost(c.R.RemoteAddr)

	if !cfg.TrustProxyHeaders && len(cfg.IPAddressHeaders) == 0 {
		// Not configured for a proxy. If the traffic says otherwise,
		// say so — loudly and once. Every client behind that proxy is
		// currently sharing one rate-limit bucket.
		c.Auth.reportUnexpectedForwardedHeaders(c.R)
		return peer
	}

	peerIP := net.ParseIP(peer)
	if !c.Auth.trustedProxies.contains(peerIP) {
		// Configured for a proxy, but this request did not come
		// through one. Honouring its headers would be the footgun.
		c.Auth.reportUntrustedProxyPeer(c.R, peer)
		return peer
	}

	headers := cfg.IPAddressHeaders
	if len(headers) == 0 {
		headers = forwardedHeaders
	}
	for _, h := range headers {
		values := c.R.Header.Values(h)
		if len(values) == 0 {
			continue
		}
		if ip := c.Auth.clientFromForwarded(values); ip != "" {
			return ip
		}
	}
	return peer
}

// clientFromForwarded picks the client out of a forwarded-header chain.
//
// The chain reads left to right as client, proxy1, proxy2, ...; each
// hop appends the peer it saw. Only the entries appended by our own
// proxies are trustworthy, so we walk from the right and stop at the
// first address that is not one of them. Anything further left was
// supplied by the client and is ignored.
func (a *Auth) clientFromForwarded(values []string) string {
	var chain []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				chain = append(chain, part)
			}
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		host := strings.Trim(chain[i], "[]")
		if h, _, err := net.SplitHostPort(chain[i]); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if ip == nil {
			// An unparseable hop cannot be verified as one of ours, so
			// treat it as the (untrusted) client rather than skipping
			// past it.
			return host
		}
		if a.trustedProxies.contains(ip) {
			continue
		}
		return ip.String()
	}
	// Every hop is one of our own proxies; the leftmost is the closest
	// thing to a client this chain describes.
	if len(chain) > 0 {
		return strings.TrimSpace(chain[0])
	}
	return ""
}

// peerHost strips the port from a RemoteAddr.
func peerHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// reportUnexpectedForwardedHeaders warns, once per instance, that
// requests arrive with proxy headers that are being ignored.
//
// This is the outage-shaped misconfiguration: behind a load balancer
// with the default settings, every request resolves to the balancer's
// address, so the documented "3 sign-ins per 10 seconds per IP" becomes
// three sign-ins per 10 seconds for the entire fleet — and the limiter
// fails closed.
func (a *Auth) reportUnexpectedForwardedHeaders(r *http.Request) {
	if a.proxyWarned.Load() {
		return
	}
	var seen string
	for _, h := range append([]string{"Forwarded", "CF-Connecting-IP", "True-Client-IP"}, forwardedHeaders...) {
		if r.Header.Get(h) != "" {
			seen = h
			break
		}
	}
	if seen == "" {
		return
	}
	if a.proxyWarned.Swap(true) {
		return
	}
	a.logger.Error("go-dev-auth: requests carry the "+seen+" header but forwarded headers are not trusted, "+
		"so every client resolves to the proxy's address: rate limits apply to the whole fleet at once and "+
		"sessions record the proxy's IP. Set Advanced.TrustProxyHeaders together with Advanced.TrustedProxies "+
		"listing the proxy's addresses or CIDRs.", "header", seen, "peer", peerHost(r.RemoteAddr))
}

// reportUntrustedProxyPeer warns, once per instance, that forwarded
// headers are enabled but requests are arriving directly.
func (a *Auth) reportUntrustedProxyPeer(r *http.Request, peer string) {
	if r.Header.Get("X-Forwarded-For") == "" && r.Header.Get("X-Real-IP") == "" {
		return
	}
	if a.proxyWarned.Load() || a.proxyWarned.Swap(true) {
		return
	}
	a.logger.Error("go-dev-auth: a request carrying forwarded headers arrived from a peer that is not in "+
		"Advanced.TrustedProxies; its headers were ignored and the peer address was used. Either the service "+
		"is reachable without going through the proxy, or TrustedProxies is missing the proxy's address.",
		"peer", peer)
}

// UserAgent returns the client user agent.
func (c *Ctx) UserAgent() string { return c.R.UserAgent() }

// Session returns the authenticated session, or nil.
func (c *Ctx) Session() (*SessionData, error) {
	if c.sessionSet {
		return c.session, nil
	}
	sd, err := c.Auth.GetSession(c.R)
	if err != nil && !errors.Is(err, ErrNoSession) {
		return nil, err
	}
	c.session = sd
	c.sessionSet = true
	return sd, nil
}

// SetSession overrides the session for the rest of the request (used by
// bearer/api-key style plugins).
func (c *Ctx) SetSession(sd *SessionData) {
	c.session = sd
	c.sessionSet = true
}

// RequireSession returns the session or an ErrUnauthorized error.
func (c *Ctx) RequireSession() (*SessionData, error) {
	sd, err := c.Session()
	if err != nil {
		return nil, err
	}
	if sd == nil {
		return nil, ErrUnauthorized
	}
	return sd, nil
}

// redirectOrJSON redirects when the client supplied a callback URL,
// otherwise responds with JSON.
func (c *Ctx) redirectOrJSON(callbackURL string, status int, v any) error {
	if callbackURL != "" {
		if to, ok := c.Auth.safeRedirect(callbackURL); ok {
			return c.Redirect(to)
		}
	}
	return c.JSON(status, v)
}

// SafeRedirect validates a redirect target: relative URLs are resolved
// against BaseURL and absolute URLs must have a trusted origin. It
// returns the absolute URL and whether it is safe to redirect to.
func (a *Auth) SafeRedirect(raw string) (string, bool) {
	return a.safeRedirect(raw)
}

// isTrustedURL reports whether raw is a relative URL or has a trusted
// origin.
func (a *Auth) safeRedirect(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return strings.TrimSuffix(a.config.BaseURL, "/") + raw, true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	origin := u.Scheme + "://" + u.Host
	if a.isTrustedOrigin(origin) {
		return raw, true
	}
	return "", false
}
