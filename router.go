package godevauth

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-dev-auth/go-dev-auth/ratelimit"
)

// This file is the HTTP front door. It answers the two questions a
// contributor arrives with — "what endpoints exist?" and "what happens
// to a request before it reaches a handler?" — in that order: the Route
// type, then the built-in route table, then indexing, matching and the
// per-request pipeline (origin check, rate limit, hooks, handler).
//
// The handlers themselves live in handler_*.go; the Auth lifecycle that
// assembles all of this lives in auth.go.

// Route is an HTTP endpoint exposed under the auth base path. Plugins
// return these from Plugin.Routes to add endpoints of their own.
type Route struct {
	// Method is "GET", "POST", etc., or "*" for any.
	Method string
	// Path is relative to BasePath, e.g. "/sign-in/email". A single
	// ":param" segment is supported, e.g. "/callback/:provider".
	Path string
	// Handler handles the request.
	Handler func(c *Ctx) error
	// RateLimit overrides the default rate limit rule for this path.
	RateLimit *ratelimit.Rule
	// SkipOriginCheck exempts this route from the CSRF origin check.
	// Reserve it for endpoints that are legitimately driven cross-site
	// by a third party AND authenticate the request some other way —
	// the OAuth callback (state cookie + PKCE) is the canonical case,
	// where form_post providers like Apple deliver the callback as a
	// cross-site POST that no origin policy can allow. A route that
	// relies on the session cookie alone must never set this.
	SkipOriginCheck bool
}

// coreRoutes is the built-in endpoint table: every URL this library
// serves without any plugin installed. Endpoints that an attacker would
// otherwise use as an online guessing oracle carry a tighter rate limit
// than the global default.
func (a *Auth) coreRoutes() []Route {
	strict := &ratelimit.Rule{Window: 10 * time.Second, Max: 3}
	moderate := &ratelimit.Rule{Window: 10 * time.Second, Max: 5}

	routes := []Route{
		{Method: http.MethodGet, Path: "/ok", Handler: func(c *Ctx) error {
			return c.JSON(http.StatusOK, map[string]any{"ok": true})
		}},
		{Method: http.MethodGet, Path: "/error", Handler: func(c *Ctx) error {
			c.W.Header().Set("Content-Type", "text/html; charset=utf-8")
			c.markWritten(http.StatusOK)
			_, _ = c.W.Write([]byte(errorPageHTML))
			return nil
		}},

		// session
		{Method: http.MethodGet, Path: "/get-session", Handler: a.handleGetSession},
		{Method: http.MethodPost, Path: "/sign-out", Handler: a.handleSignOut},
		{Method: http.MethodGet, Path: "/list-sessions", Handler: a.handleListSessions},
		{Method: http.MethodPost, Path: "/revoke-session", Handler: a.handleRevokeSession},
		{Method: http.MethodPost, Path: "/revoke-sessions", Handler: a.handleRevokeSessions},
		{Method: http.MethodPost, Path: "/revoke-other-sessions", Handler: a.handleRevokeOtherSessions},

		// social
		{Method: http.MethodPost, Path: "/sign-in/social", Handler: a.handleSignInSocial, RateLimit: moderate},
		{Method: http.MethodPost, Path: "/id-token/nonce", Handler: a.handleIDTokenNonce, RateLimit: moderate},
		// The callback is driven by the provider, not the application:
		// Apple (response_mode=form_post) delivers it as a cross-site
		// POST from appleid.apple.com, which an origin check can only
		// reject. The flow is protected by the single-use state (bound
		// to this browser via the state cookie) and PKCE instead.
		{Method: "*", Path: "/callback/:provider", Handler: a.handleOAuthCallback, SkipOriginCheck: true},
		{Method: http.MethodPost, Path: "/link-social", Handler: a.handleLinkSocial},
		{Method: http.MethodPost, Path: "/unlink-account", Handler: a.handleUnlinkAccount},
		{Method: http.MethodGet, Path: "/list-accounts", Handler: a.handleListAccounts},
		{Method: http.MethodPost, Path: "/refresh-token", Handler: a.handleRefreshToken},
		{Method: http.MethodGet, Path: "/account-info", Handler: a.handleAccountInfo},

		// user
		{Method: http.MethodPost, Path: "/update-user", Handler: a.handleUpdateUser},
	}

	if a.config.EmailAndPassword.Enabled {
		routes = append(routes,
			Route{Method: http.MethodPost, Path: "/sign-up/email", Handler: a.handleSignUpEmail, RateLimit: strict},
			Route{Method: http.MethodPost, Path: "/sign-in/email", Handler: a.handleSignInEmail, RateLimit: strict},
			Route{Method: http.MethodPost, Path: "/forget-password", Handler: a.handleForgetPassword, RateLimit: strict},
			Route{Method: http.MethodPost, Path: "/request-password-reset", Handler: a.handleForgetPassword, RateLimit: strict},
			Route{Method: http.MethodPost, Path: "/reset-password", Handler: a.handleResetPassword, RateLimit: strict},
			// The redirect endpoint validates the emailed token, so it
			// answers "is this token real?" and needs a limit of its
			// own. It only became limitable once the bucket key used
			// the route pattern instead of the resolved path.
			Route{Method: http.MethodGet, Path: "/reset-password/:token", Handler: a.handleResetPasswordRedirect, RateLimit: moderate},
			Route{Method: http.MethodPost, Path: "/change-password", Handler: a.handleChangePassword},
			// set-password mints a permanent, offline-usable credential for
			// a social-only account, so it is exactly the endpoint an
			// attacker with a stolen cookie would hammer. Like its
			// password-flow neighbours it carries the strict per-IP limit
			// so a single session cannot be used to grind attempts.
			Route{Method: http.MethodPost, Path: "/set-password", Handler: a.handleSetPassword, RateLimit: strict},
		)
	}

	if a.config.EmailVerification.SendVerificationEmail != nil {
		routes = append(routes,
			Route{Method: http.MethodPost, Path: "/send-verification-email", Handler: a.handleSendVerificationEmail, RateLimit: strict},
		)
	}
	routes = append(routes,
		Route{Method: http.MethodGet, Path: "/verify-email", Handler: a.handleVerifyEmail},
		// POST performs the verification when ConfirmationPage is on, so
		// the token is consumed by a human submitting a form, not by a
		// scanner firing the GET link.
		Route{Method: http.MethodPost, Path: "/verify-email", Handler: a.handleVerifyEmailPost},
	)

	if a.config.User.ChangeEmail.Enabled {
		routes = append(routes,
			Route{Method: http.MethodPost, Path: "/change-email", Handler: a.handleChangeEmail, RateLimit: strict},
		)
	}
	if a.config.User.DeleteUser.Enabled {
		routes = append(routes,
			Route{Method: http.MethodPost, Path: "/delete-user", Handler: a.handleDeleteUser, RateLimit: strict},
			// GET renders a confirmation page; only POST deletes, so a
			// link scanner or prefetch cannot destroy an account.
			Route{Method: http.MethodGet, Path: "/delete-user/callback", Handler: a.handleDeleteUserConfirm},
			Route{Method: http.MethodPost, Path: "/delete-user/callback", Handler: a.handleDeleteUserCallback},
		)
	}
	return routes
}

const errorPageHTML = `<!DOCTYPE html>
<html><head><title>Authentication Error</title></head>
<body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center"><h1>Authentication Error</h1>
<p>Something went wrong during authentication. Please try again.</p></div>
</body></html>`

// buildRouteIndex builds an O(1) lookup for literal paths, leaving only
// parameterised routes to be scanned linearly.
func (a *Auth) buildRouteIndex() {
	a.static = map[string]map[string]*Route{}
	a.dynamic = nil
	for i := range a.routes {
		rt := &a.routes[i]
		if strings.Contains(rt.Path, ":") {
			a.dynamic = append(a.dynamic, *rt)
			continue
		}
		byMethod, ok := a.static[rt.Path]
		if !ok {
			byMethod = map[string]*Route{}
			a.static[rt.Path] = byMethod
		}
		byMethod[rt.Method] = rt
	}
}

func (a *Auth) serveHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, a.config.BasePath) {
		http.NotFound(w, r)
		return
	}
	rel := strings.TrimPrefix(path, a.config.BasePath)
	if rel == "" {
		rel = "/"
	}
	rel = strings.TrimSuffix(rel, "/")
	if rel == "" {
		rel = "/"
	}

	route, params := a.match(r.Method, rel)
	if route == nil {
		// Distinguish "no such endpoint" from "wrong method on a real
		// endpoint" so integration mistakes are obvious.
		if allowed := a.allowedMethods(rel); len(allowed) > 0 {
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
				"Method not allowed for this endpoint")
			return
		}
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "Not found")
		return
	}

	c := &Ctx{W: w, R: r, Auth: a, Path: rel, Params: params, pattern: route.Path}

	// CSRF / origin check. Routes that opt out (SkipOriginCheck) are
	// driven cross-site by design and authenticate the request some
	// other way.
	if !route.SkipOriginCheck {
		if err := a.checkOrigin(r, rel, route.Path); err != nil {
			_ = c.Error(err)
			return
		}
	}

	// rate limiting
	if !a.config.RateLimit.Disabled {
		rule := ratelimit.Rule{Window: a.config.RateLimit.Window, Max: a.config.RateLimit.Max}
		if custom, ok := a.config.RateLimit.CustomRules[rel]; ok {
			rule = custom
		} else if custom, ok := a.config.RateLimit.CustomRules[route.Path]; ok {
			rule = custom
		} else if route.RateLimit != nil {
			rule = *route.RateLimit
		}
		// Bucket by route *pattern*, not by resolved path. Keying on
		// the resolved path gave "/reset-password/<token>" a fresh
		// bucket per request, so the limit on the endpoint an attacker
		// would guess tokens against never engaged at all.
		key := c.ClientIP() + ":" + route.Path
		ok, err := a.limiter.Allow(key, rule)
		if err != nil {
			// Fail closed by default: a limiter outage must not
			// silently disable brute-force protection.
			a.logger.Error("go-dev-auth: rate limiter store failed", "err", err)
			if !a.config.RateLimit.FailOpen {
				_ = c.Error(ErrRateLimited)
				return
			}
		} else if !ok {
			// 429s never reach Ctx.Error's logging threshold, so
			// without this the only trace of a brute-force attempt
			// being throttled is on the client side.
			a.EmitEvent(c, Event{Type: EventRateLimited, Outcome: OutcomeFailure, Reason: ReasonRateLimited})
			_ = c.Error(ErrRateLimited)
			return
		}
	}

	// before hooks
	for _, p := range a.config.Plugins {
		if hp, ok := p.(HookPlugin); ok {
			if err := hp.BeforeRequest(c); err != nil {
				_ = c.Error(err)
				return
			}
			if c.Written() {
				return
			}
		}
	}
	for _, h := range a.config.Hooks.Before {
		if err := h(c); err != nil {
			_ = c.Error(err)
			return
		}
		if c.Written() {
			return
		}
	}

	if err := route.Handler(c); err != nil {
		if !c.Written() {
			_ = c.Error(err)
		}
	} else if !c.Written() {
		_ = c.OK()
	}

	for _, h := range a.config.Hooks.After {
		if err := h(c); err != nil {
			a.logger.Error("go-dev-auth: after hook failed", "err", err)
		}
	}
	for _, p := range a.config.Plugins {
		if hp, ok := p.(HookPlugin); ok {
			if err := hp.AfterRequest(c); err != nil {
				a.logger.Error("go-dev-auth: after hook failed", "plugin", p.ID(), "err", err)
			}
		}
	}
}

// match finds a route for method and path. Routes with ":param"
// segments capture the parameter values.
func (a *Auth) match(method, path string) (*Route, map[string]string) {
	if byMethod, ok := a.static[path]; ok {
		if rt, ok := byMethod[method]; ok {
			return rt, nil
		}
		if rt, ok := byMethod["*"]; ok {
			return rt, nil
		}
	}
	for i := range a.dynamic {
		rt := &a.dynamic[i]
		params, ok := matchPath(rt.Path, path)
		if !ok {
			continue
		}
		if rt.Method == method || rt.Method == "*" {
			return rt, params
		}
	}
	return nil, nil
}

// allowedMethods returns the methods registered for a path, or nil when
// the path itself is unknown.
func (a *Auth) allowedMethods(path string) []string {
	var out []string
	if byMethod, ok := a.static[path]; ok {
		for m := range byMethod {
			out = append(out, m)
		}
	}
	for i := range a.dynamic {
		if _, ok := matchPath(a.dynamic[i].Path, path); ok {
			out = append(out, a.dynamic[i].Method)
		}
	}
	for i, m := range out {
		if m == "*" {
			out[i] = http.MethodGet + ", " + http.MethodPost
		}
	}
	sort.Strings(out)
	return out
}

func matchPath(pattern, path string) (map[string]string, bool) {
	if !strings.Contains(pattern, ":") {
		if pattern == path {
			return nil, true
		}
		return nil, false
	}
	pp := strings.Split(pattern, "/")
	sp := strings.Split(path, "/")
	if len(pp) != len(sp) {
		return nil, false
	}
	var params map[string]string
	for i := range pp {
		if strings.HasPrefix(pp[i], ":") {
			if sp[i] == "" {
				return nil, false
			}
			if params == nil {
				params = map[string]string{}
			}
			params[pp[i][1:]] = sp[i]
			continue
		}
		if pp[i] != sp[i] {
			return nil, false
		}
	}
	return params, true
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"code":"` + code + `","message":"` + message + `"}`))
}
