package plugintest_test

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/plugins/apikey"
	"github.com/go-dev-auth/go-dev-auth/plugins/bearer"
	"github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/plugins/magiclink"
	"github.com/go-dev-auth/go-dev-auth/plugins/organization"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// The authorization sweep.
//
// This test exists to make one specific mistake impossible to ship: a
// new endpoint that forgets to check for a session. It enumerates every
// route the library registers — core plus every plugin, via
// Auth.Routes(), so it cannot drift out of date when a route is added —
// and calls each one with no credentials at all.
//
// A route that answers anything other than 401 must be listed in
// publicRoutes below, with a reason. Adding a route to that list is a
// deliberate, reviewable act; forgetting to is a test failure.
//
// It then repeats the sweep with an ordinary user's session, and again
// with a second, unrelated user's session, and asserts that privileged
// routes (the admin plugin's) reject both and that nothing anywhere
// answers 5xx.

// publicRoutes is the allowlist: routes that intentionally answer
// without a session. Every entry needs a reason, because every entry is
// unauthenticated attack surface.
var publicRoutes = map[string]string{
	// --- core: liveness and the hosted error page ---
	"GET /ok":    "liveness probe; returns a constant",
	"GET /error": "static HTML shown after a failed provider redirect",

	// --- core: session endpoints that must work without one ---
	"GET /get-session": "returns null when unauthenticated; that is its contract",
	"POST /sign-out":   "clearing a cookie must succeed even if the session is already gone",

	// --- core: credential entry points ---
	"POST /sign-up/email":  "registration",
	"POST /sign-in/email":  "authentication",
	"POST /sign-in/social": "starts an OAuth flow; the provider authenticates",

	// --- core: link-carried authorization (the token is the credential) ---
	"* /callback/:provider":         "OAuth provider redirect; state cookie binds it to the browser",
	"POST /forget-password":         "answers uniformly to avoid disclosing which addresses exist",
	"POST /request-password-reset":  "alias of /forget-password",
	"POST /reset-password":          "single-use reset token is the credential",
	"GET /reset-password/:token":    "redirects the emailed link to the reset page",
	"GET /verify-email":             "single-use verification token is the credential",
	"POST /send-verification-email": "answers uniformly; sends only to an unverified, existing address",
	"GET /delete-user/callback":     "renders a confirmation page for an emailed single-use token",
	"POST /delete-user/callback":    "consumes a single-use deletion token bound to one user",

	// --- plugins ---
	"POST /sign-in/magic-link":   "requests a sign-in link; answers uniformly",
	"GET /magic-link/verify":     "single-use magic-link token is the credential",
	"GET /jwks":                  "public key set; publishing it is the point",
	"GET /.well-known/jwks.json": "standard alias for /jwks",
	"POST /api-key/verify":       "verifies a caller-supplied API key; the key is the credential",
}

// privilegedPrefixes are route prefixes that require more than a valid
// session. An ordinary user reaching one must be refused.
var privilegedPrefixes = []string{"/admin/"}

// privilegedExceptions are routes under a privileged prefix that an
// ordinary user may legitimately reach. Same rule as publicRoutes: an
// entry needs a reason.
var privilegedExceptions = map[string]string{
	"POST /admin/stop-impersonating": "called by the impersonated (non-admin) session to hand " +
		"control back; it only does anything when the server itself set " +
		"session.impersonatedBy, which a client cannot forge",
}

// sessionErrorCodes are the codes a handler returns when it refused the
// request for lack of a session. Matching on the code rather than on the
// 401 status is what separates "this endpoint is protected" from "these
// credentials were wrong", which /sign-in/email also answers 401 to.
var sessionErrorCodes = map[string]bool{
	"UNAUTHORIZED":    true,
	"SESSION_EXPIRED": true,
}

// sweepAuth builds an instance with every plugin loaded and every
// optional route group switched on, so the sweep sees the largest
// surface the library can present.
func sweepAuth(t *testing.T) *plugintest.Env {
	t.Helper()
	return plugintest.NewWith(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{
			admin.New(),
			apikey.New(),
			bearer.New(),
			jwt.New(),
			magiclink.New(magiclink.Options{
				SendMagicLink: func(context.Context, string, string, string) error { return nil },
			}),
			organization.New(organization.Options{Teams: true}),
			twofactor.New(twofactor.Options{
				SendOTP: func(context.Context, *storage.User, string) error { return nil },
			}),
		}
		// Switch on every optional core route group.
		cfg.EmailVerification.SendVerificationEmail = func(context.Context, *storage.User, string, string) error { return nil }
		cfg.User.ChangeEmail.Enabled = true
		cfg.User.DeleteUser.Enabled = true
	})
}

// routeKey is the stable identifier used in publicRoutes.
func routeKey(r godevauth.Route) string { return r.Method + " " + r.Path }

// requestFor turns a route into a concrete method and path, filling any
// ":param" segment with a placeholder that will not resolve to a real
// record.
func requestFor(r godevauth.Route) (method, path string) {
	method = r.Method
	if method == "*" {
		method = http.MethodGet
	}
	segs := strings.Split(r.Path, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") {
			segs[i] = "sweep-placeholder"
		}
	}
	return method, strings.Join(segs, "/")
}

// TestEveryRouteRequiresAuthentication is the sweep itself.
func TestEveryRouteRequiresAuthentication(t *testing.T) {
	env := sweepAuth(t)
	routes := env.Auth.Routes()
	if len(routes) < 50 {
		t.Fatalf("only %d routes registered; the sweep is not seeing the full surface", len(routes))
	}

	// A client that has never authenticated.
	anon := env.Client()

	var unexpectedlyPublic []string
	for _, r := range routes {
		key := routeKey(r)
		method, path := requestFor(r)

		res, body := anon.Do(method, path, map[string]any{})
		reason, allowed := publicRoutes[key]

		code, _ := body["code"].(string)
		protected := res.StatusCode == http.StatusUnauthorized && sessionErrorCodes[code]

		switch {
		case protected:
			if allowed {
				t.Errorf("%s is on the public allowlist (%q) but rejects unauthenticated "+
					"requests with %s; remove the allowlist entry", key, reason, code)
			}
		case allowed:
			// Intentionally public. Nothing to assert beyond "not 5xx",
			// which is checked below.
		default:
			unexpectedlyPublic = append(unexpectedlyPublic,
				fmt.Sprintf("  %-42s -> %d %v", key, res.StatusCode, body["code"]))
		}

		if res.StatusCode >= 500 {
			t.Errorf("%s answered %d to an unauthenticated request; "+
				"a server error on the unauthenticated path is a finding", key, res.StatusCode)
		}
	}

	t.Logf("swept %d routes: %d require a session, %d are on the documented public allowlist",
		len(routes), len(routes)-len(publicRoutes), len(publicRoutes))

	if len(unexpectedlyPublic) > 0 {
		sort.Strings(unexpectedlyPublic)
		t.Fatalf("%d route(s) answered an unauthenticated request without 401 and are not on "+
			"the public allowlist in authsweep_test.go:\n%s\n\n"+
			"Either make the handler call Ctx.RequireSession, or add the route to publicRoutes "+
			"with a written reason. Do not add it without one.",
			len(unexpectedlyPublic), strings.Join(unexpectedlyPublic, "\n"))
	}
}

// TestPrivilegedRoutesRejectOrdinaryUsers covers the second credential
// state: a real, valid session belonging to somebody with no claim on
// the resource. A 200 here is privilege escalation.
func TestPrivilegedRoutesRejectOrdinaryUsers(t *testing.T) {
	env := sweepAuth(t)

	// Two unrelated users on two independent clients: neither owns
	// anything of the other's.
	owner := env.Client()
	owner.SignUp("owner@example.com", "password-owner-1")
	stranger := env.Client()
	stranger.SignUp("stranger@example.com", "password-stranger-1")

	if !stranger.Signed() {
		t.Fatal("the stranger client is not authenticated; the sweep would be vacuous")
	}

	for _, r := range env.Auth.Routes() {
		key := routeKey(r)
		if !isPrivileged(r.Path) {
			continue
		}
		if _, excepted := privilegedExceptions[key]; excepted {
			continue
		}
		method, path := requestFor(r)
		res, body := stranger.Do(method, path, map[string]any{})
		if res.StatusCode == http.StatusOK {
			t.Errorf("%s answered 200 to an ordinary (non-admin) user: %v", key, body)
		}
		if res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusUnauthorized {
			// Anything else (400 on a bad body, say) is acceptable only
			// if the privilege check ran first, which a 403 proves. Flag
			// it so a reviewer looks.
			t.Errorf("%s answered %d %v to an ordinary user; expected 401 or 403 so the "+
				"privilege check demonstrably runs before the handler body",
				key, res.StatusCode, body["code"])
		}
	}
}

// TestAuthenticatedSweepNeverErrors runs every route with an ordinary
// valid session. Nothing may answer 5xx: arbitrary-but-valid callers
// reaching a server error usually means an unhandled edge.
func TestAuthenticatedSweepNeverErrors(t *testing.T) {
	env := sweepAuth(t)
	user := env.Client()
	user.SignUp("sweep@example.com", "password-sweep-1")

	for _, r := range env.Auth.Routes() {
		method, path := requestFor(r)
		// Skip the routes that end this client's own session, or the
		// remainder of the sweep would run unauthenticated.
		switch r.Path {
		case "/sign-out", "/revoke-sessions", "/revoke-other-sessions", "/delete-user":
			continue
		}
		res, body := user.Do(method, path, map[string]any{})
		if res.StatusCode >= 500 {
			t.Errorf("%s answered %d %v to an authenticated request", routeKey(r), res.StatusCode, body)
		}
	}
}

// TestPublicAllowlistHasNoStaleEntries keeps the allowlist honest: an
// entry naming a route that no longer exists hides the fact that the
// route was renamed rather than secured.
func TestPublicAllowlistHasNoStaleEntries(t *testing.T) {
	env := sweepAuth(t)
	registered := map[string]bool{}
	for _, r := range env.Auth.Routes() {
		registered[routeKey(r)] = true
	}
	for key := range publicRoutes {
		if !registered[key] {
			t.Errorf("publicRoutes lists %q, which is not a registered route; "+
				"remove the stale entry", key)
		}
	}
}

// TestRouteTableHasNoDuplicates guards the other way a route can end up
// unprotected: two registrations for the same method and path, where the
// index keeps whichever came last.
func TestRouteTableHasNoDuplicates(t *testing.T) {
	env := sweepAuth(t)
	seen := map[string]bool{}
	for _, r := range env.Auth.Routes() {
		key := routeKey(r)
		if seen[key] {
			t.Errorf("route %q is registered twice; only one handler is reachable", key)
		}
		seen[key] = true
	}
}

func isPrivileged(path string) bool {
	for _, p := range privilegedPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
