package godevauth

import (
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Fuzz targets for the unexported request-routing and trust decisions:
// signed-cookie parsing, route matching and trusted-origin matching.
//
// These are in the internal test package because the functions they
// exercise are the ones an attacker actually reaches — splitSigned,
// matchPath, isTrustedOrigin — and testing them through the HTTP surface
// would spend most of the fuzzing budget in net/http instead.
//
//	go test -run '^$' -fuzz=FuzzIsTrustedOrigin -fuzztime=30s .

const fuzzSecret = "fuzz-secret-0123456789abcdefghij"

var (
	fuzzAuthOnce sync.Once
	fuzzAuthInst *Auth
	fuzzAuthErr  error
)

// fuzzAuth returns an Auth with a fixed, deliberately awkward trusted
// origin list: an exact origin, one with a port, one with a trailing
// slash, and both spellings of a wildcard.
//
// It is built once for the whole run. The targets below only read
// configuration through it, so sharing one instance is safe and keeps
// the fuzzer from spending its budget constructing storage adapters.
func fuzzAuth(tb testing.TB) *Auth {
	tb.Helper()
	fuzzAuthOnce.Do(func() {
		fuzzAuthInst, fuzzAuthErr = New(Config{
			BaseURL:  "https://app.example.com",
			Secret:   fuzzSecret,
			Database: memory.New(),
			TrustedOrigins: []string{
				"https://trusted.example.org",
				"https://other.example.net:8443",
				"https://slash.example.org/",
				"https://*.wild.example.com",
				"*.schemeless.example.com",
			},
		})
	})
	if fuzzAuthErr != nil {
		tb.Fatalf("building Auth: %v", fuzzAuthErr)
	}
	return fuzzAuthInst
}

// ---------------------------------------------------------------------
// signed cookies
// ---------------------------------------------------------------------

// FuzzSplitSigned asserts that splitting a signed cookie value is
// lossless and unambiguous: whatever comes back must reassemble into the
// exact input, and neither half may be empty. A split that loses or
// invents a byte is how a signature ends up being verified over
// something other than the value it protects.
func FuzzSplitSigned(f *testing.F) {
	f.Add("value.signature")
	f.Add("")
	f.Add(".")
	f.Add("a.")
	f.Add(".b")
	f.Add("a.b.c")
	f.Add("...")
	f.Add(strings.Repeat("a", 100) + "." + strings.Repeat("b", 43))
	f.Add("no-dot-at-all")

	f.Fuzz(func(t *testing.T, signed string) {
		parts, ok := splitSigned(signed)
		if !ok {
			if parts.body != "" || parts.sig != "" {
				t.Fatalf("splitSigned(%q) failed but returned %+v", signed, parts)
			}
			return
		}
		if parts.body == "" || parts.sig == "" {
			t.Fatalf("splitSigned(%q) succeeded with an empty half: %+v", signed, parts)
		}
		if got := parts.body + "." + parts.sig; got != signed {
			t.Fatalf("splitSigned(%q) is lossy: reassembles to %q", signed, got)
		}
		// The signature half must be the last segment: a value
		// containing dots must not be able to move the split point.
		if strings.Contains(parts.sig, ".") {
			t.Fatalf("splitSigned(%q) put a dot in the signature half %q", signed, parts.sig)
		}
	})
}

// FuzzVerifyCookieValue is the forgery property for signed cookies:
// verifyCookieValue may only accept a value the server itself signed for
// that exact purpose. Anything else accepted is a session-forgery bug.
func FuzzVerifyCookieValue(f *testing.F) {
	genuine := crypto.SignHMACPurpose(fuzzSecret, sessionTokenPurpose, "session-token-value")
	f.Add(sessionTokenPurpose, "session-token-value."+genuine)
	f.Add(sessionTokenPurpose, "session-token-value.")
	f.Add(sessionTokenPurpose, "."+genuine)
	f.Add(sessionTokenPurpose, "")
	f.Add(sessionTokenPurpose, "a.b")
	// A signature minted for a different purpose must not be reusable.
	f.Add(cookieCachePurpose, "session-token-value."+genuine)
	f.Add("", ".")

	f.Fuzz(func(t *testing.T, purpose, signed string) {
		if len(signed) > 8192 {
			return
		}
		a := fuzzAuth(t)
		body, ok := a.verifyCookieValue(purpose, signed)
		if !ok {
			if body != "" {
				t.Fatalf("verifyCookieValue rejected %q but returned body %q", signed, body)
			}
			return
		}
		want := body + "." + crypto.SignHMACPurpose(fuzzSecret, purpose, body)
		if signed != want {
			t.Fatalf("verifyCookieValue accepted a value the server never signed\n got: %q\nwant: %q", signed, want)
		}
		// Domain separation: the same bytes must not verify under the
		// other purpose the library uses.
		other := cookieCachePurpose
		if purpose == cookieCachePurpose {
			other = sessionTokenPurpose
		}
		if _, crossOK := a.verifyCookieValue(other, signed); crossOK {
			t.Fatalf("cookie value signed for %q also verified for %q: %q", purpose, other, signed)
		}
	})
}

// ---------------------------------------------------------------------
// routing
// ---------------------------------------------------------------------

// FuzzMatchPath asserts the two properties route matching must have for
// authorization to mean anything:
//
//   - substituting the captured parameters back into the pattern
//     reproduces the request path exactly, so a match can never be for a
//     different path than the client asked for;
//   - no captured parameter contains "/", so a value like "../admin"
//     cannot smuggle extra path segments into a handler.
func FuzzMatchPath(f *testing.F) {
	for _, p := range []string{
		"/callback/:provider", "/reset-password/:token", "/ok",
		"/admin/list-users", "/:a/:b", "/", "", ":x", "/a/:b/c",
	} {
		for _, path := range []string{
			"/callback/google", "/ok", "/", "", "/a//b", "//",
			"/callback/", "/callback/a/b", "/reset-password/..%2Fadmin",
			"/reset-password/../admin",
		} {
			f.Add(p, path)
		}
	}

	f.Fuzz(func(t *testing.T, pattern, path string) {
		if len(pattern) > 512 || len(path) > 512 {
			return
		}
		params, ok := matchPath(pattern, path)
		if !ok {
			if params != nil {
				t.Fatalf("matchPath(%q, %q) failed but returned params %v", pattern, path, params)
			}
			return
		}
		if !strings.Contains(pattern, ":") {
			if pattern != path {
				t.Fatalf("literal pattern %q matched a different path %q", pattern, path)
			}
			return
		}
		// Reconstruct the path from the pattern and the captures.
		segs := strings.Split(pattern, "/")
		// A pattern that names the same parameter twice cannot be
		// reconstructed from a map, and no route in this library has
		// one. Route patterns are written by the library and its
		// plugins, not by clients, so this is a limitation of the
		// oracle rather than an input worth chasing.
		if duplicateParamNames(segs) {
			return
		}
		for i, seg := range segs {
			if !strings.HasPrefix(seg, ":") {
				continue
			}
			name := seg[1:]
			v, present := params[name]
			if !present {
				t.Fatalf("matchPath(%q, %q) did not capture %q: %v", pattern, path, name, params)
			}
			if strings.Contains(v, "/") {
				t.Fatalf("parameter %q captured %q, which spans a path separator", name, v)
			}
			if v == "" {
				t.Fatalf("parameter %q captured an empty segment", name)
			}
			segs[i] = v
		}
		if got := strings.Join(segs, "/"); got != path {
			t.Fatalf("matchPath(%q, %q) captured %v, which reconstructs to %q", pattern, path, params, got)
		}
	})
}

func duplicateParamNames(segs []string) bool {
	seen := map[string]bool{}
	for _, s := range segs {
		if !strings.HasPrefix(s, ":") {
			continue
		}
		if seen[s] {
			return true
		}
		seen[s] = true
	}
	return false
}

// ---------------------------------------------------------------------
// trusted origins
// ---------------------------------------------------------------------

// referenceTrusted is an independent, conservative decision about
// whether origin should be trusted, written against parsed URLs rather
// than string operations. isTrustedOrigin may be stricter than this, but
// never looser: anything it accepts that this rejects is a CSRF/CORS
// hole.
func referenceTrusted(a *Auth, origin string) bool {
	o, err := url.Parse(strings.TrimSuffix(origin, "/"))
	if err != nil || o.Host == "" {
		return false
	}

	// An exact entry only covers its own scheme and host.
	matches := func(candidate string) bool {
		c, err := url.Parse(strings.TrimSuffix(candidate, "/"))
		if err != nil || c.Host == "" || c.Scheme == "" {
			return false
		}
		return strings.EqualFold(o.Scheme, c.Scheme) && strings.EqualFold(o.Host, c.Host)
	}

	if matches(a.config.BaseURL) {
		return true
	}
	for _, trusted := range a.config.TrustedOrigins {
		trusted = strings.TrimSuffix(trusted, "/")
		if !strings.Contains(trusted, "*") {
			if matches(trusted) {
				return true
			}
			continue
		}
		pattern, scheme := trusted, ""
		if i := strings.Index(pattern, "://"); i >= 0 {
			scheme, pattern = pattern[:i], pattern[i+3:]
		}
		// A wildcard entry that names a scheme covers only that scheme;
		// one written without a scheme ("*.example.com") covers any,
		// which is the documented behaviour.
		if scheme != "" && !strings.EqualFold(scheme, o.Scheme) {
			continue
		}
		if !strings.HasPrefix(pattern, "*.") {
			continue
		}
		// A wildcard covers strict subdomains only: the "*" must stand
		// for at least one character.
		suffix := pattern[1:]
		if len(o.Host) > len(suffix) && strings.HasSuffix(o.Host, suffix) {
			return true
		}
	}
	return false
}

// FuzzIsTrustedOrigin is the deny property: an origin that is not in the
// configured list must never be accepted. The fuzzer drives arbitrary
// origin strings past both isTrustedOrigin and the conservative
// reference above; acceptance by the former without the latter fails the
// test.
//
// This is the check that guards CORS and CSRF at once — both read
// isTrustedOrigin — so a false accept here is directly exploitable.
func FuzzIsTrustedOrigin(f *testing.F) {
	for _, o := range []string{
		"", "https://app.example.com", "https://app.example.com/",
		"HTTPS://APP.EXAMPLE.COM", "http://app.example.com",
		"https://trusted.example.org", "https://slash.example.org",
		"https://other.example.net:8443", "https://other.example.net",
		"https://sub.wild.example.com", "https://wild.example.com",
		"https://.wild.example.com", "https://evil.com",
		"https://evilwild.example.com", "https://evil.com/.wild.example.com",
		"https://evil.com#.wild.example.com", "https://user@evil.com",
		"http://sub.schemeless.example.com", "null", "app.example.com",
		"https://app.example.com:443", "//app.example.com",
		"https://app.example.com\\@evil.com",
	} {
		f.Add(o)
	}

	f.Fuzz(func(t *testing.T, origin string) {
		if len(origin) > 2048 {
			return
		}
		a := fuzzAuth(t)
		if !a.isTrustedOrigin(origin) {
			return
		}
		if origin == "" {
			t.Fatal("the empty origin was trusted")
		}
		if !referenceTrusted(a, origin) {
			t.Fatalf("isTrustedOrigin accepted %q, which is not in the trusted set\n"+
				"BaseURL: %s\nTrustedOrigins: %v", origin, a.config.BaseURL, a.config.TrustedOrigins)
		}
	})
}

// FuzzSafeRedirect asserts the open-redirect property: safeRedirect may
// only return a target that is either relative to BaseURL or on a
// trusted origin.
func FuzzSafeRedirect(f *testing.F) {
	for _, s := range []string{
		"", "/dashboard", "//evil.com", "///evil.com", "/\\evil.com",
		"https://app.example.com/x", "https://evil.com",
		"javascript:alert(1)", "data:text/html,x", "http://evil.com\\@app.example.com",
		"https://trusted.example.org/path?q=1", "/a\r\nSet-Cookie: x=1",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 2048 {
			return
		}
		a := fuzzAuth(t)
		to, ok := a.safeRedirect(raw)
		if !ok {
			if to != "" {
				t.Fatalf("safeRedirect(%q) refused but returned %q", raw, to)
			}
			return
		}
		if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
			if want := strings.TrimSuffix(a.config.BaseURL, "/") + raw; to != want {
				t.Fatalf("relative redirect %q resolved to %q, want %q", raw, to, want)
			}
			return
		}
		u, err := url.Parse(to)
		if err != nil {
			t.Fatalf("safeRedirect returned an unparseable target %q", to)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			t.Fatalf("safeRedirect returned a %q-scheme target: %q", u.Scheme, to)
		}
		if !a.isTrustedOrigin(u.Scheme + "://" + u.Host) {
			t.Fatalf("safeRedirect(%q) returned %q on the untrusted origin %q",
				raw, to, u.Scheme+"://"+u.Host)
		}
	})
}
