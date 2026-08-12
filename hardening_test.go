package godevauth_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// --- S-4: /set-password carries the strict rate limit ---------------------

// TestSetPasswordRouteRateLimited asserts /set-password is throttled by
// the strict per-IP rule its password-flow neighbours use. Without it a
// stolen cookie could grind the credential-minting endpoint at the global
// default (100/window) instead of the strict rate (3/window); the rate
// limit runs before the handler, so unauthenticated probes count too.
func TestSetPasswordRouteRateLimited(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		// The shared harness disables rate limiting; this test needs it on
		// so the route's own rule can engage. Defaults fill Window=10s and
		// the global Max=100, well above the strict Max of 3.
		cfg.RateLimit = godevauth.RateLimitConfig{}
	})

	var got429 bool
	for i := 0; i < 6; i++ {
		res, _ := tc.post("/set-password", map[string]any{"newPassword": "irrelevant-1"})
		if res.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("/set-password was not throttled: six rapid requests from one IP " +
			"never hit 429, so the endpoint is running at the global default rather " +
			"than the strict per-IP limit")
	}
}

// --- /get-session returns null, not an empty body -------------------------

// TestGetSessionSignedOutIsNullNotEmpty asserts a signed-out /get-session
// answers with the JSON literal null, which res.json()/JSON.parse accept,
// rather than a zero-length body under an application/json content type,
// which makes them throw.
func TestGetSessionSignedOutIsNullNotEmpty(t *testing.T) {
	_, tc := newTestAuth(t, nil)

	// A fresh client with no session cookie.
	req, _ := http.NewRequest(http.MethodGet, tc.server.URL+"/api/auth/get-session", nil)
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get-session while signed out: %d", res.StatusCode)
	}
	buf := make([]byte, 1<<12)
	n, _ := res.Body.Read(buf)
	body := strings.TrimSpace(string(buf[:n]))

	if body == "" {
		t.Fatal("signed-out /get-session returned an empty body; JSON.parse and " +
			"res.json() throw on that under an application/json content type")
	}
	if !json.Valid([]byte(body)) {
		t.Fatalf("signed-out /get-session body is not valid JSON: %q", body)
	}
	if body != "null" {
		t.Fatalf("signed-out /get-session body = %q, want the JSON literal null", body)
	}
}

// --- S-8: Auth.Config() hands out an isolated snapshot --------------------

// TestConfigReturnsIsolatedSnapshot asserts that writing through the
// pointer returned by Config() does not reach the running instance, so a
// caller (a plugin, a test) mutating Secret/DisableCSRFCheck cannot race
// the per-request readers of those authenticity-deciding fields.
func TestConfigReturnsIsolatedSnapshot(t *testing.T) {
	auth, _ := newTestAuth(t, nil)

	first := auth.Config()
	origSecret := first.Secret
	origCSRF := first.Advanced.DisableCSRFCheck

	// Mutate the snapshot as several tests used to mutate the live config.
	first.Secret = origSecret + "-tampered"
	first.Advanced.DisableCSRFCheck = !origCSRF

	second := auth.Config()
	if second.Secret != origSecret {
		t.Fatalf("Config() exposed the live Secret: mutation leaked (%q != %q)",
			second.Secret, origSecret)
	}
	if second.Advanced.DisableCSRFCheck != origCSRF {
		t.Fatal("Config() exposed the live DisableCSRFCheck: mutation leaked")
	}
	if first == second {
		t.Fatal("Config() returned the same pointer twice; it must hand out a copy")
	}

	// Concurrent snapshotting + mutation must stay clean under -race: each
	// caller works on its own copy, so there is no shared write to race.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c := auth.Config()
			c.Secret = origSecret + string(rune('a'+n%26))
			_ = c.Secret
		}(i)
	}
	wg.Wait()
	if auth.Config().Secret != origSecret {
		t.Fatal("Secret changed under concurrent Config() mutation")
	}
}

// --- S-5: cookie cache excludes unlisted fields and is size-bounded -------

// sessionDataCookie returns the value of the signed session-data cache
// cookie from a response, or "" if none was set with a live value.
func sessionDataCookie(res *http.Response) string {
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "session_data") {
			if c.MaxAge < 0 {
				// A deletion cookie: the cache was intentionally cleared.
				return ""
			}
			return c.Value
		}
	}
	return ""
}

// decodeCacheUser splits the signed cache value, decodes the payload and
// returns its "user" object.
func decodeCacheUser(t *testing.T, value string) map[string]any {
	t.Helper()
	idx := strings.LastIndex(value, ".")
	if idx <= 0 {
		t.Fatalf("cache cookie is not signed: %q", value)
	}
	raw, err := base64.RawURLEncoding.DecodeString(value[:idx])
	if err != nil {
		t.Fatalf("cache cookie body is not base64: %v", err)
	}
	var payload struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("cache cookie payload is not JSON: %v", err)
	}
	return payload.User
}

// TestCookieCacheOmitsUnlistedUserFields covers part (a) of S-5: an
// additional user field that is not on the CookieCache.UserFields
// allow-list must never travel in the signed-but-unencrypted cache cookie,
// even though it is present on the user record. The core fields the guards
// rely on (id, email, emailVerified) are still there.
func TestCookieCacheOmitsUnlistedUserFields(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Session.CookieCache.Enabled = true
		cfg.User.AdditionalFields = []storage.Field{
			{Name: "ssn", Type: storage.FieldString, Input: true},
		}
		// Deliberately NOT adding "ssn" to CookieCache.UserFields.
	})

	res, body := tc.do(http.MethodPost, "/sign-up/email", map[string]any{
		"email": "cache-omit@example.com", "password": "password123",
		"name": "Cache", "ssn": "123-45-6789",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-up: %d %v", res.StatusCode, body)
	}

	value := sessionDataCookie(res)
	if value == "" {
		t.Fatal("no session-data cache cookie was written")
	}
	user := decodeCacheUser(t, value)

	if _, leaked := user["ssn"]; leaked {
		t.Fatalf("an unlisted additional field leaked into the cache cookie: %v", user)
	}
	// The fields the session/guards actually read must still be present.
	for _, k := range []string{"id", "email", "emailVerified"} {
		if _, ok := user[k]; !ok {
			t.Fatalf("cache cookie is missing the core field %q the session needs: %v", k, user)
		}
	}
	if raw, _ := json.Marshal(user); strings.Contains(string(raw), "123-45-6789") {
		t.Fatalf("the SSN value is client-readable in the cache cookie: %s", raw)
	}
}

// TestCookieCacheSkipsOversizedPayload covers part (b) of S-5: a cache
// payload that would exceed the ~4KB a browser will store must be skipped
// (falling back to a database lookup) rather than emitted as a cookie the
// browser silently drops. The session must keep working.
func TestCookieCacheSkipsOversizedPayload(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Session.CookieCache.Enabled = true
		cfg.Session.CookieCache.MaxAge = time.Hour
		cfg.User.AdditionalFields = []storage.Field{
			{Name: "bio", Type: storage.FieldString, Input: true},
		}
		// bio is allow-listed, so only the size guard can stop it.
		cfg.Session.CookieCache.UserFields = []string{"bio"}
	})

	huge := strings.Repeat("a", 5000) // on its own past the 4096-byte cap
	res, body := tc.do(http.MethodPost, "/sign-up/email", map[string]any{
		"email": "cache-big@example.com", "password": "password123",
		"name": "Big", "bio": huge,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-up: %d %v", res.StatusCode, body)
	}

	// The oversized cache must not have been emitted as a live cookie.
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "session_data") && c.MaxAge >= 0 && c.Value != "" {
			t.Fatalf("an oversized cache cookie was emitted (%d bytes) instead of "+
				"being skipped; browsers would silently drop it", len(c.String()))
		}
	}

	// The session still resolves — via the database, since the cache was skipped.
	if r, sess := tc.get("/get-session"); r.StatusCode != http.StatusOK || sess["user"] == nil {
		t.Fatalf("session did not resolve after the cache was skipped: %d %v", r.StatusCode, sess)
	}
}
