package apikey_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/apikey"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// newEnv returns an environment with the api key plugin mounted and a
// signed-in owner for the keys created in each test.
func newEnv(t *testing.T, opts ...apikey.Options) *plugintest.Env {
	t.Helper()
	if len(opts) == 0 {
		opts = []apikey.Options{{KeyPrefix: "gda_"}}
	}
	env := plugintest.New(t, apikey.New(opts...))
	env.SignUp("owner@example.com", "password123")
	return env
}

// createKey creates a key on the given client and returns its id and the
// plaintext, which is the only time the plaintext is ever available.
func createKey(t *testing.T, env *plugintest.Env, body any) (id, plain string) {
	t.Helper()
	res, out := env.POST("/api-key/create", body)
	env.RequireStatus(res, out, http.StatusOK)
	id, _ = out["id"].(string)
	plain, _ = out["key"].(string)
	if id == "" || plain == "" {
		t.Fatalf("create returned id=%q key=%q", id, plain)
	}
	return id, plain
}

func TestRoutesRequireASession(t *testing.T) {
	env := newEnv(t)

	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api-key/create", map[string]any{"name": "x"}},
		{http.MethodGet, "/api-key/get?id=some-id", nil},
		{http.MethodGet, "/api-key/list", nil},
		{http.MethodPost, "/api-key/update", map[string]any{"keyId": "some-id", "name": "x"}},
		{http.MethodPost, "/api-key/delete", map[string]any{"keyId": "some-id"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			anon := env.Client()
			res, body := anon.Do(tc.method, tc.path, tc.body)
			env.RequireErrorCode(res, body, http.StatusUnauthorized, "UNAUTHORIZED")
		})
	}

	// /api-key/verify is deliberately open: it authenticates by the key
	// in the body, which is how a downstream service checks a key it was
	// handed. It must still refuse an unknown one.
	t.Run("/api-key/verify", func(t *testing.T) {
		anon := env.Client()
		res, body := anon.POST("/api-key/verify", map[string]any{"key": "gda_not-a-key"})
		env.RequireStatus(res, body, http.StatusOK)
		if body["valid"] != false {
			t.Fatalf("verify of an unknown key = %v, want valid:false", body)
		}
	})
}

func TestKeysAreInvisibleAndUntouchableToOtherUsers(t *testing.T) {
	env := newEnv(t)
	id, plain := createKey(t, env, map[string]any{"name": "owner-key"})

	// A second account on its own browser.
	intruder := env.Client()
	intruder.SignUp("intruder@example.com", "password123")
	intruderCookie := sessionCookie(t, intruder, "intruder@example.com", "password123")

	// Reading, updating or deleting somebody else's key must be
	// indistinguishable from the key not existing: a different status
	// would confirm the id is real.
	t.Run("get", func(t *testing.T) {
		res, body := intruder.GET("/api-key/get?id=" + id)
		env.RequireErrorCode(res, body, http.StatusNotFound, "KEY_NOT_FOUND")
	})
	t.Run("update", func(t *testing.T) {
		res, body := intruder.POST("/api-key/update", map[string]any{"keyId": id, "enabled": false})
		env.RequireErrorCode(res, body, http.StatusNotFound, "KEY_NOT_FOUND")
	})
	t.Run("delete", func(t *testing.T) {
		res, body := intruder.POST("/api-key/delete", map[string]any{"keyId": id})
		env.RequireErrorCode(res, body, http.StatusNotFound, "KEY_NOT_FOUND")
	})
	t.Run("list", func(t *testing.T) {
		raw := rawGET(t, env, "/api-key/list", "Cookie", intruderCookie)
		if strings.Contains(string(raw), id) {
			t.Fatalf("another user's key appeared in the list: %s", raw)
		}
	})

	// None of the attempts may have taken effect.
	res, body := env.POST("/api-key/verify", map[string]any{"key": plain})
	env.RequireStatus(res, body, http.StatusOK)
	if body["valid"] != true {
		t.Fatalf("the owner's key stopped working after another user poked at it: %v", body)
	}
}

func TestPlainKeyIsReturnedOnlyOnCreation(t *testing.T) {
	env := newEnv(t)
	id, plain := createKey(t, env, map[string]any{"name": "ci"})

	if !strings.HasPrefix(plain, "gda_") {
		t.Fatalf("key = %q, want the configured prefix", plain)
	}

	res, got := env.GET("/api-key/get?id=" + id)
	env.RequireStatus(res, got, http.StatusOK)
	if _, leaked := got["key"]; leaked {
		t.Fatalf("get returned key material: %v", got)
	}
	// The display prefix is a hint for the UI, not the credential.
	if start, _ := got["start"].(string); start != plain[:6] {
		t.Fatalf("start = %q, want the first six characters of the key", start)
	}

	// Assert on the raw bytes: a leak through any field, not just "key",
	// hands out a working credential.
	cookie := sessionCookie(t, env, "owner@example.com", "password123")
	for _, path := range []string{"/api-key/list", "/api-key/get?id=" + id} {
		raw := rawGET(t, env, path, "Cookie", cookie)
		if strings.Contains(string(raw), plain) {
			t.Fatalf("%s echoed the plaintext key: %s", path, raw)
		}
	}

	// Nor is the plaintext recoverable from storage.
	recs, err := env.Auth.Storage().FindMany(context.Background(), apikey.ModelAPIKey, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if stored, _ := rec["key"].(string); stored == plain {
			t.Fatal("the key is stored in plaintext")
		}
	}
}

func TestKeyAuthenticatesRequestsInPlaceOfASession(t *testing.T) {
	env := newEnv(t)
	_, plain := createKey(t, env, map[string]any{"name": "service"})

	// A fresh client holds no cookies, so only the header can produce a
	// session here.
	client := env.Client()
	res, body := client.GET("/get-session", "x-api-key", plain)
	env.RequireStatus(res, body, http.StatusOK)
	user, _ := body["user"].(map[string]any)
	if user == nil || user["email"] != "owner@example.com" {
		t.Fatalf("session from api key = %v, want the key owner", body)
	}

	t.Run("unknown key grants nothing", func(t *testing.T) {
		client := env.Client()
		res, body := client.GET("/get-session", "x-api-key", "gda_unknown")
		env.RequireStatus(res, body, http.StatusOK)
		if body["user"] != nil {
			t.Fatalf("an unknown key produced a session: %v", body)
		}
	})

	t.Run("deleted key grants nothing", func(t *testing.T) {
		id, doomed := createKey(t, env, map[string]any{"name": "doomed"})
		res, body := env.POST("/api-key/delete", map[string]any{"keyId": id})
		env.RequireStatus(res, body, http.StatusOK)

		res, body = env.POST("/api-key/verify", map[string]any{"key": doomed})
		env.RequireStatus(res, body, http.StatusOK)
		if body["valid"] != false {
			t.Fatalf("a deleted key still verifies: %v", body)
		}
	})
}

func TestDisabledKeyIsRejected(t *testing.T) {
	env := newEnv(t)
	id, plain := createKey(t, env, map[string]any{"name": "revocable"})

	res, body := env.POST("/api-key/update", map[string]any{"keyId": id, "enabled": false})
	env.RequireStatus(res, body, http.StatusOK)

	// Disabling is the emergency stop; it has to take effect for both
	// the verification endpoint and header authentication.
	res, body = env.POST("/api-key/verify", map[string]any{"key": plain})
	env.RequireStatus(res, body, http.StatusOK)
	if body["valid"] != false {
		t.Fatalf("a disabled key verified: %v", body)
	}
	client := env.Client()
	res, body = client.GET("/get-session", "x-api-key", plain)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] != nil {
		t.Fatalf("a disabled key authenticated a request: %v", body)
	}

	// Re-enabling restores it, so the flag really is what is consulted.
	res, body = env.POST("/api-key/update", map[string]any{"keyId": id, "enabled": true})
	env.RequireStatus(res, body, http.StatusOK)
	res, body = env.POST("/api-key/verify", map[string]any{"key": plain})
	env.RequireStatus(res, body, http.StatusOK)
	if body["valid"] != true {
		t.Fatalf("a re-enabled key was refused: %v", body)
	}
}

func TestExpiredKeyIsRejected(t *testing.T) {
	env := newEnv(t)
	id, plain := createKey(t, env, map[string]any{"name": "short-lived", "expiresIn": 3600})

	// Reach past the API to age the key: there is no endpoint that can
	// set an expiry in the past, and waiting an hour is not a test.
	if _, err := env.Auth.Storage().UpdateMany(context.Background(), apikey.ModelAPIKey,
		[]storage.Where{storage.W("id", id)},
		map[string]any{"expiresAt": time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}

	res, body := env.POST("/api-key/verify", map[string]any{"key": plain})
	env.RequireStatus(res, body, http.StatusOK)
	if body["valid"] != false {
		t.Fatalf("an expired key verified: %v", body)
	}
	client := env.Client()
	res, body = client.GET("/get-session", "x-api-key", plain)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] != nil {
		t.Fatalf("an expired key authenticated a request: %v", body)
	}
}

func TestRemainingQuotaIsSpentAndThenRefused(t *testing.T) {
	env := newEnv(t)
	id, plain := createKey(t, env, map[string]any{"name": "metered", "remaining": 2})

	for i := 1; i <= 2; i++ {
		res, body := env.POST("/api-key/verify", map[string]any{"key": plain})
		env.RequireStatus(res, body, http.StatusOK)
		if body["valid"] != true {
			t.Fatalf("use %d of a two-request quota was refused: %v", i, body)
		}
	}

	// The third use has no budget left. A quota that does not run out is
	// not a quota.
	res, body := env.POST("/api-key/verify", map[string]any{"key": plain})
	env.RequireStatus(res, body, http.StatusOK)
	if body["valid"] != false {
		t.Fatalf("the quota did not run out: %v", body)
	}

	res, got := env.GET("/api-key/get?id=" + id)
	env.RequireStatus(res, got, http.StatusOK)
	if remaining, _ := got["remaining"].(float64); remaining != 0 {
		t.Fatalf("remaining = %v, want 0", got["remaining"])
	}
}

func TestKeyLimitPerUser(t *testing.T) {
	env := newEnv(t, apikey.Options{MaximumKeysPerUser: 1})
	createKey(t, env, map[string]any{"name": "first"})

	res, body := env.POST("/api-key/create", map[string]any{"name": "second"})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "KEY_LIMIT_REACHED")

	// The limit is per user, not global.
	other := env.Client()
	other.SignUp("second@example.com", "password123")
	res, body = other.POST("/api-key/create", map[string]any{"name": "theirs"})
	env.RequireStatus(res, body, http.StatusOK)
}

func TestMalformedAndIncompleteBodies(t *testing.T) {
	env := newEnv(t)

	cases := []struct {
		name, path string
		body       any
		status     int
		code       string
	}{
		{"create rejects a non-object body", "/api-key/create", "not-an-object",
			http.StatusBadRequest, "INVALID_BODY"},
		{"update requires a body", "/api-key/update", nil,
			http.StatusBadRequest, "INVALID_BODY"},
		{"delete requires a body", "/api-key/delete", nil,
			http.StatusBadRequest, "INVALID_BODY"},
		{"verify requires a body", "/api-key/verify", nil,
			http.StatusBadRequest, "INVALID_BODY"},
		{"update needs a real key id", "/api-key/update", map[string]any{"keyId": "nope"},
			http.StatusNotFound, "KEY_NOT_FOUND"},
		{"delete needs a real key id", "/api-key/delete", map[string]any{"keyId": ""},
			http.StatusNotFound, "KEY_NOT_FOUND"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, body := env.POST(tc.path, tc.body)
			env.RequireErrorCode(res, body, tc.status, tc.code)
		})
	}

	// An empty create body is valid: every field has a default.
	res, body := env.POST("/api-key/create", map[string]any{})
	env.RequireStatus(res, body, http.StatusOK)
}

func TestSessionsCanBeDisabledForAPIKeys(t *testing.T) {
	env := plugintest.New(t, apikey.New(apikey.Options{DisableSessionForAPIKeys: true}))
	env.SignUp("owner@example.com", "password123")
	_, plain := createKey(t, env, map[string]any{"name": "verify-only"})

	// The key must no longer stand in for a session...
	client := env.Client()
	res, body := client.GET("/get-session", "x-api-key", plain)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] != nil {
		t.Fatalf("the header produced a session despite DisableSessionForAPIKeys: %v", body)
	}
	// ...while remaining a valid credential to check explicitly.
	res, body = env.POST("/api-key/verify", map[string]any{"key": plain})
	env.RequireStatus(res, body, http.StatusOK)
	if body["valid"] != true {
		t.Fatalf("verify = %v, want the key to still be valid", body)
	}
}

func TestUsageIsRecordedByDefault(t *testing.T) {
	env := newEnv(t)
	id, plain := createKey(t, env, map[string]any{"name": "tracked"})

	client := env.Client()
	res, body := client.GET("/get-session", "x-api-key", plain)
	env.RequireStatus(res, body, http.StatusOK)

	// Operators use lastRequest to spot keys that are still live before
	// rotating them; a counter that never moves makes that impossible.
	rec, err := env.Auth.Storage().FindOne(context.Background(), apikey.ModelAPIKey,
		[]storage.Where{storage.W("id", id)})
	if err != nil {
		t.Fatal(err)
	}
	if count, _ := rec["requestCount"].(int64); count != 1 {
		t.Fatalf("requestCount = %v, want 1", rec["requestCount"])
	}
	if last, _ := rec["lastRequest"].(time.Time); last.IsZero() {
		t.Fatalf("lastRequest = %v, want the time of the request", rec["lastRequest"])
	}
}

func TestUsageTrackingCanBeTurnedOff(t *testing.T) {
	env := plugintest.New(t, apikey.New(apikey.Options{
		// A negative interval keeps api-key requests read-only, which is
		// what makes read-replica routing possible.
		UsageWriteInterval: -1,
	}))
	env.SignUp("owner@example.com", "password123")
	id, plain := createKey(t, env, map[string]any{"name": "read-only"})

	client := env.Client()
	res, body := client.GET("/get-session", "x-api-key", plain)
	env.RequireStatus(res, body, http.StatusOK)

	rec, err := env.Auth.Storage().FindOne(context.Background(), apikey.ModelAPIKey,
		[]storage.Where{storage.W("id", id)})
	if err != nil {
		t.Fatal(err)
	}
	if count, _ := rec["requestCount"].(int64); count != 0 {
		t.Fatalf("requestCount = %v, want no usage write", rec["requestCount"])
	}
	if last, ok := rec["lastRequest"].(time.Time); ok && !last.IsZero() {
		t.Fatalf("lastRequest = %v, want no usage write", last)
	}
}

func TestCustomHeaderName(t *testing.T) {
	env := plugintest.New(t, apikey.New(apikey.Options{HeaderName: "x-service-key"}))
	env.SignUp("owner@example.com", "password123")
	_, plain := createKey(t, env, map[string]any{"name": "custom"})

	client := env.Client()
	res, body := client.GET("/get-session", "x-service-key", plain)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] == nil {
		t.Fatalf("the configured header did not authenticate: %v", body)
	}

	// The default header must not keep working once it is reconfigured.
	client = env.Client()
	res, body = client.GET("/get-session", "x-api-key", plain)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] != nil {
		t.Fatalf("the default header still authenticated: %v", body)
	}
}

func TestPluginDeclaresItsSchema(t *testing.T) {
	env := newEnv(t)
	// The key column must be indexed: every authenticated request looks
	// a key up by its digest.
	table := env.Auth.Schema().Tables[apikey.ModelAPIKey]
	if table == nil {
		t.Fatalf("no %q table in the schema", apikey.ModelAPIKey)
	}
	field := table.FieldByName("key")
	if field == nil || !field.Index {
		t.Fatalf("key field = %v, want an indexed column", field)
	}
	var _ godevauth.SchemaPlugin = apikey.New()
	var _ godevauth.HookPlugin = apikey.New()
}

// sessionCookie signs the client in and returns the cookie header a raw
// request should carry to act as that user.
func sessionCookie(t *testing.T, env *plugintest.Env, email, password string) string {
	t.Helper()
	res, body := env.SignIn(email, password)
	env.RequireStatus(res, body, http.StatusOK)
	var pairs []string
	for _, sc := range res.Header.Values("Set-Cookie") {
		if i := strings.Index(sc, ";"); i >= 0 {
			sc = sc[:i]
		}
		pairs = append(pairs, sc)
	}
	return strings.Join(pairs, "; ")
}

// rawGET returns the undecoded response body. plugintest decodes JSON
// objects, but /api-key/list answers with an array and these assertions
// are about the exact bytes the endpoint hands back.
func rawGET(t *testing.T, env *plugintest.Env, path string, headers ...string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.Server.URL+env.Auth.Config().BasePath+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, res.StatusCode, raw)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("GET %s returned non-JSON: %s", path, raw)
	}
	return raw
}
