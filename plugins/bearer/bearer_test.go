package bearer_test

import (
	"net/http"
	"strings"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/bearer"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
)

// newEnv returns an environment with the bearer plugin mounted, plus the
// raw session token and the signed value the plugin advertises in the
// `set-auth-token` header. Both are what a non-browser client would
// capture at sign-in, so both are exercised as credentials below.
func newEnv(t *testing.T, opts ...bearer.Options) (env *plugintest.Env, rawToken, signedToken string) {
	t.Helper()
	env = plugintest.New(t, bearer.New(opts...))
	env.SignUp("mobile@example.com", "password123")
	res, body := env.SignIn("mobile@example.com", "password123")
	env.RequireStatus(res, body, http.StatusOK)
	rawToken, _ = body["token"].(string)
	signedToken = res.Header.Get("set-auth-token")
	if rawToken == "" {
		t.Fatal("sign-in returned no session token")
	}
	return env, rawToken, signedToken
}

// The plugin is pure middleware. If it ever grows an endpoint, that
// endpoint needs its own authorization test, so pin the surface.
func TestPluginExposesNoRoutes(t *testing.T) {
	if routes := bearer.New().Routes(); len(routes) != 0 {
		t.Fatalf("Routes() = %v, want none", routes)
	}
}

func TestSignInAdvertisesTheTokenInAHeader(t *testing.T) {
	env, _, signed := newEnv(t)

	// Without this header a client that cannot read cookies has no way
	// to obtain its own session token.
	if signed == "" {
		t.Fatal("sign-in response carried no set-auth-token header")
	}
	if _, ok := env.Auth.VerifySignedToken(signed); !ok {
		t.Fatal("the advertised token is not a valid signed session token")
	}
}

func TestBearerTokenAuthenticatesWithoutACookie(t *testing.T) {
	env, raw, signed := newEnv(t)

	t.Run("signed cookie value", func(t *testing.T) {
		// A fresh client holds no cookies, so only the header can
		// account for a session appearing.
		client := env.Client()
		res, body := client.GET("/get-session", "Authorization", "Bearer "+signed)
		env.RequireStatus(res, body, http.StatusOK)
		user, _ := body["user"].(map[string]any)
		if user == nil || user["email"] != "mobile@example.com" {
			t.Fatalf("session = %v, want mobile@example.com", body)
		}
	})

	// Regression test for M7: raw session tokens are stored in clear,
	// so accepting them by default made bearer the weakest credential
	// in the system — database read access became account takeover.
	t.Run("raw session token is refused by default", func(t *testing.T) {
		client := env.Client()
		res, body := client.GET("/get-session", "Authorization", "Bearer "+raw)
		env.RequireStatus(res, body, http.StatusOK)
		if body["user"] != nil {
			t.Fatalf("a raw token authenticated under the default options: %v", body)
		}
	})

	t.Run("raw session token works only when explicitly allowed", func(t *testing.T) {
		optIn, raw2, _ := newEnv(t, bearer.Options{AllowUnsignedTokens: true})
		client := optIn.Client()
		res, body := client.GET("/get-session", "Authorization", "Bearer "+raw2)
		optIn.RequireStatus(res, body, http.StatusOK)
		if body["user"] == nil {
			t.Fatalf("raw token rejected despite AllowUnsignedTokens: %v", body)
		}
	})
}

func TestForgedOrMalformedTokensDoNotAuthenticate(t *testing.T) {
	env, raw, signed := newEnv(t)

	cases := []struct {
		name, header string
	}{
		{"empty header", ""},
		{"no Bearer scheme", raw},
		{"wrong scheme", "Token " + raw},
		{"lowercase scheme is not accepted", "bearer " + raw},
		{"empty token", "Bearer "},
		// A truncated token must not authenticate: accepting prefixes
		// would make the token brute-forceable one character at a time.
		{"truncated raw token", "Bearer " + raw[:len(raw)-1]},
		{"truncated signed token", "Bearer " + signed[:len(signed)-1]},
		{"random token", "Bearer " + strings.Repeat("a", len(raw))},
		{"signature swapped for another value", "Bearer " + raw + ".forged"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := env.Client()
			var res *http.Response
			var body map[string]any
			if tc.header == "" {
				res, body = client.GET("/get-session")
			} else {
				res, body = client.GET("/get-session", "Authorization", tc.header)
			}
			env.RequireStatus(res, body, http.StatusOK)
			if body["user"] != nil {
				t.Fatalf("%q produced a session: %v", tc.header, body)
			}
		})
	}
}

func TestBearerCannotOverrideAnExistingSessionCookie(t *testing.T) {
	env, _, _ := newEnv(t)

	// A second account whose raw token an attacker might inject.
	other := env.Client()
	other.SignUp("other@example.com", "password123")
	_, body := other.SignIn("other@example.com", "password123")
	otherToken, _ := body["token"].(string)

	// env still holds mobile@example.com's cookie. The header must be
	// ignored, otherwise a stray Authorization value (a proxy, an SDK
	// default) could silently swap the acting user.
	res, session := env.GET("/get-session", "Authorization", "Bearer "+otherToken)
	env.RequireStatus(res, session, http.StatusOK)
	if user, _ := session["user"].(map[string]any); user == nil || user["email"] != "mobile@example.com" {
		t.Fatalf("the header displaced the cookie session: %v", session)
	}
}

func TestRequireSignatureRejectsRawTokens(t *testing.T) {
	env, raw, signed := newEnv(t, bearer.Options{RequireSignature: true})

	// With RequireSignature the server refuses to sign whatever it is
	// handed, so possession of a raw token from a leaked log or database
	// row is not enough to authenticate.
	client := env.Client()
	res, body := client.GET("/get-session", "Authorization", "Bearer "+raw)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] != nil {
		t.Fatalf("a raw token authenticated despite RequireSignature: %v", body)
	}

	client = env.Client()
	res, body = client.GET("/get-session", "Authorization", "Bearer "+signed)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] == nil {
		t.Fatalf("the signed token was rejected: %v", body)
	}
}

func TestRevokedSessionStopsWorkingAsABearerToken(t *testing.T) {
	env, raw, _ := newEnv(t)

	// Sign-out revokes the session server side; the header is only a
	// transport, so it must not outlive the session it names.
	env.SignOut()

	client := env.Client()
	res, body := client.GET("/get-session", "Authorization", "Bearer "+raw)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] != nil {
		t.Fatalf("a revoked session still authenticated: %v", body)
	}
}

func TestPluginIsRegisteredAsMiddleware(t *testing.T) {
	plugin := bearer.New()
	env := plugintest.New(t, plugin)

	// The token header only appears because the plugin wraps the whole
	// handler; assert the interface it relies on stays satisfied.
	var _ godevauth.MiddlewarePlugin = plugin
	if got := env.Auth.Plugin("bearer"); got != godevauth.Plugin(plugin) {
		t.Fatalf("Plugin(%q) = %v, want the mounted plugin", "bearer", got)
	}
}
