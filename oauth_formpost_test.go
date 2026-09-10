package godevauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
)

// fakeFormPostProvider is a provider in the shape of Sign in with Apple:
// response_mode=form_post, so the callback arrives as a cross-site POST
// from the provider's own origin rather than a top-level GET redirect.
func fakeFormPostProvider(t *testing.T, id string) oauth2.Provider {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "fake-code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "apple-user-1", "name": "Form Post", "email": "formpost@example.com",
			"email_verified": true,
		})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return oauth2.New(oauth2.Spec{
		ProviderID:   id,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: server.URL + "/authorize",
			TokenURL:         server.URL + "/token",
			UserInfoURL:      server.URL + "/userinfo",
		},
		DefaultScopes:   []string{"name", "email"},
		UsePKCE:         true,
		ExtraAuthParams: map[string]string{"response_mode": "form_post"},
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			return &oauth2.UserProfile{
				ID:            oauth2.Str(raw, "id"),
				Name:          oauth2.Str(raw, "name"),
				Email:         oauth2.Str(raw, "email"),
				EmailVerified: oauth2.Bool(raw, "email_verified"),
			}
		},
	})
}

// Regression test for the form_post callback (H3): Sign in with Apple
// delivers the authorization response as a cross-site POST from
// appleid.apple.com. The origin check used to answer 403 INVALID_ORIGIN
// before the handler ever ran, and the Lax state cookie was withheld by
// browsers on such a POST. The callback route is now exempt from the
// origin check (the single-use state bound to the browser cookie plus
// PKCE authenticate it), and the state cookie is minted SameSite=None
// for form_post providers.
func TestFormPostCallbackCompletes(t *testing.T) {
	provider := fakeFormPostProvider(t, "apple")
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{provider}
	})

	res, body := tc.post("/sign-in/social", map[string]any{
		"provider": "apple", "callbackURL": "/dashboard",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in/social: %d %v", res.StatusCode, body)
	}
	authURL, _ := body["url"].(string)
	parsed, err := url.Parse(authURL)
	if err != nil || parsed.Query().Get("response_mode") != "form_post" {
		t.Fatalf("auth url = %q, want response_mode=form_post", authURL)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("no state in auth url")
	}

	// The provider "responds" with a cross-site POST to our callback,
	// exactly as Apple does. The browser attaches the state cookie
	// (kept by tc's jar) and stamps the provider's Origin.
	form := url.Values{"code": {"fake-code"}, "state": {state}}
	req, err := http.NewRequest(http.MethodPost, tc.server.URL+"/api/auth/callback/apple",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://appleid.apple.com")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	res2, err := tc.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode == http.StatusForbidden {
		t.Fatalf("callback POST rejected with 403: the origin check is blocking form_post callbacks")
	}
	loc := res2.Header.Get("Location")
	if !strings.Contains(loc, "/dashboard") {
		t.Fatalf("callback redirect = %q, want /dashboard (an error redirect means the flow failed)", loc)
	}

	res3, session := tc.get("/get-session")
	if res3.StatusCode != http.StatusOK || session["user"] == nil {
		t.Fatalf("get-session after form_post callback: %d %v", res3.StatusCode, session)
	}
}

// The state cookie for a form_post provider must be SameSite=None (with
// Secure), or browsers withhold it from the cross-site POST and every
// flow dies with state_mismatch.
func TestFormPostStateCookieIsSameSiteNone(t *testing.T) {
	provider := fakeFormPostProvider(t, "apple")
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{provider}
		cfg.Advanced.UseSecureCookies = true
	})

	res, body := tc.post("/sign-in/social", map[string]any{"provider": "apple"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in/social: %d %v", res.StatusCode, body)
	}
	var stateCookie *http.Cookie
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "oauth_state") {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no oauth_state cookie set")
	}
	if stateCookie.SameSite != http.SameSiteNoneMode || !stateCookie.Secure {
		t.Fatalf("state cookie SameSite=%v Secure=%v, want SameSite=None; Secure for a form_post provider",
			stateCookie.SameSite, stateCookie.Secure)
	}

	// A regular redirect provider keeps the stricter Lax cookie.
	regular, _ := fakeProvider(t, "fakeco", map[string]any{"id": "u1"})
	_, tc2 := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{regular}
		cfg.Advanced.UseSecureCookies = true
	})
	res2, body2 := tc2.post("/sign-in/social", map[string]any{"provider": "fakeco"})
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("sign-in/social: %d %v", res2.StatusCode, body2)
	}
	for _, c := range res2.Cookies() {
		if strings.Contains(c.Name, "oauth_state") && c.SameSite == http.SameSiteNoneMode {
			t.Fatal("redirect provider's state cookie is SameSite=None; want Lax")
		}
	}
}
