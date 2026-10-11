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

// fakeProvider spins up a fake OAuth2 + user-info server.
func fakeProvider(t *testing.T, id string, profile map[string]any) (oauth2.Provider, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// simulate provider consent: redirect back with code
		redirect := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, redirect+"?code=fake-code&state="+url.QueryEscape(state), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "fake-code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "fake-access-token",
			"refresh_token": "fake-refresh-token",
			"token_type":    "bearer",
			"expires_in":    3600,
			"scope":         "email profile",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(profile)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	provider := oauth2.New(oauth2.Spec{
		ProviderID:   id,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: server.URL + "/authorize",
			TokenURL:         server.URL + "/token",
			UserInfoURL:      server.URL + "/userinfo",
		},
		DefaultScopes: []string{"email", "profile"},
		UsePKCE:       true,
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			return &oauth2.UserProfile{
				ID:            oauth2.Str(raw, "id"),
				Name:          oauth2.Str(raw, "name"),
				Email:         oauth2.Str(raw, "email"),
				EmailVerified: oauth2.Bool(raw, "email_verified"),
				Image:         oauth2.Str(raw, "picture"),
			}
		},
	})
	return provider, server
}

func TestSocialSignInFlow(t *testing.T) {
	provider, _ := fakeProvider(t, "fakeco", map[string]any{
		"id": "fake-user-1", "name": "Fake User", "email": "fake@example.com",
		"email_verified": true, "picture": "https://img.example.com/a.png",
	})
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{provider}
	})

	// step 1: request the authorization URL
	res, body := tc.post("/sign-in/social", map[string]any{
		"provider": "fakeco", "callbackURL": "/dashboard",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in/social: %d %v", res.StatusCode, body)
	}
	authURL, _ := body["url"].(string)
	if authURL == "" {
		t.Fatal("missing auth url")
	}
	if !strings.Contains(authURL, "code_challenge=") {
		t.Error("expected PKCE challenge in auth URL")
	}

	// step 2: follow the provider redirect (simulates consent)
	res2, err := tc.client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	loc := res2.Header.Get("Location")
	if loc == "" {
		t.Fatalf("provider did not redirect, status %d", res2.StatusCode)
	}

	// step 3: hit our callback with the code
	res3, err := tc.client.Get(loc)
	if err != nil {
		t.Fatal(err)
	}
	res3.Body.Close()
	final := res3.Header.Get("Location")
	if !strings.Contains(final, "/dashboard") {
		t.Fatalf("expected redirect to /dashboard, got %q", final)
	}

	// step 4: session should be established
	res4, session := tc.get("/get-session")
	if res4.StatusCode != http.StatusOK || session == nil {
		t.Fatalf("get-session: %d %v", res4.StatusCode, session)
	}
	user := session["user"].(map[string]any)
	if user["email"] != "fake@example.com" {
		t.Errorf("email = %v", user["email"])
	}
	if user["emailVerified"] != true {
		t.Errorf("emailVerified = %v", user["emailVerified"])
	}

	// accounts list shows the provider link
	res5, _ := tc.get("/list-accounts")
	if res5.StatusCode != http.StatusOK {
		t.Fatalf("list-accounts: %d", res5.StatusCode)
	}

	// second sign-in reuses the same user
	res6, body6 := tc.post("/sign-in/social", map[string]any{"provider": "fakeco"})
	if res6.StatusCode != http.StatusOK {
		t.Fatalf("second sign-in: %d %v", res6.StatusCode, body6)
	}
}

func TestSocialUnknownProvider(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	res, body := tc.post("/sign-in/social", map[string]any{"provider": "nope"})
	if res.StatusCode != http.StatusNotFound || body["code"] != "PROVIDER_NOT_FOUND" {
		t.Fatalf("expected PROVIDER_NOT_FOUND, got %d %v", res.StatusCode, body)
	}
}

func TestCallbackStateMismatch(t *testing.T) {
	provider, _ := fakeProvider(t, "fakeco", map[string]any{"id": "u1"})
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{provider}
	})
	res, _ := tc.get("/callback/fakeco?code=x&state=bogus")
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "error") {
		t.Fatalf("expected error redirect, got %q", loc)
	}
}

func TestAccountLinkingUntrusted(t *testing.T) {
	// provider reports an unverified email that matches an existing user
	provider, _ := fakeProvider(t, "fakeco", map[string]any{
		"id": "fake-2", "name": "Sneaky", "email": "victim@example.com",
		"email_verified": false,
	})
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{provider}
	})
	tc.signUp("victim@example.com", "password123", "Victim")
	tc.post("/sign-out", map[string]any{})

	res, body := tc.post("/sign-in/social", map[string]any{"provider": "fakeco"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in/social: %d %v", res.StatusCode, body)
	}
	authURL, _ := body["url"].(string)
	res2, _ := tc.client.Get(authURL)
	res2.Body.Close()
	res3, _ := tc.client.Get(res2.Header.Get("Location"))
	res3.Body.Close()
	final := res3.Header.Get("Location")
	if !strings.Contains(final, "ACCOUNT_NOT_LINKED") {
		t.Fatalf("expected ACCOUNT_NOT_LINKED error redirect, got %q", final)
	}
	// no session
	_, session := tc.get("/get-session")
	if session != nil {
		t.Fatal("expected no session for untrusted linking")
	}
}

// Regression test for M2: even a trusted provider asserting a verified
// email must not auto-link into a local account that never verified the
// address. The attack: pre-register the victim's email with a password
// (verification not required by default), wait for the victim to sign
// in with Google, and inherit them into the attacker's account.
func TestTrustedLinkingRequiresVerifiedLocalAccount(t *testing.T) {
	provider, _ := fakeProvider(t, "fakeco", map[string]any{
		"id": "fake-3", "name": "Victim", "email": "victim2@example.com",
		"email_verified": true,
	})
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{provider}
		cfg.Account.AccountLinking.TrustedProviders = []string{"fakeco"}
	})
	// The attacker's pre-registered, never verified account.
	tc.signUp("victim2@example.com", "password123", "Attacker")
	tc.post("/sign-out", map[string]any{})

	social := func() string {
		res, body := tc.post("/sign-in/social", map[string]any{"provider": "fakeco"})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("sign-in/social: %d %v", res.StatusCode, body)
		}
		authURL, _ := body["url"].(string)
		res2, _ := tc.client.Get(authURL)
		res2.Body.Close()
		res3, _ := tc.client.Get(res2.Header.Get("Location"))
		res3.Body.Close()
		return res3.Header.Get("Location")
	}

	if final := social(); !strings.Contains(final, "ACCOUNT_NOT_LINKED") {
		t.Fatalf("expected ACCOUNT_NOT_LINKED for an unverified local account, got %q", final)
	}
	if _, session := tc.get("/get-session"); session != nil {
		t.Fatal("expected no session when the local account is unverified")
	}

	// Once the local account has proven the address, the trusted link
	// goes through.
	markEmailVerified(t, auth, "victim2@example.com")
	if final := social(); strings.Contains(final, "ACCOUNT_NOT_LINKED") {
		t.Fatalf("expected linking to succeed for a verified local account, got %q", final)
	}
	if _, session := tc.get("/get-session"); session == nil {
		t.Fatal("expected a session after trusted linking")
	}
}
