package sso_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/plugins/sso"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// fakeIdP runs a minimal OIDC identity provider: discovery, authorize
// (auto-consent), token and userinfo endpoints.
func fakeIdP(t *testing.T, email string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"userinfo_endpoint":      server.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, redirect+"?code=idp-code&state="+url.QueryEscape(state), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "idp-code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "idp-access-token",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer idp-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "idp-user-1", "name": "Corp User", "email": email, "email_verified": true,
		})
	})
	return server
}

func allowAll(c *godevauth.Ctx, sd *godevauth.SessionData) error { return nil }

// newEnv stands up an Auth with the sso plugin, an admin session, and a
// provider registered for corp.example.com backed by a fake IdP.
func newEnv(t *testing.T) (*plugintest.Env, *httptest.Server) {
	t.Helper()
	idp := fakeIdP(t, "employee@corp.example.com")
	env := plugintest.New(t, sso.New(sso.Options{Authorize: allowAll}))
	env.SignUp("admin@example.com", "password123")

	res, body := env.POST("/sso/register", map[string]any{
		"providerId":   "acme",
		"issuer":       idp.URL,
		"domain":       "corp.example.com",
		"clientId":     "acme-client",
		"clientSecret": "acme-secret",
	})
	env.RequireStatus(res, body, http.StatusOK)
	if body["authorizationEndpoint"] != idp.URL+"/authorize" {
		t.Fatalf("discovery did not fill endpoints: %v", body)
	}
	if _, leaked := body["clientSecret"]; leaked {
		t.Fatal("register response leaked the client secret")
	}
	return env, idp
}

func TestSSOSignInFlow(t *testing.T) {
	env, _ := newEnv(t)

	// An employee arrives on a fresh browser and types their email.
	client := env.Client()
	res, body := client.POST("/sign-in/sso", map[string]any{
		"email": "employee@corp.example.com", "callbackURL": "/app",
	})
	env.RequireStatus(res, body, http.StatusOK)
	authURL, _ := body["url"].(string)
	if !strings.Contains(authURL, "/authorize") || !strings.Contains(authURL, "code_challenge=") {
		t.Fatalf("auth url = %q, want the IdP authorize endpoint with PKCE", authURL)
	}
	if !strings.Contains(authURL, "login_hint=employee%40corp.example.com") {
		t.Errorf("auth url missing login_hint: %q", authURL)
	}

	// Follow the flow: IdP consent redirect, then our callback.
	resIdP, err := clientGet(client, authURL)
	if err != nil {
		t.Fatal(err)
	}
	loc := resIdP.Header.Get("Location")
	if !strings.Contains(loc, "/callback/sso:acme") {
		t.Fatalf("IdP redirected to %q, want our sso callback", loc)
	}
	resCB, err := clientGet(client, onServer(client, loc))
	if err != nil {
		t.Fatal(err)
	}
	final := resCB.Header.Get("Location")
	if !strings.Contains(final, "/app") {
		t.Fatalf("callback redirected to %q, want /app", final)
	}

	session := client.Session()
	if session == nil {
		t.Fatal("no session after SSO sign-in")
	}
	user, _ := session["user"].(map[string]any)
	if user["email"] != "employee@corp.example.com" {
		t.Fatalf("session user = %v", user)
	}
	if user["emailVerified"] != true {
		t.Fatalf("IdP-verified email not marked verified: %v", user)
	}
}

func TestSSOUnknownDomain(t *testing.T) {
	env, _ := newEnv(t)
	client := env.Client()
	res, body := client.POST("/sign-in/sso", map[string]any{"email": "someone@other.example.com"})
	env.RequireErrorCode(res, body, http.StatusNotFound, "SSO_PROVIDER_NOT_FOUND")
}

func TestSSOManagementFailsClosedWithoutAuthorize(t *testing.T) {
	idp := fakeIdP(t, "x@corp.example.com")
	env := plugintest.New(t, sso.New()) // no Authorize configured
	env.SignUp("user@example.com", "password123")

	res, body := env.POST("/sso/register", map[string]any{
		"providerId": "acme", "issuer": idp.URL, "clientId": "c",
	})
	env.RequireErrorCode(res, body, http.StatusForbidden, "SSO_MANAGEMENT_DISABLED")

	res, body = env.GET("/sso/list")
	env.RequireErrorCode(res, body, http.StatusForbidden, "SSO_MANAGEMENT_DISABLED")
}

func TestSSOClientSecretIsEncryptedAtRest(t *testing.T) {
	env, _ := newEnv(t)
	rec, err := env.Auth.Storage().FindOne(t.Context(), sso.ModelSSOProvider,
		[]storage.Where{storage.W("providerId", "acme")})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := rec["clientSecret"].(string)
	if stored == "" || strings.Contains(stored, "acme-secret") {
		t.Fatalf("client secret stored in clear: %q", stored)
	}
}

func TestSSORejectsDiscoveryIssuerMismatch(t *testing.T) {
	// An IdP whose discovery document claims a different issuer.
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://evil.example.com",
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"userinfo_endpoint":      server.URL + "/userinfo",
		})
	})
	env := plugintest.New(t, sso.New(sso.Options{Authorize: allowAll}))
	env.SignUp("admin@example.com", "password123")
	res, body := env.POST("/sso/register", map[string]any{
		"providerId": "evil", "issuer": server.URL, "clientId": "c",
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "DISCOVERY_FAILED")
}

// onServer rewrites a URL's scheme+host to the env's live test server.
// plugintest builds Auth with BaseURL http://127.0.0.1 and cannot
// update it to the random test-server port after the fact, so the
// callback URL the IdP echoes back points at :80; the browser would
// reach the real handler at the test server's address.
func onServer(env *plugintest.Env, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	base, _ := url.Parse(env.Server.URL)
	u.Scheme, u.Host = base.Scheme, base.Host
	return u.String()
}

// clientGet issues a GET through the env client so cookies ride along,
// without following redirects.
func clientGet(env *plugintest.Env, rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return env.HTTPClient().Do(req)
}
