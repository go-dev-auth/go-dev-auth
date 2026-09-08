package providers_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/providers"
)

// creds are placeholder credentials; these tests exercise URL and
// profile construction, never a real provider.
var creds = providers.Credentials{ClientID: "client-id", ClientSecret: "client-secret"}

// all returns every shipped provider, so a newly added one is covered
// by the shared invariants below without touching each test.
func all(t *testing.T) map[string]oauth2.Provider {
	t.Helper()
	return map[string]oauth2.Provider{
		"google":    providers.Google(creds),
		"github":    providers.GitHub(creds),
		"discord":   providers.Discord(creds),
		"facebook":  providers.Facebook(creds),
		"microsoft": providers.Microsoft(creds),
		"gitlab":    providers.GitLab(creds),
		"linkedin":  providers.LinkedIn(creds),
		"spotify":   providers.Spotify(creds),
		"twitch":    providers.Twitch(creds),
		"x":         providers.X(creds),
		"apple":     providers.Apple(providers.AppleConfig{ClientID: creds.ClientID}),
	}
}

func TestProviderIDsAreStable(t *testing.T) {
	// The ID appears in callback URLs and in stored account rows, so
	// changing one silently breaks existing links and redirect URIs
	// registered with the provider.
	for want, p := range all(t) {
		if got := p.ID(); got != want {
			t.Errorf("provider registered as %q reports ID %q", want, got)
		}
	}
}

func TestAuthorizationURLsAreWellFormed(t *testing.T) {
	const redirect = "https://app.example.com/api/auth/callback/x"
	for name, p := range all(t) {
		t.Run(name, func(t *testing.T) {
			raw, err := p.AuthorizationURL(oauth2.AuthorizeRequest{
				State:        "state-value",
				RedirectURI:  redirect,
				CodeVerifier: "verifier-value",
			})
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("not a URL: %v", err)
			}
			if u.Scheme != "https" {
				t.Errorf("scheme = %q; credentials must never traverse plaintext", u.Scheme)
			}
			q := u.Query()
			if q.Get("client_id") != creds.ClientID {
				t.Errorf("client_id = %q", q.Get("client_id"))
			}
			if q.Get("redirect_uri") != redirect {
				t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
			}
			if q.Get("response_type") != "code" {
				t.Errorf("response_type = %q, want code", q.Get("response_type"))
			}
			// State is what binds the callback to this login attempt.
			if q.Get("state") != "state-value" {
				t.Errorf("state = %q", q.Get("state"))
			}
			// The client secret must never appear in a front-channel URL.
			if strings.Contains(raw, creds.ClientSecret) {
				t.Error("the client secret leaked into the authorization URL")
			}
		})
	}
}

func TestPKCEProvidersSendAChallengeNotTheVerifier(t *testing.T) {
	// Sending the verifier itself would defeat PKCE entirely.
	for _, name := range []string{"google", "microsoft", "gitlab", "spotify", "x"} {
		t.Run(name, func(t *testing.T) {
			p := all(t)[name]
			raw, err := p.AuthorizationURL(oauth2.AuthorizeRequest{
				State: "s", RedirectURI: "https://app.example.com/cb",
				CodeVerifier: "the-verifier",
			})
			if err != nil {
				t.Fatal(err)
			}
			q, _ := url.Parse(raw)
			challenge := q.Query().Get("code_challenge")
			if challenge == "" {
				t.Fatal("no code_challenge on a PKCE provider")
			}
			if challenge == "the-verifier" {
				t.Fatal("the raw verifier was sent as the challenge")
			}
			if want := oauth2.S256Challenge("the-verifier"); challenge != want {
				t.Errorf("challenge = %q, want the S256 hash", challenge)
			}
			if m := q.Query().Get("code_challenge_method"); m != "S256" {
				t.Errorf("code_challenge_method = %q, want S256", m)
			}
		})
	}
}

func TestScopesAreRequested(t *testing.T) {
	// Without scopes the provider returns a token that cannot read the
	// profile, and sign-in fails at the user-info step with an opaque
	// error.
	for name, p := range all(t) {
		if name == "x" {
			// X puts scopes in a fixed set; still expects a scope param.
		}
		t.Run(name, func(t *testing.T) {
			raw, err := p.AuthorizationURL(oauth2.AuthorizeRequest{
				State: "s", RedirectURI: "https://app.example.com/cb",
			})
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(raw)
			if u.Query().Get("scope") == "" {
				t.Error("no scope requested")
			}
		})
	}
}

func TestExtraScopesAreAppended(t *testing.T) {
	p := providers.Google(providers.Credentials{
		ClientID: "id", Scopes: []string{"https://www.googleapis.com/auth/drive.readonly"},
	})
	raw, err := p.AuthorizationURL(oauth2.AuthorizeRequest{
		State: "s", RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	scope := u.Query().Get("scope")
	if !strings.Contains(scope, "drive.readonly") {
		t.Fatalf("caller scope missing: %q", scope)
	}
	if !strings.Contains(scope, "openid") {
		t.Fatalf("default scopes dropped when caller scopes were supplied: %q", scope)
	}
}

// TestEmailVerificationIsNeverFabricated is the important one. Automatic
// account linking trusts EmailVerified; a provider that reports true
// without proof is the nOAuth account-takeover pattern.
func TestEmailVerificationIsNeverFabricated(t *testing.T) {
	cases := []struct {
		provider string
		raw      map[string]any
		want     bool
	}{
		// Only an explicit provider claim counts.
		{"google", map[string]any{"sub": "1", "email": "a@x.com", "email_verified": true}, true},
		{"google", map[string]any{"sub": "1", "email": "a@x.com", "email_verified": false}, false},
		{"google", map[string]any{"sub": "1", "email": "a@x.com"}, false},
		// A string "true" is not a boolean claim.
		{"google", map[string]any{"sub": "1", "email": "a@x.com", "email_verified": "true"}, false},
		{"microsoft", map[string]any{"sub": "1", "email": "a@x.com"}, false},
		{"discord", map[string]any{"id": "1", "email": "a@x.com", "verified": true}, true},
		{"discord", map[string]any{"id": "1", "email": "a@x.com"}, false},
		// These providers publish no per-address verification claim, so
		// the presence of an address must not imply one.
		{"facebook", map[string]any{"id": "1", "email": "a@x.com"}, false},
		{"gitlab", map[string]any{"id": "1", "email": "a@x.com"}, false},
		{"spotify", map[string]any{"id": "1", "email": "a@x.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			p, ok := all(t)[tc.provider].(*oauth2.StdProvider)
			if !ok {
				t.Skipf("%s is not a StdProvider", tc.provider)
			}
			if p.Spec.MapProfile == nil {
				t.Skipf("%s maps its profile elsewhere", tc.provider)
			}
			profile := p.Spec.MapProfile(tc.raw)
			if profile == nil {
				t.Fatal("nil profile")
			}
			if profile.EmailVerified != tc.want {
				t.Fatalf("EmailVerified = %v for %v, want %v",
					profile.EmailVerified, tc.raw, tc.want)
			}
		})
	}
}

func TestProfileMappingExtractsIdentity(t *testing.T) {
	cases := []struct {
		provider  string
		raw       map[string]any
		wantID    string
		wantEmail string
	}{
		{"google", map[string]any{"sub": "g1", "email": "g@x.com", "name": "G"}, "g1", "g@x.com"},
		{"discord", map[string]any{"id": "d1", "email": "d@x.com", "username": "D"}, "d1", "d@x.com"},
		{"linkedin", map[string]any{"sub": "l1", "email": "l@x.com"}, "l1", "l@x.com"},
		{"microsoft", map[string]any{"sub": "m1", "email": "m@x.com"}, "m1", "m@x.com"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			p := all(t)[tc.provider].(*oauth2.StdProvider)
			profile := p.Spec.MapProfile(tc.raw)
			if profile.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", profile.ID, tc.wantID)
			}
			if profile.Email != tc.wantEmail {
				t.Errorf("Email = %q, want %q", profile.Email, tc.wantEmail)
			}
		})
	}
}

func TestMalformedProviderResponsesDoNotPanic(t *testing.T) {
	// A provider can return anything; mapping must degrade, not crash.
	malformed := []map[string]any{
		{},
		{"id": nil, "email": nil},
		{"id": 12345, "email": []any{"a"}},
		{"data": "not-an-object"},
		{"data": []any{}},
		{"picture": map[string]any{"data": "not-an-object"}},
		{"images": []any{"not-an-object"}},
	}
	for name, p := range all(t) {
		std, ok := p.(*oauth2.StdProvider)
		if !ok || std.Spec.MapProfile == nil {
			continue
		}
		t.Run(name, func(t *testing.T) {
			for _, raw := range malformed {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("panic on %v: %v", raw, r)
						}
					}()
					_ = std.Spec.MapProfile(raw)
				}()
			}
		})
	}
}

func TestOIDCProvidersVerifyIDTokens(t *testing.T) {
	// The native SDK sign-in path is only safe if the provider can
	// verify a token it did not fetch itself.
	for _, name := range []string{"google", "microsoft", "apple"} {
		t.Run(name, func(t *testing.T) {
			p := all(t)[name]
			if _, ok := p.(oauth2.IDTokenVerifier); !ok {
				t.Fatalf("%s does not implement IDTokenVerifier", name)
			}
			std := p.(*oauth2.StdProvider)
			if std.Spec.IDToken == nil {
				t.Fatalf("%s has no ID token configuration", name)
			}
			if std.Spec.IDToken.Issuer == "" || std.Spec.IDToken.JWKSURL == "" {
				t.Errorf("%s: issuer or JWKS URL missing", name)
			}
			// Pinning the audience to the client id is what stops a
			// token minted for another application being accepted.
			if std.Spec.IDToken.Audience != creds.ClientID {
				t.Errorf("%s: audience = %q, want the client id",
					name, std.Spec.IDToken.Audience)
			}
		})
	}
}

func TestSelfHostedGitLabUsesItsOwnEndpoints(t *testing.T) {
	p := providers.GitLabSelfHosted(creds, "https://git.internal.example.com/")
	raw, err := p.AuthorizationURL(oauth2.AuthorizeRequest{
		State: "s", RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "https://git.internal.example.com/oauth/authorize") {
		t.Fatalf("authorization URL = %q", raw)
	}
}

func TestMicrosoftTenantIsScoped(t *testing.T) {
	// A single-tenant application must not accept tokens from the
	// common endpoint, which would admit any Entra directory.
	p := providers.MicrosoftTenant(creds, "contoso.onmicrosoft.com").(*oauth2.StdProvider)
	if !strings.Contains(p.Spec.Endpoints.AuthorizationURL, "contoso.onmicrosoft.com") {
		t.Errorf("authorization endpoint is not tenant-scoped: %q", p.Spec.Endpoints.AuthorizationURL)
	}
	if !strings.Contains(p.Spec.IDToken.Issuer, "contoso.onmicrosoft.com") {
		t.Errorf("issuer is not tenant-scoped: %q", p.Spec.IDToken.Issuer)
	}
}

// Regression test for M12: Microsoft's multi-tenant aliases never
// appear in a real token's iss (which carries the tenant GUID), so the
// exact-match config made the ID-token path fail closed on every token.
func TestMicrosoftMultiTenantIssuer(t *testing.T) {
	p, ok := providers.Microsoft(providers.Credentials{ClientID: "c"}).(*oauth2.StdProvider)
	if !ok || p.Spec.IDToken == nil {
		t.Fatal("Microsoft provider has no ID token config")
	}
	vi := p.Spec.IDToken.ValidateIssuer
	if vi == nil {
		t.Fatal("common tenant has no ValidateIssuer: real tokens can never match the alias issuer")
	}
	const tid = "9188040d-6c67-4c5b-b112-36a304b66dad"
	good := "https://login.microsoftonline.com/" + tid + "/v2.0"
	if !vi(good, crypto.Claims{"tid": tid}) {
		t.Fatalf("real-shaped issuer %q rejected", good)
	}
	for name, tc := range map[string]struct {
		iss string
		tid string
	}{
		"alias issuer": {"https://login.microsoftonline.com/common/v2.0", tid},
		"tid mismatch": {good, "00000000-0000-0000-0000-000000000000"},
		"missing tid":  {good, ""},
		"wrong host":   {"https://evil.example.com/" + tid + "/v2.0", tid},
		"not a guid":   {"https://login.microsoftonline.com/evil/v2.0", "evil"},
	} {
		claims := crypto.Claims{}
		if tc.tid != "" {
			claims["tid"] = tc.tid
		}
		if vi(tc.iss, claims) {
			t.Errorf("%s: issuer %q accepted", name, tc.iss)
		}
	}

	// A concrete tenant keeps the exact match.
	pt := providers.MicrosoftTenant(providers.Credentials{ClientID: "c"}, tid).(*oauth2.StdProvider)
	if pt.Spec.IDToken.ValidateIssuer != nil {
		t.Fatal("concrete tenant should pin the issuer exactly")
	}
}

// Regression test for the Apple dead-config: with TeamID/KeyID/
// PrivateKey set, the provider generates a valid ES256 client-secret
// JWT per exchange (previously the doc promised this but no signing
// path existed).
func TestAppleGeneratesClientSecret(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	var gotSecret string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSecret = r.Form.Get("client_secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"bearer","id_token":""}`))
	}))
	defer idp.Close()

	p := providers.Apple(providers.AppleConfig{
		ClientID: "com.example.app", TeamID: "TEAM123456", KeyID: "KEY1234567",
		PrivateKey: string(pemBytes),
	}).(*oauth2.StdProvider)
	// Point the token endpoint at the test server.
	p.Spec.Endpoints.TokenURL = idp.URL + "/token"

	if _, err := p.Exchange(context.Background(), "code", "verifier", "https://app/callback"); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if gotSecret == "" || strings.Count(gotSecret, ".") != 2 {
		t.Fatalf("client_secret is not a JWT: %q", gotSecret)
	}
	// It verifies against the public key and carries Apple's claims.
	claims, err := crypto.VerifyJWT(&key.PublicKey, gotSecret)
	if err != nil {
		t.Fatalf("generated client secret does not verify: %v", err)
	}
	if claims["iss"] != "TEAM123456" || claims["sub"] != "com.example.app" || claims["aud"] != "https://appleid.apple.com" {
		t.Fatalf("client secret claims = %v", claims)
	}
}

// The Spec.RedirectURI override (previously dead) is now used in the
// authorization URL.
func TestSpecRedirectURIOverride(t *testing.T) {
	p := oauth2.New(oauth2.Spec{
		ProviderID: "x", ClientID: "c",
		Endpoints:   oauth2.Endpoints{AuthorizationURL: "https://idp/authorize"},
		RedirectURI: "https://custom/callback",
	})
	authURL, err := p.AuthorizationURL(oauth2.AuthorizeRequest{
		RedirectURI: "https://default/callback", State: "s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(authURL, url.QueryEscape("https://custom/callback")) {
		t.Fatalf("auth URL did not use Spec.RedirectURI: %q", authURL)
	}
	if strings.Contains(authURL, url.QueryEscape("https://default/callback")) {
		t.Fatalf("auth URL used the fallback despite Spec.RedirectURI: %q", authURL)
	}
}
