// Package oauth2 implements the OAuth 2.0 / OpenID Connect client flows
// used for social sign-in, including PKCE (RFC 7636).
package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Tokens is the result of a token exchange.
type Tokens struct {
	AccessToken           string
	RefreshToken          string
	IDToken               string
	TokenType             string
	Scope                 string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	Raw                   map[string]any
}

// UserProfile is the normalized user info returned by a provider.
type UserProfile struct {
	ID            string
	Name          string
	Email         string
	EmailVerified bool
	Image         string
	Raw           map[string]any
}

// AuthorizeRequest carries per-request authorization parameters.
type AuthorizeRequest struct {
	State        string
	RedirectURI  string
	Scopes       []string // extra scopes requested by the caller
	CodeVerifier string   // PKCE verifier; used when the provider supports PKCE
	LoginHint    string
	Prompt       string
}

// Provider is an OAuth or OIDC identity provider.
type Provider interface {
	// ID is the provider identifier used in URLs, e.g. "github".
	ID() string
	// AuthorizationURL builds the URL to redirect the user to.
	AuthorizationURL(req AuthorizeRequest) (string, error)
	// Exchange swaps an authorization code for tokens.
	Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*Tokens, error)
	// UserInfo fetches the user profile for the given tokens.
	UserInfo(ctx context.Context, tokens *Tokens) (*UserProfile, error)
}

// CrossSiteCallbackProvider is implemented by providers whose callback
// arrives as a cross-site POST (response_mode=form_post; Sign in with
// Apple is the canonical case) rather than a top-level GET redirect.
// The host uses it to relax the state cookie's SameSite policy, which
// would otherwise keep the cookie off the cross-site POST.
type CrossSiteCallbackProvider interface {
	CallbackIsCrossSite() bool
}

// RefreshableProvider is implemented by providers supporting refresh
// tokens.
type RefreshableProvider interface {
	RefreshToken(ctx context.Context, refreshToken string) (*Tokens, error)
}

// IDTokenVerifier is implemented by providers that can verify externally
// issued ID tokens (used for native "sign in with X" SDK flows).
type IDTokenVerifier interface {
	VerifyIDToken(ctx context.Context, idToken, nonce string) (*UserProfile, bool)
}

// Endpoints are the OAuth 2.0 endpoints of a provider.
type Endpoints struct {
	AuthorizationURL string
	TokenURL         string
	UserInfoURL      string
}

// Spec declaratively describes a standard OAuth2/OIDC provider. Most
// providers can be implemented with a Spec plus a MapProfile function.
type Spec struct {
	// ProviderID is the stable identifier, e.g. "google".
	ProviderID string
	// ClientID and ClientSecret are the app credentials.
	ClientID     string
	ClientSecret string
	// RedirectURI overrides the default {baseURL}/callback/{id}.
	RedirectURI string
	// Endpoints are the provider endpoints.
	Endpoints Endpoints
	// DefaultScopes always requested.
	DefaultScopes []string
	// ScopeSeparator defaults to " ".
	ScopeSeparator string
	// UsePKCE enables PKCE.
	UsePKCE bool
	// AuthStyleInHeader sends client credentials via Basic auth header
	// instead of the request body.
	AuthStyleInHeader bool
	// ExtraAuthParams are appended to the authorization URL.
	ExtraAuthParams map[string]string
	// UserInfoHeaders are extra headers for the user info request.
	UserInfoHeaders map[string]string
	// MapProfile converts the raw user info JSON to a UserProfile.
	MapProfile func(raw map[string]any) *UserProfile
	// FetchProfile overrides the user info request entirely.
	FetchProfile func(ctx context.Context, s *Spec, tokens *Tokens) (*UserProfile, error)
	// HTTPClient overrides http.DefaultClient.
	HTTPClient *http.Client
	// IDToken enables verification of provider-issued ID tokens, for
	// native "sign in with X" SDK flows where the app already holds a
	// token. Without it, StdProvider refuses those sign-ins rather than
	// trusting an unverified token.
	IDToken *IDTokenConfig
}

// StdProvider implements Provider from a Spec.
type StdProvider struct {
	Spec Spec
}

// New builds a Provider from a Spec.
func New(spec Spec) *StdProvider {
	if spec.ScopeSeparator == "" {
		spec.ScopeSeparator = " "
	}
	// Wire the HTTP client once at construction. Doing it lazily inside
	// VerifyIDToken wrote to a struct shared by every concurrent
	// sign-in, which is a data race.
	if spec.IDToken != nil && spec.IDToken.HTTPClient == nil && spec.HTTPClient != nil {
		spec.IDToken.HTTPClient = spec.HTTPClient
	}
	return &StdProvider{Spec: spec}
}

// ID implements Provider.
func (p *StdProvider) ID() string { return p.Spec.ProviderID }

// CallbackIsCrossSite implements CrossSiteCallbackProvider: a provider
// that asks for response_mode=form_post delivers its callback as a
// cross-site POST.
func (p *StdProvider) CallbackIsCrossSite() bool {
	return p.Spec.ExtraAuthParams["response_mode"] == "form_post"
}

func (p *StdProvider) client() *http.Client {
	if p.Spec.HTTPClient != nil {
		return p.Spec.HTTPClient
	}
	return http.DefaultClient
}

// AuthorizationURL implements Provider.
func (p *StdProvider) AuthorizationURL(req AuthorizeRequest) (string, error) {
	u, err := url.Parse(p.Spec.Endpoints.AuthorizationURL)
	if err != nil {
		return "", err
	}
	scopes := append([]string{}, p.Spec.DefaultScopes...)
	scopes = append(scopes, req.Scopes...)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.Spec.ClientID)
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("state", req.State)
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(dedupe(scopes), p.Spec.ScopeSeparator))
	}
	if p.Spec.UsePKCE && req.CodeVerifier != "" {
		q.Set("code_challenge", S256Challenge(req.CodeVerifier))
		q.Set("code_challenge_method", "S256")
	}
	if req.LoginHint != "" {
		q.Set("login_hint", req.LoginHint)
	}
	if req.Prompt != "" {
		q.Set("prompt", req.Prompt)
	}
	for k, v := range p.Spec.ExtraAuthParams {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange implements Provider.
func (p *StdProvider) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	if p.Spec.UsePKCE && codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}
	return p.tokenRequest(ctx, form)
}

// RefreshToken implements RefreshableProvider.
func (p *StdProvider) RefreshToken(ctx context.Context, refreshToken string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	return p.tokenRequest(ctx, form)
}

func (p *StdProvider) tokenRequest(ctx context.Context, form url.Values) (*Tokens, error) {
	if p.Spec.AuthStyleInHeader {
		// credentials in Authorization header
	} else {
		form.Set("client_id", p.Spec.ClientID)
		if p.Spec.ClientSecret != "" {
			form.Set("client_secret", p.Spec.ClientSecret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Spec.Endpoints.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.Spec.AuthStyleInHeader {
		req.SetBasicAuth(url.QueryEscape(p.Spec.ClientID), url.QueryEscape(p.Spec.ClientSecret))
	}
	res, err := p.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("oauth2: token endpoint returned %d: %s", res.StatusCode, truncate(string(body), 256))
	}
	raw := map[string]any{}
	if err := json.Unmarshal(body, &raw); err != nil {
		// some providers (older GitHub style) reply form-encoded
		vals, perr := url.ParseQuery(string(body))
		if perr != nil {
			return nil, fmt.Errorf("oauth2: cannot parse token response: %w", err)
		}
		raw = map[string]any{}
		for k := range vals {
			raw[k] = vals.Get(k)
		}
	}
	return tokensFromRaw(raw)
}

func tokensFromRaw(raw map[string]any) (*Tokens, error) {
	t := &Tokens{Raw: raw}
	t.AccessToken, _ = raw["access_token"].(string)
	t.RefreshToken, _ = raw["refresh_token"].(string)
	t.IDToken, _ = raw["id_token"].(string)
	t.TokenType, _ = raw["token_type"].(string)
	t.Scope, _ = raw["scope"].(string)
	if t.AccessToken == "" && t.IDToken == "" {
		return nil, errors.New("oauth2: token response missing access_token")
	}
	if exp, ok := numeric(raw["expires_in"]); ok && exp > 0 {
		t.AccessTokenExpiresAt = time.Now().Add(time.Duration(exp) * time.Second)
	}
	if exp, ok := numeric(raw["refresh_token_expires_in"]); ok && exp > 0 {
		t.RefreshTokenExpiresAt = time.Now().Add(time.Duration(exp) * time.Second)
	}
	return t, nil
}

// VerifyIDToken implements IDTokenVerifier when the provider spec
// configures ID token verification.
func (p *StdProvider) VerifyIDToken(ctx context.Context, idToken, nonce string) (*UserProfile, bool) {
	if p.Spec.IDToken == nil {
		return nil, false
	}
	return p.Spec.IDToken.VerifyIDToken(ctx, idToken, nonce)
}

// UserInfo implements Provider.
func (p *StdProvider) UserInfo(ctx context.Context, tokens *Tokens) (*UserProfile, error) {
	if p.Spec.FetchProfile != nil {
		return p.Spec.FetchProfile(ctx, &p.Spec, tokens)
	}
	if p.Spec.Endpoints.UserInfoURL == "" {
		return nil, errors.New("oauth2: provider has no user info endpoint")
	}
	raw, err := GetJSON(ctx, p.client(), p.Spec.Endpoints.UserInfoURL, tokens.AccessToken, p.Spec.UserInfoHeaders)
	if err != nil {
		return nil, err
	}
	if p.Spec.MapProfile == nil {
		return nil, errors.New("oauth2: provider has no profile mapper")
	}
	profile := p.Spec.MapProfile(raw)
	if profile == nil || profile.ID == "" {
		return nil, errors.New("oauth2: provider returned no user id")
	}
	profile.Raw = raw
	return profile, nil
}

// GetJSON performs an authenticated GET request returning parsed JSON.
func GetJSON(ctx context.Context, client *http.Client, url, accessToken string, headers map[string]string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("oauth2: %s returned %d: %s", url, res.StatusCode, truncate(string(body), 256))
	}
	out := map[string]any{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GenerateCodeVerifier returns a new PKCE code verifier.
func GenerateCodeVerifier() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("oauth2: rand failure: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// S256Challenge computes the S256 PKCE challenge of a verifier.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateState returns a random state value.
func GenerateState() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("oauth2: rand failure: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func numeric(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case string:
		var f float64
		_, err := fmt.Sscanf(t, "%f", &f)
		return f, err == nil
	}
	return 0, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Str reads a string field from a raw JSON map. Exposed for custom
// profile mappers.
func Str(raw map[string]any, key string) string {
	if v, ok := raw[key].(string); ok {
		return v
	}
	if v, ok := raw[key].(float64); ok {
		return strings.TrimSuffix(fmt.Sprintf("%f", v), ".000000")
	}
	return ""
}

// Bool reads a boolean field from a raw JSON map.
func Bool(raw map[string]any, key string) bool {
	v, _ := raw[key].(bool)
	return v
}
