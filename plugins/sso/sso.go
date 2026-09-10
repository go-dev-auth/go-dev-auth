// Package sso implements single sign-on against OpenID Connect
// identity providers registered at runtime — Okta, Microsoft Entra,
// Google Workspace, Keycloak, or anything speaking standard OIDC. Where
// Config.SocialProviders is a compile-time list for the application's
// own login buttons, this plugin lets each customer organization bring
// its own IdP: a provider row is stored in the database, matched to
// users by email domain, and the sign-in itself runs through the same
// hardened OAuth flow as every social login (single-use browser-bound
// state, PKCE, ID-token verification against the issuer's JWKS).
//
//	auth, _ := godevauth.New(godevauth.Config{
//		// ...
//		Plugins: []godevauth.Plugin{sso.New(sso.Options{
//			Authorize: func(c *godevauth.Ctx, sd *godevauth.SessionData) error {
//				return myApp.RequireAdmin(sd) // who may manage providers
//			},
//		})},
//	})
//
// Providers registered here surface as social providers with the id
// "sso:<providerId>", so /callback/sso:<providerId> is the redirect URI
// to register at the IdP (Auth.CallbackURL("sso:"+providerId) prints
// it), and account linking trust is controlled the same way as for any
// provider: list "sso:<providerId>" in
// Config.Account.AccountLinking.TrustedProviders to let its verified
// emails auto-link.
package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/ratelimit"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// ModelSSOProvider is the provider table name.
const ModelSSOProvider = "ssoProvider"

// IDPrefix namespaces SSO provider ids in the shared provider space, so
// a database row can never shadow a compile-time provider or vice
// versa.
const IDPrefix = "sso:"

const fieldClientSecret = "clientSecret"

// Options configures the sso plugin.
type Options struct {
	// Authorize gates provider management (/sso/register, /sso/list,
	// /sso/delete): it runs with the caller's session and returns an
	// error to refuse. There is no safe default — "any signed-in user
	// may point a login domain at their own IdP" is an account-takeover
	// primitive — so management endpoints refuse everything until this
	// is set. Registration from Go code (RegisterProvider) is not
	// affected.
	Authorize func(c *godevauth.Ctx, sd *godevauth.SessionData) error
	// DefaultScopes for authorization requests. Defaults to
	// ["openid", "profile", "email"].
	DefaultScopes []string
	// DisableDiscovery turns off fetching /.well-known/openid-configuration
	// at registration for providers registered without explicit
	// endpoints.
	DisableDiscovery bool
	// HTTPClient is used for discovery requests. Defaults to a client
	// with a 15-second timeout.
	HTTPClient *http.Client
}

// Plugin implements OIDC single sign-on.
type Plugin struct {
	opts Options
	auth *godevauth.Auth
}

// New builds the plugin.
func New(opts ...Options) *Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if len(o.DefaultScopes) == 0 {
		o.DefaultScopes = []string{"openid", "profile", "email"}
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Plugin{opts: o}
}

// ID implements godevauth.Plugin.
func (p *Plugin) ID() string { return "sso" }

// Init implements godevauth.Plugin.
func (p *Plugin) Init(a *godevauth.Auth) error {
	p.auth = a
	return nil
}

// Schema implements godevauth.SchemaPlugin.
func (p *Plugin) Schema(s *storage.Schema) {
	s.AddTable(&storage.Table{Name: ModelSSOProvider, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "providerId", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "issuer", Type: storage.FieldString, Required: true},
		{Name: "domain", Type: storage.FieldString, Index: true},
		{Name: "clientId", Type: storage.FieldString, Required: true},
		{Name: fieldClientSecret, Type: storage.FieldText},
		{Name: "authorizationEndpoint", Type: storage.FieldText, Required: true},
		{Name: "tokenEndpoint", Type: storage.FieldText, Required: true},
		{Name: "jwksEndpoint", Type: storage.FieldText},
		{Name: "userInfoEndpoint", Type: storage.FieldText},
		{Name: "scopes", Type: storage.FieldText},
		{Name: "createdAt", Type: storage.FieldTime, Required: true},
		{Name: "updatedAt", Type: storage.FieldTime, Required: true},
	}})
}

// ReencryptSecrets implements godevauth.SecretRotator for the stored
// client secrets.
func (p *Plugin) ReencryptSecrets(ctx context.Context) (godevauth.ReencryptResult, error) {
	return p.auth.ReencryptRecords(ctx, ModelSSOProvider, fieldClientSecret)
}

// Routes implements godevauth.Plugin.
func (p *Plugin) Routes() []godevauth.Route {
	strict := &ratelimit.Rule{Window: 10 * time.Second, Max: 3}
	moderate := &ratelimit.Rule{Window: 10 * time.Second, Max: 5}
	return []godevauth.Route{
		{Method: http.MethodPost, Path: "/sso/register", Handler: p.handleRegister, RateLimit: strict},
		{Method: http.MethodGet, Path: "/sso/list", Handler: p.handleList},
		{Method: http.MethodPost, Path: "/sso/delete", Handler: p.handleDelete},
		{Method: http.MethodPost, Path: "/sign-in/sso", Handler: p.handleSignIn, RateLimit: moderate},
	}
}

// SocialProvider implements godevauth.ProviderSourcePlugin: it resolves
// "sso:<providerId>" ids so the core /callback route (and, if a client
// prefers it, /sign-in/social) can drive SSO flows.
func (p *Plugin) SocialProvider(id string) oauth2.Provider {
	providerID, ok := strings.CutPrefix(id, IDPrefix)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, err := p.auth.Storage().FindOne(ctx, ModelSSOProvider,
		[]storage.Where{storage.W("providerId", providerID)})
	if err != nil {
		return nil
	}
	provider, err := p.buildProvider(rec)
	if err != nil {
		p.auth.Logger().Error("sso: stored provider is unusable", "providerId", providerID, "err", err)
		return nil
	}
	return provider
}

// ---- registration & management ----

// providerIDRe keeps provider ids URL- and cookie-safe: they appear in
// the callback path.
var providerIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

type registerBody struct {
	ProviderID            string   `json:"providerId"`
	Issuer                string   `json:"issuer"`
	Domain                string   `json:"domain"`
	ClientID              string   `json:"clientId"`
	ClientSecret          string   `json:"clientSecret"`
	AuthorizationEndpoint string   `json:"authorizationEndpoint"`
	TokenEndpoint         string   `json:"tokenEndpoint"`
	JWKSEndpoint          string   `json:"jwksEndpoint"`
	UserInfoEndpoint      string   `json:"userInfoEndpoint"`
	Scopes                []string `json:"scopes"`
}

func (p *Plugin) authorize(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	if p.opts.Authorize == nil {
		// Fail closed. An unauthorized register endpoint would let any
		// account point a sign-in domain at an IdP it controls.
		return godevauth.NewAPIError(http.StatusForbidden, "SSO_MANAGEMENT_DISABLED",
			"Provider management requires sso.Options.Authorize to be configured")
	}
	return p.opts.Authorize(c, sd)
}

func (p *Plugin) handleRegister(c *godevauth.Ctx) error {
	if err := p.authorize(c); err != nil {
		return err
	}
	var body registerBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	cfg := ProviderConfig{
		ProviderID:            body.ProviderID,
		Issuer:                body.Issuer,
		Domain:                body.Domain,
		ClientID:              body.ClientID,
		ClientSecret:          body.ClientSecret,
		AuthorizationEndpoint: body.AuthorizationEndpoint,
		TokenEndpoint:         body.TokenEndpoint,
		JWKSEndpoint:          body.JWKSEndpoint,
		UserInfoEndpoint:      body.UserInfoEndpoint,
		Scopes:                body.Scopes,
	}
	rec, err := p.RegisterProvider(c.Context(), cfg)
	if err != nil {
		return err
	}
	p.auth.EmitEvent(c, godevauth.Event{
		Type: godevauth.EventType("sso.provider_registered"), Method: p.ID(),
	})
	return c.JSON(http.StatusOK, p.publicView(rec))
}

// ProviderConfig describes an OIDC provider registration.
type ProviderConfig struct {
	// ProviderID names the provider in URLs: lowercase letters, digits
	// and dashes.
	ProviderID string
	// Issuer is the OIDC issuer URL (https). When the endpoint fields
	// are empty and discovery is enabled, it is also where
	// /.well-known/openid-configuration is fetched from.
	Issuer string
	// Domain is the email domain routed to this provider by
	// /sign-in/sso, e.g. "corp.example.com". Optional: a provider can
	// also be addressed by ProviderID alone.
	Domain string
	// ClientID and ClientSecret are the relying-party credentials
	// registered at the IdP. The secret is encrypted at rest.
	ClientID     string
	ClientSecret string
	// Explicit endpoints; filled by discovery when empty.
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSEndpoint          string
	UserInfoEndpoint      string
	// Scopes overrides Options.DefaultScopes for this provider.
	Scopes []string
}

// RegisterProvider validates cfg (running OIDC discovery when the
// endpoints are not given) and stores it. It is the code path behind
// /sso/register and is exported so deployments can register providers
// at startup without opening the HTTP surface.
func (p *Plugin) RegisterProvider(ctx context.Context, cfg ProviderConfig) (map[string]any, error) {
	if !providerIDRe.MatchString(cfg.ProviderID) {
		return nil, godevauth.NewAPIError(http.StatusBadRequest, "INVALID_PROVIDER_ID",
			"providerId must be lowercase letters, digits and dashes")
	}
	if cfg.ClientID == "" {
		return nil, godevauth.NewAPIError(http.StatusBadRequest, "INVALID_BODY", "clientId is required")
	}
	if !isSecureURL(cfg.Issuer) {
		return nil, godevauth.NewAPIError(http.StatusBadRequest, "INVALID_ISSUER",
			"issuer must be an https URL")
	}
	cfg.Domain = strings.ToLower(strings.TrimSpace(cfg.Domain))
	if strings.ContainsAny(cfg.Domain, "@/ ") {
		return nil, godevauth.NewAPIError(http.StatusBadRequest, "INVALID_DOMAIN",
			"domain must be a bare host name like corp.example.com")
	}

	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
		if p.opts.DisableDiscovery {
			return nil, godevauth.NewAPIError(http.StatusBadRequest, "ENDPOINTS_REQUIRED",
				"authorizationEndpoint and tokenEndpoint are required when discovery is disabled")
		}
		disc, err := p.discover(ctx, cfg.Issuer)
		if err != nil {
			return nil, godevauth.NewAPIError(http.StatusBadRequest, "DISCOVERY_FAILED",
				"OIDC discovery failed: "+err.Error())
		}
		if cfg.AuthorizationEndpoint == "" {
			cfg.AuthorizationEndpoint = disc.AuthorizationEndpoint
		}
		if cfg.TokenEndpoint == "" {
			cfg.TokenEndpoint = disc.TokenEndpoint
		}
		if cfg.JWKSEndpoint == "" {
			cfg.JWKSEndpoint = disc.JWKSURI
		}
		if cfg.UserInfoEndpoint == "" {
			cfg.UserInfoEndpoint = disc.UserInfoEndpoint
		}
	}
	for name, ep := range map[string]string{
		"authorizationEndpoint": cfg.AuthorizationEndpoint,
		"tokenEndpoint":         cfg.TokenEndpoint,
	} {
		if !isSecureURL(ep) {
			return nil, godevauth.NewAPIError(http.StatusBadRequest, "INVALID_ENDPOINT",
				name+" must be an https URL")
		}
	}
	if cfg.JWKSEndpoint == "" && cfg.UserInfoEndpoint == "" {
		return nil, godevauth.NewAPIError(http.StatusBadRequest, "INVALID_ENDPOINT",
			"at least one of jwksEndpoint (ID-token verification) or userInfoEndpoint is required")
	}

	now := time.Now().UTC()
	recordID := crypto.GenerateID(32)
	rec := map[string]any{
		"id":                    recordID,
		"providerId":            cfg.ProviderID,
		"issuer":                cfg.Issuer,
		"domain":                cfg.Domain,
		"clientId":              cfg.ClientID,
		"authorizationEndpoint": cfg.AuthorizationEndpoint,
		"tokenEndpoint":         cfg.TokenEndpoint,
		"jwksEndpoint":          cfg.JWKSEndpoint,
		"userInfoEndpoint":      cfg.UserInfoEndpoint,
		"scopes":                strings.Join(cfg.Scopes, " "),
		"createdAt":             now,
		"updatedAt":             now,
	}
	if cfg.ClientSecret != "" {
		enc, err := p.auth.Keyring().Encrypt(crypto.Binding{
			Model: ModelSSOProvider, Record: recordID, Field: fieldClientSecret,
		}, cfg.ClientSecret)
		if err != nil {
			return nil, err
		}
		rec[fieldClientSecret] = enc
	}
	if _, err := p.auth.Storage().Create(ctx, ModelSSOProvider, rec); err != nil {
		if errors.Is(err, storage.ErrUniqueViolation) {
			return nil, godevauth.NewAPIError(http.StatusBadRequest, "PROVIDER_EXISTS",
				"A provider with this providerId is already registered")
		}
		return nil, err
	}
	return rec, nil
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

func (p *Plugin) discover(ctx context.Context, issuer string) (*discovery, error) {
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := p.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery document returned %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	// RFC 8414 §3.3: the document must assert the issuer it was fetched
	// for, or a compromised path component serves another tenant's
	// endpoints.
	if strings.TrimSuffix(d.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
		return nil, fmt.Errorf("discovery issuer %q does not match %q", d.Issuer, issuer)
	}
	return &d, nil
}

func (p *Plugin) handleList(c *godevauth.Ctx) error {
	if err := p.authorize(c); err != nil {
		return err
	}
	recs, err := p.auth.Storage().FindMany(c.Context(), ModelSSOProvider, nil, nil)
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(recs))
	for _, r := range recs {
		out = append(out, p.publicView(r))
	}
	return c.JSON(http.StatusOK, out)
}

func (p *Plugin) handleDelete(c *godevauth.Ctx) error {
	if err := p.authorize(c); err != nil {
		return err
	}
	var body struct {
		ProviderID string `json:"providerId"`
	}
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := p.auth.Storage().Delete(c.Context(), ModelSSOProvider,
		[]storage.Where{storage.W("providerId", body.ProviderID)}); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

// ---- sign-in ----

type signInBody struct {
	Email            string `json:"email"`
	Domain           string `json:"domain"`
	ProviderID       string `json:"providerId"`
	CallbackURL      string `json:"callbackURL"`
	ErrorCallbackURL string `json:"errorCallbackURL"`
	DisableRedirect  bool   `json:"disableRedirect"`
}

var errNoProvider = godevauth.NewAPIError(http.StatusNotFound, "SSO_PROVIDER_NOT_FOUND",
	"No SSO provider is registered for this domain")

func (p *Plugin) handleSignIn(c *godevauth.Ctx) error {
	var body signInBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	ctx := c.Context()

	var where []storage.Where
	loginHint := ""
	switch {
	case body.ProviderID != "":
		where = []storage.Where{storage.W("providerId", body.ProviderID)}
	case body.Domain != "":
		where = []storage.Where{storage.W("domain", strings.ToLower(body.Domain))}
	case strings.Count(body.Email, "@") == 1:
		domain := strings.ToLower(body.Email[strings.Index(body.Email, "@")+1:])
		where = []storage.Where{storage.W("domain", domain)}
		loginHint = body.Email
	default:
		return godevauth.ErrInvalidBody
	}
	rec, err := p.auth.Storage().FindOne(ctx, ModelSSOProvider, where)
	if err != nil {
		return errNoProvider
	}
	provider, err := p.buildProvider(rec)
	if err != nil {
		return err
	}
	authURL, err := p.auth.StartOAuthFlow(c, provider, godevauth.OAuthFlowOptions{
		CallbackURL:      body.CallbackURL,
		ErrorCallbackURL: body.ErrorCallbackURL,
		LoginHint:        loginHint,
	})
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"url": authURL, "redirect": !body.DisableRedirect})
}

// buildProvider assembles an oauth2 provider from a stored row.
func (p *Plugin) buildProvider(rec map[string]any) (oauth2.Provider, error) {
	secret := str(rec[fieldClientSecret])
	if secret != "" {
		plain, err := p.auth.Keyring().Decrypt(crypto.Binding{
			Model: ModelSSOProvider, Record: str(rec["id"]), Field: fieldClientSecret,
		}, secret)
		if err != nil {
			// Fail closed: an unreadable secret means a misconfigured
			// rotation, not a provider without a secret.
			return nil, fmt.Errorf("sso: decrypting client secret for %q: %w", str(rec["providerId"]), err)
		}
		secret = plain
	}
	scopes := strings.Fields(str(rec["scopes"]))
	if len(scopes) == 0 {
		scopes = p.opts.DefaultScopes
	}
	spec := oauth2.Spec{
		ProviderID:   IDPrefix + str(rec["providerId"]),
		ClientID:     str(rec["clientId"]),
		ClientSecret: secret,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: str(rec["authorizationEndpoint"]),
			TokenURL:         str(rec["tokenEndpoint"]),
			UserInfoURL:      str(rec["userInfoEndpoint"]),
		},
		DefaultScopes: scopes,
		UsePKCE:       true,
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			return &oauth2.UserProfile{
				ID:            oauth2.Str(raw, "sub"),
				Name:          oauth2.Str(raw, "name"),
				Email:         oauth2.Str(raw, "email"),
				EmailVerified: oauth2.Bool(raw, "email_verified"),
				Image:         oauth2.Str(raw, "picture"),
			}
		},
	}
	if jwks := str(rec["jwksEndpoint"]); jwks != "" {
		idToken := &oauth2.IDTokenConfig{
			Issuer:   str(rec["issuer"]),
			JWKSURL:  jwks,
			Audience: str(rec["clientId"]),
		}
		spec.IDToken = idToken
		if spec.Endpoints.UserInfoURL == "" {
			// No userinfo endpoint: the profile comes from the ID token,
			// verified against the issuer's JWKS (the Apple pattern).
			spec.FetchProfile = func(ctx context.Context, s *oauth2.Spec, tokens *oauth2.Tokens) (*oauth2.UserProfile, error) {
				if tokens.IDToken == "" {
					return nil, errors.New("sso: token response carried no id_token")
				}
				profile, ok := idToken.VerifyIDToken(ctx, tokens.IDToken, "")
				if !ok {
					return nil, errors.New("sso: id_token failed verification")
				}
				return profile, nil
			}
		}
	}
	return oauth2.New(spec), nil
}

// publicView strips the client secret from a provider row.
func (p *Plugin) publicView(rec map[string]any) map[string]any {
	out := make(map[string]any, len(rec))
	for k, v := range rec {
		if k == fieldClientSecret {
			continue
		}
		out[k] = v
	}
	return out
}

// isSecureURL accepts https URLs, plus plain http for loopback hosts so
// local development and tests can run an IdP on localhost.
func isSecureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
