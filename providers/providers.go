// Package providers ships ready-made configurations for popular OAuth /
// OIDC identity providers, mirroring better-auth's built-in social
// providers.
//
//	godevauth.Config{
//		SocialProviders: []oauth2.Provider{
//			providers.Google(providers.Credentials{ClientID: "...", ClientSecret: "..."}),
//			providers.GitHub(providers.Credentials{ClientID: "...", ClientSecret: "..."}),
//		},
//	}
package providers

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
)

// Credentials configures a provider.
type Credentials struct {
	ClientID     string
	ClientSecret string
	// RedirectURI overrides the default {baseURL}{basePath}/callback/{provider}.
	RedirectURI string
	// Scopes are appended to the provider's default scopes.
	Scopes []string
}

// Google returns the Google OIDC provider.
func Google(c Credentials) oauth2.Provider {
	return oauth2.New(oauth2.Spec{
		ProviderID:   "google",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:         "https://oauth2.googleapis.com/token",
			UserInfoURL:      "https://openidconnect.googleapis.com/v1/userinfo",
		},
		DefaultScopes: append([]string{"openid", "email", "profile"}, c.Scopes...),
		UsePKCE:       true,
		ExtraAuthParams: map[string]string{
			"access_type": "offline",
		},
		// Enables the native-SDK sign-in path: an ID token obtained by
		// a mobile app is accepted only after its signature, issuer and
		// audience are verified against Google's published keys.
		IDToken: &oauth2.IDTokenConfig{
			Issuer:   "https://accounts.google.com",
			JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
			Audience: c.ClientID,
		},
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			return &oauth2.UserProfile{
				ID:            oauth2.Str(raw, "sub"),
				Name:          oauth2.Str(raw, "name"),
				Email:         oauth2.Str(raw, "email"),
				EmailVerified: oauth2.Bool(raw, "email_verified"),
				Image:         oauth2.Str(raw, "picture"),
			}
		},
	})
}

// GitHub returns the GitHub provider.
func GitHub(c Credentials) oauth2.Provider {
	return oauth2.New(oauth2.Spec{
		ProviderID:   "github",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: "https://github.com/login/oauth/authorize",
			TokenURL:         "https://github.com/login/oauth/access_token",
			UserInfoURL:      "https://api.github.com/user",
		},
		DefaultScopes: append([]string{"read:user", "user:email"}, c.Scopes...),
		FetchProfile:  fetchGitHubProfile,
	})
}

func fetchGitHubProfile(ctx context.Context, s *oauth2.Spec, tokens *oauth2.Tokens) (*oauth2.UserProfile, error) {
	client := s.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}
	raw, err := oauth2.GetJSON(ctx, client, "https://api.github.com/user", tokens.AccessToken, nil)
	if err != nil {
		return nil, err
	}
	profile := &oauth2.UserProfile{
		ID:    oauth2.Str(raw, "id"),
		Name:  firstNonEmpty(oauth2.Str(raw, "name"), oauth2.Str(raw, "login")),
		Email: oauth2.Str(raw, "email"),
		Image: oauth2.Str(raw, "avatar_url"),
		Raw:   raw,
	}
	if profile.ID == "" {
		if v, ok := raw["id"].(float64); ok {
			profile.ID = fmt.Sprintf("%.0f", v)
		}
	}
	// fetch primary verified e-mail when not public
	if profile.Email == "" {
		emailsRaw, err := getJSONList(ctx, client, "https://api.github.com/user/emails", tokens.AccessToken)
		if err == nil {
			for _, e := range emailsRaw {
				if em, ok := e.(map[string]any); ok {
					if primary, _ := em["primary"].(bool); primary {
						profile.Email = oauth2.Str(em, "email")
						profile.EmailVerified, _ = em["verified"].(bool)
						break
					}
				}
			}
		}
	}
	// A public profile email carries no verification signal; only the
	// "verified" flag from /user/emails does, and it is set above.
	return profile, nil
}

// Discord returns the Discord provider.
func Discord(c Credentials) oauth2.Provider {
	return oauth2.New(oauth2.Spec{
		ProviderID:   "discord",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: "https://discord.com/oauth2/authorize",
			TokenURL:         "https://discord.com/api/oauth2/token",
			UserInfoURL:      "https://discord.com/api/users/@me",
		},
		DefaultScopes: append([]string{"identify", "email"}, c.Scopes...),
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			id := oauth2.Str(raw, "id")
			avatar := oauth2.Str(raw, "avatar")
			image := ""
			if avatar != "" {
				image = "https://cdn.discordapp.com/avatars/" + id + "/" + avatar + ".png"
			}
			return &oauth2.UserProfile{
				ID:            id,
				Name:          firstNonEmpty(oauth2.Str(raw, "global_name"), oauth2.Str(raw, "username")),
				Email:         oauth2.Str(raw, "email"),
				EmailVerified: oauth2.Bool(raw, "verified"),
				Image:         image,
			}
		},
	})
}

// Facebook returns the Facebook provider.
func Facebook(c Credentials) oauth2.Provider {
	return oauth2.New(oauth2.Spec{
		ProviderID:   "facebook",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: "https://www.facebook.com/v21.0/dialog/oauth",
			TokenURL:         "https://graph.facebook.com/v21.0/oauth/access_token",
			UserInfoURL:      "https://graph.facebook.com/v21.0/me?fields=id,name,email,picture",
		},
		DefaultScopes: append([]string{"email", "public_profile"}, c.Scopes...),
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			image := ""
			if pic, ok := raw["picture"].(map[string]any); ok {
				if data, ok := pic["data"].(map[string]any); ok {
					image = oauth2.Str(data, "url")
				}
			}
			// Facebook only returns an address it has confirmed, but it
			// publishes no per-address claim; treat it as unverified so
			// linking still requires the provider to be trusted.
			return &oauth2.UserProfile{
				ID:            oauth2.Str(raw, "id"),
				Name:          oauth2.Str(raw, "name"),
				Email:         oauth2.Str(raw, "email"),
				EmailVerified: false,
				Image:         image,
			}
		},
	})
}

// Microsoft returns the Microsoft Entra ID (Azure AD) provider using the
// common tenant.
func Microsoft(c Credentials) oauth2.Provider {
	return MicrosoftTenant(c, "common")
}

// MicrosoftTenant returns the Microsoft provider for a specific tenant.
func MicrosoftTenant(c Credentials, tenant string) oauth2.Provider {
	base := "https://login.microsoftonline.com/" + tenant
	return oauth2.New(oauth2.Spec{
		ProviderID:   "microsoft",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: base + "/oauth2/v2.0/authorize",
			TokenURL:         base + "/oauth2/v2.0/token",
			UserInfoURL:      "https://graph.microsoft.com/oidc/userinfo",
		},
		DefaultScopes: append([]string{"openid", "profile", "email", "offline_access"}, c.Scopes...),
		UsePKCE:       true,
		IDToken:       microsoftIDToken(c.ClientID, tenant, base),
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			// Only an explicit provider claim counts as verification.
			// Entra's "email" claim is user-settable, so treating its
			// presence as proof is the nOAuth takeover pattern.
			return &oauth2.UserProfile{
				ID:            oauth2.Str(raw, "sub"),
				Name:          oauth2.Str(raw, "name"),
				Email:         oauth2.Str(raw, "email"),
				EmailVerified: oauth2.Bool(raw, "email_verified"),
				Image:         oauth2.Str(raw, "picture"),
			}
		},
	})
}

// microsoftIDToken builds the ID-token config for a tenant. For the
// multi-tenant aliases ("common", "organizations", "consumers") real
// tokens never carry the alias in "iss" — they carry the user's tenant
// GUID — so an exact issuer match failed closed and the ID-token path
// was dead. Those aliases validate the issuer's shape instead and bind
// it to the token's own "tid" claim.
func microsoftIDToken(clientID, tenant, base string) *oauth2.IDTokenConfig {
	cfg := &oauth2.IDTokenConfig{
		Issuer:   "https://login.microsoftonline.com/" + tenant + "/v2.0",
		JWKSURL:  base + "/discovery/v2.0/keys",
		Audience: clientID,
	}
	switch tenant {
	case "common", "organizations", "consumers":
		cfg.ValidateIssuer = microsoftMultiTenantIssuer
	}
	return cfg
}

var microsoftIssuerRe = regexp.MustCompile(`^https://login\.microsoftonline\.com/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/v2\.0$`)

// microsoftMultiTenantIssuer accepts an issuer of the documented Entra
// shape whose tenant GUID equals the token's own tid claim. The tid
// binding matters: the shape check alone would accept a token from any
// Entra tenant, which for a multi-tenant app is the intended audience —
// but the claims must at least agree with each other, and consumers of
// the profile get a trustworthy tenant id in Raw["tid"].
func microsoftMultiTenantIssuer(iss string, claims crypto.Claims) bool {
	m := microsoftIssuerRe.FindStringSubmatch(iss)
	if m == nil {
		return false
	}
	tid, _ := claims["tid"].(string)
	return tid != "" && strings.EqualFold(m[1], tid)
}

// GitLab returns the GitLab provider (gitlab.com).
func GitLab(c Credentials) oauth2.Provider {
	return GitLabSelfHosted(c, "https://gitlab.com")
}

// GitLabSelfHosted returns the GitLab provider for a self-hosted
// instance.
func GitLabSelfHosted(c Credentials, baseURL string) oauth2.Provider {
	baseURL = strings.TrimSuffix(baseURL, "/")
	return oauth2.New(oauth2.Spec{
		ProviderID:   "gitlab",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: baseURL + "/oauth/authorize",
			TokenURL:         baseURL + "/oauth/token",
			UserInfoURL:      baseURL + "/api/v4/user",
		},
		DefaultScopes: append([]string{"read_user"}, c.Scopes...),
		UsePKCE:       true,
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			return &oauth2.UserProfile{
				ID:    oauth2.Str(raw, "id"),
				Name:  firstNonEmpty(oauth2.Str(raw, "name"), oauth2.Str(raw, "username")),
				Email: oauth2.Str(raw, "email"),
				// GitLab (including self-hosted, where the operator is
				// not necessarily trusted) exposes no verification
				// claim, so nothing here is treated as verified.
				EmailVerified: false,
				Image:         oauth2.Str(raw, "avatar_url"),
			}
		},
	})
}

// LinkedIn returns the LinkedIn provider (OpenID Connect).
func LinkedIn(c Credentials) oauth2.Provider {
	return oauth2.New(oauth2.Spec{
		ProviderID:   "linkedin",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: "https://www.linkedin.com/oauth/v2/authorization",
			TokenURL:         "https://www.linkedin.com/oauth/v2/accessToken",
			UserInfoURL:      "https://api.linkedin.com/v2/userinfo",
		},
		DefaultScopes: append([]string{"openid", "profile", "email"}, c.Scopes...),
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			return &oauth2.UserProfile{
				ID:            oauth2.Str(raw, "sub"),
				Name:          oauth2.Str(raw, "name"),
				Email:         oauth2.Str(raw, "email"),
				EmailVerified: oauth2.Bool(raw, "email_verified"),
				Image:         oauth2.Str(raw, "picture"),
			}
		},
	})
}

// Spotify returns the Spotify provider.
func Spotify(c Credentials) oauth2.Provider {
	return oauth2.New(oauth2.Spec{
		ProviderID:   "spotify",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: "https://accounts.spotify.com/authorize",
			TokenURL:         "https://accounts.spotify.com/api/token",
			UserInfoURL:      "https://api.spotify.com/v1/me",
		},
		DefaultScopes: append([]string{"user-read-email"}, c.Scopes...),
		UsePKCE:       true,
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			image := ""
			if imgs, ok := raw["images"].([]any); ok && len(imgs) > 0 {
				if img, ok := imgs[0].(map[string]any); ok {
					image = oauth2.Str(img, "url")
				}
			}
			return &oauth2.UserProfile{
				ID:            oauth2.Str(raw, "id"),
				Name:          oauth2.Str(raw, "display_name"),
				Email:         oauth2.Str(raw, "email"),
				EmailVerified: false,
				Image:         image,
			}
		},
	})
}

// Twitch returns the Twitch provider.
func Twitch(c Credentials) oauth2.Provider {
	spec := oauth2.Spec{
		ProviderID:   "twitch",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: "https://id.twitch.tv/oauth2/authorize",
			TokenURL:         "https://id.twitch.tv/oauth2/token",
			UserInfoURL:      "https://api.twitch.tv/helix/users",
		},
		DefaultScopes: append([]string{"user:read:email"}, c.Scopes...),
		UserInfoHeaders: map[string]string{
			"Client-Id": c.ClientID,
		},
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			data, ok := raw["data"].([]any)
			if !ok || len(data) == 0 {
				return nil
			}
			u, ok := data[0].(map[string]any)
			if !ok {
				return nil
			}
			return &oauth2.UserProfile{
				ID:            oauth2.Str(u, "id"),
				Name:          firstNonEmpty(oauth2.Str(u, "display_name"), oauth2.Str(u, "login")),
				Email:         oauth2.Str(u, "email"),
				EmailVerified: false,
				Image:         oauth2.Str(u, "profile_image_url"),
			}
		},
	}
	return oauth2.New(spec)
}

// X returns the X (Twitter) OAuth 2.0 provider.
func X(c Credentials) oauth2.Provider {
	return oauth2.New(oauth2.Spec{
		ProviderID:   "x",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: "https://x.com/i/oauth2/authorize",
			TokenURL:         "https://api.x.com/2/oauth2/token",
			UserInfoURL:      "https://api.x.com/2/users/me?user.fields=profile_image_url",
		},
		DefaultScopes:     append([]string{"users.read", "tweet.read", "offline.access"}, c.Scopes...),
		UsePKCE:           true,
		AuthStyleInHeader: true,
		MapProfile: func(raw map[string]any) *oauth2.UserProfile {
			data, ok := raw["data"].(map[string]any)
			if !ok {
				return nil
			}
			return &oauth2.UserProfile{
				ID:    oauth2.Str(data, "id"),
				Name:  firstNonEmpty(oauth2.Str(data, "name"), oauth2.Str(data, "username")),
				Image: oauth2.Str(data, "profile_image_url"),
			}
		},
	})
}

// AppleConfig configures Sign in with Apple. Apple requires a JWT client
// secret; either provide a pre-generated ClientSecret or the key
// parameters to generate one per exchange.
type AppleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// Apple returns the Sign in with Apple provider. The user profile is
// derived from the returned ID token, after verifying its signature
// against Apple's published keys.
func Apple(c AppleConfig) oauth2.Provider {
	appleIDToken := &oauth2.IDTokenConfig{
		Issuer:   "https://appleid.apple.com",
		JWKSURL:  "https://appleid.apple.com/auth/keys",
		Audience: c.ClientID,
	}
	return oauth2.New(oauth2.Spec{
		ProviderID:   "apple",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURI:  c.RedirectURI,
		Endpoints: oauth2.Endpoints{
			AuthorizationURL: "https://appleid.apple.com/auth/authorize",
			TokenURL:         "https://appleid.apple.com/auth/token",
		},
		DefaultScopes: append([]string{"name", "email"}, c.Scopes...),
		ExtraAuthParams: map[string]string{
			"response_mode": "form_post",
		},
		IDToken: appleIDToken,
		// Apple returns no user-info endpoint: the profile comes from
		// the ID token, which is verified against Apple's JWKS rather
		// than merely decoded. Decoding alone would trust whatever the
		// token endpoint returned, including its audience — so a token
		// minted for a different Apple client would be accepted.
		FetchProfile: func(ctx context.Context, s *oauth2.Spec, tokens *oauth2.Tokens) (*oauth2.UserProfile, error) {
			if tokens.IDToken == "" {
				return nil, fmt.Errorf("apple: token response missing id_token")
			}
			profile, ok := appleIDToken.VerifyIDToken(ctx, tokens.IDToken, "")
			if !ok {
				return nil, fmt.Errorf("apple: id_token failed verification")
			}
			return profile, nil
		},
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
