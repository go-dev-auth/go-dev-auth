package providers_test

import (
	"fmt"
	"log"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/providers"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Each constructor returns an oauth2.Provider ready to drop into
// Config.SocialProviders.
//
// Unless you override RedirectURI, the callback each provider must be
// configured with is {BaseURL}{BasePath}/callback/{id} — so with the
// defaults, https://example.com/api/auth/callback/google.
func Example() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		SocialProviders: []oauth2.Provider{
			providers.Google(providers.Credentials{
				// Read these from the environment; they are secrets.
				ClientID:     "google-client-id",
				ClientSecret: "google-client-secret",
			}),
			providers.GitHub(providers.Credentials{
				ClientID:     "github-client-id",
				ClientSecret: "github-client-secret",
				// Appended to the provider's own default scopes.
				Scopes: []string{"read:org"},
			}),
			providers.MicrosoftTenant(providers.Credentials{
				ClientID:     "entra-client-id",
				ClientSecret: "entra-client-secret",
				// An explicit redirect, for when the provider's
				// registration cannot use the default.
				RedirectURI: "https://example.com/api/auth/callback/microsoft",
			}, "contoso.onmicrosoft.com"),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, id := range []string{"google", "github", "microsoft"} {
		fmt.Println(auth.SocialProvider(id).ID())
	}

	// Output:
	// google
	// github
	// microsoft
}
