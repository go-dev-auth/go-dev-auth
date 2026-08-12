package godevauth_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// lastSeenPlugin records when each user was last active, in a column it
// adds to the user table, and exposes an endpoint that updates it.
//
// A plugin implements three methods — ID, Init and Routes. Everything
// beyond that is an optional interface found by type assertion
// (SchemaPlugin here, and also MiddlewarePlugin, HookPlugin,
// SignInGuard, SessionGuard, SecretRotator), so a plugin can grow into
// one later without breaking anyone.
type lastSeenPlugin struct {
	auth *godevauth.Auth
}

// ID is the unique plugin identifier. Auth.Plugin looks plugins up by
// it, and New rejects two plugins that share one.
func (p *lastSeenPlugin) ID() string { return "last-seen" }

// Init runs once during godevauth.New. Validate options here and return
// an error to refuse an unusable configuration; do not panic.
func (p *lastSeenPlugin) Init(a *godevauth.Auth) error {
	p.auth = a
	return nil
}

// Schema implements godevauth.SchemaPlugin. A plugin may add whole
// tables or, as here, columns to a table the core owns.
//
// Columns added to a table that already has rows arrive nullable
// whatever Required says, so read them defensively and give them a
// Default. Note the absence of Input: a field a plugin owns is never
// client-writable.
func (p *lastSeenPlugin) Schema(s *storage.Schema) {
	s.AddFields(storage.ModelUser, storage.Field{
		Name: "lastSeenAt",
		Type: storage.FieldTime,
	})
}

// Routes are mounted under Config.BasePath, so "/last-seen" is served
// at "/api/auth/last-seen".
func (p *lastSeenPlugin) Routes() []godevauth.Route {
	return []godevauth.Route{{
		Method: http.MethodPost,
		Path:   "/last-seen",
		Handler: func(c *godevauth.Ctx) error {
			// RequireSession returns ErrUnauthorized when there is no
			// session, which the router renders as a 401.
			sd, err := c.RequireSession()
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			// Scope every write to the caller's own user.
			if _, err := p.auth.UpdateUserRecord(c.Context(), sd.User.ID,
				map[string]any{"lastSeenAt": now}); err != nil {
				return err
			}
			return c.JSON(http.StatusOK, map[string]any{"lastSeenAt": now})
		},
	}}
}

func ExamplePlugin() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{&lastSeenPlugin{}},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Sign a user up, then call the plugin's endpoint with the session
	// cookie the sign-up returned.
	signedUp := httptest.NewRecorder()
	signUp := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email",
		strings.NewReader(`{"email":"ada@example.com","password":"correct-horse","name":"Ada"}`))
	signUp.Header.Set("Content-Type", "application/json")
	auth.Handler().ServeHTTP(signedUp, signUp)

	ping := httptest.NewRequest(http.MethodPost, "/api/auth/last-seen", nil)
	for _, cookie := range signedUp.Result().Cookies() {
		ping.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	auth.Handler().ServeHTTP(rec, ping)
	fmt.Println("status:", rec.Code)

	user, err := auth.FindUserByEmail(context.Background(), "ada@example.com")
	if err != nil {
		log.Fatal(err)
	}
	_, recorded := user.Extra["lastSeenAt"]
	fmt.Println("recorded:", recorded)
	fmt.Println("registered as:", auth.Plugin("last-seen").ID())

	// Output:
	// status: 200
	// recorded: true
	// registered as: last-seen
}
