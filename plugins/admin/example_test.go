package admin_test

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Administrative user management: listing, banning, roles and
// impersonation.
//
// The plugin adds a "role" column to the user table, but deliberately
// no endpoint that lets a user grant themselves one. Bootstrap the first
// administrator with AdminUserIDs, or write the role from your own
// tooling with Auth.UpdateUserRecord.
func ExampleNew() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{
			admin.New(admin.Options{
				DefaultRole: "user",
				AdminRoles:  []string{"admin", "superadmin"},
				// These user ids are administrators whatever their role
				// says — the escape hatch for bootstrapping.
				AdminUserIDs:                 []string{"seeded-founder-id"},
				ImpersonationSessionDuration: time.Hour,
				BannedUserMessage:            "This account has been suspended.",
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	count := 0
	for _, rt := range auth.Routes() {
		if strings.HasPrefix(rt.Path, "/admin/") {
			count++
		}
	}
	fmt.Println("admin endpoints:", count)
	fmt.Println("first one:", auth.Config().BasePath+"/admin/create-user")

	// Output:
	// admin endpoints: 13
	// first one: /api/auth/admin/create-user
}

// A ban takes effect immediately, not at the next sign-in: the plugin
// implements godevauth.SessionGuard, which runs on every request,
// including ones authenticated by an API key.
//
// Because a guard is registered, the signed session cookie cache is
// bypassed by default — a guard evaluated against a cached user would
// inspect fields that predate the ban. Set
// Session.CookieCache.AcceptStaleAuthorization to trade that back for
// the saved queries.
func ExamplePlugin_IsAdmin() {
	plugin := admin.New(admin.Options{AdminRoles: []string{"admin"}})

	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{plugin},
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	user, err := auth.CreateUser(ctx, &storage.User{Email: "root@example.com"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("before:", plugin.IsAdmin(user))

	// There is no endpoint for this on purpose.
	promoted, err := auth.UpdateUserRecord(ctx, user.ID, map[string]any{"role": "admin"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("after:", plugin.IsAdmin(promoted))

	// Output:
	// before: false
	// after: true
}
