package organization_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/organization"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Multi-tenant organizations with members, roles and invitations.
//
// The plugin adds an activeOrganizationId column to the session, so the
// "which tenant am I acting in" question is answered per session rather
// than per request.
func ExampleNew() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{
			organization.New(organization.Options{
				OrganizationLimit:   5,
				MembershipLimit:     100,
				CreatorRole:         organization.RoleOwner,
				InvitationExpiresIn: 48 * time.Hour,
				SendInvitationEmail: func(ctx context.Context, inv *organization.Invitation,
					org *organization.Organization, inviter *storage.User) error {
					log.Printf("email to %s: %s invited you to %s as %s (invitation %s)",
						inv.Email, inviter.Email, org.Name, inv.Role, inv.ID)
					return nil
				},
				// Adds the /organization/*-team endpoints and the team
				// tables. Off by default.
				Teams: true,
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// The tables the plugin contributes, on top of the four core ones.
	var added []string
	for _, name := range auth.Schema().TableNames() {
		switch name {
		case storage.ModelUser, storage.ModelSession, storage.ModelAccount, storage.ModelVerification:
		default:
			added = append(added, name)
		}
	}
	fmt.Println(strings.Join(added, " "))

	// Output: organization member invitation team teamMember
}

// Creating an organization. The creator becomes its owner, and setting
// it active records it on their session so later calls do not have to
// pass an organizationId.
func Example_createOrganization() {
	plugin := organization.New(organization.Options{
		SendInvitationEmail: func(ctx context.Context, inv *organization.Invitation,
			org *organization.Organization, inviter *storage.User) error {
			return nil
		},
	})

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

	jar := map[string]*http.Cookie{}
	post := func(path, body string) map[string]any {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for _, cookie := range jar {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		auth.Handler().ServeHTTP(rec, req)
		res := rec.Result()
		for _, cookie := range res.Cookies() {
			jar[cookie.Name] = cookie
		}
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return out
	}

	post("/api/auth/sign-up/email",
		`{"email":"ada@example.com","password":"correct-horse","name":"Ada"}`)
	org := post("/api/auth/organization/create", `{"name":"Acme","slug":"acme"}`)
	orgID, _ := org["id"].(string)
	fmt.Println("slug:", org["slug"])

	user, err := auth.FindUserByEmail(context.Background(), "ada@example.com")
	if err != nil {
		log.Fatal(err)
	}
	member, err := plugin.Membership(context.Background(), orgID, user.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("creator role:", member.Role)

	// Output:
	// slug: acme
	// creator role: owner
}
