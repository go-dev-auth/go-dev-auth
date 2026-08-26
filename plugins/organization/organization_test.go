package organization_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/organization"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

const password = "password123"

// inviteBox records the invitations the plugin hands to the mailer.
// Delivery runs on the server goroutine while assertions run on the test
// goroutine, so the mutex is what makes reading them safe.
type inviteBox struct {
	mu   sync.Mutex
	sent []organization.Invitation
}

func (b *inviteBox) send(_ context.Context, inv *organization.Invitation,
	_ *organization.Organization, _ *storage.User) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, *inv)
	return nil
}

func (b *inviteBox) last(t *testing.T) organization.Invitation {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sent) == 0 {
		t.Fatal("no invitation was sent")
	}
	return b.sent[len(b.sent)-1]
}

// newEnv mounts the plugin with teams enabled and a capturing mailer,
// then signs the owner in. Teams are on by default here so the team
// routes are part of every authorization sweep; TestTeamsRequireTheOption
// covers the other configuration.
func newEnv(t *testing.T, opts ...organization.Options) (*plugintest.Env, *organization.Plugin, *inviteBox) {
	t.Helper()
	box := &inviteBox{}
	var o organization.Options
	if len(opts) > 0 {
		o = opts[0]
	} else {
		o.Teams = true
	}
	o.SendInvitationEmail = box.send
	plugin := organization.New(o)
	env := plugintest.New(t, plugin)
	env.SignUp("owner@example.com", password)
	return env, plugin, box
}

// createOrg creates an organization on the given client and returns it.
func createOrg(t *testing.T, env *plugintest.Env, name, slug string) map[string]any {
	t.Helper()
	res, body := env.POST("/organization/create", map[string]any{"name": name, "slug": slug})
	env.RequireStatus(res, body, http.StatusOK)
	return body
}

// addMember invites an address, signs the invitee up on their own
// browser and accepts. It returns that browser and the new user.
func addMember(t *testing.T, env *plugintest.Env, box *inviteBox,
	orgID, email, role string) (*plugintest.Env, *storage.User) {
	t.Helper()
	res, body := env.POST("/organization/invite-member", map[string]any{
		"email": email, "role": role, "organizationId": orgID,
	})
	env.RequireStatus(res, body, http.StatusOK)
	invitationID := box.last(t).ID

	client := env.Client()
	user := client.SignUp(email, password)
	res, body = client.POST("/organization/accept-invitation", map[string]any{
		"invitationId": invitationID,
	})
	env.RequireStatus(res, body, http.StatusOK)
	return client, user
}

// memberID resolves the membership row id for a user, which is what the
// member endpoints address.
func memberID(t *testing.T, plugin *organization.Plugin, orgID, userID string) string {
	t.Helper()
	m, err := plugin.Membership(context.Background(), orgID, userID)
	if err != nil {
		t.Fatalf("loading membership of %s in %s: %v", userID, orgID, err)
	}
	return m.ID
}

func TestRoutesRequireASession(t *testing.T) {
	env, _, _ := newEnv(t)
	org := createOrg(t, env, "Acme Corp", "acme")
	orgID := org["id"].(string)

	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/organization/create", map[string]any{"name": "Anon Inc"}},
		{http.MethodPost, "/organization/update", map[string]any{"organizationId": orgID, "data": map[string]any{"name": "x"}}},
		{http.MethodPost, "/organization/delete", map[string]any{"organizationId": orgID}},
		{http.MethodGet, "/organization/list", nil},
		{http.MethodPost, "/organization/set-active", map[string]any{"organizationId": orgID}},
		{http.MethodGet, "/organization/get-full-organization?organizationId=" + orgID, nil},
		{http.MethodPost, "/organization/invite-member", map[string]any{"email": "x@example.com", "organizationId": orgID}},
		{http.MethodPost, "/organization/accept-invitation", map[string]any{"invitationId": "i"}},
		{http.MethodPost, "/organization/reject-invitation", map[string]any{"invitationId": "i"}},
		{http.MethodPost, "/organization/cancel-invitation", map[string]any{"invitationId": "i"}},
		{http.MethodGet, "/organization/get-invitation?id=i", nil},
		{http.MethodGet, "/organization/list-invitations?organizationId=" + orgID, nil},
		{http.MethodPost, "/organization/remove-member", map[string]any{"memberIdOrEmail": "owner@example.com", "organizationId": orgID}},
		{http.MethodPost, "/organization/update-member-role", map[string]any{"memberId": "m", "role": "admin", "organizationId": orgID}},
		{http.MethodGet, "/organization/get-active-member", nil},
		{http.MethodPost, "/organization/leave", map[string]any{"organizationId": orgID}},
		{http.MethodPost, "/organization/create-team", map[string]any{"name": "Platform", "organizationId": orgID}},
		{http.MethodPost, "/organization/remove-team", map[string]any{"teamId": "t", "organizationId": orgID}},
		{http.MethodGet, "/organization/list-teams?organizationId=" + orgID, nil},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			anon := env.Client()
			res, body := anon.Do(tc.method, tc.path, tc.body)
			env.RequireErrorCode(res, body, http.StatusUnauthorized, "UNAUTHORIZED")
		})
	}

	// check-slug reads rather than writes, but it still requires a
	// session: without one it is an oracle telling anybody which
	// organisations exist. A signed-in caller gets a real answer.
	t.Run("/organization/check-slug", func(t *testing.T) {
		anon := env.Client()
		res, body := anon.POST("/organization/check-slug", map[string]any{"slug": "free-slug"})
		env.RequireErrorCode(res, body, http.StatusUnauthorized, "UNAUTHORIZED")

		res, body = env.POST("/organization/check-slug", map[string]any{"slug": "free-slug"})
		env.RequireStatus(res, body, http.StatusOK)
		res, body = env.POST("/organization/check-slug", map[string]any{"slug": "acme"})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "SLUG_TAKEN")
	})

	// Nothing above may have taken effect.
	if n := env.Count(organization.ModelOrganization); n != 1 {
		t.Fatalf("organizations = %d, want the anonymous sweep to change nothing", n)
	}
	if n := env.Count(organization.ModelMember); n != 1 {
		t.Fatalf("members = %d, want the anonymous sweep to change nothing", n)
	}
}

func TestOutsiderCannotTouchAnotherOrganization(t *testing.T) {
	env, plugin, box := newEnv(t)
	org := createOrg(t, env, "Acme Corp", "acme")
	orgID := org["id"].(string)

	owner, err := env.Auth.FindUserByEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	ownerMemberID := memberID(t, plugin, orgID, owner.ID)

	res, body := env.POST("/organization/create-team", map[string]any{"name": "Platform"})
	env.RequireStatus(res, body, http.StatusOK)
	teamID := body["id"].(string)

	res, body = env.POST("/organization/invite-member", map[string]any{"email": "invitee@example.com"})
	env.RequireStatus(res, body, http.StatusOK)
	invitationID := box.last(t).ID

	// Somebody with a perfectly good account of their own, naming the
	// organization explicitly. Every one of these must be refused on
	// membership, not merely on the absence of an active organization.
	outsider := env.Client()
	outsider.SignUp("outsider@example.com", password)

	cases := []struct {
		method, path string
		body         any
		code         string
	}{
		{http.MethodPost, "/organization/update", map[string]any{"organizationId": orgID, "data": map[string]any{"name": "Pwned"}}, "NOT_A_MEMBER"},
		{http.MethodPost, "/organization/delete", map[string]any{"organizationId": orgID}, "NOT_A_MEMBER"},
		{http.MethodPost, "/organization/set-active", map[string]any{"organizationId": orgID}, "NOT_A_MEMBER"},
		{http.MethodGet, "/organization/get-full-organization?organizationId=" + orgID, nil, "NOT_A_MEMBER"},
		{http.MethodPost, "/organization/invite-member", map[string]any{"email": "friend@example.com", "organizationId": orgID}, "NOT_A_MEMBER"},
		{http.MethodPost, "/organization/cancel-invitation", map[string]any{"invitationId": invitationID}, "NOT_A_MEMBER"},
		{http.MethodGet, "/organization/list-invitations?organizationId=" + orgID, nil, "NOT_A_MEMBER"},
		{http.MethodPost, "/organization/remove-member", map[string]any{"memberIdOrEmail": ownerMemberID, "organizationId": orgID}, "NOT_A_MEMBER"},
		{http.MethodPost, "/organization/update-member-role", map[string]any{"memberId": ownerMemberID, "role": "member", "organizationId": orgID}, "NOT_A_MEMBER"},
		{http.MethodPost, "/organization/leave", map[string]any{"organizationId": orgID}, "NOT_A_MEMBER"},
		{http.MethodPost, "/organization/create-team", map[string]any{"name": "Theirs", "organizationId": orgID}, "NOT_A_MEMBER"},
		{http.MethodPost, "/organization/remove-team", map[string]any{"teamId": teamID, "organizationId": orgID}, "NOT_A_MEMBER"},
		{http.MethodGet, "/organization/list-teams?organizationId=" + orgID, nil, "NOT_A_MEMBER"},
		// An invitation is addressed to one mailbox; anyone else holding
		// the id must not be able to redeem or read it.
		{http.MethodPost, "/organization/accept-invitation", map[string]any{"invitationId": invitationID}, "NOT_YOUR_INVITATION"},
		{http.MethodPost, "/organization/reject-invitation", map[string]any{"invitationId": invitationID}, "NOT_YOUR_INVITATION"},
		{http.MethodGet, "/organization/get-invitation?id=" + invitationID, nil, "NOT_YOUR_INVITATION"},
	}
	for _, tc := range cases {
		t.Run(tc.path+"/"+tc.code, func(t *testing.T) {
			res, body := outsider.Do(tc.method, tc.path, tc.body)
			env.RequireErrorCode(res, body, http.StatusForbidden, tc.code)
		})
	}

	// The organization is exactly as it was.
	if n := env.Count(organization.ModelMember, storage.W("organizationId", orgID)); n != 1 {
		t.Fatalf("members = %d, want 1", n)
	}
	if n := env.Count(organization.ModelTeam, storage.W("organizationId", orgID)); n != 1 {
		t.Fatalf("teams = %d, want 1", n)
	}
	if n := env.Count(organization.ModelInvitation,
		storage.W("organizationId", orgID), storage.W("status", "pending")); n != 1 {
		t.Fatalf("pending invitations = %d, want 1", n)
	}
	res, full := env.GET("/organization/get-full-organization")
	env.RequireStatus(res, full, http.StatusOK)
	if full["name"] != "Acme Corp" {
		t.Fatalf("name = %v, want it untouched", full["name"])
	}

	// An outsider's own listing must not mention the organization.
	cookie := sessionCookie(t, outsider, "outsider@example.com", password)
	if orgs := getArray(t, env, "/organization/list", cookie); len(orgs) != 0 {
		t.Fatalf("the outsider lists %d organizations, want none", len(orgs))
	}
}

func TestMemberCannotPerformOwnerOrAdminActions(t *testing.T) {
	env, plugin, box := newEnv(t)
	org := createOrg(t, env, "Acme Corp", "acme")
	orgID := org["id"].(string)

	res, body := env.POST("/organization/create-team", map[string]any{"name": "Platform"})
	env.RequireStatus(res, body, http.StatusOK)
	teamID := body["id"].(string)

	member, memberUser := addMember(t, env, box, orgID, "member@example.com", organization.RoleMember)

	// A second, still pending invitation for the member to try to cancel.
	res, body = env.POST("/organization/invite-member", map[string]any{"email": "pending@example.com"})
	env.RequireStatus(res, body, http.StatusOK)
	pendingID := box.last(t).ID

	owner, err := env.Auth.FindUserByEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	ownerMemberID := memberID(t, plugin, orgID, owner.ID)
	ownMemberID := memberID(t, plugin, orgID, memberUser.ID)

	// Accepting the invitation made the organization active for the
	// member, so these calls carry no organizationId: they are exactly
	// what the member's own UI would send.
	denied := []struct {
		name, path string
		body       any
	}{
		{"rename the organization", "/organization/update", map[string]any{"data": map[string]any{"name": "Members Inc"}}},
		{"delete the organization", "/organization/delete", map[string]any{}},
		{"invite somebody", "/organization/invite-member", map[string]any{"email": "friend@example.com"}},
		{"cancel a pending invitation", "/organization/cancel-invitation", map[string]any{"invitationId": pendingID}},
		{"remove the owner", "/organization/remove-member", map[string]any{"memberIdOrEmail": ownerMemberID}},
		{"promote themselves", "/organization/update-member-role", map[string]any{"memberId": ownMemberID, "role": "owner"}},
		{"create a team", "/organization/create-team", map[string]any{"name": "Shadow"}},
		{"remove a team", "/organization/remove-team", map[string]any{"teamId": teamID}},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			res, body := member.POST(tc.path, tc.body)
			env.RequireErrorCode(res, body, http.StatusForbidden, "INSUFFICIENT_PERMISSION")
		})
	}

	// Membership does grant read access; refusing these would make the
	// role useless rather than safe.
	allowed := []string{
		"/organization/get-full-organization",
		"/organization/list-invitations",
		"/organization/list-teams",
		"/organization/get-active-member",
	}
	for _, path := range allowed {
		t.Run("member may GET "+path, func(t *testing.T) {
			res, body := member.GET(path)
			env.RequireStatus(res, body, http.StatusOK)
		})
	}

	// Nothing the member attempted may have landed.
	res, full := env.GET("/organization/get-full-organization")
	env.RequireStatus(res, full, http.StatusOK)
	if full["name"] != "Acme Corp" {
		t.Fatalf("name = %v, want it untouched", full["name"])
	}
	if n := env.Count(organization.ModelMember, storage.W("organizationId", orgID)); n != 2 {
		t.Fatalf("members = %d, want 2", n)
	}
	if n := env.Count(organization.ModelTeam, storage.W("organizationId", orgID)); n != 1 {
		t.Fatalf("teams = %d, want the team to survive", n)
	}
	role := memberRole(t, plugin, orgID, memberUser.ID)
	if role != organization.RoleMember {
		t.Fatalf("role = %q, want the self-promotion to have failed", role)
	}
}

func TestCreateOrganization(t *testing.T) {
	env, plugin, _ := newEnv(t)

	org := createOrg(t, env, "Acme Corp", "")
	// A slug derived from the name has to be URL-safe: it ends up in
	// paths and invitation links.
	if org["slug"] != "acme-corp" {
		t.Fatalf("slug = %v, want it slugified from the name", org["slug"])
	}

	owner, err := env.Auth.FindUserByEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := memberRole(t, plugin, org["id"].(string), owner.ID); got != organization.RoleOwner {
		t.Fatalf("creator role = %q, want owner", got)
	}

	// Creating an organization selects it, so the follow-up calls a UI
	// makes do not need to name it.
	res, member := env.GET("/organization/get-active-member")
	env.RequireStatus(res, member, http.StatusOK)
	if member["organizationId"] != org["id"] {
		t.Fatalf("active member = %v, want the new organization", member)
	}

	t.Run("body validation", func(t *testing.T) {
		cases := []struct {
			name string
			body any
		}{
			{"no body", nil},
			{"non-object body", "nope"},
			{"no name", map[string]any{"slug": "nameless"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				res, body := env.POST("/organization/create", tc.body)
				env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_BODY")
			})
		}
	})
}

func TestSlugsAreUniqueAndNormalized(t *testing.T) {
	env, _, _ := newEnv(t)
	createOrg(t, env, "Acme Corp", "acme")

	// The slug is an identifier in URLs; two organizations sharing one
	// would make lookups ambiguous.
	res, body := env.POST("/organization/create", map[string]any{"name": "Other", "slug": "acme"})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "SLUG_TAKEN")

	// Normalization happens before the uniqueness check, so a slug that
	// only differs in case or punctuation is still a collision.
	res, body = env.POST("/organization/create", map[string]any{"name": "Other", "slug": "ACME"})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "SLUG_TAKEN")

	res, body = env.POST("/organization/check-slug", map[string]any{"slug": "Acme"})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "SLUG_TAKEN")
	res, body = env.POST("/organization/check-slug", map[string]any{"slug": "still free"})
	env.RequireStatus(res, body, http.StatusOK)

	second := createOrg(t, env, "Second", "My Second Team!")
	if second["slug"] != "my-second-team" {
		t.Fatalf("slug = %v, want spaces and punctuation normalized", second["slug"])
	}

	// Renaming into a taken slug is the same collision by another route.
	res, body = env.POST("/organization/update", map[string]any{
		"organizationId": second["id"], "data": map[string]any{"slug": "acme"},
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "SLUG_TAKEN")

	// Keeping its own slug is not a collision with itself.
	res, body = env.POST("/organization/update", map[string]any{
		"organizationId": second["id"], "data": map[string]any{"slug": "my-second-team", "name": "Renamed"},
	})
	env.RequireStatus(res, body, http.StatusOK)
	if body["name"] != "Renamed" {
		t.Fatalf("name = %v, want the update applied", body["name"])
	}
}

func TestInvitationLifecycle(t *testing.T) {
	env, _, box := newEnv(t)
	org := createOrg(t, env, "Acme Corp", "acme")
	orgID := org["id"].(string)

	t.Run("owner cannot be handed out by invitation", func(t *testing.T) {
		res, body := env.POST("/organization/invite-member", map[string]any{
			"email": "usurper@example.com", "role": "owner",
		})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "CANNOT_INVITE_OWNER")
	})

	res, body := env.POST("/organization/invite-member", map[string]any{"email": "  Member@Example.com "})
	env.RequireStatus(res, body, http.StatusOK)
	inv := box.last(t)
	// Addresses are compared to the invitee's account address, so both
	// sides have to be normalized or the invitation is unredeemable.
	if inv.Email != "member@example.com" {
		t.Fatalf("stored invitation address = %q, want it normalized", inv.Email)
	}
	if inv.Status != "pending" || !inv.ExpiresAt.After(time.Now()) {
		t.Fatalf("invitation = %+v, want a live pending invitation", inv)
	}

	t.Run("a duplicate invitation is refused unless resent", func(t *testing.T) {
		res, body := env.POST("/organization/invite-member", map[string]any{"email": "member@example.com"})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "INVITATION_ALREADY_SENT")

		res, body = env.POST("/organization/invite-member", map[string]any{
			"email": "member@example.com", "resend": true,
		})
		env.RequireStatus(res, body, http.StatusOK)
		if n := env.Count(organization.ModelInvitation); n != 1 {
			t.Fatalf("invitations = %d, want the resend to reuse the row", n)
		}
	})

	invitee := env.Client()
	invitee.SignUp("member@example.com", password)

	t.Run("the invitee can read their own invitation", func(t *testing.T) {
		res, body := invitee.GET("/organization/get-invitation?id=" + inv.ID)
		env.RequireStatus(res, body, http.StatusOK)
		if body["organizationName"] != "Acme Corp" || body["inviterEmail"] != "owner@example.com" {
			t.Fatalf("invitation = %v, want the organization and inviter named", body)
		}
	})

	res, body = invitee.POST("/organization/accept-invitation", map[string]any{"invitationId": inv.ID})
	env.RequireStatus(res, body, http.StatusOK)
	if n := env.Count(organization.ModelMember, storage.W("organizationId", orgID)); n != 2 {
		t.Fatalf("members = %d, want the invitee to have joined", n)
	}

	t.Run("an accepted invitation cannot be replayed", func(t *testing.T) {
		res, body := invitee.POST("/organization/accept-invitation", map[string]any{"invitationId": inv.ID})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "INVITATION_EXPIRED")
		if n := env.Count(organization.ModelMember, storage.W("organizationId", orgID)); n != 2 {
			t.Fatalf("members = %d, want no duplicate membership", n)
		}
	})

	t.Run("an existing member cannot be re-invited", func(t *testing.T) {
		res, body := env.POST("/organization/invite-member", map[string]any{"email": "member@example.com"})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "USER_ALREADY_A_MEMBER")
	})

	t.Run("an expired invitation is refused", func(t *testing.T) {
		res, body := env.POST("/organization/invite-member", map[string]any{"email": "late@example.com"})
		env.RequireStatus(res, body, http.StatusOK)
		stale := box.last(t).ID
		// Age it past its expiry: no endpoint can do that, and waiting
		// 48 hours is not a test.
		if _, err := env.Auth.Storage().UpdateMany(context.Background(), organization.ModelInvitation,
			[]storage.Where{storage.W("id", stale)},
			map[string]any{"expiresAt": time.Now().Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
		late := env.Client()
		late.SignUp("late@example.com", password)
		res, body = late.POST("/organization/accept-invitation", map[string]any{"invitationId": stale})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "INVITATION_EXPIRED")
	})

	t.Run("rejecting burns the invitation", func(t *testing.T) {
		res, body := env.POST("/organization/invite-member", map[string]any{"email": "nope@example.com"})
		env.RequireStatus(res, body, http.StatusOK)
		id := box.last(t).ID

		declines := env.Client()
		declines.SignUp("nope@example.com", password)
		res, body = declines.POST("/organization/reject-invitation", map[string]any{"invitationId": id})
		env.RequireStatus(res, body, http.StatusOK)

		res, body = declines.POST("/organization/accept-invitation", map[string]any{"invitationId": id})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "INVITATION_EXPIRED")
	})

	t.Run("an admin can cancel a pending invitation", func(t *testing.T) {
		res, body := env.POST("/organization/invite-member", map[string]any{"email": "cancelled@example.com"})
		env.RequireStatus(res, body, http.StatusOK)
		id := box.last(t).ID

		res, body = env.POST("/organization/cancel-invitation", map[string]any{"invitationId": id})
		env.RequireStatus(res, body, http.StatusOK)

		cancelled := env.Client()
		cancelled.SignUp("cancelled@example.com", password)
		res, body = cancelled.POST("/organization/accept-invitation", map[string]any{"invitationId": id})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "INVITATION_EXPIRED")
	})

	t.Run("an unknown invitation id is a 404", func(t *testing.T) {
		res, body := invitee.POST("/organization/accept-invitation", map[string]any{"invitationId": "no-such-id"})
		env.RequireErrorCode(res, body, http.StatusNotFound, "INVITATION_NOT_FOUND")
	})
}

func TestMemberRoleManagement(t *testing.T) {
	env, plugin, box := newEnv(t)
	org := createOrg(t, env, "Acme Corp", "acme")
	orgID := org["id"].(string)

	adminClient, adminUser := addMember(t, env, box, orgID, "admin@example.com", organization.RoleAdmin)
	_, plainUser := addMember(t, env, box, orgID, "member@example.com", organization.RoleMember)

	owner, err := env.Auth.FindUserByEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	ownerMemberID := memberID(t, plugin, orgID, owner.ID)
	adminMemberID := memberID(t, plugin, orgID, adminUser.ID)
	plainMemberID := memberID(t, plugin, orgID, plainUser.ID)

	t.Run("only known roles are accepted", func(t *testing.T) {
		res, body := env.POST("/organization/update-member-role", map[string]any{
			"memberId": plainMemberID, "role": "superuser",
		})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_ROLE")
	})

	t.Run("an admin cannot mint another owner", func(t *testing.T) {
		// Ownership is the escalation ceiling; an admin who could grant
		// it could take the organization from its owner.
		res, body := adminClient.POST("/organization/update-member-role", map[string]any{
			"memberId": plainMemberID, "role": "owner",
		})
		env.RequireErrorCode(res, body, http.StatusForbidden, "INSUFFICIENT_PERMISSION")

		res, body = adminClient.POST("/organization/update-member-role", map[string]any{
			"memberId": ownerMemberID, "role": "member",
		})
		env.RequireErrorCode(res, body, http.StatusForbidden, "INSUFFICIENT_PERMISSION")
		if got := memberRole(t, plugin, orgID, owner.ID); got != organization.RoleOwner {
			t.Fatalf("owner role = %q, want it unchanged", got)
		}
	})

	t.Run("an admin cannot remove the owner", func(t *testing.T) {
		res, body := adminClient.POST("/organization/remove-member", map[string]any{
			"memberIdOrEmail": ownerMemberID,
		})
		env.RequireErrorCode(res, body, http.StatusForbidden, "CANNOT_REMOVE_OWNER")
	})

	t.Run("removing yourself is done by leaving", func(t *testing.T) {
		res, body := adminClient.POST("/organization/remove-member", map[string]any{
			"memberIdOrEmail": adminMemberID,
		})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "CANNOT_REMOVE_YOURSELF")
	})

	t.Run("an owner can promote and demote", func(t *testing.T) {
		res, body := env.POST("/organization/update-member-role", map[string]any{
			"memberId": plainMemberID, "role": "admin",
		})
		env.RequireStatus(res, body, http.StatusOK)
		if got := memberRole(t, plugin, orgID, plainUser.ID); got != organization.RoleAdmin {
			t.Fatalf("role = %q, want admin", got)
		}
	})

	t.Run("an admin can remove an ordinary member by email", func(t *testing.T) {
		res, body := env.POST("/organization/update-member-role", map[string]any{
			"memberId": plainMemberID, "role": "member",
		})
		env.RequireStatus(res, body, http.StatusOK)

		res, body = adminClient.POST("/organization/remove-member", map[string]any{
			"memberIdOrEmail": "member@example.com",
		})
		env.RequireStatus(res, body, http.StatusOK)
		if _, err := plugin.Membership(context.Background(), orgID, plainUser.ID); err == nil {
			t.Fatal("the member was not removed")
		}
	})

	t.Run("an unknown member is a 404", func(t *testing.T) {
		res, body := env.POST("/organization/remove-member", map[string]any{
			"memberIdOrEmail": "ghost@example.com",
		})
		env.RequireErrorCode(res, body, http.StatusNotFound, "MEMBER_NOT_FOUND")
	})
}

func TestLastOwnerCannotLeave(t *testing.T) {
	env, plugin, box := newEnv(t)
	org := createOrg(t, env, "Acme Corp", "acme")
	orgID := org["id"].(string)

	member, memberUser := addMember(t, env, box, orgID, "member@example.com", organization.RoleMember)

	// An organization with no owner can never be administered again, so
	// the last one is pinned in place.
	res, body := env.POST("/organization/leave", map[string]any{})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "CANNOT_LEAVE_AS_ONLY_OWNER")

	// A second owner lifts the restriction.
	res, body = env.POST("/organization/update-member-role", map[string]any{
		"memberId": memberID(t, plugin, orgID, memberUser.ID), "role": "owner",
	})
	env.RequireStatus(res, body, http.StatusOK)

	res, body = env.POST("/organization/leave", map[string]any{})
	env.RequireStatus(res, body, http.StatusOK)
	if n := env.Count(organization.ModelMember, storage.W("organizationId", orgID)); n != 1 {
		t.Fatalf("members = %d, want only the remaining owner", n)
	}

	// Leaving clears the active organization: acting on it afterwards
	// would be acting on something the user no longer belongs to.
	res, body = env.POST("/organization/update", map[string]any{"data": map[string]any{"name": "x"}})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION")

	// And the remaining owner is now the only one who cannot leave.
	res, body = member.POST("/organization/leave", map[string]any{})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "CANNOT_LEAVE_AS_ONLY_OWNER")
}

func TestDeleteRemovesEverythingItOwns(t *testing.T) {
	env, _, box := newEnv(t)
	org := createOrg(t, env, "Acme Corp", "acme")
	orgID := org["id"].(string)

	res, body := env.POST("/organization/create-team", map[string]any{"name": "Platform"})
	env.RequireStatus(res, body, http.StatusOK)
	addMember(t, env, box, orgID, "member@example.com", organization.RoleMember)
	res, body = env.POST("/organization/invite-member", map[string]any{"email": "pending@example.com"})
	env.RequireStatus(res, body, http.StatusOK)

	res, body = env.POST("/organization/delete", map[string]any{"organizationId": orgID})
	env.RequireStatus(res, body, http.StatusOK)

	// Orphaned members, invitations or teams would keep granting access
	// to an organization that no longer exists.
	for _, model := range []string{
		organization.ModelMember,
		organization.ModelInvitation,
		organization.ModelTeam,
	} {
		if n := env.Count(model, storage.W("organizationId", orgID)); n != 0 {
			t.Fatalf("%s rows = %d after delete, want 0", model, n)
		}
	}
	if n := env.Count(organization.ModelOrganization); n != 0 {
		t.Fatalf("organizations = %d, want 0", n)
	}
}

func TestSetActiveOrganization(t *testing.T) {
	env, _, _ := newEnv(t)
	first := createOrg(t, env, "First", "first")
	second := createOrg(t, env, "Second", "second")

	// Creating an organization selects it.
	res, active := env.GET("/organization/get-active-member")
	env.RequireStatus(res, active, http.StatusOK)
	if active["organizationId"] != second["id"] {
		t.Fatalf("active organization = %v, want the one just created", active["organizationId"])
	}

	// Switching back by slug is the path an organization switcher takes.
	res, body := env.POST("/organization/set-active", map[string]any{"organizationSlug": "first"})
	env.RequireStatus(res, body, http.StatusOK)
	if body["id"] != first["id"] {
		t.Fatalf("active organization = %v, want the first", body)
	}
	res, member := env.GET("/organization/get-active-member")
	env.RequireStatus(res, member, http.StatusOK)
	if member["organizationId"] != first["id"] {
		t.Fatalf("active member = %v, want the first organization", member)
	}

	t.Run("an unknown slug is a 404", func(t *testing.T) {
		res, body := env.POST("/organization/set-active", map[string]any{"organizationSlug": "nope"})
		env.RequireErrorCode(res, body, http.StatusNotFound, "ORGANIZATION_NOT_FOUND")
	})

	t.Run("clearing the selection leaves no organization active", func(t *testing.T) {
		res, body := env.POST("/organization/set-active", map[string]any{})
		env.RequireStatus(res, body, http.StatusOK)
		res, body = env.POST("/organization/update", map[string]any{"data": map[string]any{"name": "x"}})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION")
	})
}

func TestTeamsRequireTheOption(t *testing.T) {
	t.Run("routes are absent when teams are off", func(t *testing.T) {
		env, _, _ := newEnv(t, organization.Options{})
		createOrg(t, env, "Acme Corp", "acme")

		// Registering the endpoints unconditionally would let clients
		// write into tables the schema never created.
		cases := []struct {
			method, path string
			body         any
		}{
			{http.MethodPost, "/organization/create-team", map[string]any{"name": "Platform"}},
			{http.MethodPost, "/organization/remove-team", map[string]any{"teamId": "t"}},
			{http.MethodGet, "/organization/list-teams", nil},
		}
		for _, tc := range cases {
			t.Run(tc.path, func(t *testing.T) {
				res, body := env.Do(tc.method, tc.path, tc.body)
				env.RequireErrorCode(res, body, http.StatusNotFound, "NOT_FOUND")
			})
		}

		res, body := env.POST("/organization/invite-member", map[string]any{
			"email": "member@example.com", "teamId": "some-team",
		})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "TEAMS_DISABLED")
	})

	t.Run("teams belong to one organization", func(t *testing.T) {
		env, _, _ := newEnv(t)
		mine := createOrg(t, env, "Mine", "mine")
		theirs := createOrg(t, env, "Theirs", "theirs")

		res, body := env.POST("/organization/create-team", map[string]any{
			"name": "Platform", "organizationId": mine["id"],
		})
		env.RequireStatus(res, body, http.StatusOK)
		teamID := body["id"].(string)

		// The team id alone must not be enough: it has to belong to the
		// organization the request is acting on.
		res, body = env.POST("/organization/remove-team", map[string]any{
			"teamId": teamID, "organizationId": theirs["id"],
		})
		env.RequireErrorCode(res, body, http.StatusNotFound, "TEAM_NOT_FOUND")

		res, body = env.POST("/organization/invite-member", map[string]any{
			"email": "member@example.com", "organizationId": theirs["id"], "teamId": teamID,
		})
		env.RequireErrorCode(res, body, http.StatusBadRequest, "TEAM_NOT_FOUND")

		cookie := sessionCookie(t, env, "owner@example.com", password)
		teams := getArray(t, env, "/organization/list-teams?organizationId="+mine["id"].(string), cookie)
		if len(teams) != 1 || teams[0]["id"] != teamID {
			t.Fatalf("teams = %v, want exactly the one created", teams)
		}
		teams = getArray(t, env, "/organization/list-teams?organizationId="+theirs["id"].(string), cookie)
		if len(teams) != 0 {
			t.Fatalf("the other organization lists %d teams, want none", len(teams))
		}

		res, body = env.POST("/organization/remove-team", map[string]any{
			"teamId": teamID, "organizationId": mine["id"],
		})
		env.RequireStatus(res, body, http.StatusOK)
	})
}

func TestLimits(t *testing.T) {
	t.Run("organizations per user", func(t *testing.T) {
		env, _, _ := newEnv(t, organization.Options{OrganizationLimit: 1})
		createOrg(t, env, "First", "first")

		res, body := env.POST("/organization/create", map[string]any{"name": "Second"})
		env.RequireErrorCode(res, body, http.StatusForbidden, "ORGANIZATION_LIMIT_REACHED")

		// The limit counts organizations you own, not every account.
		other := env.Client()
		other.SignUp("other@example.com", password)
		res, body = other.POST("/organization/create", map[string]any{"name": "Theirs"})
		env.RequireStatus(res, body, http.StatusOK)
	})

	t.Run("members per organization", func(t *testing.T) {
		env, _, box := newEnv(t, organization.Options{MembershipLimit: 2, Teams: true})
		org := createOrg(t, env, "Acme Corp", "acme")
		orgID := org["id"].(string)
		addMember(t, env, box, orgID, "member@example.com", organization.RoleMember)

		res, body := env.POST("/organization/invite-member", map[string]any{"email": "third@example.com"})
		env.RequireErrorCode(res, body, http.StatusForbidden, "MEMBER_LIMIT_REACHED")
	})
}

func TestOrganizationCreationCanBeDisabled(t *testing.T) {
	env, _, _ := newEnv(t, organization.Options{DisableOrganizationCreation: true})
	res, body := env.POST("/organization/create", map[string]any{"name": "Acme"})
	env.RequireErrorCode(res, body, http.StatusForbidden, "ORGANIZATION_CREATION_DISABLED")

	t.Run("or restricted per user", func(t *testing.T) {
		env, _, _ := newEnv(t, organization.Options{
			Teams: true,
			CanCreateOrganization: func(_ context.Context, user *storage.User) bool {
				return user.Email == "allowed@example.com"
			},
		})
		res, body := env.POST("/organization/create", map[string]any{"name": "Acme"})
		env.RequireErrorCode(res, body, http.StatusForbidden, "NOT_ALLOWED_TO_CREATE_ORGANIZATION")

		allowed := env.Client()
		allowed.SignUp("allowed@example.com", password)
		res, body = allowed.POST("/organization/create", map[string]any{"name": "Acme"})
		env.RequireStatus(res, body, http.StatusOK)
	})
}

func TestGetFullOrganizationDescribesMembership(t *testing.T) {
	env, _, box := newEnv(t)
	org := createOrg(t, env, "Acme Corp", "acme")
	orgID := org["id"].(string)
	addMember(t, env, box, orgID, "member@example.com", organization.RoleMember)
	res, body := env.POST("/organization/invite-member", map[string]any{"email": "pending@example.com"})
	env.RequireStatus(res, body, http.StatusOK)

	res, full := env.GET("/organization/get-full-organization")
	env.RequireStatus(res, full, http.StatusOK)

	members, _ := full["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("members = %d, want 2", len(members))
	}
	// Member rows carry the user they name so a UI can render the list
	// without a lookup per row.
	for _, raw := range members {
		m := raw.(map[string]any)
		user, _ := m["user"].(map[string]any)
		if user == nil || user["email"] == nil {
			t.Fatalf("member %v carries no user", m)
		}
		// Only the display fields, never credentials.
		for _, forbidden := range []string{"password", "twoFactorEnabled", "role"} {
			if _, leaked := user[forbidden]; leaked {
				t.Fatalf("member user exposes %q: %v", forbidden, user)
			}
		}
	}

	// Only invitations still awaiting an answer are worth showing.
	invitations, _ := full["invitations"].([]any)
	if len(invitations) != 1 {
		t.Fatalf("invitations = %d, want only the pending one", len(invitations))
	}
}

// memberRole reads a member's current role straight from the plugin.
func memberRole(t *testing.T, plugin *organization.Plugin, orgID, userID string) string {
	t.Helper()
	m, err := plugin.Membership(context.Background(), orgID, userID)
	if err != nil {
		t.Fatalf("loading membership: %v", err)
	}
	return m.Role
}

// sessionCookie signs the client in and returns the cookie header a raw
// request must carry to act as that user. Note that it starts a new
// session, so the active organization resets.
func sessionCookie(t *testing.T, env *plugintest.Env, email, pass string) string {
	t.Helper()
	res, body := env.SignIn(email, pass)
	env.RequireStatus(res, body, http.StatusOK)
	var pairs []string
	for _, sc := range res.Header.Values("Set-Cookie") {
		if i := strings.Index(sc, ";"); i >= 0 {
			sc = sc[:i]
		}
		pairs = append(pairs, sc)
	}
	return strings.Join(pairs, "; ")
}

// getArray decodes a JSON array response. plugintest decodes objects,
// and the list endpoints answer with arrays.
func getArray(t *testing.T, env *plugintest.Env, path, cookie string) []map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.Server.URL+env.Auth.Config().BasePath+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, res.StatusCode, raw)
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("GET %s returned %s: %v", path, raw, err)
	}
	return out
}

// TestMemberCompositeUniqueBackstop proves the composite unique
// constraint on member (organizationId, userId) is wired through the
// plugin schema and enforced by the adapter, so a user cannot end up with
// two membership rows in one organization even if the up-front check is
// bypassed by a race. Here the second row is inserted directly to stand
// in for the losing writer of that race.
func TestMemberCompositeUniqueBackstop(t *testing.T) {
	env, _, _ := newEnv(t)
	org := createOrg(t, env, "Acme", "acme")
	orgID, _ := org["id"].(string)

	ctx := context.Background()
	members, err := env.Auth.Storage().FindMany(ctx, organization.ModelMember,
		[]storage.Where{storage.W("organizationId", orgID)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("expected the creator's single membership, got %d", len(members))
	}
	userID, _ := members[0]["userId"].(string)

	_, err = env.Auth.Storage().Create(ctx, organization.ModelMember, map[string]any{
		"id":             "duplicate-member",
		"organizationId": orgID,
		"userId":         userID,
		"role":           organization.RoleMember,
		"createdAt":      time.Now().UTC(),
	})
	if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("a second membership for the same (organizationId, userId) must be refused, got %v", err)
	}
	if n := env.Count(organization.ModelMember, storage.W("organizationId", orgID)); n != 1 {
		t.Fatalf("the duplicate membership was stored: %d member rows, want 1", n)
	}
}

var _ godevauth.SchemaPlugin = organization.New()

// TestInviteMemberRejectsUnknownRole pins the sibling of the admin
// create-user gap: invite-member must constrain the role to the same
// known set that update-member-role enforces. An unknown role would
// otherwise be written to the invitation and copied onto the member on
// accept, where no requireRole check ever matches it — a member silently
// locked out of every role-gated route. It also validates the address.
func TestInviteMemberRejectsUnknownRole(t *testing.T) {
	env, _, _ := newEnv(t)
	org := createOrg(t, env, "Acme", "acme")
	orgID, _ := org["id"].(string)

	res, body := env.POST("/organization/invite-member", map[string]any{
		"email": "eng@example.com", "role": "maintainer", "organizationId": orgID,
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_ROLE")

	res, body = env.POST("/organization/invite-member", map[string]any{
		"email": "not-an-email", "role": "member", "organizationId": orgID,
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_EMAIL")

	// a known role and a valid address still work
	res, body = env.POST("/organization/invite-member", map[string]any{
		"email": "ok@example.com", "role": "admin", "organizationId": orgID,
	})
	env.RequireStatus(res, body, http.StatusOK)
}
