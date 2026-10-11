package admin_test

import (
	"context"
	"net/http"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// newEnv returns an environment with the admin plugin mounted and a
// signed-in administrator. Promotion happens through storage because
// there is deliberately no endpoint that lets a user grant themselves a
// role.
func newEnv(t *testing.T) (*plugintest.Env, *admin.Plugin) {
	t.Helper()
	plugin := admin.New()
	env := plugintest.New(t, plugin)
	user := env.SignUp("root@example.com", "password123")
	if _, err := env.Auth.UpdateUserRecord(context.Background(), user.ID,
		map[string]any{"role": "admin"}); err != nil {
		t.Fatalf("promoting the test administrator: %v", err)
	}
	return env, plugin
}

func TestRoutesRequireAdmin(t *testing.T) {
	env, _ := newEnv(t)

	// An ordinary user, signed in on their own client.
	member := env.Client()
	member.SignUp("member@example.com", "password123")

	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/admin/list-users", nil},
		{http.MethodPost, "/admin/create-user", map[string]any{"email": "x@example.com"}},
		{http.MethodPost, "/admin/set-role", map[string]any{"userId": "u", "role": "admin"}},
		{http.MethodPost, "/admin/ban-user", map[string]any{"userId": "u"}},
		{http.MethodPost, "/admin/unban-user", map[string]any{"userId": "u"}},
		{http.MethodPost, "/admin/impersonate-user", map[string]any{"userId": "u"}},
		{http.MethodPost, "/admin/remove-user", map[string]any{"userId": "u"}},
		{http.MethodPost, "/admin/set-user-password", map[string]any{"userId": "u", "newPassword": "password123"}},
		{http.MethodPost, "/admin/revoke-user-sessions", map[string]any{"userId": "u"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			// signed in, but not an administrator
			res, body := member.Do(tc.method, tc.path, tc.body)
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("as a member: status %d, want 403: %v", res.StatusCode, body)
			}
			// not signed in at all
			anon := env.Client()
			res, body = anon.Do(tc.method, tc.path, tc.body)
			if res.StatusCode != http.StatusUnauthorized {
				t.Errorf("anonymous: status %d, want 401: %v", res.StatusCode, body)
			}
		})
	}
}

func TestCreateAndListUsers(t *testing.T) {
	env, _ := newEnv(t)

	res, body := env.POST("/admin/create-user", map[string]any{
		"email": "worker@example.com", "password": "password123",
		"name": "Worker", "role": "support",
	})
	env.RequireStatus(res, body, http.StatusOK)

	// The created account must be usable.
	worker := env.Client()
	res, body = worker.SignIn("worker@example.com", "password123")
	env.RequireStatus(res, body, http.StatusOK)

	res, body = env.GET("/admin/list-users?limit=10")
	env.RequireStatus(res, body, http.StatusOK)
	if total, _ := body["total"].(float64); total != 2 {
		t.Fatalf("total = %v, want 2", body["total"])
	}

	// A duplicate address is a client error, not a server error.
	res, body = env.POST("/admin/create-user", map[string]any{
		"email": "worker@example.com", "password": "password123",
	})
	if res.StatusCode < 400 || res.StatusCode >= 500 {
		t.Fatalf("duplicate create: status %d, want a 4xx: %v", res.StatusCode, body)
	}
}

func TestListUsersInputIsBounded(t *testing.T) {
	env, _ := newEnv(t)

	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'a'
	}
	res, body := env.GET("/admin/list-users?searchValue=" + string(long))
	env.RequireErrorCode(res, body, http.StatusBadRequest, "SEARCH_TOO_LONG")

	res, body = env.GET("/admin/list-users?filterField=notAColumn&filterValue=x")
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_FILTER_FIELD")

	// An absurd limit must be clamped, not honoured or overflowed.
	res, body = env.GET("/admin/list-users?limit=99999999999999999999")
	env.RequireStatus(res, body, http.StatusOK)
	if users, ok := body["users"].([]any); ok && len(users) > 500 {
		t.Fatalf("limit was not clamped: %d users returned", len(users))
	}
}

func TestSearchIsLiteralAndCaseInsensitive(t *testing.T) {
	env, _ := newEnv(t)
	env.POST("/admin/create-user", map[string]any{"email": "Alice@example.com", "name": "Alice"})
	env.POST("/admin/create-user", map[string]any{"email": "bob@example.com", "name": "Bob"})

	// "%" is a LIKE wildcard and a regex metacharacter; it must match
	// literally, not everything.
	res, body := env.GET("/admin/list-users?searchField=email&searchValue=%25")
	env.RequireStatus(res, body, http.StatusOK)
	if total, _ := body["total"].(float64); total != 0 {
		t.Fatalf("a wildcard search matched %v users; it must be literal", body["total"])
	}

	res, body = env.GET("/admin/list-users?searchField=email&searchValue=ALICE")
	env.RequireStatus(res, body, http.StatusOK)
	if total, _ := body["total"].(float64); total != 1 {
		t.Fatalf("case-insensitive search matched %v, want 1", body["total"])
	}
}

func TestBanBlocksAccessImmediately(t *testing.T) {
	env, _ := newEnv(t)
	res, body := env.POST("/admin/create-user", map[string]any{
		"email": "banned@example.com", "password": "password123",
	})
	env.RequireStatus(res, body, http.StatusOK)
	victimID := body["user"].(map[string]any)["id"].(string)

	// The victim signs in and holds a live session.
	victim := env.Client()
	victim.SignIn("banned@example.com", "password123")
	if !victim.Signed() {
		t.Fatal("victim should start out signed in")
	}

	res, body = env.POST("/admin/ban-user", map[string]any{
		"userId": victimID, "banReason": "spam",
	})
	env.RequireStatus(res, body, http.StatusOK)

	// The existing session must stop working, not merely future logins.
	if victim.Signed() {
		t.Error("a banned user kept an active session")
	}
	res, body = victim.SignIn("banned@example.com", "password123")
	env.RequireErrorCode(res, body, http.StatusForbidden, "BANNED_USER")

	// Unbanning restores access.
	res, body = env.POST("/admin/unban-user", map[string]any{"userId": victimID})
	env.RequireStatus(res, body, http.StatusOK)
	res, body = victim.SignIn("banned@example.com", "password123")
	env.RequireStatus(res, body, http.StatusOK)
}

func TestImpersonation(t *testing.T) {
	env, _ := newEnv(t)
	res, body := env.POST("/admin/create-user", map[string]any{
		"email": "target@example.com", "password": "password123",
	})
	env.RequireStatus(res, body, http.StatusOK)
	targetID := body["user"].(map[string]any)["id"].(string)

	res, body = env.POST("/admin/impersonate-user", map[string]any{"userId": targetID})
	env.RequireStatus(res, body, http.StatusOK)

	session := env.Session()
	if session == nil {
		t.Fatal("no session after impersonating")
	}
	if got := session["user"].(map[string]any)["email"]; got != "target@example.com" {
		t.Fatalf("impersonating gave a session for %v", got)
	}

	res, body = env.POST("/admin/stop-impersonating", map[string]any{})
	env.RequireStatus(res, body, http.StatusOK)
	session = env.Session()
	if got := session["user"].(map[string]any)["email"]; got != "root@example.com" {
		t.Fatalf("after stopping, session belongs to %v, want the administrator", got)
	}
}

func TestAdminCannotActOnSelf(t *testing.T) {
	env, _ := newEnv(t)
	user, err := env.Auth.FindUserByEmail(context.Background(), "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Banning or removing yourself locks the last administrator out.
	res, body := env.POST("/admin/ban-user", map[string]any{"userId": user.ID})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "CANNOT_BAN_YOURSELF")

	res, body = env.POST("/admin/remove-user", map[string]any{"userId": user.ID})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "CANNOT_REMOVE_YOURSELF")
}

func TestIsAdminReadsRolesSafely(t *testing.T) {
	plugin := admin.New(admin.Options{AdminRoles: []string{"admin", "owner"}})
	cases := []struct {
		name  string
		extra map[string]any
		want  bool
	}{
		{"no role", nil, false},
		{"plain user", map[string]any{"role": "user"}, false},
		{"admin", map[string]any{"role": "admin"}, true},
		{"second configured role", map[string]any{"role": "owner"}, true},
		{"comma separated", map[string]any{"role": "user,owner"}, true},
		{"spaced list", map[string]any{"role": "user, admin"}, true},
		{"substring must not match", map[string]any{"role": "administrator"}, false},
		// A value of the wrong type must not be read as a grant.
		{"wrong type", map[string]any{"role": 42}, false},
		{"nil value", map[string]any{"role": nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user := &storage.User{ID: "u1", Extra: tc.extra}
			if got := plugin.IsAdmin(user); got != tc.want {
				t.Fatalf("IsAdmin = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAdminUserIDsGrantAccess(t *testing.T) {
	// A bootstrap administrator identified by ID, for the first deploy
	// when no account has a role yet.
	var plugin *admin.Plugin
	env := plugintest.NewWith(t, func(cfg *godevauth.Config) {
		plugin = admin.New(admin.Options{AdminUserIDs: []string{"bootstrap-id"}})
		cfg.Plugins = []godevauth.Plugin{plugin}
	})
	user := env.SignUp("nobody@example.com", "password123")

	if plugin.IsAdmin(user) {
		t.Fatal("an ordinary user was treated as an administrator")
	}
	if !plugin.IsAdmin(&storage.User{ID: "bootstrap-id"}) {
		t.Fatal("the configured bootstrap ID was not treated as an administrator")
	}
}

// TestCreateUserEnforcesCredentialRules is the regression test for the
// live bug found on a downstream project: admin create-user validated
// only that the e-mail was non-empty. It accepted "not-an-email" with the
// password "123" and returned 200. With public sign-up disabled,
// create-user is the only way accounts are made, so every account was
// bypassing every credential rule — a typo'd address is a user who can
// never receive a password reset.
func TestCreateUserEnforcesCredentialRules(t *testing.T) {
	env, _ := newEnv(t)

	// malformed e-mail is rejected with the library's own error, exactly
	// as the public sign-up path would reject it.
	res, body := env.POST("/admin/create-user", map[string]any{
		"email": "not-an-email", "password": "password123",
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_EMAIL")

	// too-short password is rejected too.
	res, body = env.POST("/admin/create-user", map[string]any{
		"email": "ok@example.com", "password": "123",
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "PASSWORD_TOO_SHORT")

	// a valid pair still works.
	res, body = env.POST("/admin/create-user", map[string]any{
		"email": "good@example.com", "password": "password123",
	})
	env.RequireStatus(res, body, http.StatusOK)
}

// TestCreateUserIsNotAValidationOracle pins the ordering the downstream
// author had to correct by hand: the admin check must run before any
// input validation, so a stranger cannot probe which e-mails are valid.
// A non-admin must be refused with an authorization error, never with
// "Invalid email".
func TestCreateUserIsNotAValidationOracle(t *testing.T) {
	env, _ := newEnv(t)

	member := env.Client()
	member.SignUp("member@example.com", "password123")
	res, body := member.Do(http.MethodPost, "/admin/create-user",
		map[string]any{"email": "not-an-email", "password": "123"})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin: status %d, want 403", res.StatusCode)
	}
	if code, _ := body["code"].(string); code == "INVALID_EMAIL" || code == "PASSWORD_TOO_SHORT" {
		t.Fatalf("validation ran before the admin check — leaks validity to a non-admin: %v", body)
	}

	anon := env.Client()
	res, body = anon.Do(http.MethodPost, "/admin/create-user",
		map[string]any{"email": "not-an-email", "password": "123"})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous: status %d, want 401", res.StatusCode)
	}
	if code, _ := body["code"].(string); code == "INVALID_EMAIL" || code == "PASSWORD_TOO_SHORT" {
		t.Fatalf("validation ran before the admin check for an anonymous caller: %v", body)
	}
}

// TestCreateUserRejectsUnknownRoleWhenConstrained pins the role
// allow-list: a role outside it — a typo, or one carried over from
// another system — would otherwise create an account silently locked out
// of every route.
func TestCreateUserRejectsUnknownRoleWhenConstrained(t *testing.T) {
	plugin := admin.New(admin.Options{Roles: []string{"engineer", "support"}})
	env := plugintest.New(t, plugin)
	root := env.SignUp("root@example.com", "password123")
	if _, err := env.Auth.UpdateUserRecord(context.Background(), root.ID,
		map[string]any{"role": "admin"}); err != nil {
		t.Fatal(err)
	}

	res, body := env.POST("/admin/create-user", map[string]any{
		"email": "typo@example.com", "password": "password123", "role": "superuser",
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_ROLE")

	// the correctly spelled role is accepted.
	res, body = env.POST("/admin/create-user", map[string]any{
		"email": "eng@example.com", "password": "password123", "role": "engineer",
	})
	env.RequireStatus(res, body, http.StatusOK)
}

// TestSetUserPasswordEnforcesRules is the sibling of the create-user
// gap: an admin setting a user's password must be held to the same
// length rule as every other password path.
func TestSetUserPasswordEnforcesRules(t *testing.T) {
	env, _ := newEnv(t)
	res, body := env.POST("/admin/create-user", map[string]any{
		"email": "target@example.com", "password": "password123",
	})
	env.RequireStatus(res, body, http.StatusOK)
	target, _ := body["user"].(map[string]any)
	id, _ := target["id"].(string)

	res, body = env.POST("/admin/set-user-password", map[string]any{
		"userId": id, "newPassword": "123",
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "PASSWORD_TOO_SHORT")

	res, body = env.POST("/admin/set-user-password", map[string]any{
		"userId": id, "newPassword": "a-good-password",
	})
	env.RequireStatus(res, body, http.StatusOK)
}

// TestUpdateUserCannotBypassSiblingValidation reproduces a downstream
// report: update-user wrote its data map straight onto the record with
// only "id" stripped, so it bypassed the rules its siblings enforce.
// The proof was two pairs — set-role refuses "superuser" but update-user
// set it on the same user; create-user refuses "not-an-email" but
// update-user accepted it. An endpoint that accepts what its sibling
// refuses is a trap for anyone scripting against the API.
func TestUpdateUserCannotBypassSiblingValidation(t *testing.T) {
	plugin := admin.New(admin.Options{Roles: []string{"engineer", "support"}})
	env := plugintest.New(t, plugin)
	root := env.SignUp("root@example.com", "password123")
	if _, err := env.Auth.UpdateUserRecord(context.Background(), root.ID,
		map[string]any{"role": "admin"}); err != nil {
		t.Fatal(err)
	}

	res, body := env.POST("/admin/create-user", map[string]any{
		"email": "target@example.com", "password": "password123", "role": "engineer",
	})
	env.RequireStatus(res, body, http.StatusOK)
	target, _ := body["user"].(map[string]any)
	id, _ := target["id"].(string)

	// set-role refuses an unknown role...
	res, body = env.POST("/admin/set-role", map[string]any{"userId": id, "role": "superuser"})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_ROLE")
	// ...so update-user must refuse it too, on the same user.
	res, body = env.POST("/admin/update-user", map[string]any{
		"userId": id, "data": map[string]any{"role": "superuser"},
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_ROLE")

	// create-user refuses a malformed address, so update-user must too.
	res, body = env.POST("/admin/update-user", map[string]any{
		"userId": id, "data": map[string]any{"email": "not-an-email"},
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_EMAIL")

	// A non-string in a validated field is rejected, not coerced.
	res, body = env.POST("/admin/update-user", map[string]any{
		"userId": id, "data": map[string]any{"role": 42},
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_ROLE")

	// Legitimate updates still work, including unvalidated fields.
	res, body = env.POST("/admin/update-user", map[string]any{
		"userId": id,
		"data":   map[string]any{"role": "support", "name": "Renamed"},
	})
	env.RequireStatus(res, body, http.StatusOK)
	updated, _ := body["user"].(map[string]any)
	if updated["name"] != "Renamed" {
		t.Fatalf("name = %#v", updated["name"])
	}
}

// TestCreateUserDataMapIsNotASideDoor pins the second instance of the
// same class, found while sweeping for siblings of the update-user
// report: create-user validated its "email" parameter but then merged
// the free-form data map over the top, so data.email could reinstate a
// malformed address that the parameter had just refused.
func TestCreateUserDataMapIsNotASideDoor(t *testing.T) {
	plugin := admin.New(admin.Options{Roles: []string{"engineer"}})
	env := plugintest.New(t, plugin)
	root := env.SignUp("root@example.com", "password123")
	if _, err := env.Auth.UpdateUserRecord(context.Background(), root.ID,
		map[string]any{"role": "admin"}); err != nil {
		t.Fatal(err)
	}

	// a malformed address smuggled through data is refused
	res, body := env.POST("/admin/create-user", map[string]any{
		"email": "ok@example.com", "password": "password123", "role": "engineer",
		"data": map[string]any{"email": "not-an-email"},
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_EMAIL")

	// an unknown role smuggled through data is refused
	res, body = env.POST("/admin/create-user", map[string]any{
		"email": "ok2@example.com", "password": "password123", "role": "engineer",
		"data": map[string]any{"role": "superuser"},
	})
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_ROLE")

	// the dedicated parameters win over the same keys in data
	res, body = env.POST("/admin/create-user", map[string]any{
		"email": "wins@example.com", "password": "password123", "role": "engineer",
		"data": map[string]any{"email": "other@example.com"},
	})
	env.RequireStatus(res, body, http.StatusOK)
	created, _ := body["user"].(map[string]any)
	if created["email"] != "wins@example.com" {
		t.Fatalf("data.email overrode the validated parameter: %#v", created["email"])
	}
	if created["role"] != "engineer" {
		t.Fatalf("role = %#v", created["role"])
	}
}

// Regression test for M14: an impersonated session must not be able to
// use admin powers, even when the impersonated user is an admin —
// otherwise admin actions taken while impersonating are attributed to
// the target and the real actor vanishes from the audit trail.
func TestImpersonatedSessionCannotActAsAdmin(t *testing.T) {
	env, _ := newEnv(t)

	// A second admin to impersonate (allowed only via the opt-in).
	second := env.Client()
	su := second.SignUp("admin2@example.com", "password123")
	if _, err := env.Auth.UpdateUserRecord(context.Background(), su.ID,
		map[string]any{"role": "admin"}); err != nil {
		t.Fatal(err)
	}

	// By default, impersonating another admin is refused outright.
	res, body := env.POST("/admin/impersonate-user", map[string]any{"userId": su.ID})
	env.RequireErrorCode(res, body, http.StatusForbidden, "CANNOT_IMPERSONATE_ADMIN")

	// Impersonate an ordinary user instead, then try an admin action
	// through that session.
	victim := env.Client()
	vu := victim.SignUp("victim@example.com", "password123")

	imp := env.Client()
	iu := imp.SignUp("imp-admin@example.com", "password123")
	if _, err := env.Auth.UpdateUserRecord(context.Background(), iu.ID,
		map[string]any{"role": "admin"}); err != nil {
		t.Fatal(err)
	}
	res, body = imp.POST("/admin/impersonate-user", map[string]any{"userId": vu.ID})
	env.RequireStatus(res, body, http.StatusOK)

	// The impersonating client now holds the victim's (non-admin)
	// session, so admin routes are refused — but even if the victim
	// were an admin, the impersonated marker alone blocks it.
	res, body = imp.GET("/admin/list-users")
	if res.StatusCode == http.StatusOK {
		t.Fatalf("admin route reachable from an impersonated session: %v", body)
	}
}

// Companion: an impersonated *admin* session (allowed via opt-in) still
// cannot use admin powers — the containment does not depend on the
// impersonated user's role.
func TestImpersonatedAdminSessionStillCannotActAsAdmin(t *testing.T) {
	plugin := admin.New(admin.Options{AllowImpersonatingAdmins: true})
	env := plugintest.New(t, plugin)
	root := env.SignUp("root@example.com", "password123")
	if _, err := env.Auth.UpdateUserRecord(context.Background(), root.ID,
		map[string]any{"role": "admin"}); err != nil {
		t.Fatal(err)
	}

	other := env.Client()
	ou := other.SignUp("other-admin@example.com", "password123")
	if _, err := env.Auth.UpdateUserRecord(context.Background(), ou.ID,
		map[string]any{"role": "admin"}); err != nil {
		t.Fatal(err)
	}

	res, body := env.POST("/admin/impersonate-user", map[string]any{"userId": ou.ID})
	env.RequireStatus(res, body, http.StatusOK)

	// env now holds the impersonated admin session. Admin actions must
	// still be refused with the impersonation-specific error.
	res, body = env.GET("/admin/list-users")
	env.RequireErrorCode(res, body, http.StatusForbidden, "NOT_ALLOWED_WHILE_IMPERSONATING")
}
