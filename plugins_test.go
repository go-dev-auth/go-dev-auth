package godevauth_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/plugins/apikey"
	"github.com/go-dev-auth/go-dev-auth/plugins/bearer"
	jwtplugin "github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/plugins/magiclink"
	"github.com/go-dev-auth/go-dev-auth/plugins/organization"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

func TestMagicLinkFlow(t *testing.T) {
	var linkURL, token string
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{
			magiclink.New(magiclink.Options{
				SendMagicLink: func(ctx context.Context, email, url, tok string) error {
					linkURL, token = url, tok
					return nil
				},
			}),
		}
	})
	res, _ := tc.post("/sign-in/magic-link", map[string]any{
		"email": "magic@example.com", "name": "Magic User", "callbackURL": "/welcome",
	})
	if res.StatusCode != http.StatusOK || token == "" {
		t.Fatalf("magic-link request: %d token=%q", res.StatusCode, token)
	}
	if !strings.Contains(linkURL, token) {
		t.Fatalf("link %q missing token", linkURL)
	}

	// bad token fails
	res, _ = tc.get("/magic-link/verify?token=bogus")
	if res.StatusCode == http.StatusFound {
		loc := res.Header.Get("Location")
		if !strings.Contains(loc, "error") {
			t.Fatalf("expected error redirect, got %q", loc)
		}
	}

	// real token creates user + session
	res, _ = tc.get("/magic-link/verify?token=" + url.QueryEscape(token))
	if res.StatusCode != http.StatusFound {
		t.Fatalf("verify: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "/welcome") {
		t.Fatalf("redirect = %q", res.Header.Get("Location"))
	}
	_, session := tc.get("/get-session")
	if session == nil || session["user"].(map[string]any)["email"] != "magic@example.com" {
		t.Fatalf("session = %v", session)
	}
	if session["user"].(map[string]any)["emailVerified"] != true {
		t.Error("magic link user should be email verified")
	}

	// token is single use
	res, _ = tc.get("/magic-link/verify?token=" + url.QueryEscape(token))
	loc := res.Header.Get("Location")
	if res.StatusCode == http.StatusFound && !strings.Contains(loc, "error") {
		t.Fatalf("expected reused token to fail, got redirect %q", loc)
	}
}

func TestTwoFactorFlow(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{twofactor.New()}
	})
	tc.signUp("tf@example.com", "password123", "TF User")

	// enable 2FA
	res, body := tc.post("/two-factor/enable", map[string]any{"password": "password123"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enable: %d %v", res.StatusCode, body)
	}
	totpURI, _ := body["totpURI"].(string)
	if !strings.HasPrefix(totpURI, "otpauth://totp/") {
		t.Fatalf("totpURI = %q", totpURI)
	}
	codes, _ := body["backupCodes"].([]any)
	if len(codes) != 10 {
		t.Fatalf("backup codes = %d", len(codes))
	}

	// extract secret and confirm via verify-totp
	u, err := url.Parse(totpURI)
	if err != nil {
		t.Fatal(err)
	}
	secret := u.Query().Get("secret")
	code, err := crypto.TOTP(secret, time.Now(), 30, 6)
	if err != nil {
		t.Fatal(err)
	}
	res, body = tc.post("/two-factor/verify-totp", map[string]any{"code": code})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify-totp: %d %v", res.StatusCode, body)
	}

	// sign out; sign in should now require the second factor
	tc.post("/sign-out", map[string]any{})
	res, body = tc.post("/sign-in/email", map[string]any{
		"email": "tf@example.com", "password": "password123",
	})
	if res.StatusCode != http.StatusOK || body["twoFactorRedirect"] != true {
		t.Fatalf("expected twoFactorRedirect, got %d %v", res.StatusCode, body)
	}
	_, session := tc.get("/get-session")
	if session != nil {
		t.Fatal("no session should exist before second factor")
	}

	// wrong TOTP fails
	res, _ = tc.post("/two-factor/verify-totp", map[string]any{"code": "000000"})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad code, got %d", res.StatusCode)
	}

	// correct TOTP completes sign-in
	code, _ = crypto.TOTP(secret, time.Now(), 30, 6)
	res, body = tc.post("/two-factor/verify-totp", map[string]any{"code": code})
	if res.StatusCode != http.StatusOK || body["token"] == nil {
		t.Fatalf("verify-totp sign-in: %d %v", res.StatusCode, body)
	}
	_, session = tc.get("/get-session")
	if session == nil {
		t.Fatal("expected session after 2FA")
	}

	// backup code flow
	tc.post("/sign-out", map[string]any{})
	tc.post("/sign-in/email", map[string]any{"email": "tf@example.com", "password": "password123"})
	backup := codes[0].(string)
	res, body = tc.post("/two-factor/verify-backup-code", map[string]any{"code": backup})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("verify-backup-code: %d %v", res.StatusCode, body)
	}
	// same code can't be reused
	tc.post("/sign-out", map[string]any{})
	tc.post("/sign-in/email", map[string]any{"email": "tf@example.com", "password": "password123"})
	res, _ = tc.post("/two-factor/verify-backup-code", map[string]any{"code": backup})
	if res.StatusCode == http.StatusOK {
		t.Fatal("expected consumed backup code to fail")
	}

	// disable
	code, _ = crypto.TOTP(secret, time.Now(), 30, 6)
	tc.post("/two-factor/verify-totp", map[string]any{"code": code})
	res, _ = tc.post("/two-factor/disable", map[string]any{"password": "password123"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("disable: %d", res.StatusCode)
	}
	tc.post("/sign-out", map[string]any{})
	res, body = tc.post("/sign-in/email", map[string]any{
		"email": "tf@example.com", "password": "password123",
	})
	if body["twoFactorRedirect"] == true {
		t.Fatal("2FA should be disabled")
	}
}

func TestAPIKeyFlow(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{apikey.New(apikey.Options{KeyPrefix: "gda_"})}
	})
	tc.signUp("keys@example.com", "password123", "Key User")

	res, body := tc.post("/api-key/create", map[string]any{"name": "ci-key"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %v", res.StatusCode, body)
	}
	plain, _ := body["key"].(string)
	if !strings.HasPrefix(plain, "gda_") {
		t.Fatalf("key = %q", plain)
	}
	keyID, _ := body["id"].(string)

	// list does not leak the key
	res, _ = tc.get("/api-key/list")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: %d", res.StatusCode)
	}

	// verify endpoint
	res, body = tc.post("/api-key/verify", map[string]any{"key": plain})
	if res.StatusCode != http.StatusOK || body["valid"] != true {
		t.Fatalf("verify: %d %v", res.StatusCode, body)
	}
	res, body = tc.post("/api-key/verify", map[string]any{"key": "gda_bogus"})
	if body["valid"] != false {
		t.Fatalf("expected invalid, got %v", body)
	}

	// authenticate a request with the API key only (no cookies)
	req, _ := http.NewRequest(http.MethodGet, tc.server.URL+"/api/auth/get-session", nil)
	req.Header.Set("x-api-key", plain)
	plainClient := &http.Client{}
	res2, err := plainClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("apikey session: %d", res2.StatusCode)
	}

	// delete
	res, _ = tc.post("/api-key/delete", map[string]any{"keyId": keyID})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d", res.StatusCode)
	}
	res, body = tc.post("/api-key/verify", map[string]any{"key": plain})
	if body["valid"] != false {
		t.Fatal("deleted key should be invalid")
	}
}

func TestJWTPlugin(t *testing.T) {
	p := jwtplugin.New()
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{p}
	})
	tc.signUp("jwt@example.com", "password123", "JWT User")

	res, body := tc.get("/token")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/token: %d %v", res.StatusCode, body)
	}
	token, _ := body["token"].(string)
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token = %q", token)
	}

	// verify through the plugin API
	claims, err := p.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if claims["email"] != "jwt@example.com" {
		t.Errorf("claims = %v", claims)
	}
	if claims["iss"] != auth.Config().BaseURL {
		t.Errorf("iss = %v", claims["iss"])
	}

	// JWKS endpoint
	res, jwks := tc.get("/jwks")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/jwks: %d", res.StatusCode)
	}
	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("keys = %v", jwks)
	}
	k := keys[0].(map[string]any)
	if k["kty"] != "OKP" || k["crv"] != "Ed25519" {
		t.Errorf("jwk = %v", k)
	}

	// unauthenticated /token
	tc.post("/sign-out", map[string]any{})
	res, _ = tc.get("/token")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestBearerPlugin(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{bearer.New()}
	})
	body := tc.signUp("bearer@example.com", "password123", "Bearer User")
	token, _ := body["token"].(string)
	if token == "" {
		t.Fatal("no token from sign-up")
	}

	// use the raw session token via Authorization header, no cookies
	req, _ := http.NewRequest(http.MethodGet, tc.server.URL+"/api/auth/get-session", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("bearer get-session: %d", res.StatusCode)
	}
}

func TestAdminPlugin(t *testing.T) {
	adminPlugin := admin.New()
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{adminPlugin}
	})
	// first user; promote to admin directly in the database
	body := tc.signUp("root@example.com", "password123", "Root")
	rootID := body["user"].(map[string]any)["id"].(string)
	_, err := auth.UpdateUserRecord(context.Background(), rootID, map[string]any{"role": "admin"})
	if err != nil {
		t.Fatal(err)
	}

	// create a user via admin API
	res, body := tc.post("/admin/create-user", map[string]any{
		"email": "worker@example.com", "password": "password123", "name": "Worker",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create-user: %d %v", res.StatusCode, body)
	}
	workerID := body["user"].(map[string]any)["id"].(string)

	// list users
	res, body = tc.get("/admin/list-users?limit=10")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list-users: %d %v", res.StatusCode, body)
	}
	if body["total"].(float64) != 2 {
		t.Fatalf("total = %v", body["total"])
	}

	// set role
	res, _ = tc.post("/admin/set-role", map[string]any{"userId": workerID, "role": "support"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("set-role: %d", res.StatusCode)
	}

	// ban user; banned user cannot sign in
	res, _ = tc.post("/admin/ban-user", map[string]any{"userId": workerID, "banReason": "spam"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ban-user: %d", res.StatusCode)
	}
	res, body = tc.post("/sign-in/email", map[string]any{
		"email": "worker@example.com", "password": "password123",
	})
	if res.StatusCode != http.StatusForbidden || body["code"] != "BANNED_USER" {
		t.Fatalf("expected BANNED_USER, got %d %v", res.StatusCode, body)
	}

	// unban
	res, _ = tc.post("/admin/unban-user", map[string]any{"userId": workerID})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unban-user: %d", res.StatusCode)
	}

	// impersonate
	res, body = tc.post("/admin/impersonate-user", map[string]any{"userId": workerID})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("impersonate: %d %v", res.StatusCode, body)
	}
	_, session := tc.get("/get-session")
	if session["user"].(map[string]any)["email"] != "worker@example.com" {
		t.Fatalf("impersonated session = %v", session["user"])
	}
	res, _ = tc.post("/admin/stop-impersonating", map[string]any{})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("stop-impersonating: %d", res.StatusCode)
	}
	_, session = tc.get("/get-session")
	if session["user"].(map[string]any)["email"] != "root@example.com" {
		t.Fatalf("expected admin session back, got %v", session["user"])
	}

	// non-admin cannot access admin routes
	tc.post("/sign-out", map[string]any{})
	tc.post("/sign-in/email", map[string]any{"email": "worker@example.com", "password": "password123"})
	res, _ = tc.get("/admin/list-users")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", res.StatusCode)
	}

	// remove user (as admin again)
	tc.post("/sign-out", map[string]any{})
	tc.post("/sign-in/email", map[string]any{"email": "root@example.com", "password": "password123"})
	res, _ = tc.post("/admin/remove-user", map[string]any{"userId": workerID})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("remove-user: %d", res.StatusCode)
	}
}

func TestOrganizationPlugin(t *testing.T) {
	var invitationID string
	orgPlugin := organization.New(organization.Options{
		Teams: true,
		SendInvitationEmail: func(ctx context.Context, inv *organization.Invitation, org *organization.Organization, inviter *storage.User) error {
			invitationID = inv.ID
			return nil
		},
	})
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{orgPlugin}
	})
	tc.signUp("owner@example.com", "password123", "Owner")

	// create org
	res, org := tc.post("/organization/create", map[string]any{
		"name": "Acme Corp", "slug": "acme",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %v", res.StatusCode, org)
	}
	if org["slug"] != "acme" {
		t.Fatalf("slug = %v", org["slug"])
	}

	// duplicate slug rejected
	res, body := tc.post("/organization/create", map[string]any{"name": "Other", "slug": "acme"})
	if res.StatusCode != http.StatusBadRequest || body["code"] != "SLUG_TAKEN" {
		t.Fatalf("expected SLUG_TAKEN, got %d %v", res.StatusCode, body)
	}

	// active member
	res, member := tc.get("/organization/get-active-member")
	if res.StatusCode != http.StatusOK || member["role"] != "owner" {
		t.Fatalf("active member = %v", member)
	}

	// invite a member
	res, inv := tc.post("/organization/invite-member", map[string]any{
		"email": "member@example.com", "role": "member",
	})
	if res.StatusCode != http.StatusOK || invitationID == "" {
		t.Fatalf("invite: %d %v", res.StatusCode, inv)
	}

	// the invitee signs up and accepts
	tc2 := secondClient(t, tc)
	tc2.signUp("member@example.com", "password123", "Member")
	markEmailVerified(t, auth, "member@example.com")
	res, body = tc2.post("/organization/accept-invitation", map[string]any{
		"invitationId": invitationID,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("accept: %d %v", res.StatusCode, body)
	}

	// full org shows 2 members
	res, full := tc.get("/organization/get-full-organization")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get-full: %d", res.StatusCode)
	}
	members := full["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("members = %d", len(members))
	}

	// member cannot invite
	res, _ = tc2.post("/organization/invite-member", map[string]any{
		"email": "third@example.com",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for member invite, got %d", res.StatusCode)
	}

	// teams
	res, team := tc.post("/organization/create-team", map[string]any{"name": "Platform"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create-team: %d %v", res.StatusCode, team)
	}
	res, teams := tc.do(http.MethodGet, "/organization/list-teams", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list-teams: %d %v", res.StatusCode, teams)
	}

	// owner cannot leave as only owner
	res, body = tc.post("/organization/leave", map[string]any{})
	if res.StatusCode != http.StatusBadRequest || body["code"] != "CANNOT_LEAVE_AS_ONLY_OWNER" {
		t.Fatalf("expected CANNOT_LEAVE_AS_ONLY_OWNER, got %d %v", res.StatusCode, body)
	}

	// member leaves
	res, _ = tc2.post("/organization/leave", map[string]any{})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("leave: %d", res.StatusCode)
	}

	// list organizations
	res, _ = tc.get("/organization/list")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: %d", res.StatusCode)
	}
}

// secondClient returns a fresh cookie-jar client for the same server.
func secondClient(t *testing.T, tc *testClient) *testClient {
	t.Helper()
	jar := &cookieJar{cookies: map[string]*http.Cookie{}}
	return &testClient{
		t:      t,
		server: tc.server,
		client: &http.Client{
			Jar: jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}
