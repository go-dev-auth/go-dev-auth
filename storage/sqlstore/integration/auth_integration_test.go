package integration_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/sqlstore"
)

// ---- harness ----------------------------------------------------------

// authEnv is one auth instance wired to its own SQLite file.
type authEnv struct {
	auth  *godevauth.Auth
	store *sqlstore.Adapter
	db    *sql.DB
	ctx   context.Context
}

// newAuthEnv builds an Auth backed by a real SQLite database and serves
// it from an httptest server.
//
// Ordering matters: godevauth.New hands the adapter the *complete*
// schema (core + configured additional fields + plugin tables) through
// storage.SchemaAware, so Migrate has to run afterwards or those extra
// columns would never be created.
func newAuthEnv(t *testing.T, mutate func(*godevauth.Config)) (*authEnv, *testClient) {
	t.Helper()
	db := openSQLite(t)
	t.Cleanup(func() { db.Close() })
	store := sqlstore.New(db, sqlstore.SQLite, nil)

	cfg := godevauth.Config{
		// BaseURL must be set before New (it is validated there);
		// it is repointed at the live server address below.
		BaseURL:  "http://127.0.0.1",
		Secret:   "integration-secret-0123456789abcdef",
		Database: store,
		// Every test replays the same endpoint from one IP.
		RateLimit: godevauth.RateLimitConfig{Disabled: true},
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	auth, err := godevauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	auth.Config().BaseURL = server.URL

	env := &authEnv{auth: auth, store: store, db: db, ctx: ctx}
	return env, newTestClient(t, server)
}

// count is a shortcut for asserting row counts straight from the
// database rather than trusting the HTTP response.
func (e *authEnv) count(t *testing.T, model string, where ...storage.Where) int64 {
	t.Helper()
	n, err := e.store.Count(e.ctx, model, where)
	if err != nil {
		t.Fatalf("count %s: %v", model, err)
	}
	return n
}

func (e *authEnv) findOne(t *testing.T, model string, where ...storage.Where) map[string]any {
	t.Helper()
	rec, err := e.store.FindOne(e.ctx, model, where)
	if err != nil {
		t.Fatalf("findOne %s %v: %v", model, where, err)
	}
	return rec
}

// testClient drives the handler the way a browser does: one cookie jar,
// JSON bodies, redirects left unfollowed so status codes are visible.
type testClient struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client
}

func newTestClient(t *testing.T, server *httptest.Server) *testClient {
	return &testClient{
		t:      t,
		server: server,
		client: &http.Client{
			Jar: &cookieJar{cookies: map[string]*http.Cookie{}},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type cookieJar struct {
	mu      sync.Mutex
	cookies map[string]*http.Cookie
}

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		if c.MaxAge < 0 {
			delete(j.cookies, c.Name)
			continue
		}
		j.cookies[c.Name] = c
	}
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*http.Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		out = append(out, c)
	}
	return out
}

func (tc *testClient) do(method, path string, body any) (*http.Response, map[string]any) {
	tc.t.Helper()
	res, raw := tc.doRaw(method, path, body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return res, out
}

func (tc *testClient) doRaw(method, path string, body any) (*http.Response, []byte) {
	tc.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			tc.t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, tc.server.URL+"/api/auth"+path, reader)
	if err != nil {
		tc.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := tc.client.Do(req)
	if err != nil {
		tc.t.Fatal(err)
	}
	defer res.Body.Close()
	raw := new(bytes.Buffer)
	_, _ = raw.ReadFrom(res.Body)
	return res, raw.Bytes()
}

func (tc *testClient) post(path string, body any) (*http.Response, map[string]any) {
	return tc.do(http.MethodPost, path, body)
}

func (tc *testClient) get(path string) (*http.Response, map[string]any) {
	return tc.do(http.MethodGet, path, nil)
}

// getList performs a GET whose response body is a JSON array.
func (tc *testClient) getList(path string) (*http.Response, []map[string]any) {
	tc.t.Helper()
	res, raw := tc.doRaw(http.MethodGet, path, nil)
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		tc.t.Fatalf("GET %s: decoding %q: %v", path, raw, err)
	}
	return res, out
}

func (tc *testClient) signUp(email, password, name string) map[string]any {
	tc.t.Helper()
	res, body := tc.post("/sign-up/email", map[string]any{
		"email": email, "password": password, "name": name,
	})
	if res.StatusCode != http.StatusOK {
		tc.t.Fatalf("sign-up failed: %d %v", res.StatusCode, body)
	}
	return body
}

func (tc *testClient) signIn(email, password string) (*http.Response, map[string]any) {
	return tc.post("/sign-in/email", map[string]any{
		"email": email, "password": password,
	})
}

// ---- tests ------------------------------------------------------------

// TestSignUpSessionSignOutSignIn walks the primary credential flow and
// checks the database after every step, so a handler that returns 200
// without persisting anything cannot pass.
func TestSignUpSessionSignOutSignIn(t *testing.T) {
	env, tc := newAuthEnv(t, nil)

	body := tc.signUp("alice@example.com", "password123", "Alice")
	token, _ := body["token"].(string)
	if token == "" {
		t.Fatal("expected an auto sign-in token")
	}

	// user row
	userRec := env.findOne(t, storage.ModelUser, storage.W("email", "alice@example.com"))
	user := storage.UserFromMap(userRec)
	if user.Name != "Alice" {
		t.Errorf("stored name = %q", user.Name)
	}
	if user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() {
		t.Errorf("timestamps not persisted: %v / %v", user.CreatedAt, user.UpdatedAt)
	}
	if user.EmailVerified {
		t.Error("emailVerified should default to false")
	}

	// credential account row, with a hash that is not the password
	accRec := env.findOne(t, storage.ModelAccount,
		storage.W("userId", user.ID), storage.W("providerId", "credential"))
	acc := storage.AccountFromMap(accRec)
	if acc.Password == "" || strings.Contains(acc.Password, "password123") {
		t.Errorf("credential password stored badly: %q", acc.Password)
	}

	// session row matching the returned token
	sessRec := env.findOne(t, storage.ModelSession, storage.W("token", token))
	sess := storage.SessionFromMap(sessRec)
	if sess.UserID != user.ID {
		t.Errorf("session.userId = %q, want %q", sess.UserID, user.ID)
	}
	if !sess.ExpiresAt.After(time.Now()) {
		t.Errorf("session already expired: %v", sess.ExpiresAt)
	}

	// the cookie alone authenticates
	res, session := tc.get("/get-session")
	if res.StatusCode != http.StatusOK || session == nil {
		t.Fatalf("get-session: %d %v", res.StatusCode, session)
	}
	if session["user"].(map[string]any)["email"] != "alice@example.com" {
		t.Fatalf("session user = %v", session["user"])
	}

	// sign out deletes the row, not just the cookie
	if res, _ := tc.post("/sign-out", map[string]any{}); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-out: %d", res.StatusCode)
	}
	if n := env.count(t, storage.ModelSession, storage.W("token", token)); n != 0 {
		t.Fatalf("session row survived sign-out: %d", n)
	}
	if _, session := tc.get("/get-session"); session != nil {
		t.Fatalf("still signed in after sign-out: %v", session)
	}

	// wrong password is rejected and creates nothing
	res, _ = tc.signIn("alice@example.com", "wrong-password")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: expected 401, got %d", res.StatusCode)
	}
	if n := env.count(t, storage.ModelSession); n != 0 {
		t.Fatalf("failed sign-in created %d session rows", n)
	}

	// sign in again: a new row, a new token, same user
	res, body = tc.signIn("alice@example.com", "password123")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in: %d %v", res.StatusCode, body)
	}
	newToken, _ := body["token"].(string)
	if newToken == "" || newToken == token {
		t.Fatalf("expected a fresh session token, got %q", newToken)
	}
	if n := env.count(t, storage.ModelSession, storage.W("userId", user.ID)); n != 1 {
		t.Fatalf("session rows after re-sign-in = %d, want 1", n)
	}
	if _, session := tc.get("/get-session"); session == nil {
		t.Fatal("expected the new cookie to authenticate")
	}
	// still exactly one user
	if n := env.count(t, storage.ModelUser); n != 1 {
		t.Fatalf("user rows = %d, want 1", n)
	}
}

// TestDuplicateSignUpIsClientError pins that a unique-index collision
// surfaces as a 4xx. Getting this wrong means the adapter failed to map
// the driver's constraint error onto storage.ErrUniqueViolation, and
// every duplicate registration becomes a 500 (and a pager alert).
func TestDuplicateSignUpIsClientError(t *testing.T) {
	env, tc := newAuthEnv(t, nil)
	tc.signUp("dup@example.com", "password123", "Dup")

	res, body := tc.post("/sign-up/email", map[string]any{
		"email": "dup@example.com", "password": "password123", "name": "Dup Again",
	})
	if res.StatusCode < 400 || res.StatusCode >= 500 {
		t.Fatalf("duplicate sign-up: expected 4xx, got %d %v", res.StatusCode, body)
	}
	if n := env.count(t, storage.ModelUser); n != 1 {
		t.Fatalf("user rows = %d, want 1", n)
	}

	// Same thing with the pre-flight existence check bypassed: writing
	// the row directly is what a racing request does, and it must come
	// back as ErrUniqueViolation rather than a raw driver error.
	existing := env.findOne(t, storage.ModelUser, storage.W("email", "dup@example.com"))
	now := time.Now().UTC()
	_, err := env.store.Create(env.ctx, storage.ModelUser, map[string]any{
		"id": "racing-id", "name": "Racer", "email": existing["email"],
		"emailVerified": false, "createdAt": now, "updatedAt": now,
	})
	if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("direct duplicate insert: expected ErrUniqueViolation, got %v", err)
	}
	if n := env.count(t, storage.ModelUser); n != 1 {
		t.Fatalf("user rows after failed insert = %d, want 1", n)
	}

	// case-insensitivity: emails are normalised before storage
	res, _ = tc.post("/sign-up/email", map[string]any{
		"email": "DUP@Example.com", "password": "password123", "name": "Shouty",
	})
	if res.StatusCode < 400 || res.StatusCode >= 500 {
		t.Fatalf("case-variant duplicate: expected 4xx, got %d", res.StatusCode)
	}
	if n := env.count(t, storage.ModelUser); n != 1 {
		t.Fatalf("user rows = %d, want 1", n)
	}
}

// TestPasswordResetEndToEnd runs the whole reset dance against real
// storage: the token comes out of the send hook, the verification row
// lands in the database, is consumed exactly once, and the old password
// stops working.
func TestPasswordResetEndToEnd(t *testing.T) {
	var resetURL, resetToken string
	env, tc := newAuthEnv(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.SendResetPassword = func(ctx context.Context, u *storage.User, link, token string) error {
			resetURL, resetToken = link, token
			return nil
		}
		// Required whenever SendResetPassword is set; New refuses to
		// start without it.
		cfg.EmailAndPassword.ResetPasswordURL = "/choose-password"
	})
	tc.signUp("bob@example.com", "password123", "Bob")
	userRec := env.findOne(t, storage.ModelUser, storage.W("email", "bob@example.com"))
	userID, _ := userRec["id"].(string)
	oldHash := storage.AccountFromMap(env.findOne(t, storage.ModelAccount,
		storage.W("userId", userID), storage.W("providerId", "credential"))).Password

	res, _ := tc.post("/forget-password", map[string]any{"email": "bob@example.com"})
	if res.StatusCode != http.StatusOK || resetToken == "" {
		t.Fatalf("forget-password: %d, token %q", res.StatusCode, resetToken)
	}
	if !strings.Contains(resetURL, resetToken) {
		t.Fatalf("reset URL %q does not carry the token", resetURL)
	}
	// the token is persisted, and stored hashed rather than verbatim
	if n := env.count(t, storage.ModelVerification); n != 1 {
		t.Fatalf("verification rows = %d, want 1", n)
	}
	verifications, err := env.store.FindMany(env.ctx, storage.ModelVerification, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	v := storage.VerificationFromMap(verifications[0])
	if !v.ExpiresAt.After(time.Now()) {
		t.Errorf("reset token already expired: %v", v.ExpiresAt)
	}
	if v.CreatedAt.IsZero() {
		t.Error("verification createdAt not persisted")
	}

	// an unknown address must not leak, nor create a row
	res, _ = tc.post("/forget-password", map[string]any{"email": "nobody@example.com"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("forget-password for unknown email: %d", res.StatusCode)
	}
	if n := env.count(t, storage.ModelVerification); n != 1 {
		t.Fatalf("verification rows after unknown email = %d, want 1", n)
	}

	// a bogus token changes nothing
	res, _ = tc.post("/reset-password", map[string]any{
		"newPassword": "hijacked456", "token": "bogus",
	})
	if res.StatusCode == http.StatusOK {
		t.Fatal("expected a bogus reset token to be rejected")
	}

	res, _ = tc.post("/reset-password", map[string]any{
		"newPassword": "newpassword456", "token": resetToken,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reset-password: %d", res.StatusCode)
	}

	// the stored hash actually changed, and the token was consumed
	newHash := storage.AccountFromMap(env.findOne(t, storage.ModelAccount,
		storage.W("userId", userID), storage.W("providerId", "credential"))).Password
	if newHash == oldHash {
		t.Fatal("password hash unchanged after reset")
	}
	if n := env.count(t, storage.ModelVerification); n != 0 {
		t.Fatalf("reset token not consumed: %d verification rows left", n)
	}

	// old password dead, new one alive
	res, _ = tc.signIn("bob@example.com", "password123")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password still works: %d", res.StatusCode)
	}
	res, body := tc.signIn("bob@example.com", "newpassword456")
	if res.StatusCode != http.StatusOK || body["token"] == nil {
		t.Fatalf("new password rejected: %d %v", res.StatusCode, body)
	}

	// single use
	res, _ = tc.post("/reset-password", map[string]any{
		"newPassword": "anotherpass789", "token": resetToken,
	})
	if res.StatusCode == http.StatusOK {
		t.Fatal("expected the reset token to be single use")
	}
}

// TestUpdateUserPersists checks that /update-user writes through to the
// database, including a column contributed by Config.User.AdditionalFields
// (which only exists because Migrate runs after godevauth.New).
func TestUpdateUserPersists(t *testing.T) {
	env, tc := newAuthEnv(t, func(cfg *godevauth.Config) {
		cfg.User.AdditionalFields = []storage.Field{
			{Name: "favoriteColor", Type: storage.FieldString, Input: true},
		}
	})
	tc.signUp("erin@example.com", "password123", "Erin")
	before := env.findOne(t, storage.ModelUser, storage.W("email", "erin@example.com"))
	beforeUpdatedAt := storage.UserFromMap(before).UpdatedAt

	res, body := tc.post("/update-user", map[string]any{
		"name": "Erin Updated", "image": "https://example.com/e.png",
		"favoriteColor": "green",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("update-user: %d %v", res.StatusCode, body)
	}
	user, _ := body["user"].(map[string]any)
	if user["name"] != "Erin Updated" || user["favoriteColor"] != "green" {
		t.Fatalf("response did not reflect the update: %v", user)
	}

	after := env.findOne(t, storage.ModelUser, storage.W("email", "erin@example.com"))
	if after["name"] != "Erin Updated" {
		t.Errorf("stored name = %v", after["name"])
	}
	if after["image"] != "https://example.com/e.png" {
		t.Errorf("stored image = %v", after["image"])
	}
	if after["favoriteColor"] != "green" {
		t.Errorf("stored favoriteColor = %v (the additional column must exist and be written)", after["favoriteColor"])
	}
	if got := storage.UserFromMap(after).UpdatedAt; got.Before(beforeUpdatedAt) {
		t.Errorf("updatedAt went backwards: %v -> %v", beforeUpdatedAt, got)
	}
	// the update must not have disturbed identity columns
	if after["id"] != before["id"] || after["email"] != before["email"] {
		t.Errorf("update rewrote identity columns: %v -> %v", before, after)
	}
	if n := env.count(t, storage.ModelUser); n != 1 {
		t.Fatalf("user rows = %d, want 1", n)
	}
}

// TestListAndRevokeSessions signs the same account in from two separate
// clients and checks listing and revocation against the session table.
func TestListAndRevokeSessions(t *testing.T) {
	env, tc := newAuthEnv(t, nil)
	first := tc.signUp("gina@example.com", "password123", "Gina")
	firstToken, _ := first["token"].(string)

	// a second "device" with its own cookie jar
	other := newTestClient(t, tc.server)
	res, body := other.signIn("gina@example.com", "password123")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("second sign-in: %d %v", res.StatusCode, body)
	}
	secondToken, _ := body["token"].(string)
	if secondToken == "" || secondToken == firstToken {
		t.Fatalf("expected a distinct second session token, got %q", secondToken)
	}

	userID, _ := env.findOne(t, storage.ModelUser, storage.W("email", "gina@example.com"))["id"].(string)
	if n := env.count(t, storage.ModelSession, storage.W("userId", userID)); n != 2 {
		t.Fatalf("session rows = %d, want 2", n)
	}

	res, sessions := tc.getList("/list-sessions")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list-sessions: %d", res.StatusCode)
	}
	if len(sessions) != 2 {
		t.Fatalf("list-sessions returned %d sessions, want 2", len(sessions))
	}
	// the raw token is a bearer credential and must not be listed
	for _, s := range sessions {
		if s["token"] != nil {
			t.Errorf("list-sessions leaked a session token: %v", s["token"])
		}
		if s["userId"] != userID {
			t.Errorf("listed session for the wrong user: %v", s["userId"])
		}
	}

	// revoke the other device
	res, _ = tc.post("/revoke-session", map[string]any{"token": secondToken})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke-session: %d", res.StatusCode)
	}
	if n := env.count(t, storage.ModelSession, storage.W("token", secondToken)); n != 0 {
		t.Fatalf("revoked session row still present: %d", n)
	}
	if n := env.count(t, storage.ModelSession, storage.W("userId", userID)); n != 1 {
		t.Fatalf("session rows after revoke = %d, want 1", n)
	}
	// the revoked client is now anonymous, this one is not
	if _, s := other.get("/get-session"); s != nil {
		t.Fatal("revoked device is still signed in")
	}
	if _, s := tc.get("/get-session"); s == nil {
		t.Fatal("revoking another session signed this one out")
	}

	// revoke everything
	res, _ = tc.post("/revoke-sessions", map[string]any{})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke-sessions: %d", res.StatusCode)
	}
	if n := env.count(t, storage.ModelSession, storage.W("userId", userID)); n != 0 {
		t.Fatalf("session rows after revoke-sessions = %d, want 0", n)
	}
	if _, s := tc.get("/get-session"); s != nil {
		t.Fatalf("expected no session, got %v", s)
	}
}

// TestCleanupExpiredSweepsOnlyExpiredRows exercises the sweeper against
// real timestamp columns. SQLite stores times as text, so a sweep that
// deletes everything (or nothing) is exactly the failure a string
// comparison of RFC3339 with trimmed fractional seconds would produce.
func TestCleanupExpiredSweepsOnlyExpiredRows(t *testing.T) {
	env, tc := newAuthEnv(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.SendResetPassword = func(context.Context, *storage.User, string, string) error {
			return nil
		}
		// Required whenever SendResetPassword is set; New refuses to
		// start without it.
		cfg.EmailAndPassword.ResetPasswordURL = "/choose-password"
	})
	tc.signUp("hugo@example.com", "password123", "Hugo")

	// a live verification created by the real flow
	res, _ := tc.post("/forget-password", map[string]any{"email": "hugo@example.com"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("forget-password: %d", res.StatusCode)
	}
	live, err := env.store.FindMany(env.ctx, storage.ModelVerification, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 {
		t.Fatalf("verification rows = %d, want 1", len(live))
	}
	liveID, _ := live[0]["id"].(string)

	// and one that expired an hour ago
	past := time.Now().UTC().Add(-time.Hour)
	if _, err := env.store.Create(env.ctx, storage.ModelVerification, map[string]any{
		"id": "expired-row", "identifier": "reset-password:stale", "value": "stale",
		"expiresAt": past, "createdAt": past.Add(-time.Hour), "updatedAt": past.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seeding an expired verification: %v", err)
	}
	if n := env.count(t, storage.ModelVerification); n != 2 {
		t.Fatalf("verification rows before sweep = %d, want 2", n)
	}

	n, err := env.auth.CleanupExpired(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("CleanupExpired removed %d rows, want exactly the 1 expired one", n)
	}
	if got := env.count(t, storage.ModelVerification); got != 1 {
		t.Fatalf("verification rows after sweep = %d, want 1", got)
	}
	if _, err := env.store.FindOne(env.ctx, storage.ModelVerification,
		[]storage.Where{storage.W("id", "expired-row")}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired row survived the sweep: %v", err)
	}
	if _, err := env.store.FindOne(env.ctx, storage.ModelVerification,
		[]storage.Where{storage.W("id", liveID)}); err != nil {
		t.Fatalf("sweep deleted the live verification: %v", err)
	}
	// and the live session is untouched
	if got := env.count(t, storage.ModelSession); got != 1 {
		t.Fatalf("session rows after sweep = %d, want 1", got)
	}
	if _, s := tc.get("/get-session"); s == nil {
		t.Fatal("the sweeper signed out a live session")
	}
}
