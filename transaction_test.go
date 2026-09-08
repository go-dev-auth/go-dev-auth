package godevauth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// accountFailAdapter is a memory adapter that fails the first insert
// into the account table, to force sign-up's second write to error
// after the user row was created.
type accountFailAdapter struct {
	storage.Adapter
	failed *bool // shared across transaction wrappers, one-shot
}

func (a *accountFailAdapter) Create(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	if model == storage.ModelAccount && !*a.failed {
		*a.failed = true
		return nil, errors.New("injected: account insert failed")
	}
	return a.Adapter.Create(ctx, model, data)
}

// Transaction runs fn against a wrapper sharing the same one-shot flag,
// so the injected failure participates in (and rolls back) the
// transaction and does not fire again on retry.
func (a *accountFailAdapter) Transaction(ctx context.Context, fn func(tx storage.Adapter) error) error {
	tr, ok := a.Adapter.(storage.Transactor)
	if !ok {
		return fn(a)
	}
	return tr.Transaction(ctx, func(inner storage.Adapter) error {
		return fn(&accountFailAdapter{Adapter: inner, failed: a.failed})
	})
}

// Regression test for M10: sign-up is two writes (user + credential
// account). If the second fails, the first must be rolled back, or the
// address is taken by a user who can never sign in.
func TestSignUpIsAtomic(t *testing.T) {
	base := memory.New()
	db := &accountFailAdapter{Adapter: base, failed: new(bool)}
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Database = db
	})

	// First attempt hits the injected account-insert failure.
	res, _ := tc.post("/sign-up/email", map[string]any{
		"email": "atomic@example.com", "password": "password123", "name": "Atomic",
	})
	if res.StatusCode == http.StatusOK {
		t.Fatal("sign-up reported success despite a failed account insert")
	}

	// The user row must not survive the rolled-back transaction, so the
	// address is free and a retry (the injection is one-shot) succeeds.
	if _, err := findUser(db, "atomic@example.com"); err == nil {
		t.Fatal("a user row survived a rolled-back sign-up: the address is now taken by a credential-less account")
	}
	res, body := tc.post("/sign-up/email", map[string]any{
		"email": "atomic@example.com", "password": "password123", "name": "Atomic",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("retry after rollback failed: %d %v", res.StatusCode, body)
	}
}

func findUser(db storage.Adapter, email string) (map[string]any, error) {
	return db.FindOne(context.Background(), storage.ModelUser,
		[]storage.Where{storage.W("email", email)})
}

// Regression test for L19: DeleteUser must also remove rows in plugin
// tables that reference the user, so an adapter without database-level
// foreign keys (memory, Mongo, or SQLite without the pragma) does not
// orphan them — or worse, hand them to the next user to reuse the id.
func TestDeleteUserCascadesPluginTables(t *testing.T) {
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{stubUserDataPlugin{}}
		cfg.User.DeleteUser.Enabled = true
	})
	tc.signUp("cascade@example.com", "password123", "Cascade")
	user, err := auth.FindUserByEmail(t.Context(), "cascade@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Insert a plugin row owned by the user.
	if _, err := auth.Storage().Create(t.Context(), "stubUserData", map[string]any{
		"id": "row-1", "userId": user.ID, "secret": "x",
	}); err != nil {
		t.Fatal(err)
	}

	if err := auth.DeleteUserByID(t.Context(), user.ID); err != nil {
		t.Fatal(err)
	}
	n, err := auth.Storage().Count(t.Context(), "stubUserData",
		[]storage.Where{storage.W("userId", user.ID)})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("plugin rows for the deleted user = %d, want 0 (orphaned)", n)
	}
}

// stubUserDataPlugin contributes a table that references the user, to
// verify the plugin-cascade fallback finds and clears it.
type stubUserDataPlugin struct{}

func (stubUserDataPlugin) ID() string                 { return "stub-user-data" }
func (stubUserDataPlugin) Init(*godevauth.Auth) error { return nil }
func (stubUserDataPlugin) Routes() []godevauth.Route  { return nil }
func (stubUserDataPlugin) Schema(s *storage.Schema) {
	s.AddTable(&storage.Table{Name: "stubUserData", Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "userId", Type: storage.FieldString, Required: true, Index: true,
			References: &storage.Reference{Model: storage.ModelUser, Field: "id", OnDelete: "cascade"}},
		{Name: "secret", Type: storage.FieldText},
	}})
}
