package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/plugins/apikey"
	"github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/plugins/organization"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/sqlstore"
)

// fullSchema returns the schema of an auth instance loaded with every
// plugin that contributes tables or columns. Going through
// godevauth.New rather than assembling the schema by hand is
// deliberate: it also proves the adapter is handed the complete schema
// via storage.SchemaAware.
func fullSchema(t *testing.T) *storage.Schema {
	t.Helper()
	store := sqlstore.New(nil, sqlstore.SQLite, nil)
	auth, err := godevauth.New(godevauth.Config{
		// This instance exists only to assemble the schema; there is no
		// database handle behind it, so New must not try to migrate.
		Advanced:         godevauth.AdvancedConfig{DisableAutoMigrate: true},
		BaseURL:          "http://127.0.0.1",
		Secret:           "integration-secret-0123456789abcdef",
		Database:         store,
		RateLimit:        godevauth.RateLimitConfig{Disabled: true},
		EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},
		User: godevauth.UserConfig{
			AdditionalFields: []storage.Field{
				{Name: "favoriteColor", Type: storage.FieldString, Input: true},
				{Name: "loginCount", Type: storage.FieldInt},
				{Name: "lastSeenAt", Type: storage.FieldTime},
				{Name: "newsletter", Type: storage.FieldBool, Default: false},
			},
		},
		Plugins: []godevauth.Plugin{
			admin.New(),
			apikey.New(),
			jwt.New(),
			twofactor.New(),
			organization.New(organization.Options{Teams: true}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth.Schema()
}

// TestGeneratedDDLExecutes runs the DDL that MigrationSQL prints — the
// text an operator would paste into a migration tool — against a real
// SQLite database. The unit tests only substring-match the generated
// SQL, which cannot tell a valid statement from one the engine rejects.
func TestGeneratedDDLExecutes(t *testing.T) {
	schema := fullSchema(t)
	db := openSQLite(t)
	defer db.Close()

	ddl := sqlstore.New(db, sqlstore.SQLite, schema).MigrationSQL()
	if !strings.Contains(ddl, `CREATE TABLE IF NOT EXISTS "apikey"`) {
		t.Fatalf("plugin tables missing from the generated DDL:\n%s", ddl)
	}
	if _, err := db.Exec(ddl); err != nil {
		t.Fatalf("generated DDL rejected by SQLite: %v\n%s", err, ddl)
	}

	// Every declared table and column must actually be there. A dialect
	// that silently dropped a column would still produce runnable DDL.
	for _, name := range schema.TableNames() {
		table := schema.Tables[name]
		cols := columnsOf(t, db, name)
		if len(cols) == 0 {
			t.Errorf("table %q was not created", name)
			continue
		}
		for _, f := range table.Fields {
			if _, ok := cols[f.Name]; !ok {
				t.Errorf("table %q is missing column %q", name, f.Name)
			}
		}
		if len(cols) != len(table.Fields) {
			t.Errorf("table %q has %d columns, schema declares %d", name, len(cols), len(table.Fields))
		}
	}

	// And the declared indexes: without them the expiry sweep and every
	// userId lookup degrade to a table scan.
	indexes := indexesOf(t, db)
	for _, name := range schema.TableNames() {
		for _, f := range schema.Tables[name].Fields {
			if !f.Index || f.Unique {
				continue
			}
			want := "idx_" + name + "_" + f.Name
			if !indexes[want] {
				t.Errorf("missing index %q (have %v)", want, sortedKeys(indexes))
			}
		}
	}
}

// TestMigrateIsIdempotent asserts a second Migrate on a populated
// database is a no-op rather than an error or a data loss event —
// applications call it on every boot.
func TestMigrateIsIdempotent(t *testing.T) {
	schema := fullSchema(t)
	db := openSQLite(t)
	defer db.Close()
	store := sqlstore.New(db, sqlstore.SQLite, schema)
	ctx := context.Background()

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.Create(ctx, storage.ModelUser, map[string]any{
		"id": "keep-me", "name": "Keeper", "email": "keeper@example.com",
		"createdAt": now, "updatedAt": now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("third migrate: %v", err)
	}

	if _, err := store.FindOne(ctx, storage.ModelUser,
		[]storage.Where{storage.W("id", "keep-me")}); err != nil {
		t.Fatalf("re-migrating destroyed existing data: %v", err)
	}
	if n, _ := store.Count(ctx, storage.ModelUser, nil); n != 1 {
		t.Fatalf("user rows after re-migrate = %d, want 1", n)
	}

	// A fresh adapter over the same file sees the same schema, and the
	// plugin columns are writable.
	other := sqlstore.New(db, sqlstore.SQLite, schema)
	if _, err := other.Update(ctx, storage.ModelUser,
		[]storage.Where{storage.W("id", "keep-me")},
		map[string]any{"role": "admin", "banned": true, "loginCount": int64(3)}); err != nil {
		t.Fatalf("writing plugin columns: %v", err)
	}
	rec, err := other.FindOne(ctx, storage.ModelUser, []storage.Where{storage.W("id", "keep-me")})
	if err != nil {
		t.Fatal(err)
	}
	if rec["role"] != "admin" {
		t.Errorf("role = %#v", rec["role"])
	}
	if banned, _ := rec["banned"].(bool); !banned {
		t.Errorf("banned = %#v (plugin bool column must round-trip)", rec["banned"])
	}
	if n, _ := rec["loginCount"].(int64); n != 3 {
		t.Errorf("loginCount = %#v", rec["loginCount"])
	}
	// a column that was never written stays NULL rather than becoming 0
	if v, ok := rec["lastSeenAt"]; ok && v != nil {
		t.Errorf("unset time column = %#v, want nil", v)
	}
}

// TestIntegrityErrorsAreNotDuplicates is a regression test: the error
// classifier used to match a bare "constraint failed", so SQLite's NOT
// NULL and FOREIGN KEY failures were reported as
// storage.ErrUniqueViolation and surfaced to users as "that account
// already exists".
func TestIntegrityErrorsAreNotDuplicates(t *testing.T) {
	store, _ := newStore(t, storage.CoreSchema())
	ctx := context.Background()
	now := time.Now().UTC()

	_, err := store.Create(ctx, storage.ModelUser, map[string]any{
		"id": "nn", "name": "No Email", "email": nil,
		"createdAt": now, "updatedAt": now,
	})
	if err == nil {
		t.Fatal("expected a NOT NULL violation")
	}
	if errors.Is(err, storage.ErrUniqueViolation) {
		t.Errorf("NOT NULL violation misreported as a duplicate: %v", err)
	}

	// _fk=1 in the DSN makes SQLite enforce foreign keys.
	_, err = store.Create(ctx, storage.ModelSession, map[string]any{
		"id": "s", "userId": "does-not-exist", "token": "tok",
		"expiresAt": now.Add(time.Hour), "createdAt": now, "updatedAt": now,
	})
	if err == nil {
		t.Fatal("expected a FOREIGN KEY violation")
	}
	if errors.Is(err, storage.ErrUniqueViolation) {
		t.Errorf("FOREIGN KEY violation misreported as a duplicate: %v", err)
	}

	// the real thing still classifies
	if _, err := store.Create(ctx, storage.ModelUser, map[string]any{
		"id": "a", "name": "A", "email": "a@example.com", "createdAt": now, "updatedAt": now,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = store.Create(ctx, storage.ModelUser, map[string]any{
		"id": "b", "name": "B", "email": "a@example.com", "createdAt": now, "updatedAt": now,
	})
	if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Errorf("duplicate email: expected ErrUniqueViolation, got %v", err)
	}
}

// TestOffsetWithoutLimit is a regression test: SQLite and MySQL reject
// OFFSET unless a LIMIT precedes it, so "skip the first N rows" used to
// be a syntax error even though FindOptions allows it and the in-memory
// and Mongo adapters honour it.
func TestOffsetWithoutLimit(t *testing.T) {
	store, _ := newStore(t, storage.CoreSchema())
	ctx := context.Background()
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		if _, err := store.Create(ctx, storage.ModelUser, map[string]any{
			"id": string(rune('a' + i)), "name": "u", "email": string(rune('a'+i)) + "@example.com",
			"createdAt": ts, "updatedAt": ts,
		}); err != nil {
			t.Fatal(err)
		}
	}
	sortBy := &storage.SortBy{Field: "createdAt", Direction: "asc"}
	recs, err := store.FindMany(ctx, storage.ModelUser, nil,
		&storage.FindOptions{Offset: 2, SortBy: sortBy})
	if err != nil {
		t.Fatalf("offset without limit: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d rows, want 3", len(recs))
	}
	if recs[0]["id"] != "c" {
		t.Fatalf("first row after offset = %v, want \"c\"", recs[0]["id"])
	}
	// past the end is empty, not an error
	recs, err = store.FindMany(ctx, storage.ModelUser, nil,
		&storage.FindOptions{Offset: 99, SortBy: sortBy})
	if err != nil || len(recs) != 0 {
		t.Fatalf("offset past end: %d rows, err %v", len(recs), err)
	}
}

// TestLikeOperatorsMatchLiterally is a regression test: contains /
// starts_with / ends_with interpolated the caller's value straight into
// a LIKE pattern, so "%" matched every row and "a_c" matched "abc".
// The admin plugin feeds a query parameter into these operators, which
// made ?searchValue=%25 a whole-table dump.
func TestLikeOperatorsMatchLiterally(t *testing.T) {
	store, _ := newStore(t, storage.CoreSchema())
	ctx := context.Background()
	now := time.Now().UTC()
	names := []string{"alpha", "alphabet", "a_c", "100%", "plain"}
	for i, name := range names {
		if _, err := store.Create(ctx, storage.ModelUser, map[string]any{
			"id": string(rune('a' + i)), "name": name,
			"email":     string(rune('a'+i)) + "@example.com",
			"createdAt": now, "updatedAt": now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		where storage.Where
		want  int
	}{
		{"contains-percent", storage.Where{Field: "name", Operator: storage.OpContains, Value: "%"}, 1},
		{"contains-underscore", storage.Where{Field: "name", Operator: storage.OpContains, Value: "a_c"}, 1},
		{"contains-plain", storage.Where{Field: "name", Operator: storage.OpContains, Value: "lph"}, 2},
		{"starts-with-underscore", storage.Where{Field: "name", Operator: storage.OpStartsWith, Value: "a_"}, 1},
		{"ends-with-percent", storage.Where{Field: "name", Operator: storage.OpEndsWith, Value: "0%"}, 1},
		{"escape-char-is-literal", storage.Where{Field: "name", Operator: storage.OpContains, Value: "!"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs, err := store.FindMany(ctx, storage.ModelUser, []storage.Where{tc.where}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != tc.want {
				got := make([]string, 0, len(recs))
				for _, r := range recs {
					got = append(got, r["name"].(string))
				}
				t.Fatalf("matched %v, want %d rows", got, tc.want)
			}
			n, err := store.Count(ctx, storage.ModelUser, []storage.Where{tc.where})
			if err != nil {
				t.Fatal(err)
			}
			if int(n) != tc.want {
				t.Fatalf("Count = %d, want %d", n, tc.want)
			}
		})
	}
}

// ---- SQLite introspection helpers ------------------------------------

func columnsOf(t *testing.T, db *sql.DB, table string) map[string]string {
	t.Helper()
	rows, err := db.Query(`SELECT name, type FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatalf("pragma_table_info(%q): %v", table, err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			t.Fatal(err)
		}
		out[name] = typ
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func indexesOf(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'index'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
