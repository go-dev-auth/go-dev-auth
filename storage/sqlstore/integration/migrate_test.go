package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/sqlstore"
)

// These tests cover the upgrade path: a database created by an older
// version of the schema, then brought forward. That is the case
// CREATE TABLE IF NOT EXISTS cannot serve, and the one that broke
// production — plugins add *columns to existing tables*, so enabling one
// on a live database used to change nothing at all and the next
// SELECT ... "role","banned" FROM "user" failed inside every sign-in.

// upgradedSchema is the core schema plus the columns the admin and
// twofactor plugins contribute and a few application fields — i.e. what
// the code expects after a plugin is switched on.
func upgradedSchema() *storage.Schema {
	s := storage.CoreSchema()
	admin.New().Schema(s)
	twofactor.New().Schema(s)
	s.AddFields(storage.ModelUser,
		storage.Field{Name: "loginCount", Type: storage.FieldInt},
		storage.Field{Name: "lastSeenAt", Type: storage.FieldTime},
		storage.Field{Name: "nickname", Type: storage.FieldString, Unique: true},
		storage.Field{Name: "tenantId", Type: storage.FieldString, Index: true},
	)
	return s
}

// oldDatabase returns a SQLite database migrated to the *core* schema
// only, with one user row already in it.
func oldDatabase(t *testing.T) (*sql.DB, string) {
	t.Helper()
	db := openSQLite(t)
	t.Cleanup(func() { db.Close() })
	old := sqlstore.New(db, sqlstore.SQLite, storage.CoreSchema())
	ctx := context.Background()
	if err := old.Migrate(ctx); err != nil {
		t.Fatalf("migrating the old schema: %v", err)
	}
	now := time.Date(2026, 2, 1, 9, 30, 0, 0, time.UTC)
	if _, err := old.Create(ctx, storage.ModelUser, map[string]any{
		"id": "existing", "name": "Already Here", "email": "existing@example.com",
		"emailVerified": true, "createdAt": now, "updatedAt": now,
	}); err != nil {
		t.Fatalf("seeding the old database: %v", err)
	}
	return db, "existing"
}

// TestMigrateAddsMissingColumns is the regression test for the blocker:
// enabling a plugin on a populated database must add its columns, and
// everything must still read and write afterwards.
func TestMigrateAddsMissingColumns(t *testing.T) {
	db, seeded := oldDatabase(t)
	ctx := context.Background()
	schema := upgradedSchema()

	// Before the migration the new columns genuinely are not there — if
	// they were, this test would pass for the wrong reason.
	if cols := columnsOf(t, db, storage.ModelUser); cols["role"] != "" {
		t.Fatal("the old database already had a \"role\" column")
	}

	store := sqlstore.New(db, sqlstore.SQLite, schema)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("upgrade migrate: %v", err)
	}

	// every declared column of every declared table now exists
	for _, name := range schema.TableNames() {
		cols := columnsOf(t, db, name)
		if len(cols) == 0 {
			t.Errorf("table %q was not created", name)
			continue
		}
		for _, f := range schema.Tables[name].Fields {
			if _, ok := cols[f.Name]; !ok {
				t.Errorf("table %q is still missing column %q after Migrate", name, f.Name)
			}
		}
	}

	// the row that predates the migration survived, intact
	rec, err := store.FindOne(ctx, storage.ModelUser, []storage.Where{storage.W("id", seeded)})
	if err != nil {
		t.Fatalf("reading the pre-existing row: %v", err)
	}
	if rec["email"] != "existing@example.com" {
		t.Errorf("pre-existing row was damaged: %#v", rec["email"])
	}
	if v, _ := rec["emailVerified"].(bool); !v {
		t.Errorf("pre-existing emailVerified = %#v", rec["emailVerified"])
	}
	// and its new columns read back as unset, not as a zero value: the
	// row really has no value for them
	for _, col := range []string{"role", "banReason", "banExpires", "loginCount", "lastSeenAt"} {
		if v, ok := rec[col]; ok && v != nil {
			t.Errorf("added column %q on a pre-existing row = %#v, want nil", col, v)
		}
	}

	// full round trip through the new columns, on the old row
	updated, err := store.Update(ctx, storage.ModelUser,
		[]storage.Where{storage.W("id", seeded)},
		map[string]any{
			"role": "admin", "banned": true, "banReason": "spam",
			"banExpires": time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			"loginCount": int64(7), "twoFactorEnabled": true, "nickname": "ah",
		})
	if err != nil {
		t.Fatalf("writing the added columns: %v", err)
	}
	if updated["role"] != "admin" {
		t.Errorf("role = %#v", updated["role"])
	}
	if v, _ := updated["banned"].(bool); !v {
		t.Errorf("banned = %#v", updated["banned"])
	}
	if v, _ := updated["twoFactorEnabled"].(bool); !v {
		t.Errorf("twoFactorEnabled = %#v", updated["twoFactorEnabled"])
	}
	if v, _ := updated["loginCount"].(int64); v != 7 {
		t.Errorf("loginCount = %#v", updated["loginCount"])
	}
	if v, _ := updated["banExpires"].(time.Time); v.Year() != 2026 || v.Month() != time.June {
		t.Errorf("banExpires = %#v", updated["banExpires"])
	}

	// and they are queryable, which is the operation that used to fail
	n, err := store.Count(ctx, storage.ModelUser, []storage.Where{storage.W("role", "admin")})
	if err != nil {
		t.Fatalf("filtering on an added column: %v", err)
	}
	if n != 1 {
		t.Errorf("count by role = %d, want 1", n)
	}

	// a brand-new row writes the added columns too, and picks up the
	// declared default for the ones it omits
	now := time.Now().UTC()
	if _, err := store.Create(ctx, storage.ModelUser, map[string]any{
		"id": "fresh", "name": "Fresh", "email": "fresh@example.com",
		"role": "user", "createdAt": now, "updatedAt": now,
	}); err != nil {
		t.Fatalf("insert after migration: %v", err)
	}
	fresh, err := store.FindOne(ctx, storage.ModelUser, []storage.Where{storage.W("id", "fresh")})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := fresh["banned"].(bool); !ok || v {
		t.Errorf("declared default not applied to an added column: banned = %#v", fresh["banned"])
	}
}

// TestMigrateTwiceIsANoOp: applications call Migrate on every boot, so
// re-running it against an already-upgraded database must neither error
// (ADD COLUMN has no IF NOT EXISTS on SQLite or MySQL) nor touch data.
func TestMigrateTwiceIsANoOp(t *testing.T) {
	db, seeded := oldDatabase(t)
	ctx := context.Background()
	store := sqlstore.New(db, sqlstore.SQLite, upgradedSchema())

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if _, err := store.Update(ctx, storage.ModelUser,
		[]storage.Where{storage.W("id", seeded)},
		map[string]any{"role": "admin", "loginCount": int64(3)}); err != nil {
		t.Fatal(err)
	}

	// nothing left to do, and saying so is the contract of an empty plan
	pending, err := store.PendingMigrationSQL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("PendingMigrationSQL after a full migrate = %v, want none", pending)
	}

	for i := 0; i < 3; i++ {
		if err := store.Migrate(ctx); err != nil {
			t.Fatalf("migrate #%d: %v", i+2, err)
		}
	}

	rec, err := store.FindOne(ctx, storage.ModelUser, []storage.Where{storage.W("id", seeded)})
	if err != nil {
		t.Fatalf("re-migrating lost the row: %v", err)
	}
	if rec["role"] != "admin" {
		t.Errorf("re-migrating reset an added column: role = %#v", rec["role"])
	}
	if v, _ := rec["loginCount"].(int64); v != 3 {
		t.Errorf("re-migrating reset loginCount = %#v", rec["loginCount"])
	}
	if n, _ := store.Count(ctx, storage.ModelUser, nil); n != 1 {
		t.Errorf("user rows after re-migrating = %d, want 1", n)
	}
}

// TestPendingMigrationSQLIsOnlyWhatIsMissing checks the DDL an operator
// applies by hand: ALTER for tables that exist, CREATE for those that do
// not, and nothing for what is already right.
func TestPendingMigrationSQLIsOnlyWhatIsMissing(t *testing.T) {
	db, _ := oldDatabase(t)
	ctx := context.Background()
	store := sqlstore.New(db, sqlstore.SQLite, upgradedSchema())

	pending, err := store.PendingMigrationSQL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(pending, "\n")

	for _, want := range []string{
		`ALTER TABLE "user" ADD COLUMN "role" TEXT`,
		`ALTER TABLE "user" ADD COLUMN "banned" INTEGER DEFAULT FALSE`,
		`ALTER TABLE "user" ADD COLUMN "twoFactorEnabled" INTEGER`,
		`ALTER TABLE "session" ADD COLUMN "impersonatedBy" TEXT`,
		// a table that genuinely does not exist is created outright
		`CREATE TABLE IF NOT EXISTS "twoFactor"`,
		// an added unique column gets a unique index, because SQLite
		// cannot add a UNIQUE column
		`CREATE UNIQUE INDEX IF NOT EXISTS "uniq_user_nickname"`,
		// an added indexed column gets its index
		`CREATE INDEX IF NOT EXISTS "idx_user_tenantId"`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("pending DDL missing %q:\n%s", want, all)
		}
	}
	// tables that already exist are not re-created, and columns that are
	// already there are not re-added
	for _, unwanted := range []string{
		`CREATE TABLE IF NOT EXISTS "user"`,
		`CREATE TABLE IF NOT EXISTS "session"`,
		`ADD COLUMN "email"`,
		`ADD COLUMN "createdAt"`,
	} {
		if strings.Contains(all, unwanted) {
			t.Errorf("pending DDL should not contain %q:\n%s", unwanted, all)
		}
	}

	// and it is exactly the DDL that fixes the database: applying it by
	// hand must leave nothing pending
	for _, stmt := range pending {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("SQLite rejected a generated statement: %v\n%s", err, stmt)
		}
	}
	again, err := store.PendingMigrationSQL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("still pending after applying the plan: %v", again)
	}
	if err := store.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema after applying the plan: %v", err)
	}
}

// TestAddedColumnsAreNullable pins the constraint that forces the
// design: a table with rows in it cannot take a NOT NULL column without
// a default, so an added column is nullable whatever the schema says.
func TestAddedColumnsAreNullable(t *testing.T) {
	db, seeded := oldDatabase(t)
	ctx := context.Background()

	schema := storage.CoreSchema()
	schema.AddFields(storage.ModelUser,
		// Required in the schema — and still added nullable, because the
		// row already in the table has no value for it.
		storage.Field{Name: "tenantId", Type: storage.FieldString, Required: true},
	)
	store := sqlstore.New(db, sqlstore.SQLite, schema)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("adding a required column to a populated table: %v", err)
	}

	if notNull := columnIsNotNull(t, db, storage.ModelUser, "tenantId"); notNull {
		t.Error("added column was declared NOT NULL; the pre-existing rows have no value for it")
	}
	rec, err := store.FindOne(ctx, storage.ModelUser, []storage.Where{storage.W("id", seeded)})
	if err != nil {
		t.Fatalf("pre-existing row after adding a required column: %v", err)
	}
	if v, ok := rec["tenantId"]; ok && v != nil {
		t.Errorf("tenantId on the pre-existing row = %#v, want nil", v)
	}
}

// TestCheckSchemaNamesWhatIsMissing: the drift check has to be readable.
// Before it existed the failure mode was a driver error from the first
// SELECT, naming neither the plugin nor the migration that was skipped.
func TestCheckSchemaNamesWhatIsMissing(t *testing.T) {
	db, _ := oldDatabase(t)
	ctx := context.Background()
	store := sqlstore.New(db, sqlstore.SQLite, upgradedSchema())

	err := store.CheckSchema(ctx)
	if err == nil {
		t.Fatal("CheckSchema found no drift on a database that is missing every plugin column")
	}
	msg := err.Error()
	for _, want := range []string{
		`"user"`, `"role"`, `"banned"`, `"banReason"`, `"banExpires"`,
		`"twoFactorEnabled"`, `"session"`, `"impersonatedBy"`, `"twoFactor"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("drift report does not mention %s:\n%s", want, msg)
		}
	}

	// the structured form is accurate, not just the prose
	var drift *sqlstore.SchemaDrift
	if !errors.As(err, &drift) {
		t.Fatalf("CheckSchema returned %T, want *sqlstore.SchemaDrift", err)
	}
	if got := drift.MissingColumns[storage.ModelUser]; !sameSet(got, []string{
		"role", "banned", "banReason", "banExpires", "twoFactorEnabled",
		"loginCount", "lastSeenAt", "nickname", "tenantId",
	}) {
		t.Errorf("missing user columns = %v", got)
	}
	if got := drift.MissingColumns[storage.ModelSession]; !sameSet(got, []string{"impersonatedBy"}) {
		t.Errorf("missing session columns = %v", got)
	}
	if !sameSet(drift.MissingTables, []string{"twoFactor"}) {
		t.Errorf("missing tables = %v", drift.MissingTables)
	}
	// tables that are complete are not reported
	for _, name := range []string{storage.ModelAccount, storage.ModelVerification} {
		if cols, ok := drift.MissingColumns[name]; ok {
			t.Errorf("table %q reported as drifted: %v", name, cols)
		}
	}

	// after migrating, the check is silent
	if err := sqlstore.New(db, sqlstore.SQLite, upgradedSchema()).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema still reports drift after Migrate: %v", err)
	}
}

// TestVerifySchemaFailsStartup wires the drift check where it is useful:
// an operator who owns migrations separately and forgot to run one gets
// a startup failure instead of a broken sign-in endpoint.
func TestVerifySchemaFailsStartup(t *testing.T) {
	db, _ := oldDatabase(t)
	store := sqlstore.New(db, sqlstore.SQLite, nil)

	cfg := func() godevauth.Config {
		return godevauth.Config{
			BaseURL:          "http://127.0.0.1",
			Secret:           "integration-secret-0123456789abcdef",
			Database:         store,
			RateLimit:        godevauth.RateLimitConfig{Disabled: true},
			EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},
			Plugins:          []godevauth.Plugin{admin.New(), twofactor.New()},
			Advanced: godevauth.AdvancedConfig{
				DisableAutoMigrate: true,
				VerifySchema:       true,
			},
		}
	}

	_, err := godevauth.New(cfg())
	if err == nil {
		t.Fatal("New succeeded against a database missing every plugin column")
	}
	for _, want := range []string{`"user"`, `"role"`, `"twoFactor"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("startup error does not name %s:\n%v", want, err)
		}
	}

	// the same configuration with auto-migration on repairs the database
	// and then starts, and the verification agrees
	repair := cfg()
	repair.Advanced.DisableAutoMigrate = false
	if _, err := godevauth.New(repair); err != nil {
		t.Fatalf("New with auto-migration on: %v", err)
	}
	if _, err := godevauth.New(cfg()); err != nil {
		t.Fatalf("New with VerifySchema after a repair: %v", err)
	}
}

// TestUpgradedDatabaseServesSignIn is the end of the story the blocker
// tells: an old database, a plugin switched on, and a real sign-in over
// HTTP afterwards. Sign-in is what the missing columns broke, because
// every session lookup selects them.
func TestUpgradedDatabaseServesSignIn(t *testing.T) {
	db, seeded := oldDatabase(t)
	store := sqlstore.New(db, sqlstore.SQLite, nil)

	auth, err := godevauth.New(godevauth.Config{
		BaseURL:          "http://127.0.0.1",
		Secret:           "integration-secret-0123456789abcdef",
		Database:         store,
		RateLimit:        godevauth.RateLimitConfig{Disabled: true},
		EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},
		Plugins:          []godevauth.Plugin{admin.New(), twofactor.New()},
		// auto-migration is on, so New itself has to perform the upgrade
	})
	if err != nil {
		t.Fatalf("New against an old database: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	auth.Config().BaseURL = server.URL
	client := newTestClient(t, server)

	client.signUp("new@example.com", "correct horse battery", "New")
	res, body := client.signIn("new@example.com", "correct horse battery")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in after upgrade: %d %v", res.StatusCode, body)
	}
	// get-session reads the session and the user, selecting every column
	// the plugins added; this is the request that used to fail.
	res, body = client.get("/get-session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session lookup after upgrade: %d %v", res.StatusCode, body)
	}
	if body["user"] == nil {
		t.Fatalf("get-session returned no user: %v", body)
	}

	// the user that predates the upgrade is still readable through the
	// same path
	ctx := context.Background()
	if _, err := store.FindOne(ctx, storage.ModelUser,
		[]storage.Where{storage.W("id", seeded)}); err != nil {
		t.Fatalf("pre-existing user after upgrade: %v", err)
	}
}

// linkSchema returns a schema with a single account-like table, with or
// without the composite unique constraint on (providerId, accountId). It
// is the minimal fixture for the BL-3 reproduction and migration tests.
func linkSchema(withComposite bool) *storage.Schema {
	tbl := &storage.Table{Name: "linkacct", Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "providerId", Type: storage.FieldString, Required: true},
		{Name: "accountId", Type: storage.FieldString, Required: true},
		{Name: "userId", Type: storage.FieldString, Required: true},
	}}
	if withComposite {
		tbl.AddUniqueConstraint("providerId", "accountId")
	}
	s := storage.NewSchema()
	s.AddTable(tbl)
	return s
}

func insertLink(store *sqlstore.Adapter, id, provider, account string) error {
	_, err := store.Create(context.Background(), "linkacct", map[string]any{
		"id": id, "providerId": provider, "accountId": account, "userId": "u-" + id,
	})
	return err
}

// TestCompositeUniqueReproducesAndFixesBL3 is the before/after proof for
// the blocker. Without the constraint two rows with the same
// (providerId, accountId) both insert — the exact defect. After Migrate
// adds the constraint to the same live table, the duplicate is rejected
// with ErrUniqueViolation, and CheckSchema reports the gap in between.
func TestCompositeUniqueReproducesAndFixesBL3(t *testing.T) {
	db := openSQLite(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()

	// BEFORE: schema without the constraint. Two identical external
	// identities both land — one external identity, two local users.
	old := sqlstore.New(db, sqlstore.SQLite, linkSchema(false))
	if err := old.Migrate(ctx); err != nil {
		t.Fatalf("migrating the pre-constraint schema: %v", err)
	}
	if err := insertLink(old, "a1", "google", "acc-1"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insertLink(old, "a2", "google", "acc-1"); err != nil {
		t.Fatalf("defect not reproduced: the duplicate should insert with no constraint, got %v", err)
	}
	if n, _ := old.Count(ctx, "linkacct", nil); n != 2 {
		t.Fatalf("expected 2 duplicate rows before the fix, got %d", n)
	}
	// Remove the duplicate so the constraint can be added below.
	if _, err := db.ExecContext(ctx, `DELETE FROM "linkacct" WHERE "id" = 'a2'`); err != nil {
		t.Fatalf("cleaning the duplicate: %v", err)
	}

	// The drift check must SEE the missing constraint before it is added.
	store := sqlstore.New(db, sqlstore.SQLite, linkSchema(true))
	drift, err := store.Inspect(ctx)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got := drift.MissingCompositeUniques["linkacct"]; len(got) != 1 ||
		got[0][0] != "providerId" || got[0][1] != "accountId" {
		t.Fatalf("Inspect did not report the missing composite constraint: %#v", drift.MissingCompositeUniques)
	}
	if err := store.CheckSchema(ctx); err == nil {
		t.Fatal("CheckSchema reported all-clear while the composite constraint was missing")
	} else if !strings.Contains(err.Error(), "providerId") {
		t.Fatalf("CheckSchema error should name the columns, got: %v", err)
	}

	// AFTER: Migrate adds the constraint to the existing table.
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate adding the composite constraint: %v", err)
	}
	if err := store.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema still reports drift after Migrate: %v", err)
	}
	// The same duplicate is now rejected by the database.
	if err := insertLink(store, "a3", "google", "acc-1"); !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("constraint not enforced after Migrate: expected ErrUniqueViolation, got %v", err)
	}
	// A different identity still inserts, and the surviving row is intact.
	if err := insertLink(store, "a4", "google", "acc-2"); err != nil {
		t.Fatalf("distinct identity after Migrate: %v", err)
	}
	if _, err := store.FindOne(ctx, "linkacct", []storage.Where{storage.W("id", "a1")}); err != nil {
		t.Fatalf("the pre-existing row was lost: %v", err)
	}

	// Re-running Migrate is a no-op and stays clean (idempotent).
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := store.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema after re-migrate: %v", err)
	}
}

// TestMigrateCompositeUniqueRejectsExistingDuplicates covers the risky
// case: adding the constraint to a table that already holds duplicates
// cannot silently drop data, so Migrate fails with a DuplicateRowsError
// naming the offending rows and leaves the data untouched.
func TestMigrateCompositeUniqueRejectsExistingDuplicates(t *testing.T) {
	db := openSQLite(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()

	old := sqlstore.New(db, sqlstore.SQLite, linkSchema(false))
	if err := old.Migrate(ctx); err != nil {
		t.Fatalf("pre-constraint migrate: %v", err)
	}
	if err := insertLink(old, "d1", "google", "dupacc"); err != nil {
		t.Fatal(err)
	}
	if err := insertLink(old, "d2", "google", "dupacc"); err != nil {
		t.Fatal(err)
	}
	// a non-duplicate row, to prove only the real conflict is reported
	if err := insertLink(old, "d3", "github", "solo"); err != nil {
		t.Fatal(err)
	}

	store := sqlstore.New(db, sqlstore.SQLite, linkSchema(true))
	err := store.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate must fail when the table already contains duplicates")
	}
	var dup *sqlstore.DuplicateRowsError
	if !errors.As(err, &dup) {
		t.Fatalf("want *sqlstore.DuplicateRowsError, got %T: %v", err, err)
	}
	if dup.Table != "linkacct" || !sameSet(dup.Columns, []string{"providerId", "accountId"}) {
		t.Fatalf("DuplicateRowsError does not describe the constraint: %#v", dup)
	}
	// the message names the duplicate value so an operator can find it
	for _, want := range []string{"providerId", "accountId", "dupacc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message missing %q:\n%s", want, err.Error())
		}
	}
	// no data was dropped: both duplicate rows are still there
	if n, _ := store.Count(ctx, "linkacct", nil); n != 3 {
		t.Fatalf("Migrate dropped data: %d rows remain, want 3", n)
	}

	// after the operator resolves the duplicate, Migrate succeeds and the
	// constraint is enforced.
	if _, err := db.ExecContext(ctx, `DELETE FROM "linkacct" WHERE "id" = 'd2'`); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate after resolving the duplicate: %v", err)
	}
	if err := insertLink(store, "d4", "google", "dupacc"); !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("constraint not enforced after the repair: %v", err)
	}
}

// ---- helpers ----------------------------------------------------------

func columnIsNotNull(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var notNull int
	err := db.QueryRow(`SELECT "notnull" FROM pragma_table_info(?) WHERE name = ?`,
		table, column).Scan(&notNull)
	if err != nil {
		t.Fatalf("pragma_table_info(%q).%q: %v", table, column, err)
	}
	return notNull != 0
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	have := make(map[string]bool, len(got))
	for _, s := range got {
		have[s] = true
	}
	for _, s := range want {
		if !have[s] {
			return false
		}
	}
	return true
}

// TestMigrateHealsInterruptedUniqueIndex reproduces the release blocker
// BL-2: a migration interrupted after ADD COLUMN but before its
// CREATE UNIQUE INDEX leaves a declared-unique column silently permitting
// duplicates. Re-running Migrate must restore the constraint, and until
// it does, CheckSchema must report the drift rather than a false
// all-clear.
func TestMigrateHealsInterruptedUniqueIndex(t *testing.T) {
	db := openSQLite(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()

	// Start from a database that predates the unique column, then bring it
	// forward — the only path on which SQLite backs the constraint with a
	// separate, droppable index (a column created inline with the table
	// gets an autoindex instead, which is not the interrupted-migration
	// case).
	if err := sqlstore.New(db, sqlstore.SQLite, storage.CoreSchema()).Migrate(ctx); err != nil {
		t.Fatalf("old migrate: %v", err)
	}
	schema := storage.CoreSchema()
	schema.AddFields(storage.ModelUser,
		storage.Field{Name: "nickname", Type: storage.FieldString, Unique: true},
	)
	store := sqlstore.New(db, sqlstore.SQLite, schema)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("upgrade migrate: %v", err)
	}

	// Simulate the interrupted migration: drop the unique index that backs
	// the constraint, leaving the column in place. This is exactly the
	// on-disk state a crash between the two statements produces.
	if _, err := db.ExecContext(ctx, `DROP INDEX "uniq_user_nickname"`); err != nil {
		t.Fatalf("dropping the index to simulate the interruption: %v", err)
	}

	// Duplicates now slip through — this is the vulnerability.
	insert := func(id, nick string) error {
		_, err := store.Create(ctx, storage.ModelUser, map[string]any{
			"id": id, "name": id, "email": id + "@x.com",
			"emailVerified": false, "nickname": nick,
			"createdAt": time.Now(), "updatedAt": time.Now(),
		})
		return err
	}
	if err := insert("u1", "dup"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insert("u2", "dup"); err == nil {
		// clean the duplicate so the heal below can create the index
		_, _ = db.ExecContext(ctx, `DELETE FROM "user" WHERE "id" = 'u2'`)
	} else {
		t.Fatalf("expected the dropped index to allow a duplicate, got %v", err)
	}

	// CheckSchema must SEE the missing constraint, not report all-clear.
	if err := store.CheckSchema(ctx); err == nil {
		t.Fatal("CheckSchema reported all-clear while a unique constraint was missing")
	} else if !strings.Contains(err.Error(), "nickname") {
		t.Fatalf("CheckSchema error should name nickname, got: %v", err)
	}

	// Re-running Migrate heals it.
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("healing migrate: %v", err)
	}
	if err := store.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema still reports drift after heal: %v", err)
	}

	// And the constraint is enforced again.
	if err := insert("u3", "dup2"); err != nil {
		t.Fatalf("insert after heal: %v", err)
	}
	if err := insert("u4", "dup2"); err == nil {
		t.Fatal("duplicate accepted after heal: the unique constraint was not restored")
	} else if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("expected ErrUniqueViolation after heal, got %v", err)
	}
}
