package sqlstore

import (
	"context"
	"strings"
	"testing"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

func TestCreateTableSQLPostgres(t *testing.T) {
	schema := storage.CoreSchema()
	sql := CreateTableSQL(Postgres, schema.Tables[storage.ModelSession])
	for _, want := range []string{
		`CREATE TABLE IF NOT EXISTS "session"`,
		`"id" TEXT PRIMARY KEY`,
		`"token" TEXT NOT NULL UNIQUE`,
		`"expiresAt" TIMESTAMPTZ NOT NULL`,
		`REFERENCES "user"("id") ON DELETE CASCADE`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("postgres DDL missing %q:\n%s", want, sql)
		}
	}
}

func TestCreateTableSQLMySQL(t *testing.T) {
	schema := storage.CoreSchema()
	sql := CreateTableSQL(MySQL, schema.Tables[storage.ModelUser])
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS `user`",
		"`email` VARCHAR(255) NOT NULL UNIQUE",
		"`emailVerified` BOOLEAN",
		"`createdAt` DATETIME(3) NOT NULL",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("mysql DDL missing %q:\n%s", want, sql)
		}
	}
}

func TestSchemaSQLAllTables(t *testing.T) {
	schema := storage.CoreSchema()
	sql := SchemaSQL(SQLite, schema)
	for _, table := range []string{"user", "session", "account", "verification"} {
		if !strings.Contains(sql, `"`+table+`"`) {
			t.Errorf("schema DDL missing table %q", table)
		}
	}
	if !strings.Contains(sql, `CREATE INDEX IF NOT EXISTS "idx_session_userId"`) {
		t.Errorf("schema DDL missing index:\n%s", sql)
	}
}

// TestCompositeUniqueDDL pins the two ways a composite unique constraint
// reaches the database: inline in CREATE TABLE for a fresh table, and a
// separate CREATE UNIQUE INDEX for a table that predates it. Postgres and
// MySQL are only checked here (the integration module executes the SQLite
// path against a real database), so check the text carefully.
func TestCompositeUniqueDDL(t *testing.T) {
	table := &storage.Table{
		Name: "account",
		Fields: []storage.Field{
			{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
			{Name: "providerId", Type: storage.FieldString, Required: true},
			{Name: "accountId", Type: storage.FieldString, Required: true},
		},
		UniqueConstraints: []storage.UniqueConstraint{{Columns: []string{"providerId", "accountId"}}},
	}

	// CreateTableSQL declares the constraint inline for every dialect.
	inline := map[Dialect]string{
		Postgres: `UNIQUE ("providerId", "accountId")`,
		MySQL:    "UNIQUE (`providerId`, `accountId`)",
		SQLite:   `UNIQUE ("providerId", "accountId")`,
	}
	for d, want := range inline {
		got := CreateTableSQL(d, table)
		if !strings.Contains(got, want) {
			t.Errorf("%s CreateTableSQL missing %q:\n%s", d.Name(), want, got)
		}
	}

	// compositeUniqueIndexSQL is the migration counterpart: idempotent
	// with IF NOT EXISTS where the engine supports it, none on MySQL.
	idx := map[Dialect]struct{ want, absent string }{
		Postgres: {`CREATE UNIQUE INDEX IF NOT EXISTS "uniq_account_providerId_accountId" ON "account" ("providerId", "accountId");`, ""},
		SQLite:   {`CREATE UNIQUE INDEX IF NOT EXISTS "uniq_account_providerId_accountId" ON "account" ("providerId", "accountId");`, ""},
		MySQL:    {"CREATE UNIQUE INDEX `uniq_account_providerId_accountId` ON `account` (`providerId`, `accountId`);", "IF NOT EXISTS"},
	}
	for d, tc := range idx {
		got := compositeUniqueIndexSQL(d, table, table.UniqueConstraints[0])
		if got != tc.want {
			t.Errorf("%s compositeUniqueIndexSQL =\n  %s\nwant\n  %s", d.Name(), got, tc.want)
		}
		if tc.absent != "" && strings.Contains(got, tc.absent) {
			t.Errorf("%s compositeUniqueIndexSQL must not contain %q: %s", d.Name(), tc.absent, got)
		}
	}
}

func TestBuildWhere(t *testing.T) {
	schema := storage.CoreSchema()
	a := New(nil, Postgres, schema)
	table := schema.Tables[storage.ModelUser]

	sql, args, err := a.buildWhere(table, []storage.Where{
		storage.W("email", "x@y.com"),
		{Field: "emailVerified", Operator: storage.OpEq, Value: true},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sql != ` WHERE ("email" = $1) AND "emailVerified" = $2` {
		t.Errorf("sql = %q", sql)
	}
	if len(args) != 2 {
		t.Errorf("args = %v", args)
	}

	sql, args, err = a.buildWhere(table, []storage.Where{
		{Field: "email", Operator: storage.OpIn, Value: []string{"a", "b"}},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sql != ` WHERE "email" IN ($1, $2)` || len(args) != 2 {
		t.Errorf("in sql = %q args = %v", sql, args)
	}

	if _, _, err := a.buildWhere(table, []storage.Where{storage.W("nope", 1)}, 1); err == nil {
		t.Error("expected unknown field error")
	}
}

func TestMigrationSQLWithUnknownModelQuery(t *testing.T) {
	a := New(nil, SQLite, nil)
	if _, err := a.FindOne(context.Background(), "bogus", nil); err == nil {
		t.Error("expected unknown model error")
	}
}

// TestAddColumnSQLPerDialect covers the ALTER statements for the two
// engines this package cannot run in tests. The integration module
// executes the SQLite ones against a real database; Postgres and MySQL
// only get their generated text checked, so check it carefully.
func TestAddColumnSQLPerDialect(t *testing.T) {
	user := &storage.Table{Name: "user"}
	cases := []struct {
		name    string
		dialect Dialect
		field   storage.Field
		want    []string
		absent  []string
	}{
		{
			name:    "postgres plain",
			dialect: Postgres,
			field:   storage.Field{Name: "role", Type: storage.FieldString},
			want:    []string{`ALTER TABLE "user" ADD COLUMN "role" TEXT;`},
		},
		{
			name:    "postgres bool with default",
			dialect: Postgres,
			field:   storage.Field{Name: "banned", Type: storage.FieldBool, Default: false},
			want:    []string{`ALTER TABLE "user" ADD COLUMN "banned" BOOLEAN DEFAULT FALSE;`},
		},
		{
			// Required must NOT become NOT NULL: the rows already in the
			// table have no value for the new column.
			name:    "required column is added nullable",
			dialect: Postgres,
			field:   storage.Field{Name: "tenantId", Type: storage.FieldString, Required: true},
			want:    []string{`ALTER TABLE "user" ADD COLUMN "tenantId" TEXT;`},
			absent:  []string{"NOT NULL"},
		},
		{
			name:    "mysql required column is added nullable",
			dialect: MySQL,
			field:   storage.Field{Name: "tenantId", Type: storage.FieldString, Required: true},
			want:    []string{"ALTER TABLE `user` ADD COLUMN `tenantId` VARCHAR(255);"},
			absent:  []string{"NOT NULL"},
		},
		{
			name:    "sqlite required column is added nullable",
			dialect: SQLite,
			field:   storage.Field{Name: "tenantId", Type: storage.FieldString, Required: true},
			want:    []string{`ALTER TABLE "user" ADD COLUMN "tenantId" TEXT;`},
			absent:  []string{"NOT NULL"},
		},
		{
			// Postgres and MySQL accept an inline UNIQUE on ADD COLUMN.
			name:    "postgres unique inline",
			dialect: Postgres,
			field:   storage.Field{Name: "nickname", Type: storage.FieldString, Unique: true},
			want:    []string{`ALTER TABLE "user" ADD COLUMN "nickname" TEXT UNIQUE;`},
			absent:  []string{"CREATE UNIQUE INDEX"},
		},
		{
			name:    "mysql unique inline",
			dialect: MySQL,
			field:   storage.Field{Name: "nickname", Type: storage.FieldString, Unique: true},
			want:    []string{"ALTER TABLE `user` ADD COLUMN `nickname` VARCHAR(255) UNIQUE;"},
			absent:  []string{"CREATE UNIQUE INDEX"},
		},
		{
			// SQLite rejects "Cannot add a UNIQUE column", so the
			// constraint moves to an index. NULLs do not collide in a
			// unique index, so the pre-existing rows are fine.
			name:    "sqlite unique becomes an index",
			dialect: SQLite,
			field:   storage.Field{Name: "nickname", Type: storage.FieldString, Unique: true},
			want: []string{
				`ALTER TABLE "user" ADD COLUMN "nickname" TEXT;`,
				`CREATE UNIQUE INDEX IF NOT EXISTS "uniq_user_nickname" ON "user" ("nickname");`,
			},
			absent: []string{"ADD COLUMN \"nickname\" TEXT UNIQUE"},
		},
		{
			name:    "postgres indexed column",
			dialect: Postgres,
			field:   storage.Field{Name: "tenantId", Type: storage.FieldString, Index: true},
			want: []string{
				`ALTER TABLE "user" ADD COLUMN "tenantId" TEXT;`,
				`CREATE INDEX IF NOT EXISTS "idx_user_tenantId" ON "user" ("tenantId");`,
			},
		},
		{
			// MySQL has no CREATE INDEX IF NOT EXISTS. It is safe here
			// because the column was missing a moment ago, so its index
			// cannot exist either.
			name:    "mysql indexed column",
			dialect: MySQL,
			field:   storage.Field{Name: "tenantId", Type: storage.FieldString, Index: true},
			want: []string{
				"ALTER TABLE `user` ADD COLUMN `tenantId` VARCHAR(255);",
				"CREATE INDEX `idx_user_tenantId` ON `user` (`tenantId`);",
			},
			absent: []string{"IF NOT EXISTS"},
		},
		{
			name:    "postgres foreign key",
			dialect: Postgres,
			field: storage.Field{Name: "orgId", Type: storage.FieldString,
				References: &storage.Reference{Model: "organization", Field: "id", OnDelete: "cascade"}},
			want: []string{`ALTER TABLE "user" ADD COLUMN "orgId" TEXT REFERENCES "organization"("id") ON DELETE CASCADE;`},
		},
		{
			// SQLite refuses ADD COLUMN with both REFERENCES and a
			// non-NULL default; the foreign key is worth more than the
			// SQL-level default, which Table.ApplyDefaults supplies anyway.
			name:    "sqlite foreign key drops the default",
			dialect: SQLite,
			field: storage.Field{Name: "orgId", Type: storage.FieldString, Default: "none",
				References: &storage.Reference{Model: "organization", Field: "id"}},
			want:   []string{`ALTER TABLE "user" ADD COLUMN "orgId" TEXT REFERENCES "organization"("id");`},
			absent: []string{"DEFAULT"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AddColumnSQL(tc.dialect, user, tc.field)
			joined := strings.Join(got, "\n")
			if len(got) != len(tc.want) {
				t.Fatalf("got %d statements, want %d:\n%s", len(got), len(tc.want), joined)
			}
			for i, want := range tc.want {
				if got[i] != want {
					t.Errorf("statement %d =\n  %s\nwant\n  %s", i, got[i], want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(joined, absent) {
					t.Errorf("statement must not contain %q:\n%s", absent, joined)
				}
			}
		})
	}
}

// TestColumnsQueryPerDialect pins the introspection each dialect uses.
// Getting the scoping wrong (any schema, any database) would report a
// column as present because a same-named table elsewhere has it, and
// the migration would then skip it silently.
func TestColumnsQueryPerDialect(t *testing.T) {
	cases := []struct {
		dialect Dialect
		want    string
	}{
		{Postgres, `SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1`},
		{MySQL, "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?"},
		{SQLite, `SELECT name FROM pragma_table_info(?, 'main')`},
	}
	for _, tc := range cases {
		t.Run(tc.dialect.Name(), func(t *testing.T) {
			query, args := columnsQuery(tc.dialect, "user")
			if query != tc.want {
				t.Errorf("query =\n  %s\nwant\n  %s", query, tc.want)
			}
			// The table name is always bound, never interpolated.
			if len(args) != 1 || args[0] != "user" {
				t.Errorf("args = %v, want [user]", args)
			}
			if strings.Contains(query, "user") {
				t.Errorf("table name was pasted into the SQL: %s", query)
			}
		})
	}
}

// TestIntrospectionNeedsADatabase: the adapter doubles as a DDL
// generator with a nil handle, and every introspecting entry point has
// to say so rather than dereference it.
func TestIntrospectionNeedsADatabase(t *testing.T) {
	a := New(nil, Postgres, nil)
	ctx := context.Background()
	if _, err := a.TableColumns(ctx, "user"); err == nil {
		t.Error("TableColumns with no handle must fail")
	}
	if _, err := a.PendingMigrationSQL(ctx); err == nil {
		t.Error("PendingMigrationSQL with no handle must fail")
	}
	if err := a.CheckSchema(ctx); err == nil {
		t.Error("CheckSchema with no handle must fail")
	}
	if err := a.Migrate(ctx); err == nil {
		t.Error("Migrate with no handle must fail")
	}
	// MigrationSQL still works: it needs no database.
	if !strings.Contains(a.MigrationSQL(), `CREATE TABLE IF NOT EXISTS "user"`) {
		t.Error("MigrationSQL must work without a handle")
	}
}

func TestSchemaDriftMessage(t *testing.T) {
	var empty *SchemaDrift
	if !empty.Empty() {
		t.Error("nil drift must be empty")
	}
	if !(&SchemaDrift{}).Empty() {
		t.Error("zero drift must be empty")
	}
	d := &SchemaDrift{
		MissingTables:  []string{"apikey"},
		MissingColumns: map[string][]string{"user": {"role", "banned"}, "session": {"impersonatedBy"}},
	}
	if d.Empty() {
		t.Fatal("drift with contents must not be empty")
	}
	msg := d.Error()
	for _, want := range []string{
		`table "apikey" is missing`,
		`table "session" is missing column(s) "impersonatedBy"`,
		`table "user" is missing column(s) "role", "banned"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("drift message missing %q:\n%s", want, msg)
		}
	}
	// tables are listed in a stable order so the message does not churn
	if strings.Index(msg, `"session"`) > strings.Index(msg, `"user" is missing column`) {
		t.Errorf("missing columns are not reported in table order:\n%s", msg)
	}
	var asErr error = d
	if asErr.Error() != msg {
		t.Error("SchemaDrift must be usable as an error")
	}
}

// TestWritesRejectUnknownFields: writes used to render themselves by
// walking the schema and skipping everything else, so a key the schema
// did not declare was dropped and the caller was told it succeeded.
// Reads have always rejected the same key.
func TestWritesRejectUnknownFields(t *testing.T) {
	schema := storage.CoreSchema()
	a := New(nil, Postgres, schema)
	ctx := context.Background()

	// Create and UpdateMany must fail before they touch the (nil) handle,
	// which is also what proves they fail early rather than half-writing.
	_, err := a.Create(ctx, storage.ModelUser, map[string]any{
		"id": "u1", "email": "u1@example.com", "nope": 1,
	})
	if err == nil {
		t.Fatal("Create with an undeclared field must fail")
	}
	if !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("error does not name the field: %v", err)
	}

	if _, err := a.UpdateMany(ctx, storage.ModelUser,
		[]storage.Where{storage.W("id", "u1")}, map[string]any{"nope": 1}); err == nil {
		t.Fatal("UpdateMany with an undeclared field must fail")
	}

	// Several unknown keys are all reported, in a stable order.
	_, err = a.Create(ctx, storage.ModelUser, map[string]any{"zebra": 1, "apple": 2})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), `"apple", "zebra"`) {
		t.Errorf("unknown fields must be listed in a stable order: %v", err)
	}
}

// TestDefaultLiteralEscapesBackslashOnMySQL is the regression test for the
// DDL-injection finding: under MySQL's default sql_mode a backslash is a
// string escape, so a field default ending in a backslash would escape
// its own closing quote and let the rest of the CREATE TABLE be reparsed.
// The generated literal must neutralise that.
func TestDefaultLiteralEscapesBackslashOnMySQL(t *testing.T) {
	inject := storage.Field{Name: "a", Type: storage.FieldString, Default: `\`}
	got := defaultLiteral(MySQL, inject)
	// One input backslash must render as an escaped (doubled) backslash so
	// MySQL reads a single literal backslash and the quote still closes.
	if got != `'\\'` {
		t.Fatalf("MySQL default for a lone backslash = %s, want '\\\\'", got)
	}
	// Postgres and SQLite treat backslash literally, so it is left alone.
	if pg := defaultLiteral(Postgres, inject); pg != `'\'` {
		t.Fatalf("Postgres default = %s, want '\\'", pg)
	}

	// A crafted value that tried to break out on MySQL must stay inside the
	// literal: after escaping there is no unescaped closing quote before
	// the intended one.
	evil := storage.Field{Name: "b", Type: storage.FieldString, Default: `x\`}
	lit := defaultLiteral(MySQL, evil)
	if !strings.HasPrefix(lit, "'") || !strings.HasSuffix(lit, "'") {
		t.Fatalf("literal not quoted: %s", lit)
	}
	inner := lit[1 : len(lit)-1]
	// every backslash doubled, every quote doubled: no lone terminator
	if strings.Count(inner, `\`)%2 != 0 {
		t.Fatalf("odd number of backslashes leaves the quote escapable: %s", lit)
	}
}

// Regression test for M11: MySQL parses column-inline REFERENCES
// clauses and silently discards them, so every foreign key — cascades
// included — was a no-op there. DeleteUser only cleans core tables
// explicitly; plugin rows (2FA secrets, API keys, org memberships) rely
// on the database cascade, which therefore must be a table-level
// FOREIGN KEY constraint on MySQL.
func TestMySQLForeignKeysAreTableLevel(t *testing.T) {
	schema := storage.CoreSchema()
	sql := CreateTableSQL(MySQL, schema.Tables[storage.ModelSession])
	if !strings.Contains(sql, "FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON DELETE CASCADE") {
		t.Errorf("mysql session DDL missing table-level foreign key:\n%s", sql)
	}
	if strings.Contains(sql, "`userId` VARCHAR(255) NOT NULL REFERENCES") {
		t.Errorf("mysql DDL still carries an inline (ignored) REFERENCES clause:\n%s", sql)
	}

	// A column added by migration gets its constraint via ADD CONSTRAINT.
	table := schema.Tables[storage.ModelSession]
	var userID storage.Field
	for _, f := range table.Fields {
		if f.Name == "userId" {
			userID = f
		}
	}
	stmts := AddColumnSQL(MySQL, table, userID)
	joined := strings.Join(stmts, "\n")
	if !strings.Contains(joined, "ADD CONSTRAINT `fk_session_userId` FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON DELETE CASCADE") {
		t.Errorf("mysql ADD COLUMN migration missing foreign key constraint:\n%s", joined)
	}

	// Postgres and SQLite keep their (enforced) inline clauses.
	for _, d := range []Dialect{Postgres, SQLite} {
		sql := CreateTableSQL(d, schema.Tables[storage.ModelSession])
		if !strings.Contains(sql, `REFERENCES "user"("id") ON DELETE CASCADE`) {
			t.Errorf("%s DDL lost its inline foreign key:\n%s", d.Name(), sql)
		}
	}
}
