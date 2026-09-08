// Package sqlstore implements the go-dev-auth storage adapter on top
// of database/sql. It supports PostgreSQL, MySQL and SQLite through a
// small dialect abstraction; bring your own driver:
//
//	db, _ := sql.Open("pgx", dsn)
//	store := sqlstore.New(db, sqlstore.Postgres, nil)
//	auth, _ := godevauth.New(godevauth.Config{Database: store, ...})
//
// Pass nil for the schema. That is the right answer for an application:
// godevauth.New hands the adapter the complete schema — core tables plus
// every column the configured plugins and AdditionalFields contribute —
// and then migrates. Passing storage.CoreSchema() instead pins the
// adapter to the core tables before plugins have contributed theirs, so
// the plugin columns are never created and the first query that selects
// one fails. Supply a schema only when using the adapter standalone,
// without godevauth.New.
//
// # Foreign keys and cascading deletes
//
// Schema foreign keys carry ON DELETE CASCADE so rows owned by a
// deleted user (plugin tables included) go with them. Two engines need
// a word of care. SQLite ships with foreign-key enforcement OFF per
// connection: open the database with the pragma enabled or the
// cascades silently do nothing —
//
//	sql.Open("sqlite3", "file:auth.db?_fk=1")            // mattn/go-sqlite3
//	sql.Open("sqlite", "file:auth.db?_pragma=foreign_keys(1)") // modernc.org/sqlite
//
// MySQL discards column-inline REFERENCES clauses, so the MySQL dialect
// emits table-level FOREIGN KEY constraints instead; tables created by
// versions that predate this fix have no enforced constraints — run
// PendingMigrationSQL or recreate the tables to pick them up.
//
// # Migrations
//
// Migrate is idempotent and does two things: it creates missing tables
// and indexes, and it adds missing columns to tables that already exist.
// The second is not a nicety. Plugins extend the *core* tables rather
// than only adding their own — the admin plugin adds role, banned,
// banReason and banExpires to user and impersonatedBy to session,
// twofactor adds twoFactorEnabled to user, organization adds
// activeOrganizationId to session, and Config.User.AdditionalFields does
// the same. On a database that already has those tables, creating them
// again does nothing, so before the ALTER pass existed enabling a plugin
// changed nothing and the next SELECT of the new columns failed inside
// every sign-in and session lookup.
//
// For operators who apply DDL by hand there are two generators:
// MigrationSQL renders the full create-from-nothing schema, and
// PendingMigrationSQL introspects the live database and returns only the
// statements it is missing. CheckSchema reports drift as an error naming
// the tables and columns, so a deployment that forgot its migration
// fails at startup instead of at the first request.
//
// Columns added to an existing table are always nullable, whatever
// Field.Required says; see AddColumnSQL.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// sqliteTimeLayout is a fixed-width RFC3339 layout so that text
// comparison of timestamps matches chronological order.
const sqliteTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

func parseTime(s string) any {
	for _, layout := range []string{
		sqliteTimeLayout,
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05",
	} {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts
		}
	}
	return time.Time{}
}

// Queryer is the subset of *sql.DB / *sql.Tx used by the storage.
type Queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Adapter implements storage.Adapter using database/sql.
type Adapter struct {
	db      *sql.DB
	q       Queryer
	dialect Dialect
	schema  *storage.Schema
}

var _ storage.Adapter = (*Adapter)(nil)
var _ storage.Transactor = (*Adapter)(nil)

// New builds a SQL storage. schema must contain every model the auth
// instance uses; pass auth.Schema() after construction, or build the
// schema with storage.CoreSchema() plus plugin schemas. If schema is nil
// the core schema is used.
func New(db *sql.DB, dialect Dialect, schema *storage.Schema) *Adapter {
	if schema == nil {
		schema = storage.CoreSchema()
	}
	a := &Adapter{db: db, dialect: dialect, schema: schema}
	// Assigning a nil *sql.DB to the Queryer interface would produce a
	// non-nil interface holding a nil pointer, so every `a.q == nil`
	// guard below would be false and the "no database handle" errors
	// they exist to return would be nil dereferences instead. Migrate
	// documents that it reports this rather than crashing; leaving q as
	// a genuine nil interface is what makes that true.
	if db != nil {
		a.q = db
	}
	return a
}

// SetSchema replaces the schema. godevauth.New calls this automatically
// (storage.SchemaAware) so plugin tables are picked up without extra
// wiring; call it yourself only when using the adapter standalone.
func (a *Adapter) SetSchema(s *storage.Schema) { a.schema = s }

var _ storage.SchemaAware = (*Adapter)(nil)

// Migrate brings the database up to the schema: it creates missing
// tables and indexes, and adds missing columns to tables that already
// exist. It is idempotent, so applications can call it on every boot.
//
// The second part matters as soon as the database has data in it.
// Plugins contribute *columns* to the core tables — admin adds role,
// banned, banReason and banExpires to user — and so does
// Config.User.AdditionalFields. CREATE TABLE IF NOT EXISTS does nothing
// for a table that is already there, so without the ALTER pass enabling
// a plugin was a silent no-op and the next
// SELECT ... "role","banned" FROM "user" broke every sign-in.
//
// Added columns are always nullable; see AddColumnSQL for why.
//
// An adapter built with a nil *sql.DB is a DDL generator only (see
// MigrationSQL); migrating it is a programming error, reported rather
// than dereferenced.
func (a *Adapter) Migrate(ctx context.Context) error {
	if a.q == nil {
		return errors.New("sqlstore: Migrate called on an adapter with no database handle")
	}

	// Serialise concurrent migrations (rolling deploy) so two boots do not
	// both run ADD COLUMN, which has no IF NOT EXISTS and would error for
	// the loser.
	unlock, err := a.lockForMigration(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	// Pass one: idempotent creates. Each table's create-and-index batch is
	// applied atomically where the engine allows it (see applyTableDDL).
	// This also restores an ordinary index dropped from a table that
	// otherwise matches, which the column-only introspection below would
	// not see.
	for _, name := range a.schema.TableNames() {
		t := a.schema.Tables[name]
		stmts := []string{CreateTableSQL(a.dialect, t)}
		stmts = append(stmts, CreateIndexSQL(a.dialect, t)...)
		if err := a.applyTableDDL(ctx, name, stmts); err != nil {
			return err
		}
	}

	// Pass two: add the columns existing tables are missing, one table's
	// additions at a time and atomically where possible so a unique column
	// and its index land together.
	if err := a.eachMissing(ctx,
		func(t *storage.Table) error {
			// Pass one just created it, so introspection returning no
			// columns means introspection itself is not working (an
			// unsupported engine behind a custom Dialect, or a role
			// without catalog access). Adding columns would then be a
			// silent no-op, which is the bug this pass exists to fix.
			return fmt.Errorf("sqlstore: cannot read the columns of table %s after creating it; "+
				"schema introspection is not working against this database", t.Name)
		},
		func(t *storage.Table, f storage.Field) error {
			return a.applyTableDDL(ctx, t.Name, AddColumnSQL(a.dialect, t, f))
		}); err != nil {
		return err
	}

	// Pass three: SQLite only. Every unique column now exists (pass two
	// added the missing ones), so re-issue their unique indexes
	// idempotently. This *repairs* the one state the earlier passes cannot
	// see: a migration interrupted between ADD COLUMN and its
	// CREATE UNIQUE INDEX leaves a unique column silently permitting
	// duplicates, and column-only introspection reports it as present.
	// Re-creating the index heals the constraint on the next boot. On a
	// column that already has its index this is a harmless no-op. It runs
	// last, and only here, because in earlier passes the columns it names
	// may not exist yet.
	if a.dialect.Name() == "sqlite" {
		for _, name := range a.schema.TableNames() {
			t := a.schema.Tables[name]
			if err := a.applyTableDDL(ctx, name, uniqueIndexSQL(a.dialect, t)); err != nil {
				return err
			}
		}
	}

	// Pass four: composite (multi-column) unique constraints. A fresh
	// table already carries them inline from CreateTableSQL, but a table
	// that predates the constraint has its columns without it — and unlike
	// a single-column unique there is no ADD COLUMN to hang the constraint
	// on, so it needs a separate statement on every engine. Adding it to a
	// table that already holds duplicates cannot silently drop data, so it
	// fails with a DuplicateRowsError naming the offending rows.
	if err := a.ensureCompositeUniques(ctx); err != nil {
		return err
	}
	return nil
}

// MigrationSQL returns the full create-from-nothing DDL without
// executing it: every table and index the schema declares. It is what an
// operator provisioning a new database pastes into a migration tool.
//
// It cannot know what an existing database already has, so it never
// contains an ALTER. To upgrade a database that already has data — after
// enabling a plugin, or taking a library version that adds a column —
// use PendingMigrationSQL, which introspects the live database and
// returns only the statements it is missing.
func (a *Adapter) MigrationSQL() string { return SchemaSQL(a.dialect, a.schema) }

func (a *Adapter) table(model string) (*storage.Table, error) {
	t, ok := a.schema.Tables[model]
	if !ok {
		return nil, fmt.Errorf("sqlstore: unknown model %q", model)
	}
	return t, nil
}

// encode converts a Go value to a driver value based on the field type.
func (a *Adapter) encode(f *storage.Field, v any) any {
	if v == nil {
		return nil
	}
	switch f.Type {
	case storage.FieldTime:
		t, ok := v.(time.Time)
		if !ok {
			return v
		}
		if t.IsZero() {
			return nil
		}
		if a.dialect.Name() == "sqlite" {
			// Fixed-width layout: RFC3339Nano trims trailing zeros,
			// which makes text comparison disagree with chronological
			// order ("...:05Z" would sort after "...:05.5Z"). Every
			// ORDER BY createdAt and every expiresAt <= now sweep
			// depends on this.
			return t.UTC().Format(sqliteTimeLayout)
		}
		return t.UTC()
	case storage.FieldBool:
		b, ok := v.(bool)
		if ok && a.dialect.Name() == "sqlite" {
			if b {
				return int64(1)
			}
			return int64(0)
		}
		return v
	default:
		return v
	}
}

func (a *Adapter) decode(f *storage.Field, v any) any {
	if v == nil {
		// NULL stays nil. Substituting a zero value here would make
		// "unset" indistinguishable from "zero", which silently breaks
		// callers that treat 0 as an exhausted quota or false as an
		// explicit deny.
		return nil
	}
	switch f.Type {
	case storage.FieldTime:
		switch t := v.(type) {
		case time.Time:
			return t
		case string:
			return parseTime(t)
		case []byte:
			return parseTime(string(t))
		}
		return v
	case storage.FieldBool:
		switch t := v.(type) {
		case bool:
			return t
		case int64:
			return t != 0
		case []byte:
			return len(t) > 0 && (t[0] == '1' || t[0] == 't')
		}
		return v
	case storage.FieldInt:
		switch t := v.(type) {
		case int64:
			return t
		case int:
			return int64(t)
		case []byte:
			var n int64
			_, _ = fmt.Sscanf(string(t), "%d", &n)
			return n
		}
		return v
	default:
		if b, ok := v.([]byte); ok {
			return string(b)
		}
		return v
	}
}

// buildWhere renders where clauses to SQL.
func (a *Adapter) buildWhere(t *storage.Table, where []storage.Where, startIdx int) (string, []any, error) {
	if len(where) == 0 {
		return "", nil, nil
	}
	var acc string
	var args []any
	idx := startIdx
	for i, w := range where {
		f := t.FieldByName(w.Field)
		if f == nil {
			return "", nil, fmt.Errorf("sqlstore: unknown field %q on %q", w.Field, t.Name)
		}
		op := w.Operator
		if op == "" {
			op = storage.OpEq
		}
		var expr string
		col := a.dialect.Quote(w.Field)
		switch op {
		case storage.OpEq:
			expr = col + " = " + a.dialect.Placeholder(idx)
			args = append(args, a.encode(f, w.Value))
			idx++
		case storage.OpNe:
			expr = col + " <> " + a.dialect.Placeholder(idx)
			args = append(args, a.encode(f, w.Value))
			idx++
		case storage.OpGt, storage.OpGte, storage.OpLt, storage.OpLte:
			sym := map[storage.Operator]string{
				storage.OpGt: ">", storage.OpGte: ">=", storage.OpLt: "<", storage.OpLte: "<=",
			}[op]
			expr = col + " " + sym + " " + a.dialect.Placeholder(idx)
			args = append(args, a.encode(f, w.Value))
			idx++
		case storage.OpIn:
			vals, ok := anyList(w.Value)
			if !ok || len(vals) == 0 {
				expr = "1=0"
			} else {
				var ph []string
				for _, v := range vals {
					ph = append(ph, a.dialect.Placeholder(idx))
					args = append(args, a.encode(f, v))
					idx++
				}
				expr = col + " IN (" + strings.Join(ph, ", ") + ")"
			}
		case storage.OpContains, storage.OpStartsWith, storage.OpEndsWith:
			// Substring matching is case-insensitive on every backend.
			// It exists for human-facing search (the admin user list),
			// where a query for "Bob" must find "bob@example.com", and
			// the dialects disagree by default: SQLite's LIKE ignores
			// ASCII case, PostgreSQL's does not, MySQL depends on the
			// column collation. LOWER() on both sides makes the
			// behaviour identical everywhere and matches the memory and
			// Mongo adapters.
			pattern := escapeLike(strings.ToLower(fmt.Sprint(w.Value)))
			switch op {
			case storage.OpContains:
				pattern = "%" + pattern + "%"
			case storage.OpStartsWith:
				pattern = pattern + "%"
			case storage.OpEndsWith:
				pattern = "%" + pattern
			}
			expr = "LOWER(" + col + ") LIKE " + a.dialect.Placeholder(idx) + likeEscapeClause
			args = append(args, pattern)
			idx++
		default:
			return "", nil, fmt.Errorf("sqlstore: unsupported operator %q", op)
		}
		// Clause lists fold left to right: each clause combines with
		// everything to its left using its own connector, so
		// [a, b, OR c] means (a AND b) OR c. SQL's native precedence
		// would bind AND tighter and give a OR (b AND c), so the
		// accumulated expression is parenthesised explicitly. All three
		// adapters (memory, SQL, Mongo) must agree here — the
		// conformance suite pins it.
		if i == 0 {
			acc = expr
			continue
		}
		conn := "AND"
		if w.Connector == storage.ConnectorOr {
			conn = "OR"
		}
		acc = "(" + acc + ") " + conn + " " + expr
	}
	return " WHERE " + acc, args, nil
}

// likeEscapeChar is the escape character used with LIKE patterns. It is
// deliberately not a backslash: MySQL treats a backslash as an escape
// inside string literals while PostgreSQL (with standard_conforming_strings
// on) does not, so ESCAPE '\' would have to be spelled differently per
// dialect. '!' is literal everywhere.
const likeEscapeChar = '!'

const likeEscapeClause = ` ESCAPE '!'`

// escapeLike neutralises the LIKE wildcards % and _ in a user-supplied
// value so contains/starts_with/ends_with match literal text, the way
// the in-memory adapter's strings.Contains does. Without it a search
// for "%" matches every row and "a_c" matches "abc" — the admin
// plugin's user search feeds a query parameter straight into these
// operators.
func escapeLike(s string) string {
	if !strings.ContainsAny(s, "%_"+string(likeEscapeChar)) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		if r == '%' || r == '_' || r == likeEscapeChar {
			b.WriteRune(likeEscapeChar)
		}
		b.WriteRune(r)
	}
	return b.String()
}

func anyList(v any) ([]any, bool) {
	switch t := v.(type) {
	case []any:
		return t, true
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// checkWritableFields rejects keys the schema does not declare.
//
// Writes render the SET/VALUES list by walking the schema's fields and
// skipping anything the caller did not supply, which also skips anything
// the schema does not know about: a stale, typo'd or plugin-gated key
// used to be dropped without a word, and the caller was told the write
// succeeded. Reads have always been strict — buildWhere errors on the
// same key — so the two disagreed, and filtering on a column the backend
// had refused to store just returned nothing.
func checkWritableFields(t *storage.Table, data map[string]any) error {
	var unknown []string
	for k := range data {
		if t.FieldByName(k) == nil {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	// Map iteration order is random; sort so the message is stable.
	sort.Strings(unknown)
	quoted := make([]string, len(unknown))
	for i, k := range unknown {
		quoted[i] = fmt.Sprintf("%q", k)
	}
	return fmt.Errorf("sqlstore: unknown field(s) %s on %q",
		strings.Join(quoted, ", "), t.Name)
}

// Create implements storage.Adapter.
func (a *Adapter) Create(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	t, err := a.table(model)
	if err != nil {
		return nil, err
	}
	if err := checkWritableFields(t, data); err != nil {
		return nil, err
	}
	t.ApplyDefaults(data)
	var cols, ph []string
	var args []any
	i := 1
	for _, f := range t.Fields {
		v, ok := data[f.Name]
		if !ok {
			continue
		}
		cols = append(cols, a.dialect.Quote(f.Name))
		ph = append(ph, a.dialect.Placeholder(i))
		args = append(args, a.encode(&f, v))
		i++
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		a.dialect.Quote(model), strings.Join(cols, ", "), strings.Join(ph, ", "))
	if _, err := a.q.ExecContext(ctx, query, args...); err != nil {
		return nil, classifyError(err)
	}
	return data, nil
}

// classifyError maps driver-specific constraint errors onto the
// adapter's sentinel errors so handlers can return a 4xx instead of a
// 500 when two writers race.
func classifyError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	// Every needle must name a *unique* constraint. A bare "constraint
	// failed" also matches SQLite's "NOT NULL constraint failed",
	// "FOREIGN KEY constraint failed" and "CHECK constraint failed",
	// which would report a genuine integrity failure as "that record
	// already exists": the caller turns a 500 into a 4xx, the bug never
	// reaches the error budget, and a sign-up that can never succeed
	// looks like a duplicate registration.
	for _, needle := range []string{
		"unique constraint", // Postgres, SQLite ("UNIQUE constraint failed")
		"duplicate key",     // Postgres
		"duplicate entry",   // MySQL
		"sqlstate 23505",    // Postgres code
		"error 1062",        // MySQL code
		"unique violation",  // generic
	} {
		if strings.Contains(msg, needle) {
			return fmt.Errorf("%w: %s", storage.ErrUniqueViolation, err)
		}
	}
	return err
}

func (a *Adapter) selectQuery(t *storage.Table, where []storage.Where, opts *storage.FindOptions) (string, []any, error) {
	var cols []string
	for _, f := range t.Fields {
		cols = append(cols, a.dialect.Quote(f.Name))
	}
	whereSQL, args, err := a.buildWhere(t, where, 1)
	if err != nil {
		return "", nil, err
	}
	query := fmt.Sprintf("SELECT %s FROM %s%s", strings.Join(cols, ", "), a.dialect.Quote(t.Name), whereSQL)
	if opts != nil && opts.SortBy != nil {
		dir := "ASC"
		if strings.EqualFold(opts.SortBy.Direction, "desc") {
			dir = "DESC"
		}
		if t.FieldByName(opts.SortBy.Field) != nil {
			query += " ORDER BY " + a.dialect.Quote(opts.SortBy.Field) + " " + dir
		}
	}
	if opts != nil {
		query += a.limitOffset(opts.Limit, opts.Offset)
	}
	return query, args, nil
}

// limitOffset renders the LIMIT/OFFSET tail.
//
// SQLite and MySQL reject OFFSET without a preceding LIMIT, so paging
// with only an offset ("everything after row N", which FindOptions
// allows and the other adapters honour) needs a sentinel row count
// there. PostgreSQL accepts a bare OFFSET.
func (a *Adapter) limitOffset(limit, offset int) string {
	var out string
	switch {
	case limit > 0:
		out = fmt.Sprintf(" LIMIT %d", limit)
	case offset > 0:
		switch a.dialect.Name() {
		case "sqlite":
			out = " LIMIT -1"
		case "mysql":
			out = " LIMIT 18446744073709551615"
		}
	}
	if offset > 0 {
		out += fmt.Sprintf(" OFFSET %d", offset)
	}
	return out
}

func (a *Adapter) scanRows(t *storage.Table, rows *sql.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(t.Fields))
		ptrs := make([]any, len(t.Fields))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		rec := make(map[string]any, len(t.Fields))
		for i, f := range t.Fields {
			rec[f.Name] = a.decode(&t.Fields[i], vals[i])
			_ = f
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// FindOne implements storage.Adapter.
func (a *Adapter) FindOne(ctx context.Context, model string, where []storage.Where) (map[string]any, error) {
	recs, err := a.FindMany(ctx, model, where, &storage.FindOptions{Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, storage.ErrNotFound
	}
	return recs[0], nil
}

// FindMany implements storage.Adapter.
func (a *Adapter) FindMany(ctx context.Context, model string, where []storage.Where, opts *storage.FindOptions) ([]map[string]any, error) {
	t, err := a.table(model)
	if err != nil {
		return nil, err
	}
	query, args, err := a.selectQuery(t, where, opts)
	if err != nil {
		return nil, err
	}
	rows, err := a.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return a.scanRows(t, rows)
}

// Update implements storage.Adapter: it updates the FIRST record matching
// where and returns it, or ErrNotFound.
//
// It resolves that first row by its primary key and updates only that
// row, rather than issuing an unbounded UPDATE. The contract says "first
// match", the memory and Mongo adapters honour it, and an unbounded
// UPDATE on a non-unique where would silently rewrite every match — a
// difference no test would catch as long as callers happen to pass a
// unique key. Selecting the id first makes the three backends agree.
func (a *Adapter) Update(ctx context.Context, model string, where []storage.Where, update map[string]any) (map[string]any, error) {
	current, err := a.FindOne(ctx, model, where)
	if err != nil {
		return nil, err // ErrNotFound when nothing matches
	}
	id, ok := current["id"]
	if !ok {
		// A model with no id column cannot be addressed to a single row;
		// fall back to the (bounded-by-caller) many update rather than
		// guessing. No core model is in this position.
		if _, err := a.UpdateMany(ctx, model, where, update); err != nil {
			return nil, err
		}
		return a.FindOne(ctx, model, where2Identity(where, update))
	}
	if _, err := a.UpdateMany(ctx, model, []storage.Where{{Field: "id", Value: id}}, update); err != nil {
		return nil, err
	}
	return a.FindOne(ctx, model, []storage.Where{{Field: "id", Value: firstNonNil(update["id"], id)}})
}

// firstNonNil returns a if it is non-nil, else b. Used so that an update
// which changes the primary key is read back by its new value.
func firstNonNil(a, b any) any {
	if a != nil {
		return a
	}
	return b
}

// where2Identity adjusts the lookup after an update: if an updated column
// was part of the where clause, use the new value.
func where2Identity(where []storage.Where, update map[string]any) []storage.Where {
	out := make([]storage.Where, len(where))
	copy(out, where)
	for i, w := range out {
		if v, ok := update[w.Field]; ok && (w.Operator == "" || w.Operator == storage.OpEq) {
			out[i].Value = v
		}
	}
	return out
}

// UpdateMany implements storage.Adapter.
func (a *Adapter) UpdateMany(ctx context.Context, model string, where []storage.Where, update map[string]any) (int64, error) {
	t, err := a.table(model)
	if err != nil {
		return 0, err
	}
	if err := checkWritableFields(t, update); err != nil {
		return 0, err
	}
	var sets []string
	var args []any
	i := 1
	for _, f := range t.Fields {
		v, ok := update[f.Name]
		if !ok {
			continue
		}
		sets = append(sets, a.dialect.Quote(f.Name)+" = "+a.dialect.Placeholder(i))
		args = append(args, a.encode(&f, v))
		i++
	}
	if len(sets) == 0 {
		return 0, nil
	}
	whereSQL, whereArgs, err := a.buildWhere(t, where, i)
	if err != nil {
		return 0, err
	}
	args = append(args, whereArgs...)
	query := fmt.Sprintf("UPDATE %s SET %s%s", a.dialect.Quote(model), strings.Join(sets, ", "), whereSQL)
	res, err := a.q.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, classifyError(err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Delete implements storage.Adapter.
func (a *Adapter) Delete(ctx context.Context, model string, where []storage.Where) error {
	_, err := a.DeleteMany(ctx, model, where)
	return err
}

// DeleteMany implements storage.Adapter.
func (a *Adapter) DeleteMany(ctx context.Context, model string, where []storage.Where) (int64, error) {
	t, err := a.table(model)
	if err != nil {
		return 0, err
	}
	whereSQL, args, err := a.buildWhere(t, where, 1)
	if err != nil {
		return 0, err
	}
	query := fmt.Sprintf("DELETE FROM %s%s", a.dialect.Quote(model), whereSQL)
	res, err := a.q.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Count implements storage.Adapter.
func (a *Adapter) Count(ctx context.Context, model string, where []storage.Where) (int64, error) {
	t, err := a.table(model)
	if err != nil {
		return 0, err
	}
	whereSQL, args, err := a.buildWhere(t, where, 1)
	if err != nil {
		return 0, err
	}
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s%s", a.dialect.Quote(model), whereSQL)
	rows, err := a.q.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var n int64
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return 0, err
		}
	}
	return n, rows.Err()
}

// Transaction implements storage.Transactor. A panic inside fn rolls
// back and re-panics rather than leaking the connection.
func (a *Adapter) Transaction(ctx context.Context, fn func(tx storage.Adapter) error) error {
	if a.db == nil {
		// Already inside a transaction (or constructed without a *sql.DB).
		// Running fn here without a transaction would silently drop the
		// atomicity the caller asked for, so say so.
		return errors.New("sqlstore: nested transactions are not supported")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txAdapter := &Adapter{db: nil, q: tx, dialect: a.dialect, schema: a.schema}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
		if p := recover(); p != nil {
			panic(p)
		}
	}()
	if err := fn(txAdapter); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return classifyError(err)
	}
	committed = true
	return nil
}
