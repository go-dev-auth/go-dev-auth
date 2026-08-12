package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Introspector is optionally implemented by a Dialect that knows how to
// list the columns of a table. The three built-in dialects implement it.
// A custom Dialect that does not gets the ANSI information_schema query,
// which is right for most engines but not for all of them.
type Introspector interface {
	// ColumnsQuery returns a query yielding one row per existing column
	// of table, with the column name in the first result column. A table
	// that does not exist must yield no rows rather than an error.
	ColumnsQuery(table string) (query string, args []any)
}

// Postgres resolves an unqualified table name through search_path, but
// CREATE TABLE puts it in current_schema(); scoping introspection the
// same way keeps the two consistent.
func (postgresDialect) ColumnsQuery(table string) (string, []any) {
	return `SELECT column_name FROM information_schema.columns ` +
		`WHERE table_schema = current_schema() AND table_name = $1`, []any{table}
}

func (mysqlDialect) ColumnsQuery(table string) (string, []any) {
	return "SELECT column_name FROM information_schema.columns " +
		"WHERE table_schema = DATABASE() AND table_name = ?", []any{table}
}

// pragma_table_info is the table-valued form of PRAGMA table_info; it
// takes a bound parameter, so the table name never has to be pasted into
// the SQL. It needs SQLite 3.16 (2017) — see TableColumns for the
// fallback used on older libraries.
//
// The second argument pins the lookup to the main database. Without it
// SQLite resolves an unqualified name temp → main → attached, while our
// CREATE TABLE always targets main; a TEMP table of the same name would
// otherwise make a missing column look present and turn the migration
// into a silent no-op.
func (sqliteDialect) ColumnsQuery(table string) (string, []any) {
	return `SELECT name FROM pragma_table_info(?, 'main')`, []any{table}
}

var _, _, _ Introspector = postgresDialect{}, mysqlDialect{}, sqliteDialect{}

// columnsQuery picks the introspection query for d.
func columnsQuery(d Dialect, table string) (string, []any) {
	if in, ok := d.(Introspector); ok {
		return in.ColumnsQuery(table)
	}
	// ANSI fallback for a third-party dialect. The placeholder comes from
	// the dialect so at least the parameter syntax is right.
	return `SELECT column_name FROM information_schema.columns WHERE table_name = ` +
		d.Placeholder(1), []any{table}
}

// TableColumns returns the names of the columns table currently has in
// the live database. An empty (non-nil) result means the table does not
// exist yet.
//
// Names are compared exactly. Every statement this package generates
// quotes its identifiers, so a table created by this adapter reports the
// same mixed-case names the schema declares. A table created by hand
// with unquoted DDL on PostgreSQL will have folded them to lower case,
// and this will report the declared spelling as missing.
func (a *Adapter) TableColumns(ctx context.Context, table string) (map[string]bool, error) {
	if a.q == nil {
		return nil, errors.New("sqlstore: introspection needs a database handle")
	}
	query, args := columnsQuery(a.dialect, table)
	rows, err := a.q.QueryContext(ctx, query, args...)
	if err != nil && a.dialect.Name() == "sqlite" &&
		strings.Contains(err.Error(), "pragma_table_info") {
		// SQLite older than 3.16 has no table-valued pragma. The bare
		// PRAGMA takes no parameters, so the name has to be quoted into
		// the statement; a.dialect.Quote escapes embedded quotes. It is
		// scoped to main. for the same reason the table-valued form is —
		// otherwise a TEMP table shadows the real one.
		rows, err = a.q.QueryContext(ctx, `PRAGMA main.table_info(`+a.dialect.Quote(table)+`)`)
		if err == nil {
			return scanPragmaTableInfo(rows)
		}
	}
	if err != nil {
		return nil, err
	}
	return scanColumnNames(rows)
}

func scanColumnNames(rows rowScanner) (map[string]bool, error) {
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

// scanPragmaTableInfo reads the fallback `PRAGMA table_info` result,
// whose shape is (cid, name, type, notnull, dflt_value, pk).
func scanPragmaTableInfo(rows rowScanner) (map[string]bool, error) {
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var (
			cid          int
			name, typ    string
			notNull, pk  int
			defaultValue any
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

// rowScanner is the part of *sql.Rows the scanners use.
type rowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

// AddColumnSQL generates the statements that add f to the existing table
// t: an ALTER TABLE ... ADD COLUMN, plus the index the field implies.
//
// The added column is never NOT NULL, whatever the schema says. A table
// that already has rows has no value to put in the new column, so
// PostgreSQL and MySQL reject a NOT NULL addition without a default and
// SQLite rejects it outright. Nullable is the only thing that can be
// applied to a live table, and it is also honest: the existing rows
// really do not have a value.
//
// This does mean a required column added by a migration is enforced only
// by the application, not by the database, until someone backfills the
// rows and tightens it by hand. See Adapter.PendingMigrationSQL.
func AddColumnSQL(d Dialect, t *storage.Table, f storage.Field) []string {
	sqlite := d.Name() == "sqlite"

	col := d.Quote(f.Name) + " " + d.ColumnType(f)
	// SQLite cannot add a UNIQUE column at all; the others can, and for
	// SQLite a unique index below does the same job. NULLs do not
	// conflict in a unique index on any of the three, so the rows that
	// predate the column are fine either way.
	if f.Unique && !sqlite {
		col += " UNIQUE"
	}
	def := defaultLiteral(d, f)
	if sqlite && f.References != nil {
		// SQLite refuses ADD COLUMN with both a REFERENCES clause and a
		// non-NULL default. Keep the foreign key, drop the default: the
		// adapter applies declared defaults itself in Create
		// (Table.ApplyDefaults), so nothing is lost for new rows.
		def = ""
	}
	if def != "" {
		col += " DEFAULT " + def
	}
	if f.References != nil {
		col += fmt.Sprintf(" REFERENCES %s(%s)",
			d.Quote(f.References.Model), d.Quote(f.References.Field))
		if strings.EqualFold(f.References.OnDelete, "cascade") {
			col += " ON DELETE CASCADE"
		}
	}

	out := []string{fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s;", d.Quote(t.Name), col)}
	switch {
	case f.Unique && sqlite:
		out = append(out, fmt.Sprintf("CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (%s);",
			d.Quote("uniq_"+t.Name+"_"+f.Name), d.Quote(t.Name), d.Quote(f.Name)))
	case f.Index && !f.Unique:
		out = append(out, addIndexSQL(d, t, f))
	}
	return out
}

// uniqueIndexSQL returns the CREATE UNIQUE INDEX statements that back the
// unique constraint on a table's unique columns, for the one engine that
// needs them applied separately: SQLite.
//
// On PostgreSQL and MySQL a unique column carries its constraint inline
// in the same CREATE TABLE / ADD COLUMN statement, so the constraint and
// the column can never come apart. SQLite cannot add a UNIQUE column with
// ALTER, so a migrated unique column gets its constraint from a separate
// CREATE UNIQUE INDEX — and if a migration was interrupted after the
// ADD COLUMN but before that index, the column exists and silently
// permits duplicates. Re-issuing these (idempotently) on every Migrate
// repairs that: uniqueness self-heals on the next boot. On a freshly
// created table the inline UNIQUE already enforces it and this named
// index is a harmless redundant one.
func uniqueIndexSQL(d Dialect, t *storage.Table) []string {
	if d.Name() != "sqlite" {
		return nil
	}
	var out []string
	for _, f := range t.Fields {
		if f.Unique && f.Name != "id" {
			out = append(out, fmt.Sprintf("CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (%s);",
				d.Quote("uniq_"+t.Name+"_"+f.Name), d.Quote(t.Name), d.Quote(f.Name)))
		}
	}
	return out
}

// sqliteUniqueIndexPresent reports whether a unique index covering column
// col of table exists in the main database. It is how Inspect detects the
// interrupted-migration case where a unique column exists without its
// backing index. Best effort: any query error is treated as "cannot
// tell" (returns true), so a drift check never fails a boot over an
// introspection quirk.
func (a *Adapter) sqliteUniqueIndexPresent(ctx context.Context, table, col string) bool {
	list, err := a.q.QueryContext(ctx, `SELECT name, "unique" FROM pragma_index_list(?)`, table)
	if err != nil {
		return true
	}
	var indexes []string
	for list.Next() {
		var name string
		var uniq int
		if err := list.Scan(&name, &uniq); err != nil {
			list.Close()
			return true
		}
		if uniq == 1 {
			indexes = append(indexes, name)
		}
	}
	list.Close()
	if err := list.Err(); err != nil {
		return true
	}
	for _, idx := range indexes {
		cols, err := a.q.QueryContext(ctx, `SELECT name FROM pragma_index_info(?)`, idx)
		if err != nil {
			return true
		}
		for cols.Next() {
			var name string
			if err := cols.Scan(&name); err == nil && name == col {
				cols.Close()
				return true
			}
		}
		cols.Close()
	}
	return false
}

// addIndexSQL indexes a column that has just been added. MySQL has no
// CREATE INDEX IF NOT EXISTS — CreateTableSQL works around that by
// declaring indexes inline, which is not available here. It is safe: the
// statement only runs for a column that did not exist a moment ago, so
// neither can its index.
func addIndexSQL(d Dialect, t *storage.Table, f storage.Field) string {
	exists := "IF NOT EXISTS "
	if d.Name() == "mysql" {
		exists = ""
	}
	return fmt.Sprintf("CREATE INDEX %s%s ON %s (%s);",
		exists, d.Quote("idx_"+t.Name+"_"+f.Name), d.Quote(t.Name), d.Quote(f.Name))
}

// PendingMigrationSQL inspects the live database and returns only the
// statements needed to bring it up to the schema: a CREATE TABLE (with
// its indexes) for every table that does not exist yet, and an ALTER
// TABLE ... ADD COLUMN for every declared column an existing table is
// missing. It returns nil when the database already matches, so an empty
// result is the "nothing to do" answer.
//
// This is the counterpart to MigrationSQL, which always renders the full
// create-from-nothing DDL. Use MigrationSQL to provision a new database
// and this to upgrade one that already has data — enabling a plugin, or
// taking a library version that adds a core column.
//
// The statements are returned separately rather than as one blob because
// several drivers refuse more than one statement per Exec. Run them in
// order.
func (a *Adapter) PendingMigrationSQL(ctx context.Context) ([]string, error) {
	var out []string
	err := a.eachMissing(ctx,
		func(t *storage.Table) error {
			out = append(out, CreateTableSQL(a.dialect, t))
			out = append(out, CreateIndexSQL(a.dialect, t)...)
			return nil
		},
		func(t *storage.Table, f storage.Field) error {
			out = append(out, AddColumnSQL(a.dialect, t, f)...)
			return nil
		})
	if err != nil {
		return nil, err
	}
	// A composite unique constraint on a table that already exists needs a
	// separate CREATE UNIQUE INDEX (the columns are already there, so no
	// ADD COLUMN carries it). A table that does not exist yet gets it
	// inline from the CreateTableSQL emitted above. Emit it only when the
	// constraint is not already enforced.
	for _, name := range a.schema.TableNames() {
		t := a.schema.Tables[name]
		if len(t.UniqueConstraints) == 0 {
			continue
		}
		have, err := a.TableColumns(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("sqlstore: inspecting table %s: %w", name, err)
		}
		if len(have) == 0 {
			continue // created from scratch above, with the constraint inline
		}
		for _, uc := range t.UniqueConstraints {
			// Where the index is introspectable (SQLite, MySQL) skip a
			// constraint that is already enforced; on PostgreSQL emit it
			// unconditionally, since the IF NOT EXISTS in the statement
			// makes re-applying it a no-op.
			switch a.dialect.Name() {
			case "sqlite", "mysql":
				if a.compositeUniqueIndexPresent(ctx, name, uc) {
					continue
				}
			}
			out = append(out, compositeUniqueIndexSQL(a.dialect, t, uc))
		}
	}
	return out, nil
}

// eachMissing introspects every table in the schema and calls
// missingTable for tables that do not exist and missingColumn for each
// declared column an existing table lacks.
func (a *Adapter) eachMissing(
	ctx context.Context,
	missingTable func(*storage.Table) error,
	missingColumn func(*storage.Table, storage.Field) error,
) error {
	if a.q == nil {
		return errors.New("sqlstore: this operation needs a database handle")
	}
	for _, name := range a.schema.TableNames() {
		t := a.schema.Tables[name]
		have, err := a.TableColumns(ctx, name)
		if err != nil {
			return fmt.Errorf("sqlstore: inspecting table %s: %w", name, err)
		}
		if len(have) == 0 {
			if err := missingTable(t); err != nil {
				return err
			}
			continue
		}
		for _, f := range t.Fields {
			if have[f.Name] {
				continue
			}
			if f.Name == "id" {
				// Adding a primary key to a populated table is not
				// something a generated ALTER can get right (the existing
				// rows have no value for it, and the column has to be
				// unique). Say so instead of adding a nullable "id".
				return fmt.Errorf(
					"sqlstore: table %s exists without its primary key column \"id\"; "+
						"this cannot be repaired automatically", name)
			}
			if err := missingColumn(t, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// DuplicateRowsError is returned by Migrate when a composite unique
// constraint cannot be added because the table already contains rows that
// would violate it. Migrate never drops data, so the operator has to
// resolve the duplicates by hand and then re-run it. Samples names a few
// of the conflicting column tuples so the operator has somewhere to start.
type DuplicateRowsError struct {
	Table   string
	Columns []string
	Samples []map[string]any
}

func (e *DuplicateRowsError) Error() string {
	msg := fmt.Sprintf("sqlstore: cannot add the UNIQUE constraint on %s (%s): the table already "+
		"contains rows that violate it; remove the duplicates and re-run Migrate",
		e.Table, strings.Join(e.Columns, ", "))
	if len(e.Samples) > 0 {
		var tuples []string
		for _, s := range e.Samples {
			var parts []string
			for _, c := range e.Columns {
				parts = append(parts, fmt.Sprintf("%s=%v", c, s[c]))
			}
			tuples = append(tuples, "("+strings.Join(parts, ", ")+")")
		}
		msg += " — duplicate values: " + strings.Join(tuples, ", ")
	}
	return msg
}

// ensureCompositeUniques adds every declared composite unique constraint
// to the table it belongs to when that table already exists without it.
// It is idempotent: on SQLite and MySQL it introspects the live indexes
// first, and on PostgreSQL the CREATE UNIQUE INDEX IF NOT EXISTS is a
// no-op once the index is there. A fresh table already has the constraint
// inline (CreateTableSQL), so this only does work on a database that
// predates it. Adding it to a table holding duplicates fails with a
// DuplicateRowsError rather than dropping data.
func (a *Adapter) ensureCompositeUniques(ctx context.Context) error {
	if a.q == nil {
		return errors.New("sqlstore: this operation needs a database handle")
	}
	for _, name := range a.schema.TableNames() {
		t := a.schema.Tables[name]
		if len(t.UniqueConstraints) == 0 {
			continue
		}
		for _, uc := range t.UniqueConstraints {
			// SQLite and MySQL carry no IF-NOT-EXISTS guarantee for a
			// composite index (MySQL has no such clause; on SQLite an
			// inline UNIQUE produces a differently named autoindex), so
			// introspect before issuing it. PostgreSQL relies on the
			// IF NOT EXISTS in the statement instead.
			switch a.dialect.Name() {
			case "sqlite", "mysql":
				if a.compositeUniqueIndexPresent(ctx, name, uc) {
					continue
				}
			}
			stmt := compositeUniqueIndexSQL(a.dialect, t, uc)
			if _, err := a.q.ExecContext(ctx, stmt); err != nil {
				if errors.Is(classifyError(err), storage.ErrUniqueViolation) {
					return a.duplicateRowsError(ctx, t, uc)
				}
				return fmt.Errorf("sqlstore: adding the UNIQUE constraint on %s (%s): %w",
					name, strings.Join(uc.Columns, ", "), err)
			}
		}
	}
	return nil
}

// duplicateRowsError builds a DuplicateRowsError, querying the table for a
// few of the offending tuples so the message is actionable. Gathering the
// samples is best effort: if the query fails the error is still returned,
// just without examples.
func (a *Adapter) duplicateRowsError(ctx context.Context, t *storage.Table, uc storage.UniqueConstraint) error {
	err := &DuplicateRowsError{Table: t.Name, Columns: uc.Columns}
	cols := strings.Join(quoteAll(a.dialect, uc.Columns), ", ")
	query := fmt.Sprintf("SELECT %s FROM %s GROUP BY %s HAVING COUNT(*) > 1%s",
		cols, a.dialect.Quote(t.Name), cols, a.limitOffset(5, 0))
	rows, qerr := a.q.QueryContext(ctx, query)
	if qerr != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		vals := make([]any, len(uc.Columns))
		ptrs := make([]any, len(uc.Columns))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if scanErr := rows.Scan(ptrs...); scanErr != nil {
			break
		}
		sample := make(map[string]any, len(uc.Columns))
		for i, c := range uc.Columns {
			f := t.FieldByName(c)
			if f != nil {
				sample[c] = a.decode(f, vals[i])
			} else {
				sample[c] = vals[i]
			}
		}
		err.Samples = append(err.Samples, sample)
	}
	return err
}

// compositeUniqueIndexPresent reports whether a unique index (or the
// autoindex behind an inline UNIQUE) already covers exactly the columns
// of uc on table. It is implemented for the engines whose migration path
// needs it — SQLite and MySQL — and is best effort: any introspection
// failure is read as "present" so a re-migration or drift check never
// fails a boot over an introspection quirk, mirroring
// sqliteUniqueIndexPresent.
func (a *Adapter) compositeUniqueIndexPresent(ctx context.Context, table string, uc storage.UniqueConstraint) bool {
	switch a.dialect.Name() {
	case "sqlite":
		return a.sqliteCompositeUniquePresent(ctx, table, uc)
	case "mysql":
		return a.mysqlCompositeUniquePresent(ctx, table, uc)
	default:
		return true
	}
}

func columnSetEqual(have map[string]bool, want []string) bool {
	if len(have) != len(want) {
		return false
	}
	for _, c := range want {
		if !have[c] {
			return false
		}
	}
	return true
}

// sqliteCompositeUniquePresent walks the table's unique indexes via
// pragma and reports whether one of them covers exactly uc's columns.
func (a *Adapter) sqliteCompositeUniquePresent(ctx context.Context, table string, uc storage.UniqueConstraint) bool {
	list, err := a.q.QueryContext(ctx, `SELECT name, "unique" FROM pragma_index_list(?)`, table)
	if err != nil {
		return true
	}
	var uniqueIndexes []string
	for list.Next() {
		var name string
		var uniq int
		if err := list.Scan(&name, &uniq); err != nil {
			list.Close()
			return true
		}
		if uniq == 1 {
			uniqueIndexes = append(uniqueIndexes, name)
		}
	}
	list.Close()
	if err := list.Err(); err != nil {
		return true
	}
	for _, idx := range uniqueIndexes {
		cols, err := a.q.QueryContext(ctx, `SELECT name FROM pragma_index_info(?)`, idx)
		if err != nil {
			return true
		}
		have := map[string]bool{}
		for cols.Next() {
			var name string
			if err := cols.Scan(&name); err == nil {
				have[name] = true
			}
		}
		cols.Close()
		if columnSetEqual(have, uc.Columns) {
			return true
		}
	}
	return false
}

// mysqlCompositeUniquePresent reads information_schema.statistics for the
// table's unique indexes and reports whether one covers exactly uc's
// columns. MySQL cannot be run in this repository's test suite, so this
// mirrors the ColumnsQuery scoping (table_schema = DATABASE()) it sits
// next to and is exercised only for its shape.
func (a *Adapter) mysqlCompositeUniquePresent(ctx context.Context, table string, uc storage.UniqueConstraint) bool {
	rows, err := a.q.QueryContext(ctx,
		"SELECT index_name, column_name FROM information_schema.statistics "+
			"WHERE table_schema = DATABASE() AND table_name = ? AND non_unique = 0", table)
	if err != nil {
		return true
	}
	byIndex := map[string]map[string]bool{}
	for rows.Next() {
		var idx, col string
		if err := rows.Scan(&idx, &col); err != nil {
			rows.Close()
			return true
		}
		if byIndex[idx] == nil {
			byIndex[idx] = map[string]bool{}
		}
		byIndex[idx][col] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return true
	}
	for _, have := range byIndex {
		if columnSetEqual(have, uc.Columns) {
			return true
		}
	}
	return false
}

// migrationLockKey is a fixed 63-bit key for the PostgreSQL session
// advisory lock. Any constant works as long as it is stable across
// versions; this is the low 63 bits of fnv-1a("go-dev-auth:migrate").
const migrationLockKey = int64(0x2b3c8f19a7d64e21)

const migrationLockName = "go-dev-auth:migrate"

// transactionalDDL reports whether the engine keeps DDL inside a
// transaction — so that a create-table-plus-its-indexes batch either all
// lands or none does. PostgreSQL and SQLite do; MySQL commits implicitly
// after each DDL statement and cannot.
func (a *Adapter) transactionalDDL() bool {
	switch a.dialect.Name() {
	case "postgres", "sqlite":
		return true
	default:
		return false
	}
}

// lockForMigration serialises concurrent migrations so a rolling deploy
// does not run two ADD COLUMNs at once (they have no IF NOT EXISTS, so
// the loser would error). It returns an unlock function that is always
// safe to call. Where the engine has no advisory lock, it degrades to a
// no-op — SQLite is single-writer already, and a custom engine gets best
// effort rather than a hard failure.
func (a *Adapter) lockForMigration(ctx context.Context) (func(), error) {
	noop := func() {}
	switch a.dialect.Name() {
	case "postgres":
		if _, err := a.q.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
			return noop, fmt.Errorf("sqlstore: acquiring migration lock: %w", err)
		}
		return func() {
			_, _ = a.q.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockKey)
		}, nil
	case "mysql":
		// GET_LOCK blocks up to the timeout and returns 1 on success, 0 on
		// timeout, NULL on error. A 60s ceiling keeps a wedged migration
		// from hanging a boot forever.
		rows, err := a.q.QueryContext(ctx, "SELECT GET_LOCK(?, 60)", migrationLockName)
		if err != nil {
			return noop, fmt.Errorf("sqlstore: acquiring migration lock: %w", err)
		}
		var res *int
		if rows.Next() {
			_ = rows.Scan(&res)
		}
		_ = rows.Close()
		if res == nil || *res != 1 {
			return noop, errors.New("sqlstore: timed out waiting for the migration lock")
		}
		return func() {
			_, _ = a.q.ExecContext(context.Background(), "SELECT RELEASE_LOCK(?)", migrationLockName)
		}, nil
	default:
		return noop, nil
	}
}

// applyTableDDL runs one table's statements, atomically where the engine
// allows it. On PostgreSQL and SQLite the batch runs in a transaction, so
// an interrupted migration cannot leave a column without the unique index
// that enforces its constraint. On MySQL, which cannot roll DDL back, the
// statements run in order and the self-healing unique-index pass on the
// next boot is what closes the gap instead.
func (a *Adapter) applyTableDDL(ctx context.Context, name string, stmts []string) error {
	if len(stmts) == 0 {
		return nil
	}
	if a.transactionalDDL() && a.db != nil {
		tx, err := a.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("sqlstore: migrating table %s: %w", name, err)
		}
		for _, stmt := range stmts {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("sqlstore: migrating table %s: %w", name, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("sqlstore: migrating table %s: %w", name, err)
		}
		return nil
	}
	for _, stmt := range stmts {
		if _, err := a.q.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrating table %s: %w", name, err)
		}
	}
	return nil
}

// SchemaDrift describes what the live database is missing relative to
// the schema the code expects. It is an error, so a caller can return it
// directly.
type SchemaDrift struct {
	// MissingTables are declared tables the database does not have.
	MissingTables []string
	// MissingColumns maps a table that exists to the declared columns it
	// does not have.
	MissingColumns map[string][]string
	// MissingUniqueConstraints maps a table to columns that exist but
	// whose declared UNIQUE constraint is not enforced by the database —
	// the fingerprint of a migration interrupted between adding a column
	// and creating its unique index. Re-running Migrate repairs it.
	MissingUniqueConstraints map[string][]string
	// MissingCompositeUniques maps a table to declared composite (multi
	// column) UNIQUE constraints the database does not enforce — a table
	// that predates the constraint, or a migration interrupted before its
	// index was created. Each entry is the ordered column list of one
	// constraint. Re-running Migrate adds it (or reports duplicates).
	MissingCompositeUniques map[string][][]string
}

// Empty reports whether the live schema has everything the code expects.
func (d *SchemaDrift) Empty() bool {
	return d == nil || (len(d.MissingTables) == 0 && len(d.MissingColumns) == 0 &&
		len(d.MissingUniqueConstraints) == 0 && len(d.MissingCompositeUniques) == 0)
}

// Error implements error, naming every missing table and column.
func (d *SchemaDrift) Error() string {
	if d.Empty() {
		return "sqlstore: database schema matches"
	}
	var parts []string
	for _, name := range d.MissingTables {
		parts = append(parts, fmt.Sprintf("table %q is missing", name))
	}
	tables := make([]string, 0, len(d.MissingColumns))
	for name := range d.MissingColumns {
		tables = append(tables, name)
	}
	sort.Strings(tables)
	for _, name := range tables {
		cols := d.MissingColumns[name]
		quoted := make([]string, len(cols))
		for i, c := range cols {
			quoted[i] = fmt.Sprintf("%q", c)
		}
		parts = append(parts, fmt.Sprintf("table %q is missing column(s) %s",
			name, strings.Join(quoted, ", ")))
	}
	uniqTables := make([]string, 0, len(d.MissingUniqueConstraints))
	for name := range d.MissingUniqueConstraints {
		uniqTables = append(uniqTables, name)
	}
	sort.Strings(uniqTables)
	for _, name := range uniqTables {
		cols := d.MissingUniqueConstraints[name]
		quoted := make([]string, len(cols))
		for i, c := range cols {
			quoted[i] = fmt.Sprintf("%q", c)
		}
		parts = append(parts, fmt.Sprintf("table %q is missing the UNIQUE constraint on %s "+
			"(an interrupted migration left the column without its index)",
			name, strings.Join(quoted, ", ")))
	}
	compTables := make([]string, 0, len(d.MissingCompositeUniques))
	for name := range d.MissingCompositeUniques {
		compTables = append(compTables, name)
	}
	sort.Strings(compTables)
	for _, name := range compTables {
		for _, cols := range d.MissingCompositeUniques[name] {
			quoted := make([]string, len(cols))
			for i, c := range cols {
				quoted[i] = fmt.Sprintf("%q", c)
			}
			parts = append(parts, fmt.Sprintf("table %q is missing the composite UNIQUE constraint on (%s)",
				name, strings.Join(quoted, ", ")))
		}
	}
	return "sqlstore: the database schema is out of date: " + strings.Join(parts, "; ") +
		" — run Migrate, or apply PendingMigrationSQL with your migration tool"
}

// Inspect compares the live database against the schema and reports what
// is missing. A nil error with an empty *SchemaDrift means the database
// is up to date; the error return is for introspection failures only.
func (a *Adapter) Inspect(ctx context.Context) (*SchemaDrift, error) {
	drift := &SchemaDrift{MissingColumns: map[string][]string{}}
	err := a.eachMissing(ctx,
		func(t *storage.Table) error {
			drift.MissingTables = append(drift.MissingTables, t.Name)
			return nil
		},
		func(t *storage.Table, f storage.Field) error {
			drift.MissingColumns[t.Name] = append(drift.MissingColumns[t.Name], f.Name)
			return nil
		})
	if err != nil {
		return nil, err
	}
	if len(drift.MissingColumns) == 0 {
		drift.MissingColumns = nil
	}
	// On SQLite a unique column's constraint lives in a separate index, so
	// a column can exist without it (an interrupted migration). Detect
	// that so a drift check reports it rather than a duplicate slipping
	// through silently. Only columns that actually exist are checked;
	// missing columns are already reported above.
	if a.dialect.Name() == "sqlite" {
		missing := map[string][]string{}
		for _, name := range a.schema.TableNames() {
			t := a.schema.Tables[name]
			have, err := a.TableColumns(ctx, name)
			if err != nil || len(have) == 0 {
				continue
			}
			for _, f := range t.Fields {
				if f.Unique && f.Name != "id" && have[f.Name] &&
					!a.sqliteUniqueIndexPresent(ctx, name, f.Name) {
					missing[name] = append(missing[name], f.Name)
				}
			}
		}
		if len(missing) > 0 {
			drift.MissingUniqueConstraints = missing
		}
		// Composite unique constraints live in their own index too, so a
		// SQLite table can exist with its columns but without the
		// constraint (it predates it, or a migration was interrupted).
		// Report it so a drift check names it rather than a duplicate
		// slipping through. Kept SQLite-only for the same reason the
		// single-column check above is: on PostgreSQL and MySQL the
		// constraint is added atomically with its statement.
		missingComp := map[string][][]string{}
		for _, name := range a.schema.TableNames() {
			t := a.schema.Tables[name]
			if len(t.UniqueConstraints) == 0 {
				continue
			}
			have, err := a.TableColumns(ctx, name)
			if err != nil || len(have) == 0 {
				continue
			}
			for _, uc := range t.UniqueConstraints {
				if !a.sqliteCompositeUniquePresent(ctx, name, uc) {
					missingComp[name] = append(missingComp[name], uc.Columns)
				}
			}
		}
		if len(missingComp) > 0 {
			drift.MissingCompositeUniques = missingComp
		}
	}
	return drift, nil
}

// CheckSchema returns a *SchemaDrift error when the live database is
// missing a table or column the code expects, and nil when it matches.
//
// Without it the first query is what fails, with a driver-level message
// naming neither the plugin that added the column nor the migration that
// was skipped — and it fails inside a sign-in, not at startup. Call this
// after godevauth.New (which supplies the full schema, core plus
// plugins), or set Advanced.VerifySchema to have New call it.
func (a *Adapter) CheckSchema(ctx context.Context) error {
	drift, err := a.Inspect(ctx)
	if err != nil {
		return err
	}
	if drift.Empty() {
		return nil
	}
	return drift
}
