package sqlstore

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Dialect abstracts the SQL flavor differences between databases.
type Dialect interface {
	// Name returns the dialect name ("postgres", "mysql", "sqlite").
	Name() string
	// Placeholder returns the parameter placeholder for index i (1-based).
	Placeholder(i int) string
	// Quote quotes an identifier.
	Quote(ident string) string
	// ColumnType maps a schema field to a column type.
	ColumnType(f storage.Field) string
}

// Postgres is the PostgreSQL dialect.
var Postgres Dialect = postgresDialect{}

// MySQL is the MySQL/MariaDB dialect.
var MySQL Dialect = mysqlDialect{}

// SQLite is the SQLite dialect.
var SQLite Dialect = sqliteDialect{}

type postgresDialect struct{}

func (postgresDialect) Name() string             { return "postgres" }
func (postgresDialect) Placeholder(i int) string { return fmt.Sprintf("$%d", i) }
func (postgresDialect) Quote(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}
func (postgresDialect) ColumnType(f storage.Field) string {
	switch f.Type {
	case storage.FieldBool:
		return "BOOLEAN"
	case storage.FieldInt:
		return "BIGINT"
	case storage.FieldTime:
		return "TIMESTAMPTZ"
	case storage.FieldText:
		return "TEXT"
	default:
		return "TEXT"
	}
}

type mysqlDialect struct{}

func (mysqlDialect) Name() string           { return "mysql" }
func (mysqlDialect) Placeholder(int) string { return "?" }
func (mysqlDialect) Quote(ident string) string {
	return "`" + strings.ReplaceAll(ident, "`", "``") + "`"
}
func (mysqlDialect) ColumnType(f storage.Field) string {
	switch f.Type {
	case storage.FieldBool:
		return "BOOLEAN"
	case storage.FieldInt:
		return "BIGINT"
	case storage.FieldTime:
		return "DATETIME(3)"
	case storage.FieldText:
		// MySQL cannot index a TEXT column without a prefix length, so
		// any indexed or referenced "text" field has to be a VARCHAR.
		if f.Unique || f.Index || f.References != nil {
			return "VARCHAR(255)"
		}
		return "TEXT"
	default:
		return "VARCHAR(255)"
	}
}

type sqliteDialect struct{}

func (sqliteDialect) Name() string           { return "sqlite" }
func (sqliteDialect) Placeholder(int) string { return "?" }
func (sqliteDialect) Quote(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}
func (sqliteDialect) ColumnType(f storage.Field) string {
	switch f.Type {
	case storage.FieldBool:
		return "INTEGER"
	case storage.FieldInt:
		return "INTEGER"
	case storage.FieldTime:
		return "TEXT"
	default:
		return "TEXT"
	}
}

// CreateTableSQL generates a CREATE TABLE statement for t.
func CreateTableSQL(d Dialect, t *storage.Table) string {
	var cols []string
	for _, f := range t.Fields {
		col := d.Quote(f.Name) + " " + d.ColumnType(f)
		if f.Name == "id" {
			col += " PRIMARY KEY"
		} else {
			if f.Required {
				col += " NOT NULL"
			}
			if f.Unique {
				col += " UNIQUE"
			}
			if def := defaultLiteral(d, f); def != "" {
				col += " DEFAULT " + def
			}
		}
		if f.References != nil && d.Name() != "mysql" {
			col += fmt.Sprintf(" REFERENCES %s(%s)",
				d.Quote(f.References.Model), d.Quote(f.References.Field))
			if strings.EqualFold(f.References.OnDelete, "cascade") {
				col += " ON DELETE CASCADE"
			}
		}
		cols = append(cols, col)
	}
	// MySQL parses a column-inline REFERENCES clause and then silently
	// discards it (documented InnoDB behaviour), so every foreign key
	// there — cascades included — was a no-op. Table-level FOREIGN KEY
	// constraints are what MySQL actually enforces.
	if d.Name() == "mysql" {
		for _, f := range t.Fields {
			if f.References == nil {
				continue
			}
			fk := fmt.Sprintf("FOREIGN KEY (%s) REFERENCES %s(%s)",
				d.Quote(f.Name), d.Quote(f.References.Model), d.Quote(f.References.Field))
			if strings.EqualFold(f.References.OnDelete, "cascade") {
				fk += " ON DELETE CASCADE"
			}
			cols = append(cols, fk)
		}
	}
	// Composite unique constraints are table-level, so they are declared
	// inline in every dialect. On a fresh table this is the whole story;
	// a table that predates the constraint gets it from Migrate's
	// composite-unique pass instead (the columns already exist, so there
	// is no ADD COLUMN to carry it).
	for _, uc := range t.UniqueConstraints {
		cols = append(cols, "UNIQUE ("+strings.Join(quoteAll(d, uc.Columns), ", ")+")")
	}
	// MySQL has no CREATE INDEX IF NOT EXISTS, so indexes are declared
	// inline where the CREATE TABLE IF NOT EXISTS already makes the
	// whole statement idempotent.
	if d.Name() == "mysql" {
		for _, f := range t.Fields {
			if f.Index && !f.Unique {
				cols = append(cols, fmt.Sprintf("INDEX %s (%s)",
					d.Quote("idx_"+t.Name+"_"+f.Name), d.Quote(f.Name)))
			}
		}
	}
	return fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n  %s\n);",
		d.Quote(t.Name), strings.Join(cols, ",\n  "))
}

// quoteAll quotes every identifier in names with the dialect's quoting.
func quoteAll(d Dialect, names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = d.Quote(n)
	}
	return out
}

// compositeUniqueIndexName is the stable name of the index that backs a
// composite unique constraint on a migrated (pre-existing) table.
func compositeUniqueIndexName(t *storage.Table, uc storage.UniqueConstraint) string {
	return "uniq_" + t.Name + "_" + strings.Join(uc.Columns, "_")
}

// compositeUniqueIndexSQL renders the CREATE UNIQUE INDEX statement that
// adds a composite unique constraint to a table that already exists — the
// migration counterpart of the inline UNIQUE(...) CreateTableSQL emits
// for a fresh table. IF NOT EXISTS makes it idempotent on the engines
// that support it; MySQL has none, so Migrate introspects before issuing
// it there (see ensureCompositeUniques).
func compositeUniqueIndexSQL(d Dialect, t *storage.Table, uc storage.UniqueConstraint) string {
	ifNotExists := "IF NOT EXISTS "
	if d.Name() == "mysql" {
		ifNotExists = ""
	}
	return fmt.Sprintf("CREATE UNIQUE INDEX %s%s ON %s (%s);",
		ifNotExists, d.Quote(compositeUniqueIndexName(t, uc)),
		d.Quote(t.Name), strings.Join(quoteAll(d, uc.Columns), ", "))
}

// CreateIndexSQL generates CREATE INDEX statements for t. MySQL returns
// none because its indexes are declared inline by CreateTableSQL.
func CreateIndexSQL(d Dialect, t *storage.Table) []string {
	if d.Name() == "mysql" {
		return nil
	}
	var out []string
	for _, f := range t.Fields {
		if f.Index && !f.Unique {
			out = append(out, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (%s);",
				d.Quote("idx_"+t.Name+"_"+f.Name), d.Quote(t.Name), d.Quote(f.Name)))
		}
	}
	return out
}

// defaultLiteral renders a field default as a SQL literal, or "" when
// the field has no default or the value is not representable.
//
// String rendering has to defeat two escape conventions, not one.
// Doubling the single quote is the SQL standard and covers PostgreSQL
// and SQLite. MySQL, under its default sql_mode, *also* treats backslash
// as an escape inside a string literal, so a value ending in a backslash
// would escape its own closing quote and let the rest of the DDL be
// reparsed — a field default is developer- or plugin-supplied, but it is
// still untrusted input to the DDL generator. Doubling the backslash as
// well closes that on MySQL and is harmless on the others, where a
// backslash is an ordinary character and `\\` in a literal is two
// backslashes — which is why this is only applied for MySQL.
func defaultLiteral(d Dialect, f storage.Field) string {
	switch v := f.Default.(type) {
	case nil:
		return ""
	case bool:
		if v {
			return "TRUE"
		}
		return "FALSE"
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	case time.Time:
		return "'" + v.UTC().Format("2006-01-02 15:04:05") + "'"
	case string:
		s := strings.ReplaceAll(v, "'", "''")
		if d.Name() == "mysql" {
			s = strings.ReplaceAll(s, "\\", "\\\\")
			// re-double: the line above turned each ' into '' already, and
			// a backslash before a quote must not now escape it. Order is
			// fine because we escaped quotes first, then backslashes, so a
			// literal backslash-quote in the input becomes \\'' — a literal
			// backslash followed by an escaped quote.
		}
		return "'" + s + "'"
	}
	return ""
}

// SchemaSQL generates the full DDL for a schema.
func SchemaSQL(d Dialect, s *storage.Schema) string {
	var b strings.Builder
	for _, name := range s.TableNames() {
		t := s.Tables[name]
		b.WriteString(CreateTableSQL(d, t))
		b.WriteString("\n")
		for _, idx := range CreateIndexSQL(d, t) {
			b.WriteString(idx)
			b.WriteString("\n")
		}
	}
	return b.String()
}
