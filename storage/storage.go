// Package adapter defines the storage interface used by go-dev-auth.
//
// Records are passed around as generic map[string]any values keyed by the
// field names declared in the schema. This mirrors the design of
// better-auth's database adapters and makes it possible for plugins to
// declare additional models and fields without code generation.
package storage

import (
	"context"
	"errors"
)

// ErrNotFound is returned when a record cannot be found.
var ErrNotFound = errors.New("adapter: record not found")

// ErrUniqueViolation is returned when a write conflicts with a unique
// constraint. Adapters must translate their driver's constraint error
// into this sentinel so callers can distinguish "already exists" (a
// client error) from an infrastructure failure (a server error).
var ErrUniqueViolation = errors.New("adapter: unique constraint violation")

// Operator is a comparison operator used in Where clauses.
type Operator string

const (
	OpEq         Operator = "eq"
	OpNe         Operator = "ne"
	OpGt         Operator = "gt"
	OpGte        Operator = "gte"
	OpLt         Operator = "lt"
	OpLte        Operator = "lte"
	OpIn         Operator = "in"
	OpContains   Operator = "contains"
	OpStartsWith Operator = "starts_with"
	OpEndsWith   Operator = "ends_with"
)

// Connector joins Where clauses.
type Connector string

const (
	ConnectorAnd Connector = "AND"
	ConnectorOr  Connector = "OR"
)

// Where is a single filter condition.
type Where struct {
	Field     string
	Operator  Operator // defaults to OpEq when empty
	Value     any
	Connector Connector // defaults to ConnectorAnd when empty
}

// W is shorthand for an equality Where clause.
func W(field string, value any) Where {
	return Where{Field: field, Operator: OpEq, Value: value}
}

// SortBy describes result ordering.
type SortBy struct {
	Field     string
	Direction string // "asc" or "desc"
}

// FindOptions controls pagination and sorting of FindMany.
type FindOptions struct {
	Limit  int
	Offset int
	SortBy *SortBy
}

// Adapter is the storage interface. Implementations must be safe for
// concurrent use.
type Adapter interface {
	// Create inserts data into model and returns the stored record.
	Create(ctx context.Context, model string, data map[string]any) (map[string]any, error)
	// FindOne returns the first record matching where, or ErrNotFound.
	FindOne(ctx context.Context, model string, where []Where) (map[string]any, error)
	// FindMany returns all records matching where.
	FindMany(ctx context.Context, model string, where []Where, opts *FindOptions) ([]map[string]any, error)
	// Update updates the first record matching where and returns it,
	// or ErrNotFound.
	Update(ctx context.Context, model string, where []Where, update map[string]any) (map[string]any, error)
	// UpdateMany updates all records matching where, returning the count.
	UpdateMany(ctx context.Context, model string, where []Where, update map[string]any) (int64, error)
	// Delete removes the first record matching where. Deleting a record
	// that does not exist is not an error.
	Delete(ctx context.Context, model string, where []Where) error
	// DeleteMany removes all records matching where, returning the count.
	DeleteMany(ctx context.Context, model string, where []Where) (int64, error)
	// Count counts records matching where.
	Count(ctx context.Context, model string, where []Where) (int64, error)
}

// Transactor is optionally implemented by adapters that support
// transactions.
type Transactor interface {
	Transaction(ctx context.Context, fn func(tx Adapter) error) error
}

// SchemaAware is optionally implemented by adapters that want the full
// schema (core plus plugin tables). godevauth.New calls SetSchema
// during construction, so adapters can enforce unique constraints,
// apply field defaults and build indexes without the caller wiring it
// up manually.
type SchemaAware interface {
	SetSchema(s *Schema)
}

// ApplyDefaults fills in declared defaults for keys absent from data.
// Adapters call it from Create so that a field's Default is honoured
// even on tables created before the column existed.
func (t *Table) ApplyDefaults(data map[string]any) {
	for i := range t.Fields {
		f := &t.Fields[i]
		if f.Default == nil {
			continue
		}
		if _, ok := data[f.Name]; !ok {
			data[f.Name] = f.Default
		}
	}
}

// UniqueFields returns the names of fields declared unique.
func (t *Table) UniqueFields() []string {
	var out []string
	for i := range t.Fields {
		if t.Fields[i].Unique {
			out = append(out, t.Fields[i].Name)
		}
	}
	return out
}

// UniqueConstraint declares that the combination of Columns must be
// unique across every row of a table. It expresses the multi-column case
// that Field.Unique — which covers a single column — cannot, e.g.
// account (providerId, accountId) or member (organizationId, userId).
//
// Column order is preserved so adapters build a stable index name and a
// deterministic key order. As with a single-column unique, a row whose
// value for any of the columns is NULL does not participate in the
// constraint (NULLs never collide), matching SQL and the sparse Mongo
// index.
type UniqueConstraint struct {
	Columns []string
}

// sameColumns reports whether two column lists are equal in order.
func sameColumns(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FieldType is the type of a schema field.
type FieldType string

const (
	FieldString FieldType = "string"
	FieldBool   FieldType = "boolean"
	FieldInt    FieldType = "number"
	FieldTime   FieldType = "date"
	FieldText   FieldType = "text" // long string
)

// Field describes one column/attribute of a model.
type Field struct {
	Name       string
	Type       FieldType
	Required   bool
	Unique     bool
	Index      bool
	References *Reference
	// Default is applied by adapters when a create omits the field.
	Default any
	// Input marks the field as client-writable: it may be set directly
	// from a sign-up or update-user request body. It is opt-in on
	// purpose. Fields declared by plugins (role, banned,
	// twoFactorEnabled, ...) are never client-writable regardless of
	// this flag, because they carry authorization meaning.
	Input bool
}

// Reference declares a foreign key.
type Reference struct {
	Model    string
	Field    string
	OnDelete string // e.g. "cascade"
}

// Table describes a model.
type Table struct {
	Name   string
	Fields []Field
	// UniqueConstraints holds composite (multi-column) unique
	// constraints. A single-column unique is declared with Field.Unique
	// instead; this is only for the combinations a field flag cannot
	// express.
	UniqueConstraints []UniqueConstraint
}

// Schema is the set of all models the auth instance uses. The core schema
// is extended by plugins.
type Schema struct {
	Tables map[string]*Table
	order  []string
}

// NewSchema returns an empty schema.
func NewSchema() *Schema {
	return &Schema{Tables: map[string]*Table{}}
}

// AddTable registers a table. If it already exists the fields are merged.
func (s *Schema) AddTable(t *Table) {
	if existing, ok := s.Tables[t.Name]; ok {
		for _, f := range t.Fields {
			if existing.FieldByName(f.Name) == nil {
				existing.Fields = append(existing.Fields, f)
			}
		}
		for _, uc := range t.UniqueConstraints {
			existing.AddUniqueConstraint(uc.Columns...)
		}
		return
	}
	s.Tables[t.Name] = t
	s.order = append(s.order, t.Name)
}

// AddFields appends fields to an existing (or new) table.
func (s *Schema) AddFields(model string, fields ...Field) {
	t, ok := s.Tables[model]
	if !ok {
		t = &Table{Name: model}
		s.Tables[model] = t
		s.order = append(s.order, model)
	}
	for _, f := range fields {
		if t.FieldByName(f.Name) == nil {
			t.Fields = append(t.Fields, f)
		}
	}
}

// TableNames returns table names in registration order.
func (s *Schema) TableNames() []string {
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// AddUniqueConstraint declares a composite unique constraint over the
// given columns, unless an identical one is already declared. It is a
// no-op for fewer than two columns: a single-column unique belongs on
// the Field.
func (t *Table) AddUniqueConstraint(columns ...string) {
	if len(columns) < 2 {
		return
	}
	for _, uc := range t.UniqueConstraints {
		if sameColumns(uc.Columns, columns) {
			return
		}
	}
	cols := make([]string, len(columns))
	copy(cols, columns)
	t.UniqueConstraints = append(t.UniqueConstraints, UniqueConstraint{Columns: cols})
}

// FieldByName returns the field with the given name or nil.
func (t *Table) FieldByName(name string) *Field {
	for i := range t.Fields {
		if t.Fields[i].Name == name {
			return &t.Fields[i]
		}
	}
	return nil
}

// CoreSchema returns the schema for the four core models.
func CoreSchema() *Schema {
	s := NewSchema()
	s.AddTable(&Table{Name: ModelUser, Fields: []Field{
		{Name: "id", Type: FieldString, Required: true, Unique: true},
		{Name: "name", Type: FieldString},
		{Name: "email", Type: FieldString, Required: true, Unique: true},
		{Name: "emailVerified", Type: FieldBool, Default: false},
		{Name: "image", Type: FieldText},
		{Name: "createdAt", Type: FieldTime, Required: true},
		{Name: "updatedAt", Type: FieldTime, Required: true},
	}})
	s.AddTable(&Table{Name: ModelSession, Fields: []Field{
		{Name: "id", Type: FieldString, Required: true, Unique: true},
		{Name: "userId", Type: FieldString, Required: true, Index: true,
			References: &Reference{Model: ModelUser, Field: "id", OnDelete: "cascade"}},
		{Name: "token", Type: FieldString, Required: true, Unique: true},
		{Name: "expiresAt", Type: FieldTime, Required: true, Index: true},
		{Name: "ipAddress", Type: FieldString},
		{Name: "userAgent", Type: FieldText},
		{Name: "createdAt", Type: FieldTime, Required: true},
		{Name: "updatedAt", Type: FieldTime, Required: true},
	}})
	s.AddTable(&Table{Name: ModelAccount, Fields: []Field{
		{Name: "id", Type: FieldString, Required: true, Unique: true},
		{Name: "userId", Type: FieldString, Required: true, Index: true,
			References: &Reference{Model: ModelUser, Field: "id", OnDelete: "cascade"}},
		{Name: "accountId", Type: FieldString, Required: true},
		{Name: "providerId", Type: FieldString, Required: true},
		{Name: "accessToken", Type: FieldText},
		{Name: "refreshToken", Type: FieldText},
		{Name: "idToken", Type: FieldText},
		{Name: "accessTokenExpiresAt", Type: FieldTime},
		{Name: "refreshTokenExpiresAt", Type: FieldTime},
		{Name: "scope", Type: FieldText},
		{Name: "password", Type: FieldText},
		{Name: "createdAt", Type: FieldTime, Required: true},
		{Name: "updatedAt", Type: FieldTime, Required: true},
	},
		// One external identity maps to exactly one local user. Without
		// this backstop two concurrent OAuth callbacks for the same
		// (providerId, accountId) create two account rows pointing at two
		// different users, and sign-in resolution becomes row-order
		// dependent.
		UniqueConstraints: []UniqueConstraint{{Columns: []string{"providerId", "accountId"}}},
	})
	s.AddTable(&Table{Name: ModelVerification, Fields: []Field{
		{Name: "id", Type: FieldString, Required: true, Unique: true},
		{Name: "identifier", Type: FieldString, Required: true, Index: true},
		{Name: "value", Type: FieldText, Required: true},
		// indexed so the expiry sweeper can run without a table scan
		{Name: "expiresAt", Type: FieldTime, Required: true, Index: true},
		{Name: "createdAt", Type: FieldTime, Required: true},
		{Name: "updatedAt", Type: FieldTime, Required: true},
	}})
	return s
}

// Matches reports whether record satisfies all the given clauses
// (respecting OR connectors). Adapters may use it to implement filtering.
func Matches(record map[string]any, where []Where) bool {
	if len(where) == 0 {
		return true
	}
	result := true
	first := true
	for _, w := range where {
		ok := matchOne(record, w)
		conn := w.Connector
		if conn == "" {
			conn = ConnectorAnd
		}
		if first {
			result = ok
			first = false
			continue
		}
		if conn == ConnectorOr {
			result = result || ok
		} else {
			result = result && ok
		}
	}
	return result
}

func matchOne(record map[string]any, w Where) bool {
	v := record[w.Field]
	op := w.Operator
	if op == "" {
		op = OpEq
	}
	switch op {
	case OpEq:
		return equal(v, w.Value)
	case OpNe:
		return !equal(v, w.Value)
	case OpIn:
		vals, ok := anySlice(w.Value)
		if !ok {
			return false
		}
		for _, item := range vals {
			if equal(v, item) {
				return true
			}
		}
		return false
	case OpContains:
		return strContains(str(v), str(w.Value))
	case OpStartsWith:
		return strHasPrefix(str(v), str(w.Value))
	case OpEndsWith:
		return strHasSuffix(str(v), str(w.Value))
	case OpGt, OpGte, OpLt, OpLte:
		return compare(v, w.Value, op)
	}
	return false
}
