// Package memory provides an in-memory storage. It enforces the unique
// constraints and field defaults declared in the schema and indexes
// unique fields, so it behaves like a real database for tests, examples
// and small single-process deployments. Data is lost when the process
// exits.
package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Adapter is an in-memory implementation of storage.Adapter.
type Adapter struct {
	mu     sync.RWMutex
	tables map[string][]map[string]any
	// index maps model -> unique field -> value -> record, so lookups
	// by id/token/email are O(1) instead of a table scan.
	index  map[string]map[string]map[any]map[string]any
	schema *storage.Schema
	// unique caches the unique field names per model. It used to be
	// recomputed (and reallocated) on every index touch, which put a
	// slice allocation on the hot path of every read and write.
	unique map[string][]string
}

// New returns an empty in-memory storage.
func New() *Adapter {
	return &Adapter{
		tables: map[string][]map[string]any{},
		index:  map[string]map[string]map[any]map[string]any{},
	}
}

var _ storage.Adapter = (*Adapter)(nil)
var _ storage.Transactor = (*Adapter)(nil)
var _ storage.SchemaAware = (*Adapter)(nil)

// SetSchema implements storage.SchemaAware. godevauth.New calls it with
// the complete schema, enabling unique-constraint enforcement, field
// defaults and indexing.
func (a *Adapter) SetSchema(s *storage.Schema) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.schema = s
	a.unique = make(map[string][]string, len(s.Tables))
	for name, t := range s.Tables {
		a.unique[name] = t.UniqueFields()
	}
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// table returns the schema table for model, or nil when no schema was
// provided.
func (a *Adapter) table(model string) *storage.Table {
	if a.schema == nil {
		return nil
	}
	return a.schema.Tables[model]
}

// uniqueFields returns the indexed (unique) field names for model.
// "id" is always treated as unique even without a schema.
// defaultUniqueFields is used when no schema was supplied; "id" is
// always treated as unique.
var defaultUniqueFields = []string{"id"}

func (a *Adapter) uniqueFields(model string) []string {
	if fields, ok := a.unique[model]; ok {
		return fields
	}
	return defaultUniqueFields
}

func (a *Adapter) indexFor(model, field string) map[any]map[string]any {
	byField, ok := a.index[model]
	if !ok {
		byField = map[string]map[any]map[string]any{}
		a.index[model] = byField
	}
	idx, ok := byField[field]
	if !ok {
		idx = map[any]map[string]any{}
		byField[field] = idx
	}
	return idx
}

// indexable reports whether v can be used as a map key.
func indexable(v any) bool {
	switch v.(type) {
	case string, bool, int, int32, int64, float32, float64:
		return true
	}
	return false
}

func (a *Adapter) addToIndex(model string, rec map[string]any) {
	for _, field := range a.uniqueFields(model) {
		v, ok := rec[field]
		if !ok || !indexable(v) {
			continue
		}
		a.indexFor(model, field)[v] = rec
	}
}

func (a *Adapter) removeFromIndex(model string, rec map[string]any) {
	for _, field := range a.uniqueFields(model) {
		v, ok := rec[field]
		if !ok || !indexable(v) {
			continue
		}
		idx := a.indexFor(model, field)
		if idx[v] != nil && sameRecord(idx[v], rec) {
			delete(idx, v)
		}
	}
}

func sameRecord(a, b map[string]any) bool {
	ida, oka := a["id"]
	idb, okb := b["id"]
	if oka && okb {
		return ida == idb
	}
	return false
}

// lookupUnique returns the record matching a single equality clause on
// a unique field, or nil when the clause is not an indexed lookup.
func (a *Adapter) lookupUnique(model string, where []storage.Where) (map[string]any, bool) {
	if len(where) != 1 {
		return nil, false
	}
	w := where[0]
	if w.Operator != "" && w.Operator != storage.OpEq {
		return nil, false
	}
	if !indexable(w.Value) {
		return nil, false
	}
	for _, field := range a.uniqueFields(model) {
		if field != w.Field {
			continue
		}
		byField, ok := a.index[model]
		if !ok {
			return nil, true
		}
		idx, ok := byField[field]
		if !ok {
			return nil, true
		}
		rec, ok := idx[w.Value]
		if !ok {
			return nil, true
		}
		return rec, true
	}
	return nil, false
}

// violatesUnique reports whether inserting rec would duplicate a unique
// value. skip, when non-nil, is the record being updated.
func (a *Adapter) violatesUnique(model string, rec, skip map[string]any) bool {
	for _, field := range a.uniqueFields(model) {
		v, ok := rec[field]
		if !ok || !indexable(v) {
			continue
		}
		existing, ok := a.indexFor(model, field)[v]
		if ok && (skip == nil || !sameRecord(existing, skip)) {
			return true
		}
	}
	return a.violatesCompositeUnique(model, rec, skip)
}

// violatesCompositeUnique reports whether inserting rec would duplicate a
// declared composite unique constraint. Composite constraints are not
// indexed (they are rare), so this is a table scan — fine for the
// in-memory adapter's scale. A constraint is not evaluated when any of
// its columns is absent or nil in rec: NULLs never collide, matching SQL
// and the sparse Mongo index. skip, when non-nil, is the record being
// updated and is exempt from the comparison.
func (a *Adapter) violatesCompositeUnique(model string, rec, skip map[string]any) bool {
	t := a.table(model)
	if t == nil {
		return false
	}
	for _, uc := range t.UniqueConstraints {
		vals := make([]any, len(uc.Columns))
		complete := true
		for i, col := range uc.Columns {
			v, ok := rec[col]
			if !ok || v == nil {
				complete = false
				break
			}
			vals[i] = v
		}
		if !complete {
			continue
		}
		for _, existing := range a.tables[model] {
			if skip != nil && sameRecord(existing, skip) {
				continue
			}
			match := true
			for i, col := range uc.Columns {
				if existing[col] != vals[i] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// checkWritableFields rejects keys the schema does not declare, so a
// write is as loud as a read about a field nobody knows. The SQL and
// Mongo adapters do the same; the conformance suite pins it.
//
// It is a no-op when the adapter has no schema for the model, which is
// the standalone case (memory.New() without SetSchema): there is nothing
// to validate against, and rejecting everything would make the
// schema-less adapter useless. godevauth.New always calls SetSchema.
//
// Callers must hold a.mu.
func (a *Adapter) checkWritableFields(model string, data map[string]any) error {
	t := a.table(model)
	if t == nil {
		return nil
	}
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
	return fmt.Errorf("memory: unknown field(s) %s on %q",
		strings.Join(quoted, ", "), model)
}

// checkWhereFields rejects filters naming a field the schema does not
// declare. The SQL and Mongo adapters both refuse such a query; memory
// used to answer it, and the answer was worse than wrong.
//
// storage.Matches reads an undeclared key as a missing value, so the
// clause silently becomes a statement about nil: OpEq matches nothing
// (which merely looks like "no rows"), but OpNe matches *every* row. An
// exclusion filter — "everything except the banned ones", written
// against a column the schema does not have — therefore selects the
// whole table, and DeleteMany empties it. Failing the query is the only
// safe reading of a predicate nobody can evaluate.
//
// Like checkWritableFields it is a no-op without a schema for the model,
// which keeps the standalone memory.New() usable in tests and examples.
//
// Callers must hold a.mu.
func (a *Adapter) checkWhereFields(model string, where []storage.Where) error {
	t := a.table(model)
	if t == nil || len(where) == 0 {
		return nil
	}
	var unknown []string
	seen := map[string]bool{}
	for _, w := range where {
		if seen[w.Field] || t.FieldByName(w.Field) != nil {
			continue
		}
		seen[w.Field] = true
		unknown = append(unknown, w.Field)
	}
	if len(unknown) == 0 {
		return nil
	}
	// Clause order is caller-controlled but the message should not
	// depend on it.
	sort.Strings(unknown)
	quoted := make([]string, len(unknown))
	for i, k := range unknown {
		quoted[i] = fmt.Sprintf("%q", k)
	}
	return fmt.Errorf("memory: unknown field(s) %s in filter on %q",
		strings.Join(quoted, ", "), model)
}

// Create implements storage.Adapter.
func (a *Adapter) Create(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkWritableFields(model, data); err != nil {
		return nil, err
	}
	rec := clone(data)
	if t := a.table(model); t != nil {
		t.ApplyDefaults(rec)
	}
	if a.violatesUnique(model, rec, nil) {
		return nil, storage.ErrUniqueViolation
	}
	a.tables[model] = append(a.tables[model], rec)
	a.addToIndex(model, rec)
	return clone(rec), nil
}

// FindOne implements storage.Adapter.
func (a *Adapter) FindOne(ctx context.Context, model string, where []storage.Where) (map[string]any, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if err := a.checkWhereFields(model, where); err != nil {
		return nil, err
	}
	if rec, indexed := a.lookupUnique(model, where); indexed {
		if rec == nil {
			return nil, storage.ErrNotFound
		}
		return clone(rec), nil
	}
	for _, rec := range a.tables[model] {
		if storage.Matches(rec, where) {
			return clone(rec), nil
		}
	}
	return nil, storage.ErrNotFound
}

// FindMany implements storage.Adapter.
func (a *Adapter) FindMany(ctx context.Context, model string, where []storage.Where, opts *storage.FindOptions) ([]map[string]any, error) {
	a.mu.RLock()
	if err := a.checkWhereFields(model, where); err != nil {
		a.mu.RUnlock()
		return nil, err
	}
	var out []map[string]any
	for _, rec := range a.tables[model] {
		if storage.Matches(rec, where) {
			out = append(out, clone(rec))
		}
	}
	a.mu.RUnlock()
	if opts != nil && opts.SortBy != nil {
		field := opts.SortBy.Field
		desc := opts.SortBy.Direction == "desc"
		sort.SliceStable(out, func(i, j int) bool {
			if desc {
				return lessValue(out[j][field], out[i][field])
			}
			return lessValue(out[i][field], out[j][field])
		})
	}
	if opts != nil && opts.Offset > 0 {
		if opts.Offset >= len(out) {
			out = nil
		} else {
			out = out[opts.Offset:]
		}
	}
	if opts != nil && opts.Limit > 0 && opts.Limit < len(out) {
		out = out[:opts.Limit]
	}
	return out, nil
}

// Update implements storage.Adapter.
func (a *Adapter) Update(ctx context.Context, model string, where []storage.Where, update map[string]any) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkWhereFields(model, where); err != nil {
		return nil, err
	}
	if err := a.checkWritableFields(model, update); err != nil {
		return nil, err
	}
	for _, rec := range a.tables[model] {
		if !storage.Matches(rec, where) {
			continue
		}
		merged := clone(rec)
		for k, v := range update {
			merged[k] = v
		}
		if a.violatesUnique(model, merged, rec) {
			return nil, storage.ErrUniqueViolation
		}
		a.removeFromIndex(model, rec)
		for k, v := range update {
			rec[k] = v
		}
		a.addToIndex(model, rec)
		return clone(rec), nil
	}
	return nil, storage.ErrNotFound
}

// UpdateMany implements storage.Adapter.
func (a *Adapter) UpdateMany(ctx context.Context, model string, where []storage.Where, update map[string]any) (int64, error) {
	if len(update) == 0 {
		// An update with nothing to set changes nothing and reports no
		// rows, so a caller cannot read the match count as "the write
		// happened". The SQL and Mongo adapters agree.
		return 0, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkWhereFields(model, where); err != nil {
		return 0, err
	}
	if err := a.checkWritableFields(model, update); err != nil {
		return 0, err
	}
	var n int64
	for _, rec := range a.tables[model] {
		if !storage.Matches(rec, where) {
			continue
		}
		a.removeFromIndex(model, rec)
		for k, v := range update {
			rec[k] = v
		}
		a.addToIndex(model, rec)
		n++
	}
	return n, nil
}

// Delete implements storage.Adapter.
func (a *Adapter) Delete(ctx context.Context, model string, where []storage.Where) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkWhereFields(model, where); err != nil {
		return err
	}
	rows := a.tables[model]
	for i, rec := range rows {
		if storage.Matches(rec, where) {
			a.removeFromIndex(model, rec)
			a.tables[model] = append(rows[:i:i], rows[i+1:]...)
			return nil
		}
	}
	return nil
}

// DeleteMany implements storage.Adapter.
func (a *Adapter) DeleteMany(ctx context.Context, model string, where []storage.Where) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkWhereFields(model, where); err != nil {
		return 0, err
	}
	rows := a.tables[model]
	kept := rows[:0:0]
	var n int64
	for _, rec := range rows {
		if storage.Matches(rec, where) {
			a.removeFromIndex(model, rec)
			n++
			continue
		}
		kept = append(kept, rec)
	}
	a.tables[model] = kept
	return n, nil
}

// Count implements storage.Adapter.
func (a *Adapter) Count(ctx context.Context, model string, where []storage.Where) (int64, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if err := a.checkWhereFields(model, where); err != nil {
		return 0, err
	}
	var n int64
	for _, rec := range a.tables[model] {
		if storage.Matches(rec, where) {
			n++
		}
	}
	return n, nil
}

// Transaction implements storage.Transactor. The whole store is locked
// for the duration and restored if fn returns an error, giving
// all-or-nothing semantics for a single process.
func (a *Adapter) Transaction(ctx context.Context, fn func(tx storage.Adapter) error) error {
	a.mu.Lock()
	snapshot := make(map[string][]map[string]any, len(a.tables))
	for model, rows := range a.tables {
		cp := make([]map[string]any, 0, len(rows))
		for _, rec := range rows {
			cp = append(cp, clone(rec))
		}
		snapshot[model] = cp
	}
	a.mu.Unlock()

	if err := fn(a); err != nil {
		a.mu.Lock()
		a.tables = snapshot
		a.index = map[string]map[string]map[any]map[string]any{}
		for model, rows := range a.tables {
			for _, rec := range rows {
				a.addToIndex(model, rec)
			}
		}
		a.mu.Unlock()
		return err
	}
	return nil
}
