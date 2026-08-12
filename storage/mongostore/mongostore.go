// Package mongostore implements the go-dev-auth storage adapter on
// top of MongoDB, using the official mongo-go-driver.
//
// It lives in its own Go module so the core library keeps zero
// dependencies:
//
//	go get github.com/go-dev-auth/go-dev-auth/storage/mongostore
//
// Usage:
//
//	client, err := mongo.Connect(options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
//	store := mongostore.New(client.Database("myapp"))
//
//	auth, err := godevauth.New(godevauth.Config{Database: store, ...})
//	// godevauth.New hands the full schema (core + plugins) to the
//	// adapter; create the indexes it implies once at startup:
//	if err := store.EnsureIndexes(ctx); err != nil { ... }
//
// Records are stored with the adapter's "id" field mapped onto Mongo's
// "_id", so identity lookups use the primary index and uniqueness of
// ids is enforced by the server.
package mongostore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-dev-auth/go-dev-auth/storage"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Adapter implements storage.Adapter against a MongoDB database.
type Adapter struct {
	db     *mongo.Database
	schema *storage.Schema
	// prefix is prepended to collection names, letting several apps
	// share one database.
	prefix string
	// session, when set, scopes operations to a transaction.
	sessCtx mongo.SessionContext
}

var (
	_ storage.Adapter     = (*Adapter)(nil)
	_ storage.Transactor  = (*Adapter)(nil)
	_ storage.SchemaAware = (*Adapter)(nil)
)

// Option configures the storage.
type Option func(*Adapter)

// WithCollectionPrefix prefixes every collection name, so multiple
// applications can share a database without colliding.
func WithCollectionPrefix(prefix string) Option {
	return func(a *Adapter) { a.prefix = prefix }
}

// New builds a MongoDB storage. The schema is normally supplied
// automatically by godevauth.New (storage.SchemaAware); it is used to
// validate field names, apply defaults and derive indexes.
func New(db *mongo.Database, opts ...Option) *Adapter {
	a := &Adapter{db: db, schema: storage.CoreSchema()}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// SetSchema implements storage.SchemaAware. Names that would collide
// with MongoDB syntax are rejected loudly: a field literally called
// "_id" would hijack the document key, a name starting with "$" would
// land at the top level of a filter as an operator, and a name
// containing "." addresses a nested path.
func (a *Adapter) SetSchema(s *storage.Schema) {
	if err := validateSchemaNames(s); err != nil {
		panic(err)
	}
	a.schema = s
}

func validateSchemaNames(s *storage.Schema) error {
	for _, name := range s.TableNames() {
		if strings.ContainsAny(name, ".$") {
			return fmt.Errorf("mongostore: model name %q may not contain '.' or '$'", name)
		}
		for _, f := range s.Tables[name].Fields {
			switch {
			case f.Name == "_id":
				return fmt.Errorf("mongostore: model %q declares a field named \"_id\", which collides with the mapping of \"id\"", name)
			case strings.HasPrefix(f.Name, "$"):
				return fmt.Errorf("mongostore: model %q field %q may not start with '$'", name, f.Name)
			case strings.Contains(f.Name, "."):
				return fmt.Errorf("mongostore: model %q field %q may not contain '.'", name, f.Name)
			}
		}
	}
	return nil
}

// Database exposes the underlying handle for application queries.
func (a *Adapter) Database() *mongo.Database { return a.db }

func (a *Adapter) collection(model string) *mongo.Collection {
	return a.db.Collection(a.prefix + model)
}

// ctx returns the session context when inside a transaction, so writes
// join it instead of silently running outside.
func (a *Adapter) ctx(ctx context.Context) context.Context {
	if a.sessCtx != nil {
		return a.sessCtx
	}
	return ctx
}

func (a *Adapter) table(model string) (*storage.Table, error) {
	t, ok := a.schema.Tables[model]
	if !ok {
		return nil, fmt.Errorf("mongostore: unknown model %q", model)
	}
	return t, nil
}

// ---- field mapping ----

// mongoField maps an adapter field name onto its BSON key. "id" becomes
// "_id" so identity lookups hit the primary index.
func mongoField(name string) string {
	if name == "id" {
		return "_id"
	}
	return name
}

// toDocument converts an adapter record into a BSON document,
// validating every field against the schema. Keys the caller supplied
// with a nil or zero-time value are returned separately as "clear":
// on an update they must be removed from the document, not skipped.
// Skipping them would make a field impossible to clear — which is how
// a permanent ban could inherit a stale expiry and lift itself.
func (a *Adapter) toDocument(t *storage.Table, data map[string]any) (doc bson.M, clear []string, err error) {
	doc = bson.M{}
	for _, f := range t.Fields {
		v, ok := data[f.Name]
		if !ok {
			continue
		}
		if v == nil {
			clear = append(clear, mongoField(f.Name))
			continue
		}
		if ts, isTime := v.(time.Time); isTime {
			if ts.IsZero() {
				clear = append(clear, mongoField(f.Name))
				continue
			}
			// BSON datetimes are milliseconds since the epoch; round
			// here so what callers read back matches what they wrote.
			v = primitive.NewDateTimeFromTime(ts.UTC().Truncate(time.Millisecond))
		}
		if err := checkScalar(f.Name, v); err != nil {
			return nil, nil, err
		}
		doc[mongoField(f.Name)] = v
	}
	// A record whose fields are all unknown to the schema is a bug in
	// the caller, not something to silently write.
	for k := range data {
		if t.FieldByName(k) == nil {
			return nil, nil, fmt.Errorf("mongostore: unknown field %q on model %q", k, t.Name)
		}
	}
	return doc, clear, nil
}

// updateDocument builds the update operator document, so that a field
// set to nil is removed rather than left at its previous value.
func updateDocument(set bson.M, clear []string) bson.M {
	update := bson.M{}
	if len(set) > 0 {
		update["$set"] = set
	}
	if len(clear) > 0 {
		unset := bson.M{}
		for _, key := range clear {
			unset[key] = ""
		}
		update["$unset"] = unset
	}
	return update
}

// fromDocument converts a BSON document back into an adapter record,
// restoring Go types.
func (a *Adapter) fromDocument(t *storage.Table, doc bson.M) map[string]any {
	if doc == nil {
		return nil
	}
	out := make(map[string]any, len(doc))
	for _, f := range t.Fields {
		v, ok := doc[mongoField(f.Name)]
		if !ok || v == nil {
			continue // absent stays absent
		}
		out[f.Name] = decodeValue(f, v)
	}
	return out
}

// decodeValue normalizes BSON types onto the Go types the core expects.
func decodeValue(f storage.Field, v any) any {
	switch f.Type {
	case storage.FieldTime:
		switch t := v.(type) {
		case primitive.DateTime:
			return t.Time().UTC()
		case time.Time:
			return t.UTC()
		}
	case storage.FieldInt:
		switch n := v.(type) {
		case int32:
			return int64(n)
		case int64:
			return n
		case float64:
			return int64(n)
		}
	case storage.FieldBool:
		if b, ok := v.(bool); ok {
			return b
		}
	default:
		if s, ok := v.(string); ok {
			return s
		}
	}
	return v
}

// checkScalar rejects composite values in positions where MongoDB would
// interpret them as query or update operators. The core only ever
// stores and matches scalars, so anything else means a caller passed
// through unvalidated input — the classic NoSQL injection shape, where
// a JSON body supplies {"$ne": null} instead of a string.
func checkScalar(field string, v any) error {
	switch v.(type) {
	case string, bool, int, int32, int64, float32, float64,
		time.Time, primitive.DateTime, nil:
		return nil
	}
	return fmt.Errorf("mongostore: field %q: expected a scalar value, got %T "+
		"(composite values are rejected because MongoDB would treat them as operators)", field, v)
}

// ---- filters ----

// buildFilter renders adapter clauses into a MongoDB filter.
//
// Clause lists are folded left to right, matching storage.Matches: each
// clause combines with everything to its left using its own connector,
// so [a, b, OR c] means (a AND b) OR c.
func (a *Adapter) buildFilter(t *storage.Table, where []storage.Where) (bson.M, error) {
	if len(where) == 0 {
		return bson.M{}, nil
	}
	var acc bson.M
	for i, w := range where {
		clause, err := a.buildClause(t, w)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			acc = clause
			continue
		}
		if w.Connector == storage.ConnectorOr {
			acc = bson.M{"$or": []bson.M{acc, clause}}
		} else {
			acc = bson.M{"$and": []bson.M{acc, clause}}
		}
	}
	return acc, nil
}

func (a *Adapter) buildClause(t *storage.Table, w storage.Where) (bson.M, error) {
	f := t.FieldByName(w.Field)
	if f == nil {
		return nil, fmt.Errorf("mongostore: unknown field %q on model %q", w.Field, t.Name)
	}
	key := mongoField(w.Field)
	op := w.Operator
	if op == "" {
		op = storage.OpEq
	}

	encode := func(v any) (any, error) {
		if err := checkScalar(w.Field, v); err != nil {
			return nil, err
		}
		if ts, ok := v.(time.Time); ok {
			return primitive.NewDateTimeFromTime(ts.UTC().Truncate(time.Millisecond)), nil
		}
		return v, nil
	}

	switch op {
	case storage.OpEq:
		v, err := encode(w.Value)
		if err != nil {
			return nil, err
		}
		return bson.M{key: bson.M{"$eq": v}}, nil
	case storage.OpNe:
		v, err := encode(w.Value)
		if err != nil {
			return nil, err
		}
		return bson.M{key: bson.M{"$ne": v}}, nil
	case storage.OpGt, storage.OpGte, storage.OpLt, storage.OpLte:
		v, err := encode(w.Value)
		if err != nil {
			return nil, err
		}
		mongoOp := map[storage.Operator]string{
			storage.OpGt: "$gt", storage.OpGte: "$gte",
			storage.OpLt: "$lt", storage.OpLte: "$lte",
		}[op]
		return bson.M{key: bson.M{mongoOp: v}}, nil
	case storage.OpIn:
		vals, ok := anyList(w.Value)
		if !ok {
			return nil, fmt.Errorf("mongostore: OpIn on %q expects a slice, got %T", w.Field, w.Value)
		}
		encoded := make([]any, 0, len(vals))
		for _, v := range vals {
			ev, err := encode(v)
			if err != nil {
				return nil, err
			}
			encoded = append(encoded, ev)
		}
		return bson.M{key: bson.M{"$in": encoded}}, nil
	case storage.OpContains, storage.OpStartsWith, storage.OpEndsWith:
		s, ok := w.Value.(string)
		if !ok {
			return nil, fmt.Errorf("mongostore: %s on %q expects a string, got %T", op, w.Field, w.Value)
		}
		// QuoteMeta is essential: these values reach the adapter from
		// user input (admin user search), and an unescaped pattern is
		// both a data-disclosure and a CPU-exhaustion vector.
		pattern := regexp.QuoteMeta(s)
		switch op {
		case storage.OpStartsWith:
			pattern = "^" + pattern
		case storage.OpEndsWith:
			pattern = pattern + "$"
		}
		// Options "i": substring matching is case-insensitive on every
		// adapter (see sqlstore.buildWhere).
		return bson.M{key: bson.M{"$regex": primitive.Regex{Pattern: pattern, Options: "i"}}}, nil
	}
	return nil, fmt.Errorf("mongostore: unsupported operator %q", op)
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

// ---- errors ----

// classifyError maps MongoDB's duplicate-key error onto the adapter
// sentinel so callers return a 4xx instead of a 500 when two writers
// race for the same unique value.
func classifyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return storage.ErrNotFound
	}
	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("%w: %s", storage.ErrUniqueViolation, err)
	}
	return err
}

// ---- CRUD ----

// Create implements storage.Adapter.
func (a *Adapter) Create(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	t, err := a.table(model)
	if err != nil {
		return nil, err
	}
	t.ApplyDefaults(data)
	doc, _, err := a.toDocument(t, data)
	if err != nil {
		return nil, err
	}
	if _, err := a.collection(model).InsertOne(a.ctx(ctx), doc); err != nil {
		return nil, classifyError(err)
	}
	return data, nil
}

// FindOne implements storage.Adapter.
func (a *Adapter) FindOne(ctx context.Context, model string, where []storage.Where) (map[string]any, error) {
	t, err := a.table(model)
	if err != nil {
		return nil, err
	}
	filter, err := a.buildFilter(t, where)
	if err != nil {
		return nil, err
	}
	var doc bson.M
	if err := a.collection(model).FindOne(a.ctx(ctx), filter).Decode(&doc); err != nil {
		return nil, classifyError(err)
	}
	return a.fromDocument(t, doc), nil
}

// FindMany implements storage.Adapter.
func (a *Adapter) FindMany(ctx context.Context, model string, where []storage.Where, opts *storage.FindOptions) ([]map[string]any, error) {
	t, err := a.table(model)
	if err != nil {
		return nil, err
	}
	filter, err := a.buildFilter(t, where)
	if err != nil {
		return nil, err
	}
	findOpts := options.Find()
	if opts != nil {
		if opts.SortBy != nil && t.FieldByName(opts.SortBy.Field) != nil {
			dir := 1
			if opts.SortBy.Direction == "desc" {
				dir = -1
			}
			findOpts.SetSort(bson.D{{Key: mongoField(opts.SortBy.Field), Value: dir}})
		}
		if opts.Limit > 0 {
			findOpts.SetLimit(int64(opts.Limit))
		}
		if opts.Offset > 0 {
			findOpts.SetSkip(int64(opts.Offset))
		}
	}
	cursor, err := a.collection(model).Find(a.ctx(ctx), filter, findOpts)
	if err != nil {
		return nil, classifyError(err)
	}
	defer cursor.Close(a.ctx(ctx))

	var out []map[string]any
	for cursor.Next(a.ctx(ctx)) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			return nil, err
		}
		out = append(out, a.fromDocument(t, doc))
	}
	return out, cursor.Err()
}

// Update implements storage.Adapter. It updates a single record
// atomically and returns the updated document.
func (a *Adapter) Update(ctx context.Context, model string, where []storage.Where, update map[string]any) (map[string]any, error) {
	t, err := a.table(model)
	if err != nil {
		return nil, err
	}
	filter, err := a.buildFilter(t, where)
	if err != nil {
		return nil, err
	}
	set, clear, err := a.toDocument(t, update)
	if err != nil {
		return nil, err
	}
	if len(update) > 0 && len(set) == 0 && len(clear) == 0 {
		return nil, fmt.Errorf("mongostore: update on %q produced no writable fields", model)
	}
	if len(set) == 0 && len(clear) == 0 {
		return a.FindOne(ctx, model, where)
	}
	// FindOneAndUpdate is a single round trip and returns the record as
	// it exists after the write, with no read-after-write race.
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var doc bson.M
	err = a.collection(model).FindOneAndUpdate(a.ctx(ctx), filter, updateDocument(set, clear), opts).Decode(&doc)
	if err != nil {
		return nil, classifyError(err)
	}
	return a.fromDocument(t, doc), nil
}

// UpdateMany implements storage.Adapter, returning the number of
// records the filter matched. Callers rely on that count for
// compare-and-set (API key quotas, two-factor backup codes).
func (a *Adapter) UpdateMany(ctx context.Context, model string, where []storage.Where, update map[string]any) (int64, error) {
	t, err := a.table(model)
	if err != nil {
		return 0, err
	}
	filter, err := a.buildFilter(t, where)
	if err != nil {
		return 0, err
	}
	set, clear, err := a.toDocument(t, update)
	if err != nil {
		return 0, err
	}
	if len(update) == 0 {
		return 0, nil // an update with nothing to set is a no-op
	}
	if len(set) == 0 && len(clear) == 0 {
		return 0, fmt.Errorf("mongostore: update on %q produced no writable fields", model)
	}
	res, err := a.collection(model).UpdateMany(a.ctx(ctx), filter, updateDocument(set, clear))
	if err != nil {
		return 0, classifyError(err)
	}
	return res.MatchedCount, nil
}

// Delete implements storage.Adapter.
func (a *Adapter) Delete(ctx context.Context, model string, where []storage.Where) error {
	t, err := a.table(model)
	if err != nil {
		return err
	}
	filter, err := a.buildFilter(t, where)
	if err != nil {
		return err
	}
	if _, err := a.collection(model).DeleteOne(a.ctx(ctx), filter); err != nil {
		return classifyError(err)
	}
	return nil
}

// DeleteMany implements storage.Adapter.
func (a *Adapter) DeleteMany(ctx context.Context, model string, where []storage.Where) (int64, error) {
	t, err := a.table(model)
	if err != nil {
		return 0, err
	}
	filter, err := a.buildFilter(t, where)
	if err != nil {
		return 0, err
	}
	res, err := a.collection(model).DeleteMany(a.ctx(ctx), filter)
	if err != nil {
		return 0, classifyError(err)
	}
	return res.DeletedCount, nil
}

// Count implements storage.Adapter.
func (a *Adapter) Count(ctx context.Context, model string, where []storage.Where) (int64, error) {
	t, err := a.table(model)
	if err != nil {
		return 0, err
	}
	filter, err := a.buildFilter(t, where)
	if err != nil {
		return 0, err
	}
	n, err := a.collection(model).CountDocuments(a.ctx(ctx), filter)
	if err != nil {
		return 0, classifyError(err)
	}
	return n, nil
}

// Transaction implements storage.Transactor.
//
// MongoDB transactions require a replica set or sharded cluster; on a
// standalone server the driver returns an error, which is surfaced
// rather than silently degrading to non-atomic writes.
func (a *Adapter) Transaction(ctx context.Context, fn func(tx storage.Adapter) error) error {
	if a.sessCtx != nil {
		return errors.New("mongostore: nested transactions are not supported")
	}
	session, err := a.db.Client().StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)

	_, err = session.WithTransaction(ctx, func(sessCtx mongo.SessionContext) (any, error) {
		txAdapter := &Adapter{db: a.db, schema: a.schema, prefix: a.prefix, sessCtx: sessCtx}
		return nil, fn(txAdapter)
	})
	return err
}

// ---- indexes ----

// EnsureIndexes creates the unique constraints and secondary indexes
// the schema declares. Call it once at startup, after godevauth.New has
// supplied the full schema (core plus plugins).
//
// Unique indexes are not optional: without them, two concurrent
// sign-ups for the same address both succeed and the account is
// duplicated. Uniqueness of "id" is provided by Mongo's own _id index.
func (a *Adapter) EnsureIndexes(ctx context.Context) error {
	for _, name := range a.schema.TableNames() {
		t := a.schema.Tables[name]
		var models []mongo.IndexModel
		for _, f := range t.Fields {
			if f.Name == "id" {
				continue // _id is indexed and unique by definition
			}
			switch {
			case f.Unique:
				models = append(models, mongo.IndexModel{
					Keys: bson.D{{Key: mongoField(f.Name), Value: 1}},
					Options: options.Index().
						SetUnique(true).
						SetName("uniq_" + f.Name).
						// A record that never set the field must not
						// collide with every other record that also
						// never set it.
						SetSparse(true),
				})
			case f.Index:
				models = append(models, mongo.IndexModel{
					Keys:    bson.D{{Key: mongoField(f.Name), Value: 1}},
					Options: options.Index().SetName("idx_" + f.Name),
				})
			}
		}
		// Composite unique constraints: a single compound unique index per
		// declared constraint mirrors how single-field uniques are built
		// above. Sparse so a document missing the fields does not collide
		// with every other document that also omits them.
		for _, uc := range t.UniqueConstraints {
			keys := make(bson.D, 0, len(uc.Columns))
			for _, col := range uc.Columns {
				keys = append(keys, bson.E{Key: mongoField(col), Value: 1})
			}
			models = append(models, mongo.IndexModel{
				Keys: keys,
				Options: options.Index().
					SetUnique(true).
					SetName("uniq_" + strings.Join(uc.Columns, "_")).
					SetSparse(true),
			})
		}
		if len(models) == 0 {
			continue
		}
		if _, err := a.collection(name).Indexes().CreateMany(ctx, models); err != nil {
			return fmt.Errorf("mongostore: creating indexes on %s: %w", name, err)
		}
	}
	return nil
}

// Migrate is an alias for EnsureIndexes, so the adapter can be swapped
// with sqlstore without changing setup code. MongoDB creates
// collections lazily, so there is nothing else to do.
func (a *Adapter) Migrate(ctx context.Context) error { return a.EnsureIndexes(ctx) }
