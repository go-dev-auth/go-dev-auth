// Package storagetest provides a conformance suite that every
// storage.Adapter implementation must pass.
//
// The auth core relies on precise semantics from the storage layer:
// which errors mean "already exists", whether NULL and zero are
// distinguishable, whether sorting is chronological, whether a
// conditional update reports how many rows it touched. When those
// differ between backends, bugs appear on one database and not another
// — exactly the class of defect that made the API-key plugin work on
// the in-memory adapter and fail on every SQL one.
//
// Usage from an adapter's own test package:
//
//	func TestConformance(t *testing.T) {
//		storagetest.Run(t, func(t *testing.T) (storage.Adapter, func()) {
//			store := memory.New()
//			store.SetSchema(storagetest.Schema())
//			return store, func() {}
//		})
//	}
package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Model names used by the suite.
const (
	ModelThing = "conformanceThing"
	// ModelLink exercises composite (multi-column) unique constraints,
	// the shape of account (providerId, accountId) and member
	// (organizationId, userId).
	ModelLink = "conformanceLink"
)

// Schema returns the schema the suite exercises. Adapters that need a
// schema (for unique constraints, column types or index creation) must
// be constructed with it.
func Schema() *storage.Schema {
	s := storage.CoreSchema()
	s.AddTable(&storage.Table{Name: ModelThing, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "name", Type: storage.FieldString, Index: true},
		{Name: "email", Type: storage.FieldString, Unique: true},
		{Name: "count", Type: storage.FieldInt},
		{Name: "active", Type: storage.FieldBool, Default: true},
		{Name: "note", Type: storage.FieldText},
		{Name: "createdAt", Type: storage.FieldTime},
	}})
	s.AddTable(&storage.Table{Name: ModelLink, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		// Deliberately not Required, so the NULL-does-not-collide part of
		// the composite-unique contract can be exercised.
		{Name: "providerId", Type: storage.FieldString},
		{Name: "accountId", Type: storage.FieldString},
		{Name: "userId", Type: storage.FieldString},
	},
		UniqueConstraints: []storage.UniqueConstraint{{Columns: []string{"providerId", "accountId"}}},
	})
	return s
}

// Factory builds an adapter for one test, plus a cleanup function.
type Factory func(t *testing.T) (storage.Adapter, func())

// Run executes the full conformance suite.
func Run(t *testing.T, newAdapter Factory) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(*testing.T, storage.Adapter)
	}{
		{"CreateAndFindOne", testCreateAndFindOne},
		{"NotFound", testNotFound},
		{"UniqueViolation", testUniqueViolation},
		{"CompositeUniqueViolation", testCompositeUniqueViolation},
		{"ConcurrentCompositeUniqueInsert", testConcurrentCompositeUniqueInsert},
		{"FieldDefaults", testFieldDefaults},
		{"NullIsNotZero", testNullIsNotZero},
		{"TypeRoundTrip", testTypeRoundTrip},
		{"TimeOrdering", testTimeOrdering},
		{"Operators", testOperators},
		{"OrConnector", testOrConnector},
		{"ClauseFoldingPrecedence", testClauseFoldingPrecedence},
		{"SubstringMatchingIsLiteralAndCaseInsensitive", testSubstringMatching},
		{"EmptyUpdateIsNoOp", testEmptyUpdateIsNoOp},
		{"UndeclaredFieldIsRejected", testUndeclaredFieldIsRejected},
		{"Pagination", testPagination},
		{"UpdateReturnsRecord", testUpdateReturnsRecord},
		{"UpdateTouchesOnlyTheFirstMatch", testUpdateTouchesOnlyTheFirstMatch},
		{"ConditionalUpdateCount", testConditionalUpdateCount},
		{"UpdateMany", testUpdateMany},
		{"DeleteAndDeleteMany", testDeleteAndDeleteMany},
		{"Count", testCount},
		{"ExpirySweep", testExpirySweep},
		{"ConcurrentUniqueInsert", testConcurrentUniqueInsert},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, cleanup := newAdapter(t)
			defer cleanup()
			tc.fn(t, store)
		})
	}
}

func ctx() context.Context { return context.Background() }

func thing(id string, extra map[string]any) map[string]any {
	rec := map[string]any{"id": id, "name": "thing-" + id, "email": id + "@example.com"}
	for k, v := range extra {
		rec[k] = v
	}
	return rec
}

func mustCreate(t *testing.T, s storage.Adapter, rec map[string]any) {
	t.Helper()
	if _, err := s.Create(ctx(), ModelThing, rec); err != nil {
		t.Fatalf("Create(%v): %v", rec["id"], err)
	}
}

func testCreateAndFindOne(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, thing("a", map[string]any{"count": int64(3)}))
	got, err := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "a")})
	if err != nil {
		t.Fatal(err)
	}
	if got["id"] != "a" {
		t.Fatalf("id = %v", got["id"])
	}
	if got["name"] != "thing-a" {
		t.Fatalf("name = %v", got["name"])
	}
	// lookups by a non-id unique field must work too (session tokens,
	// user emails)
	got, err = s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("email", "a@example.com")})
	if err != nil || got["id"] != "a" {
		t.Fatalf("lookup by unique field: %v %v", got, err)
	}
}

func testNotFound(t *testing.T, s storage.Adapter) {
	_, err := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "missing")})
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	// Update of a missing record must also report not found, not
	// silently succeed.
	if _, err := s.Update(ctx(), ModelThing,
		[]storage.Where{storage.W("id", "missing")}, map[string]any{"name": "x"}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Update missing: expected ErrNotFound, got %v", err)
	}
	// Deleting a missing record is not an error.
	if err := s.Delete(ctx(), ModelThing, []storage.Where{storage.W("id", "missing")}); err != nil {
		t.Fatalf("Delete missing: %v", err)
	}
}

func testUniqueViolation(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, thing("u1", nil))
	// same id
	_, err := s.Create(ctx(), ModelThing, thing("u1", nil))
	if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("duplicate id: expected ErrUniqueViolation, got %v", err)
	}
	// same unique non-id field
	dup := thing("u2", nil)
	dup["email"] = "u1@example.com"
	_, err = s.Create(ctx(), ModelThing, dup)
	if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("duplicate email: expected ErrUniqueViolation, got %v", err)
	}
	// updating into a taken value must also conflict
	mustCreate(t, s, thing("u3", nil))
	_, err = s.Update(ctx(), ModelThing, []storage.Where{storage.W("id", "u3")},
		map[string]any{"email": "u1@example.com"})
	if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("update into duplicate email: expected ErrUniqueViolation, got %v", err)
	}
}

// testCompositeUniqueViolation pins the composite (multi-column) unique
// contract that backstops account linking: the combination of the
// columns must be unique, one column matching is not a conflict, and a
// row whose columns are NULL does not collide with another such row.
func testCompositeUniqueViolation(t *testing.T, s storage.Adapter) {
	link := func(id, provider, account, user string) map[string]any {
		return map[string]any{"id": id, "providerId": provider, "accountId": account, "userId": user}
	}
	mk := func(rec map[string]any) {
		t.Helper()
		if _, err := s.Create(ctx(), ModelLink, rec); err != nil {
			t.Fatalf("Create(%v): %v", rec["id"], err)
		}
	}

	mk(link("l1", "google", "acc-1", "user-A"))

	// Same (providerId, accountId) as l1 but a different row id and user:
	// this is exactly the concurrent-callback shape, and it must be
	// rejected by the database, not accepted as a second row.
	_, err := s.Create(ctx(), ModelLink, link("l2", "google", "acc-1", "user-B"))
	if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("duplicate (providerId, accountId): expected ErrUniqueViolation, got %v", err)
	}

	// Only one column matching is not a conflict.
	mk(link("l3", "google", "acc-2", "user-C")) // same provider, different account
	mk(link("l4", "github", "acc-1", "user-D")) // same account, different provider

	// Updating a row into a taken combination must also conflict.
	_, err = s.Update(ctx(), ModelLink, []storage.Where{storage.W("id", "l3")},
		map[string]any{"accountId": "acc-1"}) // would become (google, acc-1), which l1 holds
	if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("update into a taken (providerId, accountId): expected ErrUniqueViolation, got %v", err)
	}

	// NULLs never collide: two rows that both leave the columns unset are
	// both allowed, the same as a single-column unique.
	mk(map[string]any{"id": "n1", "userId": "user-E"})
	if _, err := s.Create(ctx(), ModelLink, map[string]any{"id": "n2", "userId": "user-F"}); err != nil {
		t.Fatalf("two rows with NULL composite columns must both be allowed, got %v", err)
	}

	// Exactly the rows we expect are present.
	n, err := s.Count(ctx(), ModelLink, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 { // l1, l3, l4, n1, n2
		t.Fatalf("stored %d link rows, want 5", n)
	}
}

// testConcurrentCompositeUniqueInsert asserts the composite constraint
// holds under concurrency: many callers racing to insert the same
// (providerId, accountId) must resolve to exactly one winner, which is
// the property that makes create-then-handle-conflict safe.
func testConcurrentCompositeUniqueInsert(t *testing.T, s storage.Adapter) {
	const n = 8
	results := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			<-start
			_, err := s.Create(ctx(), ModelLink, map[string]any{
				"id":         "race-" + string(rune('a'+i)),
				"providerId": "google",
				"accountId":  "shared-account",
				"userId":     "user-" + string(rune('a'+i)),
			})
			results <- err
		}(i)
	}
	close(start)
	success := 0
	for i := 0; i < n; i++ {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, storage.ErrUniqueViolation):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("%d concurrent inserts of the same (providerId, accountId) succeeded, want 1", success)
	}
	count, _ := s.Count(ctx(), ModelLink, []storage.Where{
		storage.W("providerId", "google"), storage.W("accountId", "shared-account"),
	})
	if count != 1 {
		t.Fatalf("%d rows stored for the shared identity, want 1", count)
	}
}

func testFieldDefaults(t *testing.T, s storage.Adapter) {
	// "active" defaults to true and must be applied when omitted
	mustCreate(t, s, map[string]any{"id": "d1", "email": "d1@example.com"})
	got, err := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "d1")})
	if err != nil {
		t.Fatal(err)
	}
	if active, ok := got["active"].(bool); !ok || !active {
		t.Fatalf("default not applied: active = %#v", got["active"])
	}
	// an explicit false must survive
	mustCreate(t, s, map[string]any{"id": "d2", "email": "d2@example.com", "active": false})
	got, _ = s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "d2")})
	if active, ok := got["active"].(bool); !ok || active {
		t.Fatalf("explicit false overwritten: active = %#v", got["active"])
	}
}

// testNullIsNotZero pins the semantics that broke the API-key plugin:
// a field that was never set must not read back as a zero value, since
// callers use "unset" to mean unlimited.
func testNullIsNotZero(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, map[string]any{"id": "n1", "email": "n1@example.com"})
	got, err := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "n1")})
	if err != nil {
		t.Fatal(err)
	}
	if v, present := got["count"]; present && v != nil {
		t.Fatalf("unset int field must read back as nil or be absent, got %#v", v)
	}
	if _, ok := got["count"].(int64); ok {
		t.Fatal("unset int field must not type-assert to int64")
	}
	// and an explicit zero must be distinguishable from unset
	mustCreate(t, s, map[string]any{"id": "n2", "email": "n2@example.com", "count": int64(0)})
	got, _ = s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "n2")})
	v, ok := got["count"].(int64)
	if !ok || v != 0 {
		t.Fatalf("explicit zero not preserved: %#v", got["count"])
	}
}

func testTypeRoundTrip(t *testing.T, s storage.Adapter) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	rec := map[string]any{
		"id": "t1", "email": "t1@example.com", "name": "Ünïcode ✓ 'quoted' \"double\"",
		"count": int64(-42), "active": false, "note": "line1\nline2\ttab",
		"createdAt": now,
	}
	mustCreate(t, s, rec)
	got, err := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "t1")})
	if err != nil {
		t.Fatal(err)
	}
	if got["name"] != rec["name"] {
		t.Errorf("string round trip: %q != %q", got["name"], rec["name"])
	}
	if got["note"] != rec["note"] {
		t.Errorf("text round trip: %q != %q", got["note"], rec["note"])
	}
	if n, ok := got["count"].(int64); !ok || n != -42 {
		t.Errorf("int round trip: %#v", got["count"])
	}
	if b, ok := got["active"].(bool); !ok || b {
		t.Errorf("bool round trip: %#v", got["active"])
	}
	ts, ok := got["createdAt"].(time.Time)
	if !ok {
		t.Fatalf("time round trip: %#v", got["createdAt"])
	}
	if diff := ts.Sub(now); diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("time round trip drifted by %v", diff)
	}
}

// testTimeOrdering catches storage that sorts timestamps lexically in a
// way that disagrees with chronological order.
func testTimeOrdering(t *testing.T, s storage.Adapter) {
	base := time.Date(2026, 1, 1, 12, 0, 5, 0, time.UTC)
	times := []time.Time{
		base,                             // .000000000
		base.Add(500 * time.Millisecond), // .500000000
		base.Add(time.Second),
		base.Add(time.Second + 250*time.Millisecond),
	}
	for i, ts := range times {
		mustCreate(t, s, map[string]any{
			"id": string(rune('a' + i)), "email": string(rune('a'+i)) + "@example.com",
			"createdAt": ts,
		})
	}
	recs, err := s.FindMany(ctx(), ModelThing, nil,
		&storage.FindOptions{SortBy: &storage.SortBy{Field: "createdAt", Direction: "asc"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != len(times) {
		t.Fatalf("got %d records", len(recs))
	}
	var prev time.Time
	for i, rec := range recs {
		ts, ok := rec["createdAt"].(time.Time)
		if !ok {
			t.Fatalf("record %d has no time", i)
		}
		if i > 0 && ts.Before(prev) {
			t.Fatalf("ascending sort out of order at %d: %v before %v", i, ts, prev)
		}
		prev = ts
	}
	// descending must be the exact reverse
	recs, err = s.FindMany(ctx(), ModelThing, nil,
		&storage.FindOptions{SortBy: &storage.SortBy{Field: "createdAt", Direction: "desc"}})
	if err != nil {
		t.Fatal(err)
	}
	prev = time.Time{}
	for i, rec := range recs {
		ts := rec["createdAt"].(time.Time)
		if i > 0 && ts.After(prev) {
			t.Fatalf("descending sort out of order at %d", i)
		}
		prev = ts
	}
}

func testOperators(t *testing.T, s storage.Adapter) {
	for i := 1; i <= 5; i++ {
		mustCreate(t, s, map[string]any{
			"id":    string(rune('0' + i)),
			"email": string(rune('0'+i)) + "@example.com",
			"name":  []string{"", "alpha", "beta", "gamma", "alphabet", "omega"}[i],
			"count": int64(i * 10),
		})
	}
	cases := []struct {
		name  string
		where []storage.Where
		want  int
	}{
		{"eq", []storage.Where{storage.W("count", int64(30))}, 1},
		{"ne", []storage.Where{{Field: "count", Operator: storage.OpNe, Value: int64(30)}}, 4},
		{"gt", []storage.Where{{Field: "count", Operator: storage.OpGt, Value: int64(30)}}, 2},
		{"gte", []storage.Where{{Field: "count", Operator: storage.OpGte, Value: int64(30)}}, 3},
		{"lt", []storage.Where{{Field: "count", Operator: storage.OpLt, Value: int64(30)}}, 2},
		{"lte", []storage.Where{{Field: "count", Operator: storage.OpLte, Value: int64(30)}}, 3},
		{"in", []storage.Where{{Field: "count", Operator: storage.OpIn, Value: []any{int64(10), int64(50)}}}, 2},
		{"in-empty", []storage.Where{{Field: "count", Operator: storage.OpIn, Value: []any{}}}, 0},
		{"contains", []storage.Where{{Field: "name", Operator: storage.OpContains, Value: "lph"}}, 2},
		{"starts_with", []storage.Where{{Field: "name", Operator: storage.OpStartsWith, Value: "alpha"}}, 2},
		{"ends_with", []storage.Where{{Field: "name", Operator: storage.OpEndsWith, Value: "bet"}}, 1},
		{"and", []storage.Where{
			{Field: "count", Operator: storage.OpGte, Value: int64(20)},
			{Field: "count", Operator: storage.OpLte, Value: int64(40)},
		}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs, err := s.FindMany(ctx(), ModelThing, tc.where, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != tc.want {
				t.Fatalf("got %d records, want %d", len(recs), tc.want)
			}
			n, err := s.Count(ctx(), ModelThing, tc.where)
			if err != nil {
				t.Fatal(err)
			}
			if int(n) != tc.want {
				t.Fatalf("Count = %d, want %d (must agree with FindMany)", n, tc.want)
			}
		})
	}
}

// testOrConnector pins how mixed AND/OR clause lists are interpreted so
// backends do not disagree on precedence.
func testOrConnector(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, thing("o1", map[string]any{"count": int64(1)}))
	mustCreate(t, s, thing("o2", map[string]any{"count": int64(2)}))
	mustCreate(t, s, thing("o3", map[string]any{"count": int64(3)}))
	recs, err := s.FindMany(ctx(), ModelThing, []storage.Where{
		storage.W("id", "o1"),
		{Field: "id", Operator: storage.OpEq, Value: "o3", Connector: storage.ConnectorOr},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("OR: got %d records, want 2", len(recs))
	}
}

// testClauseFoldingPrecedence pins how a mixed AND/OR list is grouped.
// Clauses fold left to right — [a, b, OR c] is (a AND b) OR c — which
// is NOT SQL's native precedence, so each backend has to be explicit
// about it. Left unpinned, the same query silently means different
// things on different databases.
func testClauseFoldingPrecedence(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, map[string]any{"id": "p1", "email": "p1@x.com", "name": "alpha", "count": int64(1)})
	mustCreate(t, s, map[string]any{"id": "p2", "email": "p2@x.com", "name": "alpha", "count": int64(2)})
	mustCreate(t, s, map[string]any{"id": "p3", "email": "p3@x.com", "name": "beta", "count": int64(3)})

	// (name = alpha AND count = 1) OR count = 3  ->  p1, p3
	// SQL's native precedence would give
	// name = alpha AND (count = 1 OR count = 3)  ->  p1 only
	where := []storage.Where{
		storage.W("name", "alpha"),
		storage.W("count", int64(1)),
		{Field: "count", Operator: storage.OpEq, Value: int64(3), Connector: storage.ConnectorOr},
	}
	recs, err := s.FindMany(ctx(), ModelThing, where, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, rec := range recs {
		got[rec["id"].(string)] = true
	}
	if len(recs) != 2 || !got["p1"] || !got["p3"] {
		t.Fatalf("clauses must fold left to right as (a AND b) OR c; got %v", got)
	}
	n, err := s.Count(ctx(), ModelThing, where)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("Count disagrees with FindMany on clause folding: %d", n)
	}
}

// testSubstringMatching pins two properties of contains/starts_with/
// ends_with: the needle is matched literally (no wildcard or regex
// metacharacters), and matching ignores case. The first is a security
// property — these operators are fed by the admin user-search query
// parameter, where an unescaped "%" or ".*" would dump the table.
func testSubstringMatching(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, map[string]any{"id": "s1", "email": "s1@x.com", "name": "Alice Smith"})
	mustCreate(t, s, map[string]any{"id": "s2", "email": "s2@x.com", "name": "bob jones"})
	mustCreate(t, s, map[string]any{"id": "s3", "email": "s3@x.com", "name": "100% cotton"})
	mustCreate(t, s, map[string]any{"id": "s4", "email": "s4@x.com", "name": "a_c"})

	cases := []struct {
		name  string
		op    storage.Operator
		value string
		want  int
	}{
		// wildcards and regex metacharacters are literal text
		{"percent is literal", storage.OpContains, "%", 1},
		{"underscore is literal", storage.OpContains, "_", 1},
		{"underscore does not match any char", storage.OpContains, "a_c", 1},
		{"regex star is literal", storage.OpContains, ".*", 0},
		{"regex anchor is literal", storage.OpContains, "^a", 0},
		// matching ignores case
		{"contains ignores case", storage.OpContains, "alice", 1},
		{"starts_with ignores case", storage.OpStartsWith, "ALICE", 1},
		{"ends_with ignores case", storage.OpEndsWith, "SMITH", 1},
		{"mixed case needle", storage.OpContains, "JoNeS", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs, err := s.FindMany(ctx(), ModelThing,
				[]storage.Where{{Field: "name", Operator: tc.op, Value: tc.value}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != tc.want {
				ids := make([]string, 0, len(recs))
				for _, r := range recs {
					ids = append(ids, r["id"].(string))
				}
				t.Fatalf("%s %q matched %v, want %d record(s)", tc.op, tc.value, ids, tc.want)
			}
		})
	}
}

// testEmptyUpdateIsNoOp pins the behaviour of an update with nothing to
// set: it changes nothing and reports zero rows, rather than reporting
// a match count the caller might read as "the write happened".
func testEmptyUpdateIsNoOp(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, thing("e1", map[string]any{"count": int64(7)}))
	n, err := s.UpdateMany(ctx(), ModelThing, []storage.Where{storage.W("id", "e1")}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("empty UpdateMany reported %d rows, want 0", n)
	}
	got, err := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "e1")})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := got["count"].(int64); v != 7 {
		t.Fatalf("empty update modified the record: count = %#v", got["count"])
	}
}

// testUndeclaredFieldIsRejected pins that writes are as loud as reads.
// A filter on a field the schema does not declare has always been an
// error; a *write* of one used to be dropped silently, because the SQL
// and in-memory adapters rendered the write by walking the schema's
// fields and skipping everything else. The caller was told the write
// succeeded, the value was never stored, and the later read that
// filtered on it simply found nothing — a stale key, a typo, or a
// column whose migration had not been applied all looked like success.
//
// The rejection must also be complete: a write carrying one undeclared
// key alongside valid ones stores none of them, so a caller never has to
// reason about a half-applied record.
func testUndeclaredFieldIsRejected(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, thing("w1", map[string]any{"count": int64(1)}))

	if _, err := s.Create(ctx(), ModelThing, map[string]any{
		"id": "w2", "email": "w2@example.com", "nosuchfield": "x",
	}); err == nil {
		t.Fatal("Create with an undeclared field must fail, not drop the value")
	}
	if _, err := s.FindOne(ctx(), ModelThing,
		[]storage.Where{storage.W("id", "w2")}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a rejected Create must store nothing, got %v", err)
	}

	if _, err := s.Update(ctx(), ModelThing, []storage.Where{storage.W("id", "w1")},
		map[string]any{"nosuchfield": "x"}); err == nil {
		t.Fatal("Update with an undeclared field must fail")
	}
	if _, err := s.UpdateMany(ctx(), ModelThing, []storage.Where{storage.W("id", "w1")},
		map[string]any{"name": "renamed", "nosuchfield": "x"}); err == nil {
		t.Fatal("UpdateMany with an undeclared field must fail")
	}
	got, err := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "w1")})
	if err != nil {
		t.Fatal(err)
	}
	if got["name"] != "thing-w1" {
		t.Fatalf("a rejected update was partially applied: name = %#v", got["name"])
	}
	if v, _ := got["count"].(int64); v != 1 {
		t.Fatalf("a rejected update disturbed the record: count = %#v", got["count"])
	}

	// the declared fields still write, of course
	if _, err := s.Update(ctx(), ModelThing, []storage.Where{storage.W("id", "w1")},
		map[string]any{"name": "renamed"}); err != nil {
		t.Fatalf("declared field must still be writable: %v", err)
	}
}

func testPagination(t *testing.T, s storage.Adapter) {
	for i := 0; i < 10; i++ {
		mustCreate(t, s, map[string]any{
			"id": string(rune('a' + i)), "email": string(rune('a'+i)) + "@example.com",
			"count": int64(i),
		})
	}
	sort := &storage.SortBy{Field: "count", Direction: "asc"}
	page1, err := s.FindMany(ctx(), ModelThing, nil, &storage.FindOptions{Limit: 3, SortBy: sort})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1 size = %d", len(page1))
	}
	page2, err := s.FindMany(ctx(), ModelThing, nil, &storage.FindOptions{Limit: 3, Offset: 3, SortBy: sort})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 3 {
		t.Fatalf("page2 size = %d", len(page2))
	}
	if page1[0]["id"] == page2[0]["id"] {
		t.Fatal("offset did not advance the window")
	}
	// offset past the end yields nothing, not an error
	tail, err := s.FindMany(ctx(), ModelThing, nil, &storage.FindOptions{Limit: 3, Offset: 100, SortBy: sort})
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 0 {
		t.Fatalf("offset past end returned %d records", len(tail))
	}
}

func testUpdateReturnsRecord(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, thing("up", map[string]any{"count": int64(1)}))
	got, err := s.Update(ctx(), ModelThing, []storage.Where{storage.W("id", "up")},
		map[string]any{"count": int64(2), "name": "renamed"})
	if err != nil {
		t.Fatal(err)
	}
	// the returned record must reflect the update, including fields
	// that were not part of it
	if n, _ := got["count"].(int64); n != 2 {
		t.Errorf("returned count = %#v", got["count"])
	}
	if got["name"] != "renamed" {
		t.Errorf("returned name = %#v", got["name"])
	}
	if got["email"] != "up@example.com" {
		t.Errorf("returned record lost untouched fields: %#v", got["email"])
	}
}

// testUpdateTouchesOnlyTheFirstMatch pins the documented contract of
// Update (singular): it updates the FIRST record matching where, not
// every match. sqlstore historically issued an unbounded UPDATE that hit
// all matches, diverging from memory and Mongo — a difference no test
// caught while every caller happened to pass a unique key. This is that
// test.
func testUpdateTouchesOnlyTheFirstMatch(t *testing.T, s storage.Adapter) {
	for i := 0; i < 3; i++ {
		mustCreate(t, s, map[string]any{
			"id":    "fm" + string(rune('a'+i)),
			"email": "fm" + string(rune('a'+i)) + "@example.com",
			"name":  "sharedgroup", "count": int64(0),
		})
	}
	if _, err := s.Update(ctx(), ModelThing,
		[]storage.Where{storage.W("name", "sharedgroup")},
		map[string]any{"count": int64(9)}); err != nil {
		t.Fatal(err)
	}
	// Exactly one of the three rows may have changed.
	changed, err := s.Count(ctx(), ModelThing, []storage.Where{storage.W("count", int64(9))})
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Fatalf("Update changed %d rows, want exactly 1 (the first match)", changed)
	}
}

// testConditionalUpdateCount pins the compare-and-set primitive the
// API-key quota and 2FA backup codes depend on: UpdateMany must report
// how many records it actually matched.
func testConditionalUpdateCount(t *testing.T, s storage.Adapter) {
	mustCreate(t, s, thing("cas", map[string]any{"count": int64(5)}))
	n, err := s.UpdateMany(ctx(), ModelThing,
		[]storage.Where{storage.W("id", "cas"), storage.W("count", int64(5))},
		map[string]any{"count": int64(4)})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("matching CAS returned %d, want 1", n)
	}
	// the same update must now match nothing
	n, err = s.UpdateMany(ctx(), ModelThing,
		[]storage.Where{storage.W("id", "cas"), storage.W("count", int64(5))},
		map[string]any{"count": int64(3)})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("stale CAS returned %d, want 0", n)
	}
	got, _ := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "cas")})
	if v, _ := got["count"].(int64); v != 4 {
		t.Fatalf("value after CAS = %#v, want 4", got["count"])
	}
}

func testUpdateMany(t *testing.T, s storage.Adapter) {
	for i := 0; i < 3; i++ {
		mustCreate(t, s, map[string]any{
			"id": string(rune('a' + i)), "email": string(rune('a'+i)) + "@example.com",
			"name": "batch", "count": int64(i),
		})
	}
	mustCreate(t, s, thing("z", map[string]any{"name": "other"}))
	n, err := s.UpdateMany(ctx(), ModelThing, []storage.Where{storage.W("name", "batch")},
		map[string]any{"name": "updated"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("UpdateMany returned %d, want 3", n)
	}
	left, _ := s.Count(ctx(), ModelThing, []storage.Where{storage.W("name", "other")})
	if left != 1 {
		t.Fatalf("UpdateMany touched non-matching records")
	}
}

func testDeleteAndDeleteMany(t *testing.T, s storage.Adapter) {
	for i := 0; i < 4; i++ {
		mustCreate(t, s, map[string]any{
			"id": string(rune('a' + i)), "email": string(rune('a'+i)) + "@example.com",
			"name": "gone",
		})
	}
	mustCreate(t, s, thing("keep", map[string]any{"name": "stay"}))

	if err := s.Delete(ctx(), ModelThing, []storage.Where{storage.W("id", "a")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", "a")}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("record still present after Delete")
	}
	n, err := s.DeleteMany(ctx(), ModelThing, []storage.Where{storage.W("name", "gone")})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("DeleteMany returned %d, want 3", n)
	}
	total, _ := s.Count(ctx(), ModelThing, nil)
	if total != 1 {
		t.Fatalf("%d records left, want 1", total)
	}
	// deleting an id that is now free must let it be reused
	mustCreate(t, s, thing("a", nil))
}

func testCount(t *testing.T, s storage.Adapter) {
	n, err := s.Count(ctx(), ModelThing, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("empty count = %d", n)
	}
	for i := 0; i < 3; i++ {
		mustCreate(t, s, map[string]any{
			"id": string(rune('a' + i)), "email": string(rune('a'+i)) + "@example.com",
		})
	}
	if n, _ := s.Count(ctx(), ModelThing, nil); n != 3 {
		t.Fatalf("count = %d, want 3", n)
	}
}

// testExpirySweep mirrors what CleanupExpired does: delete everything
// whose timestamp is in the past. A backend that compares timestamps
// incorrectly would delete live rows or none at all.
func testExpirySweep(t *testing.T, s storage.Adapter) {
	now := time.Now().UTC()
	mustCreate(t, s, map[string]any{"id": "old1", "email": "old1@x.com", "createdAt": now.Add(-2 * time.Hour)})
	mustCreate(t, s, map[string]any{"id": "old2", "email": "old2@x.com", "createdAt": now.Add(-1 * time.Minute)})
	mustCreate(t, s, map[string]any{"id": "new1", "email": "new1@x.com", "createdAt": now.Add(time.Hour)})
	mustCreate(t, s, map[string]any{"id": "new2", "email": "new2@x.com", "createdAt": now.Add(24 * time.Hour)})

	n, err := s.DeleteMany(ctx(), ModelThing,
		[]storage.Where{{Field: "createdAt", Operator: storage.OpLte, Value: now}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("swept %d records, want exactly the 2 expired ones", n)
	}
	for _, id := range []string{"new1", "new2"} {
		if _, err := s.FindOne(ctx(), ModelThing, []storage.Where{storage.W("id", id)}); err != nil {
			t.Fatalf("sweep deleted a live record %q: %v", id, err)
		}
	}
}

// testConcurrentUniqueInsert asserts the unique constraint holds under
// concurrency: exactly one writer may win.
func testConcurrentUniqueInsert(t *testing.T, s storage.Adapter) {
	const n = 8
	results := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			<-start
			_, err := s.Create(ctx(), ModelThing, map[string]any{
				"id": "race-" + string(rune('a'+i)), "email": "race@example.com",
			})
			results <- err
		}(i)
	}
	close(start)
	success := 0
	for i := 0; i < n; i++ {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, storage.ErrUniqueViolation):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("%d concurrent inserts of the same unique value succeeded, want 1", success)
	}
	count, _ := s.Count(ctx(), ModelThing, []storage.Where{storage.W("email", "race@example.com")})
	if count != 1 {
		t.Fatalf("%d records stored, want 1", count)
	}
}
