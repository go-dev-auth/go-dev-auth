package memory

import (
	"context"
	"testing"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

func TestCRUD(t *testing.T) {
	a := New()
	ctx := context.Background()

	if _, err := a.Create(ctx, "user", map[string]any{"id": "1", "email": "a@x.com", "age": 30}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Create(ctx, "user", map[string]any{"id": "2", "email": "b@x.com", "age": 40}); err != nil {
		t.Fatal(err)
	}

	rec, err := a.FindOne(ctx, "user", []storage.Where{storage.W("email", "a@x.com")})
	if err != nil || rec["id"] != "1" {
		t.Fatalf("FindOne: %v %v", rec, err)
	}
	if _, err := a.FindOne(ctx, "user", []storage.Where{storage.W("email", "nope")}); err != storage.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	recs, err := a.FindMany(ctx, "user", []storage.Where{
		{Field: "age", Operator: storage.OpGte, Value: 30},
	}, &storage.FindOptions{SortBy: &storage.SortBy{Field: "age", Direction: "desc"}})
	if err != nil || len(recs) != 2 || recs[0]["id"] != "2" {
		t.Fatalf("FindMany sorted: %v %v", recs, err)
	}

	recs, _ = a.FindMany(ctx, "user", nil, &storage.FindOptions{Limit: 1, Offset: 1})
	if len(recs) != 1 {
		t.Fatalf("pagination: %v", recs)
	}

	if _, err := a.Update(ctx, "user", []storage.Where{storage.W("id", "1")}, map[string]any{"age": 31}); err != nil {
		t.Fatal(err)
	}
	rec, _ = a.FindOne(ctx, "user", []storage.Where{storage.W("id", "1")})
	if rec["age"] != 31 {
		t.Fatalf("age = %v", rec["age"])
	}

	n, err := a.Count(ctx, "user", nil)
	if err != nil || n != 2 {
		t.Fatalf("Count = %d %v", n, err)
	}

	if err := a.Delete(ctx, "user", []storage.Where{storage.W("id", "1")}); err != nil {
		t.Fatal(err)
	}
	n, _ = a.Count(ctx, "user", nil)
	if n != 1 {
		t.Fatalf("Count after delete = %d", n)
	}

	dn, err := a.DeleteMany(ctx, "user", nil)
	if err != nil || dn != 1 {
		t.Fatalf("DeleteMany = %d %v", dn, err)
	}
}

func TestWhereOperators(t *testing.T) {
	a := New()
	ctx := context.Background()
	_, _ = a.Create(ctx, "m", map[string]any{"id": "1", "name": "alpha"})
	_, _ = a.Create(ctx, "m", map[string]any{"id": "2", "name": "beta"})

	recs, _ := a.FindMany(ctx, "m", []storage.Where{
		{Field: "name", Operator: storage.OpContains, Value: "lph"},
	}, nil)
	if len(recs) != 1 || recs[0]["id"] != "1" {
		t.Fatalf("contains: %v", recs)
	}
	recs, _ = a.FindMany(ctx, "m", []storage.Where{
		{Field: "name", Operator: storage.OpIn, Value: []any{"alpha", "beta"}},
	}, nil)
	if len(recs) != 2 {
		t.Fatalf("in: %v", recs)
	}
	recs, _ = a.FindMany(ctx, "m", []storage.Where{
		storage.W("id", "1"),
		{Field: "id", Operator: storage.OpEq, Value: "2", Connector: storage.ConnectorOr},
	}, nil)
	if len(recs) != 2 {
		t.Fatalf("or: %v", recs)
	}
}
