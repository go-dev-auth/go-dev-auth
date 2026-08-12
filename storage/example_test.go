package storage_test

import (
	"context"
	"fmt"
	"log"

	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Querying an adapter directly, which is what a plugin does with
// Auth.Storage(). Records are map[string]any keyed by the field names
// the schema declares, so a plugin can add models without code
// generation.
//
// W builds an equality clause; the long form of Where covers the other
// operators. Clauses are ANDed unless a Connector says otherwise.
func ExampleW() {
	// A plugin's own model. In a plugin this is registered from
	// Schema(*storage.Schema) and godevauth.New passes it to the
	// adapter; here it is wired up by hand.
	schema := storage.CoreSchema()
	schema.AddTable(&storage.Table{Name: "widget", Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "userId", Type: storage.FieldString, Required: true, Index: true},
		{Name: "label", Type: storage.FieldString},
		{Name: "size", Type: storage.FieldInt},
	}})

	db := memory.New()
	db.SetSchema(schema)

	ctx := context.Background()
	for i, label := range []string{"small", "medium", "large"} {
		if _, err := db.Create(ctx, "widget", map[string]any{
			"id":     fmt.Sprintf("w%d", i),
			"userId": "user-1",
			"label":  label,
			"size":   (i + 1) * 10,
		}); err != nil {
			log.Fatal(err)
		}
	}

	// Every write a plugin makes should be scoped to the caller, which
	// in practice means a userId clause on every query.
	found, err := db.FindMany(ctx, "widget", []storage.Where{
		storage.W("userId", "user-1"),
		{Field: "size", Operator: storage.OpGte, Value: 20},
	}, &storage.FindOptions{
		SortBy: &storage.SortBy{Field: "size", Direction: "desc"},
		Limit:  2,
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, rec := range found {
		fmt.Println(rec["label"], rec["size"])
	}

	// Output:
	// large 30
	// medium 20
}
