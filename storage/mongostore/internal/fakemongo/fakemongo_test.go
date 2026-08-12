package fakemongo_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-dev-auth/go-dev-auth/storage/mongostore/internal/fakemongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func connect(t *testing.T) (*mongo.Database, context.Context) {
	t.Helper()
	uri := fakemongo.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri).SetDirect(true))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return client.Database("fakedb"), ctx
}

// TestSparseUniqueIndex pins the sparse semantics the adapter depends on:
// records that never set a unique field must not collide with each other,
// while records that do set it must.
func TestSparseUniqueIndex(t *testing.T) {
	db, ctx := connect(t)
	coll := db.Collection("sparse")

	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true).SetSparse(true).SetName("uniq_email"),
	})
	if err != nil {
		t.Fatalf("CreateOne: %v", err)
	}

	for _, id := range []string{"a", "b", "c"} {
		if _, err := coll.InsertOne(ctx, bson.M{"_id": id}); err != nil {
			t.Fatalf("insert %q without email: %v", id, err)
		}
	}
	if _, err := coll.InsertOne(ctx, bson.M{"_id": "d", "email": "x@example.com"}); err != nil {
		t.Fatalf("insert with email: %v", err)
	}
	_, err = coll.InsertOne(ctx, bson.M{"_id": "e", "email": "x@example.com"})
	if !mongo.IsDuplicateKeyError(err) {
		t.Fatalf("duplicate email: got %v, want a duplicate key error", err)
	}
}

// TestNonSparseUniqueIndexTreatsMissingAsNull is the flip side: without
// sparse, two documents missing the field both index a null and collide.
func TestNonSparseUniqueIndexTreatsMissingAsNull(t *testing.T) {
	db, ctx := connect(t)
	coll := db.Collection("dense")

	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "token", Value: 1}},
		Options: options.Index().SetUnique(true).SetName("uniq_token"),
	})
	if err != nil {
		t.Fatalf("CreateOne: %v", err)
	}

	if _, err := coll.InsertOne(ctx, bson.M{"_id": "a"}); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	_, err = coll.InsertOne(ctx, bson.M{"_id": "b"})
	if !mongo.IsDuplicateKeyError(err) {
		t.Fatalf("second null token: got %v, want a duplicate key error", err)
	}
}

// TestUpdateManyReportsMatchedNotModified pins the distinction the
// adapter's compare-and-set relies on.
func TestUpdateManyReportsMatchedNotModified(t *testing.T) {
	db, ctx := connect(t)
	coll := db.Collection("counts")

	for _, id := range []string{"a", "b"} {
		if _, err := coll.InsertOne(ctx, bson.M{"_id": id, "n": int64(1)}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	// Both match; neither changes value.
	res, err := coll.UpdateMany(ctx, bson.M{"n": int64(1)}, bson.M{"$set": bson.M{"n": int64(1)}})
	if err != nil {
		t.Fatalf("UpdateMany: %v", err)
	}
	if res.MatchedCount != 2 {
		t.Errorf("MatchedCount = %d, want 2", res.MatchedCount)
	}
	if res.ModifiedCount != 0 {
		t.Errorf("ModifiedCount = %d, want 0", res.ModifiedCount)
	}
}

// TestDeleteLimit checks that limit 1 removes one document and limit 0
// removes every match.
func TestDeleteLimit(t *testing.T) {
	db, ctx := connect(t)
	coll := db.Collection("del")

	for _, id := range []string{"a", "b", "c"} {
		if _, err := coll.InsertOne(ctx, bson.M{"_id": id, "tag": "x"}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	one, err := coll.DeleteOne(ctx, bson.M{"tag": "x"})
	if err != nil || one.DeletedCount != 1 {
		t.Fatalf("DeleteOne: %v, deleted %d", err, one.DeletedCount)
	}
	many, err := coll.DeleteMany(ctx, bson.M{"tag": "x"})
	if err != nil || many.DeletedCount != 2 {
		t.Fatalf("DeleteMany: %v, deleted %d", err, many.DeletedCount)
	}
}

// TestFindAndModifyNoMatch checks that a null "value" surfaces as
// ErrNoDocuments rather than an empty document.
func TestFindAndModifyNoMatch(t *testing.T) {
	db, ctx := connect(t)
	coll := db.Collection("fam")

	err := coll.FindOneAndUpdate(ctx, bson.M{"_id": "missing"},
		bson.M{"$set": bson.M{"x": 1}}).Err()
	if err != mongo.ErrNoDocuments {
		t.Fatalf("got %v, want ErrNoDocuments", err)
	}
}

// TestStoreIsDeepCopied checks that a document handed back to a caller
// cannot be used to mutate the server's copy.
func TestStoreIsDeepCopied(t *testing.T) {
	db, ctx := connect(t)
	coll := db.Collection("copy")

	if _, err := coll.InsertOne(ctx, bson.M{"_id": "a", "nested": bson.M{"k": "v"}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var first bson.M
	if err := coll.FindOne(ctx, bson.M{"_id": "a"}).Decode(&first); err != nil {
		t.Fatalf("find: %v", err)
	}
	first["nested"].(bson.M)["k"] = "mutated"

	var second bson.M
	if err := coll.FindOne(ctx, bson.M{"_id": "a"}).Decode(&second); err != nil {
		t.Fatalf("refind: %v", err)
	}
	if got := second["nested"].(bson.M)["k"]; got != "v" {
		t.Fatalf("stored document was mutated through a returned copy: %v", got)
	}
}
