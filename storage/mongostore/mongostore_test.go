package mongostore_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/mongostore"
	"github.com/go-dev-auth/go-dev-auth/storage/mongostore/internal/fakemongo"
	"github.com/go-dev-auth/go-dev-auth/storage/storagetest"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// dbSeq gives every subtest its own database so state never leaks
// between conformance cases.
var dbSeq atomic.Int64

// TestConformance runs the shared adapter conformance suite against the
// in-process fake MongoDB server.
func TestConformance(t *testing.T) {
	uri := fakemongo.Start(t)

	storagetest.Run(t, func(t *testing.T) (storage.Adapter, func()) {
		t.Helper()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri).SetDirect(true))
		if err != nil {
			t.Fatalf("connect: %v", err)
		}

		dbName := fmt.Sprintf("testdb%d", dbSeq.Add(1))
		store := mongostore.New(client.Database(dbName))
		store.SetSchema(storagetest.Schema())
		if err := store.EnsureIndexes(ctx); err != nil {
			t.Fatalf("EnsureIndexes: %v", err)
		}

		return store, func() {
			disconnectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = client.Disconnect(disconnectCtx)
		}
	})
}

// TestPingAndHandshake is a smoke test that the fake server completes
// topology discovery, so a conformance failure can be attributed to the
// adapter rather than to the connection.
func TestPingAndHandshake(t *testing.T) {
	uri := fakemongo.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri).SetDirect(true))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	if err := client.Ping(ctx, nil); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// TestUnknownCommand pins the CommandNotFound shape, since the driver
// relies on it to distinguish "old server" from "broken server".
func TestUnknownCommand(t *testing.T) {
	uri := fakemongo.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri).SetDirect(true))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	err = client.Database("testdb").RunCommand(ctx, map[string]any{"noSuchThing": 1}).Err()
	var cmdErr mongo.CommandError
	if !asCommandError(err, &cmdErr) {
		t.Fatalf("expected a CommandError, got %v", err)
	}
	if cmdErr.Code != 59 || cmdErr.Name != "CommandNotFound" {
		t.Fatalf("got code %d name %q, want 59/CommandNotFound", cmdErr.Code, cmdErr.Name)
	}
}

func asCommandError(err error, target *mongo.CommandError) bool {
	if err == nil {
		return false
	}
	ce, ok := err.(mongo.CommandError)
	if !ok {
		return false
	}
	*target = ce
	return true
}
