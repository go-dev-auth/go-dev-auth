package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Regression test for L14: a rolled-back transaction must leave the
// store exactly as it was, and — unlike the previous implementation —
// must not discard writes committed by other operations. The old code
// snapshotted, released the lock, and on error overwrote the tables
// with the snapshot, wiping anything written meanwhile.
func TestTransactionRollbackIsIsolated(t *testing.T) {
	a := New()
	ctx := context.Background()
	if _, err := a.Create(ctx, "t", map[string]any{"id": "seed"}); err != nil {
		t.Fatal(err)
	}

	// A transaction that writes then fails must leave no trace.
	wantErr := errors.New("boom")
	err := a.Transaction(ctx, func(tx storage.Adapter) error {
		if _, err := tx.Create(ctx, "t", map[string]any{"id": "in-tx"}); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want boom", err)
	}
	if n, _ := a.Count(ctx, "t", nil); n != 1 {
		t.Fatalf("after rollback rows = %d, want 1 (only the seed)", n)
	}
	if _, err := a.FindOne(ctx, "t", []storage.Where{storage.W("id", "in-tx")}); err == nil {
		t.Fatal("a row written in a rolled-back transaction survived")
	}
}

// A committed transaction's writes are visible afterwards.
func TestTransactionCommit(t *testing.T) {
	a := New()
	ctx := context.Background()
	err := a.Transaction(ctx, func(tx storage.Adapter) error {
		_, err := tx.Create(ctx, "t", map[string]any{"id": "committed"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.FindOne(ctx, "t", []storage.Where{storage.W("id", "committed")}); err != nil {
		t.Fatal("a committed transaction's write is not visible")
	}
}

// Writes made by other goroutines while a transaction runs are not
// clobbered by a rollback: the transaction holds the store lock for its
// duration, so such writes are simply serialised after it, never lost.
func TestTransactionDoesNotDiscardConcurrentWrites(t *testing.T) {
	a := New()
	ctx := context.Background()

	done := make(chan struct{})
	err := a.Transaction(ctx, func(tx storage.Adapter) error {
		// Another goroutine tries to write during the transaction. It
		// blocks on the store lock until the transaction returns.
		go func() {
			_, _ = a.Create(ctx, "t", map[string]any{"id": "concurrent"})
			close(done)
		}()
		_, _ = tx.Create(ctx, "t", map[string]any{"id": "in-tx"})
		return errors.New("rollback")
	})
	if err == nil {
		t.Fatal("expected the injected rollback error")
	}
	<-done
	// The concurrent write, applied after the transaction released the
	// lock, must survive — the old snapshot-restore rollback wiped it.
	if _, err := a.FindOne(ctx, "t", []storage.Where{storage.W("id", "concurrent")}); err != nil {
		t.Fatal("a concurrent write was discarded by a transaction rollback")
	}
}
