// Package integration_test runs the go-dev-auth adapter contract and a
// full HTTP auth flow against a real SQLite database.
//
// The unit tests next to the adapter only assert on generated SQL
// strings; they cannot catch a dialect that emits valid-looking DDL the
// engine rejects, a timestamp encoding that sorts wrong, or a driver
// error that never maps onto storage.ErrUniqueViolation. Those defects
// only appear when statements actually reach a database, so they get
// their own module with a driver dependency.
package integration_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/sqlstore"
	"github.com/go-dev-auth/go-dev-auth/storage/storagetest"

	_ "github.com/mattn/go-sqlite3"
)

// openSQLite opens a file-backed SQLite database in the test's temp
// directory. A file (not :memory:) is used deliberately: an in-memory
// database is private per connection, so the pool would hand different
// goroutines different empty databases and the concurrency test would
// pass for the wrong reason.
func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "test.db") +
		"?_busy_timeout=5000&_journal=WAL&_fk=1"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// SQLite allows only one writer at a time. The busy timeout above
	// makes contending writers wait rather than fail immediately, but a
	// deadline is still reachable under a write-heavy burst; capping
	// the pool at one connection serialises writers in Go instead and
	// makes the concurrency conformance test deterministic. This
	// mirrors what every production SQLite deployment does.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("ping sqlite: %v", err)
	}
	return db
}

// newStore builds a migrated adapter over a fresh SQLite database.
func newStore(t *testing.T, schema *storage.Schema) (*sqlstore.Adapter, *sql.DB) {
	t.Helper()
	db := openSQLite(t)
	store := sqlstore.New(db, sqlstore.SQLite, schema)
	if err := store.Migrate(context.Background()); err != nil {
		db.Close()
		t.Fatalf("migrate: %v", err)
	}
	return store, db
}

// TestConformance runs the shared adapter contract against real SQLite.
func TestConformance(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) (storage.Adapter, func()) {
		store, db := newStore(t, storagetest.Schema())
		return store, func() { db.Close() }
	})
}
