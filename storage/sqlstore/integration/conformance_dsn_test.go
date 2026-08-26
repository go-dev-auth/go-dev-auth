// Real-server conformance for PostgreSQL and MySQL.
//
// The SQLite suite in conformance_test.go proves the adapter against an
// engine this repository can always run. These tests prove it against
// the servers people actually deploy on, and only run when pointed at
// one:
//
//	POSTGRES_DSN="postgres://user:pass@localhost:5432/db?sslmode=disable" go test
//	MYSQL_DSN="user:pass@tcp(localhost:3306)/db" go test
//
// Unset, each test skips with a note. In CI the environment also sets
// REQUIRE_DSN=1, which turns that skip into a failure — so the matrix
// job cannot go green because a service container failed to start and
// the suite quietly tested nothing.
//
// Isolation: every adapter the conformance factory hands out gets a
// fresh, throwaway namespace — a schema on Postgres, a database on MySQL
// — created before the test and dropped after. The adapter's own
// introspection is scoped to current_schema() / DATABASE(), so tests
// cannot see each other and reruns cannot collide with leftovers.
package integration_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/sqlstore"
	"github.com/go-dev-auth/go-dev-auth/storage/storagetest"

	mysqldrv "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// dsnFromEnv returns the DSN in the named variable, skipping the test
// when it is unset — unless REQUIRE_DSN=1, where absence is a failure
// so CI cannot pass by accidentally testing nothing.
func dsnFromEnv(t *testing.T, name string) string {
	t.Helper()
	dsn := os.Getenv(name)
	if dsn == "" {
		if os.Getenv("REQUIRE_DSN") == "1" {
			t.Fatalf("%s is not set but REQUIRE_DSN=1: this environment promised a real server", name)
		}
		t.Skipf("%s not set; skipping real-server conformance (set it to a reachable DSN to run)", name)
	}
	return dsn
}

// namespaceCounter disambiguates namespaces created within one process;
// pid and start time disambiguate across processes and reruns.
var namespaceCounter atomic.Int64

func freshNamespaceName() string {
	return fmt.Sprintf("gda_%d_%d_%d",
		os.Getpid(), time.Now().Unix(), namespaceCounter.Add(1))
}

// ---- PostgreSQL -------------------------------------------------------

// pgSearchPathDSN returns dsn altered so new connections start in the
// given schema. Both DSN forms lib/pq accepts are handled: URL form via
// a query parameter, keyword form via an appended keyword. Either way
// lib/pq forwards search_path as a run-time parameter on every
// connection in the pool, which is what makes it safe under pooling —
// a `SET search_path` after connect would only pin one connection.
func pgSearchPathDSN(t *testing.T, dsn, schema string) string {
	t.Helper()
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("POSTGRES_DSN does not parse as a URL: %v", err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	return dsn + " search_path=" + schema
}

// newPostgresStore creates a schema of its own, opens a pool scoped to
// it, and hands back a migrated adapter plus a cleanup that drops the
// schema again.
func newPostgresStore(t *testing.T, adminDSN string, schema *storage.Schema) (storage.Adapter, func()) {
	t.Helper()
	admin, err := sql.Open("postgres", adminDSN)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	ns := freshNamespaceName()
	if _, err := admin.Exec(`CREATE SCHEMA "` + ns + `"`); err != nil {
		admin.Close()
		t.Fatalf("create schema %s: %v", ns, err)
	}
	db, err := sql.Open("postgres", pgSearchPathDSN(t, adminDSN, ns))
	if err != nil {
		admin.Close()
		t.Fatalf("open postgres in schema %s: %v", ns, err)
	}
	store := sqlstore.New(db, sqlstore.Postgres, schema)
	if err := store.Migrate(context.Background()); err != nil {
		db.Close()
		admin.Close()
		t.Fatalf("migrate on postgres: %v", err)
	}
	cleanup := func() {
		db.Close()
		if _, err := admin.Exec(`DROP SCHEMA "` + ns + `" CASCADE`); err != nil {
			t.Errorf("drop schema %s: %v", ns, err)
		}
		admin.Close()
	}
	return store, cleanup
}

// TestConformancePostgres runs the shared adapter contract — including
// unique and composite-unique enforcement under concurrency — against a
// real PostgreSQL server.
func TestConformancePostgres(t *testing.T) {
	dsn := dsnFromEnv(t, "POSTGRES_DSN")
	storagetest.Run(t, func(t *testing.T) (storage.Adapter, func()) {
		return newPostgresStore(t, dsn, storagetest.Schema())
	})
}

// TestMigrateIdempotentPostgres pins boot behaviour: applications call
// Migrate on every start, so a second run against an up-to-date schema
// must change nothing and CheckSchema must report clean.
func TestMigrateIdempotentPostgres(t *testing.T) {
	dsn := dsnFromEnv(t, "POSTGRES_DSN")
	store, cleanup := newPostgresStore(t, dsn, storagetest.Schema())
	defer cleanup()
	ctx := context.Background()
	adapter := store.(*sqlstore.Adapter)
	if err := adapter.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if err := adapter.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema after Migrate reports drift: %v", err)
	}
}

// TestFullAuthFlowOnPostgres drives the primary credential flow over
// HTTP — sign-up, session, sign-out, sign-in — with the library wired to
// a real PostgreSQL database, asserting rows after each step exactly
// like the SQLite flow test does.
func TestFullAuthFlowOnPostgres(t *testing.T) {
	dsn := dsnFromEnv(t, "POSTGRES_DSN")
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { admin.Close() })
	ns := freshNamespaceName()
	if _, err := admin.Exec(`CREATE SCHEMA "` + ns + `"`); err != nil {
		t.Fatalf("create schema %s: %v", ns, err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP SCHEMA "` + ns + `" CASCADE`); err != nil {
			t.Errorf("drop schema %s: %v", ns, err)
		}
	})
	db, err := sql.Open("postgres", pgSearchPathDSN(t, dsn, ns))
	if err != nil {
		t.Fatalf("open postgres in schema %s: %v", ns, err)
	}
	t.Cleanup(func() { db.Close() })

	env, client := newAuthEnvOn(t, db, sqlstore.Postgres, nil)
	runPrimaryCredentialFlow(t, env, client)
}

// ---- MySQL ------------------------------------------------------------

// mysqlDBDSN returns dsn altered to use the given database name, with
// parseTime forced on: without it the driver scans DATETIME columns as
// []byte and every time.Time in the adapter breaks.
func mysqlDBDSN(t *testing.T, dsn, dbName string) string {
	t.Helper()
	cfg, err := mysqldrv.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("MYSQL_DSN does not parse: %v", err)
	}
	cfg.DBName = dbName
	cfg.ParseTime = true
	return cfg.FormatDSN()
}

// newMySQLStore creates a throwaway database, opens a pool on it, and
// hands back a migrated adapter plus a cleanup that drops the database.
func newMySQLStore(t *testing.T, adminDSN string, schema *storage.Schema) (storage.Adapter, func()) {
	t.Helper()
	admin, err := sql.Open("mysql", adminDSN)
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	ns := freshNamespaceName()
	if _, err := admin.Exec("CREATE DATABASE `" + ns + "`"); err != nil {
		admin.Close()
		t.Fatalf("create database %s: %v", ns, err)
	}
	db, err := sql.Open("mysql", mysqlDBDSN(t, adminDSN, ns))
	if err != nil {
		admin.Close()
		t.Fatalf("open mysql database %s: %v", ns, err)
	}
	store := sqlstore.New(db, sqlstore.MySQL, schema)
	if err := store.Migrate(context.Background()); err != nil {
		db.Close()
		admin.Close()
		t.Fatalf("migrate on mysql: %v", err)
	}
	cleanup := func() {
		db.Close()
		if _, err := admin.Exec("DROP DATABASE `" + ns + "`"); err != nil {
			t.Errorf("drop database %s: %v", ns, err)
		}
		admin.Close()
	}
	return store, cleanup
}

// TestConformanceMySQL runs the shared adapter contract against a real
// MySQL server.
func TestConformanceMySQL(t *testing.T) {
	dsn := dsnFromEnv(t, "MYSQL_DSN")
	storagetest.Run(t, func(t *testing.T) (storage.Adapter, func()) {
		return newMySQLStore(t, dsn, storagetest.Schema())
	})
}

// TestMigrateIdempotentMySQL is the MySQL twin of the Postgres test.
func TestMigrateIdempotentMySQL(t *testing.T) {
	dsn := dsnFromEnv(t, "MYSQL_DSN")
	store, cleanup := newMySQLStore(t, dsn, storagetest.Schema())
	defer cleanup()
	ctx := context.Background()
	adapter := store.(*sqlstore.Adapter)
	if err := adapter.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if err := adapter.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema after Migrate reports drift: %v", err)
	}
}

// TestFullAuthFlowOnMySQL drives the primary credential flow over HTTP
// against a real MySQL database.
func TestFullAuthFlowOnMySQL(t *testing.T) {
	dsn := dsnFromEnv(t, "MYSQL_DSN")
	admin, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	t.Cleanup(func() { admin.Close() })
	ns := freshNamespaceName()
	if _, err := admin.Exec("CREATE DATABASE `" + ns + "`"); err != nil {
		t.Fatalf("create database %s: %v", ns, err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE `" + ns + "`"); err != nil {
			t.Errorf("drop database %s: %v", ns, err)
		}
	})
	db, err := sql.Open("mysql", mysqlDBDSN(t, dsn, ns))
	if err != nil {
		t.Fatalf("open mysql database %s: %v", ns, err)
	}
	t.Cleanup(func() { db.Close() })

	env, client := newAuthEnvOn(t, db, sqlstore.MySQL, nil)
	runPrimaryCredentialFlow(t, env, client)
}

// ---- shared flow ------------------------------------------------------

// runPrimaryCredentialFlow is the backend-independent core of
// TestSignUpSessionSignOutSignIn: every assertion reads the database
// through the adapter, so a backend where writes silently fail cannot
// pass on HTTP status codes alone.
func runPrimaryCredentialFlow(t *testing.T, env *authEnv, client *testClient) {
	t.Helper()

	client.signUp("flow@example.com", "correct horse battery", "Flow")
	if n := env.count(t, "user"); n != 1 {
		t.Fatalf("after sign-up: want 1 user row, got %d", n)
	}
	if n := env.count(t, "account"); n != 1 {
		t.Fatalf("after sign-up: want 1 credential account row, got %d", n)
	}
	if n := env.count(t, "session"); n != 1 {
		t.Fatalf("after sign-up: want 1 session row, got %d", n)
	}

	res, body := client.get("/get-session")
	if res.StatusCode != http.StatusOK || body["user"] == nil {
		t.Fatalf("get-session after sign-up: %d %v", res.StatusCode, body)
	}

	if res, _ := client.post("/sign-out", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-out: %d", res.StatusCode)
	}
	if n := env.count(t, "session"); n != 0 {
		t.Fatalf("after sign-out: want 0 session rows, got %d", n)
	}

	if res, body := client.signIn("flow@example.com", "wrong password"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sign-in with wrong password: want 401, got %d %v", res.StatusCode, body)
	}
	res, body = client.signIn("flow@example.com", "correct horse battery")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign-in: %d %v", res.StatusCode, body)
	}
	if n := env.count(t, "session"); n != 1 {
		t.Fatalf("after sign-in: want 1 session row, got %d", n)
	}
}
