package sqlstore_test

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/sqlstore"
)

// Backing an Auth instance with PostgreSQL. Bring your own driver: this
// package only uses database/sql, so nothing here forces a dependency
// on you.
//
// Pass nil for the schema. godevauth.New hands the adapter the complete
// schema — core tables, plugin tables, and Config.User.AdditionalFields
// — through storage.SchemaAware, and then runs Migrate. Building the
// schema yourself and passing it here would freeze it at whatever the
// plugins looked like at that moment.
//
// This example is not run because it needs a live database.
func ExampleNew() {
	// Import the driver for its side effect, e.g.
	//   _ "github.com/jackc/pgx/v5/stdlib"   // "pgx"
	//   _ "github.com/go-sql-driver/mysql"   // "mysql"
	//   _ "github.com/mattn/go-sqlite3"      // "sqlite3"
	db, err := sql.Open("pgx", "postgres://localhost:5432/app?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	store := sqlstore.New(db, sqlstore.Postgres, nil)

	auth, err := godevauth.New(godevauth.Config{
		AppName:  "Example App",
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: store,
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{twofactor.New()},
	})
	if err != nil {
		log.Fatal(err)
	}

	// New has already created the tables, indexes and any columns the
	// plugins add to existing tables. Migrate is idempotent, so this is
	// safe on every boot.

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// When DDL belongs to a separate deploy step rather than to the
// application process.
//
// DisableAutoMigrate and VerifySchema belong together: the first stops
// New from touching the schema, the second makes it refuse to start
// when the schema it needs is not there. Without the second, a missed
// migration surfaces as a driver error inside somebody's sign-in.
//
// This example is not run because it needs a live database.
func Example_migrationsAsADeployStep() {
	db, err := sql.Open("pgx", "postgres://localhost:5432/app?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	store := sqlstore.New(db, sqlstore.Postgres, nil)

	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: store,
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{twofactor.New()},
		Advanced: godevauth.AdvancedConfig{
			DisableAutoMigrate: true,
			VerifySchema:       true,
		},
	})
	if err != nil {
		// Names the tables and columns that are missing.
		log.Fatal(err)
	}
	_ = auth

	// The migration tool's side of it: only the statements this
	// database is missing, in order. Several drivers refuse more than
	// one statement per Exec, which is why they come back separately.
	pending, err := store.PendingMigrationSQL(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	for _, stmt := range pending {
		fmt.Println(stmt + ";")
	}
}

// An adapter built with a nil *sql.DB is a DDL generator and nothing
// else: it never opens a connection. This is how you get the
// create-from-nothing schema out of the library and into a migration
// tool.
func ExampleAdapter_MigrationSQL() {
	// In an application, pass auth.Schema() instead — it includes the
	// tables and columns the plugins contribute.
	store := sqlstore.New(nil, sqlstore.Postgres, storage.CoreSchema())

	ddl := store.MigrationSQL()

	// Just the first statement, for brevity.
	first, _, _ := strings.Cut(ddl, ");")
	fmt.Println(first + ");")

	// Output:
	// CREATE TABLE IF NOT EXISTS "user" (
	//   "id" TEXT PRIMARY KEY,
	//   "name" TEXT,
	//   "email" TEXT NOT NULL UNIQUE,
	//   "emailVerified" BOOLEAN DEFAULT FALSE,
	//   "image" TEXT,
	//   "createdAt" TIMESTAMPTZ NOT NULL,
	//   "updatedAt" TIMESTAMPTZ NOT NULL
	// );
}
