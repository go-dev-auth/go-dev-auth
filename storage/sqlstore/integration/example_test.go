package integration_test

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage/sqlstore"

	_ "github.com/mattn/go-sqlite3"
)

// A complete application against a real SQL database, migration
// included.
//
// The ordering is the thing to copy: build the adapter with a nil
// schema, hand it to godevauth.New, and let New do the rest. New passes
// the adapter the *complete* schema through storage.SchemaAware — core
// tables, plus the columns and tables every configured plugin adds —
// and only then calls Migrate. Migrating before that point would create
// the four core tables and miss, for instance, the twoFactor table and
// the twoFactorEnabled column the plugin below needs.
//
// SQLite is used here so the example can run; swap the driver, the DSN
// and sqlstore.SQLite for sqlstore.Postgres or sqlstore.MySQL.
func Example() {
	dir, err := os.MkdirTemp("", "godevauth-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := sql.Open("sqlite3",
		"file:"+filepath.Join(dir, "app.db")+"?_busy_timeout=5000&_journal=WAL&_fk=1")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// SQLite takes one writer at a time; serialise them in Go.
	db.SetMaxOpenConns(1)

	store := sqlstore.New(db, sqlstore.SQLite, nil)

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

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())

	// The tables exist by now: New migrated them.
	rec := httptest.NewRecorder()
	signUp := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email",
		strings.NewReader(`{"email":"ada@example.com","password":"correct-horse","name":"Ada"}`))
	signUp.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, signUp)
	fmt.Println("sign-up:", rec.Code)

	req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	sd, err := auth.GetSession(req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("session for:", sd.User.Email)

	// The plugin's table is there too, because Migrate ran after New
	// supplied the full schema.
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM "twoFactor"`).Scan(&count); err != nil {
		log.Fatal(err)
	}
	fmt.Println("twoFactor rows:", count)

	// Output:
	// sign-up: 200
	// session for: ada@example.com
	// twoFactor rows: 0
}
