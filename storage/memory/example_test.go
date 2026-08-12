package memory_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// The store to reach for in tests, examples and single-process tools.
// It enforces the unique constraints and field defaults the schema
// declares, so code written against it behaves the same on a real
// database — but the data is gone when the process exits, and nothing
// is shared between processes.
func ExampleNew() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "http://localhost:8080",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	if _, err := auth.CreateUser(ctx, &storage.User{Email: "ada@example.com"}); err != nil {
		log.Fatal(err)
	}

	// godevauth.New handed the adapter the schema, so "email" is a real
	// unique index rather than an application-level check.
	_, err = auth.CreateUser(ctx, &storage.User{Email: "ada@example.com"})
	fmt.Println("duplicate rejected:", errors.Is(err, storage.ErrUniqueViolation))

	// Output: duplicate rejected: true
}
