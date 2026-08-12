package godevauth_test

import (
	"context"
	"fmt"
	"log"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	jwtplugin "github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Rotating Config.Secret is a three-step deploy, and this is the middle
// step: rewriting everything held encrypted at rest — OAuth tokens, TOTP
// secrets, JWT signing keys — under the new key.
//
// Note that cookie and token *signatures* are not versioned: rotating
// Secret signs every user out regardless of PreviousSecrets.
func ExampleAuth_ReencryptSecrets() {
	const (
		oldSecret = "kBQ8xu2n8HkPq0nzT9nH1vJc4wS7yA6dR2eF0gM3iK4="
		newSecret = "Xz3Lq9pT1sV7wB2nD5fH8jK0mR4uY6aC1eG3iL5oQ7s="
	)
	ctx := context.Background()

	// The instance as it ran before the rotation. The jwt plugin mints
	// an Ed25519 signing key on first use and stores the private half
	// encrypted with Config.Secret.
	db := memory.New()
	before := jwtplugin.New()
	if _, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   oldSecret,
		Database: db,
		Plugins:  []godevauth.Plugin{before},
	}); err != nil {
		log.Fatal(err)
	}
	if _, err := before.SignSession(ctx, &godevauth.SessionData{
		Session: &storage.Session{ID: "s1", UserID: "u1"},
		User:    &storage.User{ID: "u1", Email: "ada@example.com"},
	}); err != nil {
		log.Fatal(err)
	}

	// Step 1: deploy with the new secret in Secret and the old one in
	// PreviousSecrets. Nothing breaks — old values are still readable —
	// and new writes use the new key. Skipping this step is what locks
	// 2FA users out permanently.
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:         "https://example.com",
		Secret:          newSecret,
		PreviousSecrets: []string{oldSecret},
		Database:        db,
		Plugins:         []godevauth.Plugin{jwtplugin.New()},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Step 2: rewrite the stored values. Safe to run on a live
	// instance — every write is a compare-and-set on the ciphertext the
	// pass read, so a concurrent update is skipped rather than
	// reverted — and safe to re-run: values already under the current
	// key and in the current format are counted and left alone.
	//
	// The same pass migrates the on-disk format, rewriting values that
	// predate location binding (crypto v0 and v1) as bound v2 values.
	res, err := auth.ReencryptSecrets(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("scanned=%d rewritten=%d unreadable=%d\n",
		res.Scanned, res.Rewritten, res.Unreadable)

	// Step 3: when a pass reports Done — nothing rewritten, nothing
	// stranded, nothing skipped, nothing failed — no value is left
	// under the old key or in an unbound format. PreviousSecrets can be
	// emptied and Config.RequireBoundCiphertexts set on the next
	// deploy. A non-zero Unreadable means a secret is missing from
	// PreviousSecrets; a non-zero Skipped means a concurrent write beat
	// the pass to a row. Either way, do not drop anything yet — run it
	// again.
	again, err := auth.ReencryptSecrets(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("second pass: rewritten=%d unreadable=%d done=%v\n",
		again.Rewritten, again.Unreadable, again.Done())

	// Output:
	// scanned=1 rewritten=1 unreadable=0
	// second pass: rewritten=0 unreadable=0 done=true
}
