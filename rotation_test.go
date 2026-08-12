package godevauth_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Rotating Config.Secret. The library must keep reading values written
// under the previous secret, must migrate them on request, and must
// fail loudly — never silently — for values it cannot read at all.

const (
	rotOld = "rotation-old-secret-0123456789ab"
	rotNew = "rotation-new-secret-0123456789ab"
)

// recordingProvider is a social provider whose refresh endpoint records
// exactly what it was handed. That is the point of the test: the old
// maybeDecrypt returned the ciphertext on failure, so an "enc:..." blob
// was shipped to the third party.
type recordingProvider struct {
	oauth2.Provider
	mu       sync.Mutex
	received []string
}

func (p *recordingProvider) RefreshToken(_ context.Context, refreshToken string) (*oauth2.Tokens, error) {
	p.mu.Lock()
	p.received = append(p.received, refreshToken)
	p.mu.Unlock()
	if refreshToken != "the-refresh-token" {
		return nil, errors.New("provider: unknown refresh token")
	}
	return &oauth2.Tokens{AccessToken: "fresh-access-token"}, nil
}

func (p *recordingProvider) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.received...)
}

// rotationEnv builds an instance over a shared store, so a second one
// can be started on the same data with a different secret.
type rotationEnv struct {
	auth     *godevauth.Auth
	client   *http.Client
	server   *httptest.Server
	provider *recordingProvider
}

func newRotationEnv(t *testing.T, db storage.Adapter, secret string, previous ...string) *rotationEnv {
	t.Helper()
	base, _ := fakeProvider(t, "fakeco", map[string]any{"id": "u1", "email": "social@example.com"})
	provider := &recordingProvider{Provider: base}

	// Open the listener first so New is given the address the server
	// will answer on; the configuration is immutable afterwards.
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)

	auth, err := godevauth.New(godevauth.Config{
		BaseURL:          "http://" + server.Listener.Addr().String(),
		Secret:           secret,
		PreviousSecrets:  previous,
		Database:         db,
		RateLimit:        godevauth.RateLimitConfig{Disabled: true},
		EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},
		Account:          godevauth.AccountConfig{EncryptOAuthTokens: true},
		SocialProviders:  []oauth2.Provider{provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	server.Config.Handler = mux
	server.Start()

	jar := &cookieJar{cookies: map[string]*http.Cookie{}}
	return &rotationEnv{
		auth:     auth,
		provider: provider,
		server:   server,
		client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

func (e *rotationEnv) tc(t *testing.T) *testClient {
	return &testClient{t: t, server: e.server, client: e.client}
}

// seedLinkedAccount creates a user with a social account whose refresh
// token is encrypted at rest under the instance's current key.
func seedLinkedAccount(t *testing.T, env *rotationEnv, email string) string {
	t.Helper()
	tc := env.tc(t)
	body := tc.signUp(email, "password123", "Rotation User")
	user, _ := body["user"].(map[string]any)
	userID, _ := user["id"].(string)

	// The ciphertext is bound to the row it is written to, so the id
	// has to exist before the value is sealed.
	accountID := crypto.GenerateID(32)
	enc, err := env.auth.Keyring().Encrypt(
		crypto.Binding{Model: storage.ModelAccount, Record: accountID, Field: "refreshToken"},
		"the-refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.auth.Storage().Create(context.Background(), storage.ModelAccount, map[string]any{
		"id":           accountID,
		"userId":       userID,
		"accountId":    "u1",
		"providerId":   "fakeco",
		"refreshToken": "enc:" + enc,
	}); err != nil {
		t.Fatal(err)
	}
	return userID
}

func TestOAuthTokenSurvivesSecretRotation(t *testing.T) {
	db := memory.New()
	before := newRotationEnv(t, db, rotOld)
	seedLinkedAccount(t, before, "rot1@example.com")

	after := newRotationEnv(t, db, rotNew, rotOld)
	tc := after.tc(t)
	tc.post("/sign-in/email", map[string]any{"email": "rot1@example.com", "password": "password123"})

	res, body := tc.post("/refresh-token", map[string]any{"providerId": "fakeco"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("refresh-token after rotation: %d %v", res.StatusCode, body)
	}
	if body["accessToken"] != "fresh-access-token" {
		t.Fatalf("accessToken = %v", body["accessToken"])
	}
	if got := after.provider.seen(); len(got) != 1 || got[0] != "the-refresh-token" {
		t.Fatalf("provider received %q, want the decrypted token", got)
	}
}

// The failure this replaces: an undecryptable token was returned as-is,
// so the "enc:" blob went straight to the OAuth provider and the caller
// got a confusing provider-side error instead of a configuration one.
func TestOAuthTokenFailsLoudlyWhenTheKeyIsGone(t *testing.T) {
	db := memory.New()
	before := newRotationEnv(t, db, rotOld)
	seedLinkedAccount(t, before, "rot2@example.com")

	after := newRotationEnv(t, db, rotNew) // old secret dropped
	tc := after.tc(t)
	tc.post("/sign-in/email", map[string]any{"email": "rot2@example.com", "password": "password123"})

	res, body := tc.post("/refresh-token", map[string]any{"providerId": "fakeco"})
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %v", res.StatusCode, body)
	}
	if body["code"] != "TOKEN_DECRYPTION_FAILED" {
		t.Fatalf("code = %v, want TOKEN_DECRYPTION_FAILED", body["code"])
	}
	// Nothing may reach the provider at all, least of all ciphertext.
	for _, got := range after.provider.seen() {
		t.Fatalf("the provider was contacted with %q despite an unreadable token", got)
	}
}

func TestReencryptSecretsMigratesAccountTokens(t *testing.T) {
	db := memory.New()
	before := newRotationEnv(t, db, rotOld)
	seedLinkedAccount(t, before, "rot3@example.com")

	during := newRotationEnv(t, db, rotNew, rotOld)
	res, err := during.auth.ReencryptSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 1 || res.Rewritten != 1 || res.Unreadable != 0 {
		t.Fatalf("result = %+v, want one value rewritten", res)
	}

	// Old secret dropped: still works.
	after := newRotationEnv(t, db, rotNew)
	tc := after.tc(t)
	tc.post("/sign-in/email", map[string]any{"email": "rot3@example.com", "password": "password123"})
	httpRes, body := tc.post("/refresh-token", map[string]any{"providerId": "fakeco"})
	if httpRes.StatusCode != http.StatusOK {
		t.Fatalf("refresh-token after dropping the previous secret: %d %v", httpRes.StatusCode, body)
	}
}

// Values already in a database predate key ids entirely. Upgrading must
// not require a migration first.
func TestLegacyCiphertextIsStillReadable(t *testing.T) {
	db := memory.New()
	env := newRotationEnv(t, db, rotOld)

	tc := env.tc(t)
	signUp := tc.signUp("legacy@example.com", "password123", "Legacy")
	user, _ := signUp["user"].(map[string]any)
	userID, _ := user["id"].(string)

	// Written the way the library used to write it: no version, no key
	// id, key = sha256("go-dev-auth-enc:"+secret).
	legacy := legacyEncryptForTest(t, rotOld, "the-refresh-token")
	if strings.Contains(legacy, ".") {
		t.Fatal("the legacy fixture is not in the legacy format")
	}
	if _, err := env.auth.Storage().Create(context.Background(), storage.ModelAccount, map[string]any{
		"id": crypto.GenerateID(32), "userId": userID, "accountId": "u1",
		"providerId": "fakeco", "refreshToken": "enc:" + legacy,
	}); err != nil {
		t.Fatal(err)
	}

	tc.post("/sign-in/email", map[string]any{"email": "legacy@example.com", "password": "password123"})
	res, body := tc.post("/refresh-token", map[string]any{"providerId": "fakeco"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a pre-upgrade value was not readable: %d %v", res.StatusCode, body)
	}

	// And re-encryption moves it to the current format.
	migrated, err := env.auth.ReencryptSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Rewritten != 1 {
		t.Fatalf("legacy value was not migrated: %+v", migrated)
	}
}

// legacyEncryptForTest reproduces the pre-versioning on-disk format, so
// the compatibility test is pinned to the bytes a real deployment has
// in its database rather than to whatever the package writes today.
func legacyEncryptForTest(t *testing.T, secret, plaintext string) string {
	t.Helper()
	sum := sha256.Sum256([]byte("go-dev-auth-enc:" + secret))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plaintext), nil))
}

func TestConfigRejectsPreviousSecretMistakes(t *testing.T) {
	base := func() godevauth.Config {
		return godevauth.Config{
			BaseURL: "https://x.test", Secret: rotNew, Database: memory.New(),
		}
	}
	cases := map[string][]string{
		"empty entry":         {""},
		"same as the current": {rotNew},
	}
	for name, previous := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			cfg.PreviousSecrets = previous
			if _, err := godevauth.New(cfg); err == nil {
				t.Fatal("expected New to reject the configuration")
			}
		})
	}
}

// ---- S-1: ReencryptSecrets on a live instance ----
//
// ReencryptSecrets does read-decrypt-encrypt-write. Without a predicate
// on the write, anything that changed between the read and the write is
// silently reverted: a token refreshed by /refresh-token goes back to
// the stale value, and a set of backup codes regenerated after a
// compromise is restored, re-enabling codes the attacker holds.

// hookAdapter runs a callback the first time FindMany returns, which is
// exactly the window a concurrent writer would land in.
type hookAdapter struct {
	storage.Adapter
	mu    sync.Mutex
	once  bool
	model string
	hook  func()

	findManyOpts []*storage.FindOptions
}

func (h *hookAdapter) FindMany(ctx context.Context, model string, where []storage.Where, opts *storage.FindOptions) ([]map[string]any, error) {
	out, err := h.Adapter.FindMany(ctx, model, where, opts)
	h.mu.Lock()
	h.findManyOpts = append(h.findManyOpts, opts)
	fire := h.hook != nil && !h.once && model == h.model && len(out) > 0
	if fire {
		h.once = true
	}
	h.mu.Unlock()
	if fire {
		h.hook()
	}
	return out, err
}

func (h *hookAdapter) opts() []*storage.FindOptions {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*storage.FindOptions(nil), h.findManyOpts...)
}

func accountBindingFor(id, field string) crypto.Binding {
	return crypto.Binding{Model: storage.ModelAccount, Record: id, Field: field}
}

// A write that lands mid-pass must win. The re-encryption of that row is
// skipped, not applied over the top of it.
func TestReencryptSecretsDoesNotClobberAConcurrentWrite(t *testing.T) {
	base := memory.New()
	db := &hookAdapter{Adapter: base, model: storage.ModelAccount}
	before := newRotationEnv(t, db, rotOld)
	seedLinkedAccount(t, before, "cas@example.com")

	during := newRotationEnv(t, db, rotNew, rotOld)
	ctx := context.Background()

	// Find the row the pass is about to rewrite, and arrange for a
	// fresh token to be written to it the moment the pass has read it.
	rows, err := base.FindMany(ctx, storage.ModelAccount,
		[]storage.Where{storage.W("providerId", "fakeco")}, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected exactly one social account: %v (%d)", err, len(rows))
	}
	accountID, _ := rows[0]["id"].(string)

	concurrent, err := during.auth.Keyring().Encrypt(
		accountBindingFor(accountID, "refreshToken"), "token-refreshed-mid-pass")
	if err != nil {
		t.Fatal(err)
	}
	db.hook = func() {
		if _, err := base.Update(ctx, storage.ModelAccount,
			[]storage.Where{storage.W("id", accountID)},
			map[string]any{"refreshToken": "enc:" + concurrent}); err != nil {
			t.Error(err)
		}
	}

	res, err := during.auth.ReencryptSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rewritten != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the row skipped, not rewritten", res)
	}
	if res.Done() {
		t.Fatal("a pass that skipped a row must not report Done")
	}

	after, err := base.FindOne(ctx, storage.ModelAccount, []storage.Where{storage.W("id", accountID)})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := after["refreshToken"].(string)
	plain, err := during.auth.Keyring().Decrypt(
		accountBindingFor(accountID, "refreshToken"), strings.TrimPrefix(stored, "enc:"))
	if err != nil {
		t.Fatal(err)
	}
	if plain != "token-refreshed-mid-pass" {
		t.Fatalf("the concurrent write was reverted: stored token is %q", plain)
	}
}

// The pass must page through the table rather than loading it whole.
func TestReencryptSecretsWalksTheTableInBatches(t *testing.T) {
	base := memory.New()
	db := &hookAdapter{Adapter: base}
	before := newRotationEnv(t, db, rotOld)
	ctx := context.Background()

	const rows = 250 // more than one batch
	for i := 0; i < rows; i++ {
		id := crypto.GenerateID(32)
		enc, err := before.auth.Keyring().Encrypt(accountBindingFor(id, "refreshToken"), "tok")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := base.Create(ctx, storage.ModelAccount, map[string]any{
			"id": id, "userId": "u" + strconv.Itoa(i), "accountId": "a" + strconv.Itoa(i),
			"providerId": "fakeco", "refreshToken": "enc:" + enc,
		}); err != nil {
			t.Fatal(err)
		}
	}

	during := newRotationEnv(t, db, rotNew, rotOld)
	db.mu.Lock()
	db.findManyOpts = nil
	db.mu.Unlock()

	res, err := during.auth.ReencryptSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rewritten != rows {
		t.Fatalf("Rewritten = %d, want %d", res.Rewritten, rows)
	}

	var accountReads int
	for _, o := range db.opts() {
		if o == nil {
			continue
		}
		if o.Limit > 0 {
			accountReads++
			if o.Limit > 1000 {
				t.Fatalf("batch size %d is not a batch", o.Limit)
			}
		}
	}
	if accountReads < 2 {
		t.Fatalf("the account table was read in %d bounded queries; %d rows must not be loaded in one go",
			accountReads, rows)
	}
	for _, o := range db.opts() {
		if o == nil {
			t.Fatal("ReencryptSecrets issued an unbounded FindMany over a table it is migrating")
		}
	}
}

// failingRotator is a plugin whose rotation always fails.
type failingRotator struct{ called, jwtRan *bool }

func (f *failingRotator) ID() string                 { return "failing-rotator" }
func (f *failingRotator) Init(*godevauth.Auth) error { return nil }
func (f *failingRotator) Routes() []godevauth.Route  { return nil }
func (f *failingRotator) ReencryptSecrets(context.Context) (godevauth.ReencryptResult, error) {
	*f.called = true
	return godevauth.ReencryptResult{}, errors.New("transient storage failure")
}

// countingRotator records that it ran.
type countingRotator struct{ ran *bool }

func (c *countingRotator) ID() string                 { return "counting-rotator" }
func (c *countingRotator) Init(*godevauth.Auth) error { return nil }
func (c *countingRotator) Routes() []godevauth.Route  { return nil }
func (c *countingRotator) ReencryptSecrets(context.Context) (godevauth.ReencryptResult, error) {
	*c.ran = true
	return godevauth.ReencryptResult{Scanned: 1, Rewritten: 1}, nil
}

// One rotator failing must not cancel the rest: the jwt signing key
// cannot be left un-migrated because the two-factor table happened to
// be listed first.
func TestReencryptSecretsContinuesPastAFailingRotator(t *testing.T) {
	var failed, ran bool
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:   "http://127.0.0.1",
		Secret:    rotNew,
		Database:  memory.New(),
		RateLimit: godevauth.RateLimitConfig{Disabled: true},
		Plugins: []godevauth.Plugin{
			&failingRotator{called: &failed},
			&countingRotator{ran: &ran},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := auth.ReencryptSecrets(context.Background())
	if err == nil {
		t.Fatal("the failure must still be reported")
	}
	if !strings.Contains(err.Error(), "failing-rotator") {
		t.Fatalf("err = %v, want it to name the failing plugin", err)
	}
	if !failed || !ran {
		t.Fatalf("failing ran=%v, following ran=%v: every rotator must be given a turn", failed, ran)
	}
	if res.Rewritten != 1 {
		t.Fatalf("Rewritten = %d, want the second rotator's work to be counted", res.Rewritten)
	}
}

// The whole point of the format migration: a v1 value written before
// ciphertexts were bound is rewritten as a bound v2 value, after which
// the operator can refuse unbound values entirely.
func TestReencryptSecretsMigratesUnboundValuesAndLetsThemBeRefused(t *testing.T) {
	db := memory.New()
	env := newRotationEnv(t, db, rotOld)
	ctx := context.Background()

	tc := env.tc(t)
	signUp := tc.signUp("unbound@example.com", "password123", "Unbound")
	user, _ := signUp["user"].(map[string]any)
	userID, _ := user["id"].(string)

	accountID := crypto.GenerateID(32)
	unbound := v1EncryptForTest(t, rotOld, "the-refresh-token")
	if !strings.HasPrefix(unbound, "v1.") {
		t.Fatalf("fixture %q is not a v1 value", unbound)
	}
	if _, err := db.Create(ctx, storage.ModelAccount, map[string]any{
		"id": accountID, "userId": userID, "accountId": "u1",
		"providerId": "fakeco", "refreshToken": "enc:" + unbound,
	}); err != nil {
		t.Fatal(err)
	}

	// Before migrating, a strict instance cannot read it — which is why
	// the switch is not the default.
	strict, err := godevauth.New(godevauth.Config{
		BaseURL: "http://127.0.0.1", Secret: rotOld, Database: db,
		RequireBoundCiphertexts: true,
		RateLimit:               godevauth.RateLimitConfig{Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Keyring().Decrypt(
		accountBindingFor(accountID, "refreshToken"), unbound); !errors.Is(err, crypto.ErrUnboundCiphertext) {
		t.Fatalf("err = %v, want ErrUnboundCiphertext", err)
	}

	res, err := env.auth.ReencryptSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rewritten != 1 {
		t.Fatalf("the unbound value was not migrated: %+v", res)
	}
	again, err := env.auth.ReencryptSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Done() {
		t.Fatalf("second pass = %+v, want Done", again)
	}

	// After migrating, the strict instance reads it — and the value is
	// now anchored to its column.
	rec, err := db.FindOne(ctx, storage.ModelAccount, []storage.Where{storage.W("id", accountID)})
	if err != nil {
		t.Fatal(err)
	}
	stored := strings.TrimPrefix(rec["refreshToken"].(string), "enc:")
	if !strings.HasPrefix(stored, "v2.") {
		t.Fatalf("stored value %q was not rewritten in the bound format", stored)
	}
	got, err := strict.Keyring().Decrypt(accountBindingFor(accountID, "refreshToken"), stored)
	if err != nil || got != "the-refresh-token" {
		t.Fatalf("strict read after migration = %q, %v", got, err)
	}
	if _, err := strict.Keyring().Decrypt(
		accountBindingFor(accountID, "accessToken"), stored); err == nil {
		t.Fatal("the migrated value still opens in another column")
	}
}

// v1EncryptForTest reproduces the pre-binding v1 on-disk format: the
// same scrypt-derived key as today, but with only "v1.<kid>" as
// additional data, so nothing ties the value to where it is stored.
func v1EncryptForTest(t *testing.T, secret, plaintext string) string {
	t.Helper()
	// Reach the key material the same way the package does, by writing
	// a v2 value and stealing its key id.
	kr := crypto.NewKeyring(secret)
	kid, err := kr.CurrentKeyID()
	if err != nil {
		t.Fatal(err)
	}
	master, err := crypto.Scrypt([]byte(secret), []byte("go-dev-auth-enc-v1"), 1<<14, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	encSum := sha256.Sum256(append([]byte("go-dev-auth-enc-v1:key"), master...))
	block, err := aes.NewCipher(encSum[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	header := "v1." + kid
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(
		gcm.Seal(nonce, nonce, []byte(plaintext), []byte(header)))
}
