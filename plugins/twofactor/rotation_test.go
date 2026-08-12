package twofactor_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// Rotating Config.Secret used to be unrecoverable: the TOTP secret in
// the database was encrypted under a key derived from the old value and
// nothing could read it again, so every enrolled user was locked out
// permanently with no error that said so.
//
// These tests pin the behaviour that replaced it.

const (
	oldSecret = "rotation-old-secret-0123456789ab"
	newSecret = "rotation-new-secret-0123456789ab"
)

// newRotationEnv mounts an instance on a shared store, so a second
// instance can be started over the same data with a different secret —
// which is exactly what a rotation deploy does.
func newRotationEnv(t *testing.T, db storage.Adapter, secret string, previous ...string) *plugintest.Env {
	t.Helper()
	return plugintest.NewWith(t, func(cfg *godevauth.Config) {
		cfg.Database = db
		cfg.Secret = secret
		cfg.PreviousSecrets = previous
		cfg.Plugins = []godevauth.Plugin{twofactor.New()}
	})
}

func TestTOTPSurvivesSecretRotation(t *testing.T) {
	db := memory.New()

	before := newRotationEnv(t, db, oldSecret)
	before.SignUp(userEmail, userPassword)
	secret, _ := enroll(t, before)

	// The rotation deploy: new secret current, old one still listed.
	after := newRotationEnv(t, db, newSecret, oldSecret)
	client := after.Client()
	res, body := client.SignIn(userEmail, userPassword)
	after.RequireStatus(res, body, http.StatusOK)
	if body["twoFactorRedirect"] != true {
		t.Fatalf("sign-in = %v, want a pending second factor", body)
	}
	res, body = client.POST("/two-factor/verify-totp", map[string]any{"code": totp(t, secret)})
	after.RequireStatus(res, body, http.StatusOK)
	if !client.Signed() {
		t.Fatal("the enrolled user could not complete sign-in after the secret was rotated")
	}
}

// The other half of the contract: once the old secret is gone the value
// is unreadable, and that must be reported as a server-side fault, not
// swallowed or mistaken for a wrong code.
func TestTOTPFailsLoudlyWhenTheKeyIsGone(t *testing.T) {
	db := memory.New()

	before := newRotationEnv(t, db, oldSecret)
	before.SignUp(userEmail, userPassword)
	secret, backupCodes := enroll(t, before)

	// Dropped the old secret without re-encrypting: the mistake.
	after := newRotationEnv(t, db, newSecret)
	client := after.Client()
	res, body := client.SignIn(userEmail, userPassword)
	after.RequireStatus(res, body, http.StatusOK)

	res, body = client.POST("/two-factor/verify-totp", map[string]any{"code": totp(t, secret)})
	after.RequireErrorCode(res, body, http.StatusInternalServerError, "TWO_FACTOR_SECRET_UNREADABLE")
	if client.Signed() {
		t.Fatal("a session was issued despite an unreadable second factor")
	}
	// A correct code must not be reported as an invalid one: that would
	// send the user round a loop that can never succeed.
	if body["code"] == "INVALID_TWO_FACTOR_CODE" {
		t.Fatal("an unreadable stored secret was reported as a bad code")
	}

	// Backup codes are stored the same way and fail the same way.
	res, body = client.POST("/two-factor/verify-backup-code", map[string]any{"code": backupCodes[0]})
	after.RequireErrorCode(res, body, http.StatusInternalServerError, "TWO_FACTOR_SECRET_UNREADABLE")
}

// The migration step: after re-encrypting, the old secret can be
// dropped and everything still works.
func TestReencryptSecretsLetsThePreviousSecretBeDropped(t *testing.T) {
	db := memory.New()

	before := newRotationEnv(t, db, oldSecret)
	before.SignUp(userEmail, userPassword)
	secret, _ := enroll(t, before)

	during := newRotationEnv(t, db, newSecret, oldSecret)
	res, err := during.Auth.ReencryptSecrets(context.Background())
	if err != nil {
		t.Fatalf("ReencryptSecrets: %v", err)
	}
	if res.Unreadable != 0 {
		t.Fatalf("%d values were unreadable during migration", res.Unreadable)
	}
	// The TOTP secret and the backup-code blob.
	if res.Rewritten != 2 {
		t.Fatalf("Rewritten = %d, want 2 (secret + backupCodes)", res.Rewritten)
	}
	// Idempotent: a second pass finds nothing left to do.
	again, err := during.Auth.ReencryptSecrets(context.Background())
	if err != nil {
		t.Fatalf("second ReencryptSecrets: %v", err)
	}
	if again.Rewritten != 0 {
		t.Fatalf("second pass rewrote %d values, want 0", again.Rewritten)
	}
	if again.Scanned != 2 {
		t.Fatalf("second pass scanned %d values, want 2", again.Scanned)
	}

	// Final deploy: old secret gone, users unaffected.
	after := newRotationEnv(t, db, newSecret)
	client := after.Client()
	res2, body := client.SignIn(userEmail, userPassword)
	after.RequireStatus(res2, body, http.StatusOK)
	res2, body = client.POST("/two-factor/verify-totp", map[string]any{"code": totp(t, secret)})
	after.RequireStatus(res2, body, http.StatusOK)
	if !client.Signed() {
		t.Fatal("sign-in failed after the previous secret was dropped")
	}
}

// S-1. ReencryptSecrets does read-decrypt-encrypt-write. Without a
// predicate on the write, a set of backup codes regenerated while the
// pass was running is silently replaced by the set the pass read — so a
// user who regenerates their codes after a compromise has the old ones
// restored, and the codes the attacker holds work again.
type midPassWriter struct {
	storage.Adapter
	mu    sync.Mutex
	fired bool
	model string
	hook  func()
}

func (m *midPassWriter) FindMany(ctx context.Context, model string, where []storage.Where, opts *storage.FindOptions) ([]map[string]any, error) {
	out, err := m.Adapter.FindMany(ctx, model, where, opts)
	m.mu.Lock()
	fire := !m.fired && model == m.model && len(out) > 0
	if fire {
		m.fired = true
	}
	m.mu.Unlock()
	if fire {
		m.hook()
	}
	return out, err
}

func TestReencryptSecretsDoesNotRestoreRevokedBackupCodes(t *testing.T) {
	base := memory.New()
	db := &midPassWriter{Adapter: base, model: twofactor.ModelTwoFactor}

	before := newRotationEnv(t, db, oldSecret)
	before.SignUp(userEmail, userPassword)
	_, compromised := enroll(t, before)

	during := newRotationEnv(t, db, newSecret, oldSecret)
	ctx := context.Background()

	// The user regenerates their codes the moment the migration pass
	// has read the row.
	var fresh []string
	db.hook = func() {
		client := during.Client()
		res, body := client.SignIn(userEmail, userPassword)
		during.RequireStatus(res, body, http.StatusOK)
		res, body = client.POST("/two-factor/verify-totp",
			map[string]any{"code": totp(t, mustSecret(t, during))})
		during.RequireStatus(res, body, http.StatusOK)
		res, body = client.POST("/two-factor/generate-backup-codes",
			map[string]any{"password": userPassword})
		during.RequireStatus(res, body, http.StatusOK)
		for _, c := range body["backupCodes"].([]any) {
			fresh = append(fresh, c.(string))
		}
	}

	if _, err := during.Auth.ReencryptSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fresh) == 0 {
		t.Fatal("the concurrent regeneration did not happen; the test proves nothing")
	}

	// A compromised code must not work again.
	client := during.Client()
	res, body := client.SignIn(userEmail, userPassword)
	during.RequireStatus(res, body, http.StatusOK)
	res, body = client.POST("/two-factor/verify-backup-code",
		map[string]any{"code": compromised[0]})
	if res.StatusCode == http.StatusOK {
		t.Fatal("a revoked backup code was restored by the re-encryption pass")
	}
	during.RequireErrorCode(res, body, http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE")

	// ... and a freshly issued one must.
	client = during.Client()
	res, body = client.SignIn(userEmail, userPassword)
	during.RequireStatus(res, body, http.StatusOK)
	res, body = client.POST("/two-factor/verify-backup-code", map[string]any{"code": fresh[0]})
	during.RequireStatus(res, body, http.StatusOK)
	if !client.Signed() {
		t.Fatal("the current backup codes stopped working")
	}
}

// mustSecret reads the enrolled TOTP secret back through the API.
func mustSecret(t *testing.T, env *plugintest.Env) string {
	t.Helper()
	client := env.Client()
	res, body := client.SignIn(userEmail, userPassword)
	env.RequireStatus(res, body, http.StatusOK)
	// The user is challenged, so the URI endpoint is not reachable
	// without completing the factor; read the secret from storage
	// instead, which is what a test fixture may do.
	rec, err := env.Auth.Storage().FindOne(context.Background(), twofactor.ModelTwoFactor, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := rec["id"].(string)
	enc, _ := rec["secret"].(string)
	secret, err := env.Auth.Keyring().Decrypt(
		crypto.Binding{Model: twofactor.ModelTwoFactor, Record: id, Field: "secret"}, enc)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}
