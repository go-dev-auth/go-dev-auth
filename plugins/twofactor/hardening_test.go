package twofactor_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
)

// totpAt is totp for a specific time, so a test can drive distinct time
// steps without waiting 30 real seconds.
func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := crypto.TOTP(secret, at, 30, 6)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// Regression test for M5: a TOTP code accepted once must not be
// accepted again inside its skew window — a shoulder-surfed or phished
// code would otherwise be replayable for ~90s.
func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	env := newEnv(t)
	secret, _ := enroll(t, env)
	code := totpAt(t, secret, time.Now())

	first := challenge(t, env)
	res, body := first.POST("/two-factor/verify-totp", map[string]any{"code": code})
	env.RequireStatus(res, body, http.StatusOK)

	// A second sign-in presenting the very same code is a replay.
	second := challenge(t, env)
	res, body = second.POST("/two-factor/verify-totp", map[string]any{"code": code})
	if res.StatusCode == http.StatusOK {
		t.Fatal("a TOTP code was accepted twice: replay protection is not working")
	}

	// A code from the next time step still works.
	third := challenge(t, env)
	next := totpAt(t, secret, time.Now().Add(30*time.Second))
	res, body = third.POST("/two-factor/verify-totp", map[string]any{"code": next})
	env.RequireStatus(res, body, http.StatusOK)
}

// Regression test for L9: once 2FA is active, re-enrolling (which
// replaces the secret and revokes the backup codes) must require proof
// of the current factor, not just the password.
func TestReEnrollRequiresCurrentCode(t *testing.T) {
	env := newEnv(t)
	enroll(t, env)

	// Password alone is refused now that 2FA is active.
	res, body := env.POST("/two-factor/enable", map[string]any{"password": userPassword})
	env.RequireErrorCode(res, body, http.StatusUnauthorized, "CURRENT_CODE_REQUIRED")

	// With a current code it goes through.
	secret := currentSecret(t, env)
	res, body = env.POST("/two-factor/enable", map[string]any{
		"password": userPassword, "code": totpAt(t, secret, time.Now()),
	})
	env.RequireStatus(res, body, http.StatusOK)
}

// Regression test for the trustDevice feature (previously dead config):
// with a duration configured, a device that verified once and asked to
// be trusted skips the challenge on the next sign-in.
func TestTrustedDeviceSkipsSecondFactor(t *testing.T) {
	env := newEnv(t, twofactor.Options{TrustDeviceDuration: 24 * time.Hour})
	secret, _ := enroll(t, env)

	device := challenge(t, env)
	res, body := device.POST("/two-factor/verify-totp", map[string]any{
		"code": totpAt(t, secret, time.Now()), "trustDevice": true,
	})
	env.RequireStatus(res, body, http.StatusOK)

	// The same browser signs in again: no challenge, straight to a
	// session.
	res, body = device.SignIn(userEmail, userPassword)
	env.RequireStatus(res, body, http.StatusOK)
	if body["twoFactorRedirect"] == true {
		t.Fatal("a trusted device was challenged again")
	}
	if device.Session() == nil {
		t.Fatal("trusted-device sign-in produced no session")
	}

	// A fresh browser is still challenged.
	other := challenge(t, env)
	_ = other

	// And without the option, trustDevice is ignored.
	plain := newEnv(t)
	sec2, _ := enroll(t, plain)
	pd := challenge(t, plain)
	res, body = pd.POST("/two-factor/verify-totp", map[string]any{
		"code": totpAt(t, sec2, time.Now()), "trustDevice": true,
	})
	plain.RequireStatus(res, body, http.StatusOK)
	res, body = pd.SignIn(userEmail, userPassword)
	plain.RequireStatus(res, body, http.StatusOK)
	if body["twoFactorRedirect"] != true {
		t.Fatal("trustDevice honoured even though no TrustDeviceDuration was set")
	}
}

// currentSecret reads the enrolled TOTP secret from storage (a test may
// reach past the API for a precondition).
func currentSecret(t *testing.T, env *plugintest.Env) string {
	t.Helper()
	rec, err := env.Auth.Storage().FindOne(t.Context(), twofactor.ModelTwoFactor, nil)
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
